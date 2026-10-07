// Package facts collects what server-init needs to know about the host
// before asking questions (preflight results).
package facts

import (
	"context"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/mimic890/server-init/internal/sys"
)

// Facts describe the host. They are gathered once, read-only.
type Facts struct {
	OSID        string // debian, ubuntu
	OSVersion   string // 12, 24.04
	OSPretty    string
	OSSupported bool
	IsRoot      bool
	Systemd     bool
	FreeDiskMB  uint64 // on /
	Internet    bool
	SSHPorts    []int
	ClientIP    string
	ServerIP    string
	Hostname    string
	SSHSocket   bool // Ubuntu socket activation (ssh.socket)
	HasSwap     bool
	MemTotalMB  uint64
}

// MinFreeDiskMB is the lowest free space on / that preflight accepts.
const MinFreeDiskMB = 1024

// Gather collects all facts. It never changes the host.
func Gather(ctx context.Context, s sys.System, uid int) *Facts {
	f := &Facts{IsRoot: uid == 0}
	f.OSID, f.OSVersion, f.OSPretty = ParseOSRelease(sys.ReadString(s, "/etc/os-release"))
	f.OSSupported = Supported(f.OSID, f.OSVersion)
	f.Systemd = sys.Exists(s, "/run/systemd/system")
	f.FreeDiskMB = freeDiskMB("/")
	f.Internet = internet(ctx)
	f.SSHSocket = sys.UnitEnabled(ctx, s, "ssh.socket") || sys.UnitActive(ctx, s, "ssh.socket")
	f.SSHPorts = sys.SSHPorts(ctx, s)
	f.ClientIP = sys.ClientIP(s)
	f.ServerIP = sys.ServerIP(ctx, s)
	f.Hostname = strings.TrimSpace(sys.ReadString(s, "/etc/hostname"))
	swaps := sys.ReadString(s, "/proc/swaps")
	f.HasSwap = len(strings.Split(strings.TrimSpace(swaps), "\n")) > 1
	f.MemTotalMB = memTotalMB(sys.ReadString(s, "/proc/meminfo"))
	return f
}

// ParseOSRelease returns ID, VERSION_ID and PRETTY_NAME.
func ParseOSRelease(content string) (id, version, pretty string) {
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	if pretty == "" {
		pretty = strings.TrimSpace(id + " " + version)
	}
	return id, version, pretty
}

// Supported reports whether the OS is Debian 12+ or Ubuntu 24.04+.
func Supported(id, version string) bool {
	major, minor := splitVersion(version)
	switch id {
	case "debian":
		return major >= 12
	case "ubuntu":
		return major > 24 || major == 24 && minor >= 4
	}
	return false
}

func splitVersion(v string) (int, int) {
	maj, mnr, _ := strings.Cut(v, ".")
	return atoi(maj), atoi(mnr)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func freeDiskMB(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize) / (1 << 20)
}

func memTotalMB(meminfo string) uint64 {
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemTotal:" {
			return uint64(atoi(f[1])) / 1024
		}
	}
	return 0
}

// internet checks that the package mirrors are reachable.
func internet(ctx context.Context) bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	for _, addr := range []string{"deb.debian.org:80", "archive.ubuntu.com:80", "1.1.1.1:443"} {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}
