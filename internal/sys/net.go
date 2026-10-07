package sys

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ValidIPOrCIDR accepts an IPv4/IPv6 address or a CIDR network.
func ValidIPOrCIDR(v string) bool {
	if strings.Contains(v, "/") {
		_, err := netip.ParsePrefix(v)
		return err == nil
	}
	_, err := netip.ParseAddr(v)
	return err == nil
}

// PortListening reports whether something listens on TCP port.
func PortListening(ctx context.Context, s System, port int) bool {
	out, err := s.Query(ctx, "ss", "-H", "-ltn", "sport = :"+strconv.Itoa(port))
	return err == nil && strings.TrimSpace(out) != ""
}

// ParseSSListeners extracts the local ports of `ss -H -ltnp` lines whose
// process column contains proc (e.g. `"sshd"`).
func ParseSSListeners(out, proc string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, proc) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		if p, err := strconv.Atoi(local[i+1:]); err == nil && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	slices.Sort(ports)
	return ports
}

// SSHPorts returns the ports sshd really listens on. Socket activation
// (Ubuntu) shows systemd as the owner, so both are checked; the sshd -T
// configuration is the fallback, 22 the last resort.
func SSHPorts(ctx context.Context, s System) []int {
	if out, err := s.Query(ctx, "ss", "-H", "-ltnp"); err == nil {
		if p := ParseSSListeners(out, `"sshd"`); len(p) > 0 {
			return p
		}
		if UnitActive(ctx, s, "ssh.socket") {
			if p := ParseSSListeners(out, `"systemd"`); len(p) > 0 {
				if cfg := sshdConfigPorts(ctx, s); len(cfg) > 0 {
					// keep only the systemd sockets that belong to ssh
					var both []int
					for _, x := range p {
						if slices.Contains(cfg, x) {
							both = append(both, x)
						}
					}
					if len(both) > 0 {
						return both
					}
				}
			}
		}
	}
	if p := sshdConfigPorts(ctx, s); len(p) > 0 {
		return p
	}
	return []int{22}
}

func sshdConfigPorts(ctx context.Context, s System) []int {
	out, err := s.Query(ctx, "sshd", "-T")
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "port" {
			if p, err := strconv.Atoi(f[1]); err == nil && !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	slices.Sort(ports)
	return ports
}

// ClientIP returns the IP of the SSH client that started this program.
func ClientIP(s System) string {
	for _, k := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if v := strings.Fields(s.Getenv(k)); len(v) > 0 && ValidIPOrCIDR(v[0]) {
			return v[0]
		}
	}
	return ""
}

// ServerIP returns the address the client connected to, or the first
// address of the host.
func ServerIP(ctx context.Context, s System) string {
	if v := strings.Fields(s.Getenv("SSH_CONNECTION")); len(v) >= 3 {
		return v[2]
	}
	out, err := s.Query(ctx, "hostname", "-I")
	if err != nil {
		return ""
	}
	if f := strings.Fields(out); len(f) > 0 {
		return f[0]
	}
	return ""
}

// RandomFreePort returns a free port in 20000-59999 (same range as the
// original ssh-setup.sh).
func RandomFreePort(ctx context.Context, s System) int {
	for range 200 {
		p := 20000 + rand.IntN(40000)
		if !PortListening(ctx, s, p) {
			return p
		}
	}
	return 20000 + rand.IntN(40000)
}
