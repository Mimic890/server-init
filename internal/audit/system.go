package audit

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/sys"
)

func (h *host) updateChecks() {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		h.add(catUpdates, title, st, summary, details, fix)
	}
	auto := h.read("/etc/apt/apt.conf.d/20auto-upgrades")
	switch {
	case !sys.PkgInstalled(h.ctx, h.s, "unattended-upgrades"):
		add("Automatic security updates", check.Warn, "unattended-upgrades is not installed", nil, fixSystem)
	case !strings.Contains(auto, `Unattended-Upgrade "1"`):
		add("Automatic security updates", check.Warn, "installed but not enabled", nil, fixSystem)
	default:
		add("Automatic security updates", check.OK, "enabled", nil, "")
	}

	if out, err := h.query("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"); err == nil {
		all, sec := PendingUpdates(out)
		switch {
		case len(sec) > 0:
			add("Pending updates", check.Warn, fmt.Sprintf("%d security update(s) not installed (%d updates in total)", len(sec), len(all)),
				sec, "apt update && apt upgrade, or server-init → Custom setup → System basics")
		case len(all) > 0:
			add("Pending updates", check.Info, fmt.Sprintf("%d update(s), none of them security updates", len(all)), nil, "")
		default:
			add("Pending updates", check.OK, "up to date (per the current package lists)", nil, "")
		}
	}

	if sys.Exists(h.s, "/var/run/reboot-required") {
		pkgs := lines(h.read("/var/run/reboot-required.pkgs"))
		add("Reboot", check.Warn, "an installed update needs a reboot to take effect", pkgs, "reboot the server")
	}

	if _, err := h.query("systemd-detect-virt", "--container", "--quiet"); err != nil {
		out, err := h.query("timedatectl", "show", "-p", "NTPSynchronized", "--value")
		if err == nil && strings.TrimSpace(out) == "yes" {
			add("Clock", check.OK, "synchronized", nil, "")
		} else {
			add("Clock", check.Warn, "not synchronized: TLS, logs and fail2ban need the right time", nil, fixSystem)
		}
	}
}

// PendingUpdates returns the packages `apt-get -s upgrade` would install
// and the subset coming from a security pocket.
func PendingUpdates(out string) (all, security []string) {
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(l, "Inst ")
		if !ok {
			continue
		}
		pkg, _, _ := strings.Cut(rest, " ")
		all = append(all, pkg)
		if strings.Contains(l, "-security") || strings.Contains(l, "Debian-Security") {
			security = append(security, pkg)
		}
	}
	return all, security
}

// sysctlWant are the values a hardened server has (the sysctl module sets
// the network part). Keys missing on the host are skipped.
var sysctlWant = []struct {
	key  string
	want []string
}{
	{"net.ipv4.tcp_syncookies", []string{"1"}},
	{"net.ipv4.conf.all.accept_redirects", []string{"0"}},
	{"net.ipv4.conf.all.send_redirects", []string{"0"}},
	{"net.ipv4.conf.all.accept_source_route", []string{"0"}},
	{"net.ipv4.conf.all.rp_filter", []string{"1", "2"}},
	{"net.ipv6.conf.all.accept_redirects", []string{"0"}},
	{"net.ipv4.icmp_echo_ignore_broadcasts", []string{"1"}},
	{"kernel.randomize_va_space", []string{"2"}},
	{"fs.protected_hardlinks", []string{"1"}},
	{"fs.protected_symlinks", []string{"1"}},
}

func (h *host) kernelChecks() {
	var bad []string
	checked := 0
	for _, w := range sysctlWant {
		b, err := h.s.ReadFile("/proc/sys/" + strings.ReplaceAll(w.key, ".", "/"))
		if err != nil {
			continue
		}
		checked++
		if v := strings.TrimSpace(string(b)); !slices.Contains(w.want, v) {
			bad = append(bad, fmt.Sprintf("%s = %s (want %s)", w.key, v, strings.Join(w.want, " or ")))
		}
	}
	switch {
	case checked == 0:
		h.add(catKernel, "Kernel settings", check.Skip, "/proc/sys is not readable", nil, "")
	case len(bad) > 0:
		h.add(catKernel, "Kernel settings", check.Warn, "network hardening is missing", bad, fixSysctl)
	default:
		h.add(catKernel, "Kernel settings", check.OK, "hardened", nil, "")
	}
	if b := strings.TrimSpace(h.read("/proc/sys/kernel/modules_disabled")); b == "1" {
		h.add(catKernel, "Kernel modules", check.Info, "loading modules is disabled", nil, "")
	}
}

func (h *host) fileChecks() {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		h.add(catFiles, title, st, summary, details, fix)
	}
	var bad []string
	for _, f := range []struct {
		path string
		deny fs.FileMode // bits that must not be set
	}{
		{"/etc/shadow", 0o007}, {"/etc/gshadow", 0o007}, {"/etc/passwd", 0o022}, {"/etc/group", 0o022},
		{"/etc/sudoers", 0o027}, {"/etc/ssh/sshd_config", 0o022},
	} {
		st, err := h.s.Stat(f.path)
		if err != nil {
			continue
		}
		if m := st.Mode().Perm(); m&f.deny != 0 {
			bad = append(bad, fmt.Sprintf("%s is %04o", f.path, m))
		}
	}
	if len(bad) > 0 {
		add("Permissions of system files", check.Fail, "too open", bad, "chmod them back (shadow 0640, passwd 0644, sudoers 0440)")
	} else {
		add("Permissions of system files", check.OK, "", nil, "")
	}

	// one pass over the root file system: SUID programs and world-writable
	// files (container and VM images are skipped)
	args := []string{"/", "-xdev", "("}
	for i, p := range []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd",
		"/var/lib/lxc", "/var/lib/lxd", "/var/lib/libvirt", "/var/snap"} {
		if i > 0 {
			args = append(args, "-o")
		}
		args = append(args, "-path", p)
	}
	args = append(args, ")", "-prune", "-o", "-type", "f", "(", "-perm", "-4000", "-printf", `suid %p\n`,
		"-o", "-perm", "-0002", "-printf", `ww %p\n`, ")")
	out, err := h.query("find", args...)
	if err != nil && out == "" {
		return
	}
	suid, ww := ParseFind(out)
	if len(ww) > 0 {
		add("World-writable system files", check.Fail, "any user can change them", ww, "chmod o-w <file>")
	} else {
		add("World-writable system files", check.OK, "none", nil, "")
	}

	known := h.packageFiles()
	if known == nil {
		return
	}
	var unknown []string
	st := check.Warn
	for _, f := range suid {
		if known[f] {
			continue
		}
		unknown = append(unknown, f)
		for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/"} {
			if strings.HasPrefix(f, d) {
				st = check.Fail
			}
		}
	}
	if len(unknown) > 0 {
		add("SUID programs", st, "run as root but do not come from a package", unknown, "check where they come from; chmod u-s <file> if unknown")
	} else {
		add("SUID programs", check.OK, "all from packages", nil, "")
	}
}

// wwDirs are system directories where no file may be world-writable.
var wwDirs = []string{"/etc/", "/usr/", "/boot/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"}

// ParseFind splits the find output into SUID files and world-writable
// files in system directories.
func ParseFind(out string) (suid, ww []string) {
	for _, l := range strings.Split(out, "\n") {
		kind, p, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		switch kind {
		case "suid":
			suid = append(suid, p)
		case "ww":
			for _, d := range wwDirs {
				if strings.HasPrefix(p, d) {
					ww = append(ww, p)
					break
				}
			}
		}
	}
	return suid, ww
}

// packageFiles returns all paths installed by dpkg (nil when unknown).
func (h *host) packageFiles() map[string]bool {
	lists, err := h.s.Glob("/var/lib/dpkg/info/*.list")
	if err != nil || len(lists) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, l := range lists {
		for _, p := range strings.Split(h.read(l), "\n") {
			if p != "" {
				known[p] = true
				// merged /usr: /bin -> /usr/bin
				if strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/sbin/") || strings.HasPrefix(p, "/lib/") {
					known["/usr"+p] = true
				}
				if strings.HasPrefix(p, "/usr/bin/") || strings.HasPrefix(p, "/usr/sbin/") {
					known[strings.TrimPrefix(p, "/usr")] = true
				}
			}
		}
	}
	return known
}
