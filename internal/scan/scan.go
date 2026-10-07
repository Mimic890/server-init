// Package scan looks for malware on the host: miners, backdoors and
// persistence tricks that are common on hacked Linux servers. The built-in
// checks only read; the optional ClamAV scan installs the clamav package.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// Categories in report order.
const (
	catProc    = "Processes"
	catNet     = "Network"
	catPersist = "Autostart (cron, systemd, shell)"
	catFiles   = "Files"
	catClam    = "ClamAV"
)

// Options select the optional parts of the scan.
type Options struct {
	// ClamAV installs clamav (if missing), updates the signatures and
	// scans the usual malware locations.
	ClamAV bool
	// Progress gets a line per step (may be nil).
	Progress func(string)
}

type host struct {
	ctx  context.Context
	s    sys.System
	r    *check.Report
	opts Options
}

func (h *host) add(cat, title string, st check.Status, summary string, details []string, fix string) {
	h.r.Add(check.Finding{Category: cat, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
}

func (h *host) progress(format string, a ...any) {
	if h.opts.Progress != nil {
		h.opts.Progress(fmt.Sprintf(format, a...))
	}
}

func (h *host) query(name string, args ...string) (string, error) {
	return h.s.Query(h.ctx, name, args...)
}

func (h *host) read(path string) string { return sys.ReadString(h.s, path) }

// Run scans the host.
func Run(ctx context.Context, s sys.System, opts Options) check.Report {
	start := time.Now()
	r := &check.Report{Title: "Malware scan"}
	h := &host{ctx: ctx, s: s, r: r, opts: opts}
	h.progress("checking running processes")
	h.processChecks()
	h.progress("checking network connections")
	h.connectionChecks()
	h.progress("checking cron, systemd units and shell startup files")
	h.persistenceChecks()
	h.progress("checking SSH keys")
	h.keyChecks()
	h.progress("looking for programs in temporary directories")
	h.tempChecks()
	h.progress("verifying installed packages (dpkg --verify, takes a while)")
	h.packageChecks()
	if opts.ClamAV {
		h.clamav()
	}
	r.Duration = time.Since(start)
	return *r
}

// Command implements `server-init scan [--clamav]`.
func Command(ctx context.Context, env *module.Env, args []string, out io.Writer) error {
	var opts Options
	for _, a := range args {
		switch a {
		case "--clamav":
			opts.ClamAV = true
		default:
			return errors.New("usage: server-init scan [--clamav]")
		}
	}
	if !env.Facts.IsRoot {
		return errors.New("run as root: other users' processes and files are not readable otherwise")
	}
	opts.Progress = func(s string) { env.Infof("%s", s) }
	r := Run(ctx, env.Sys, opts)
	check.Render(out, r, check.Plain)
	if n := r.Count(check.Fail); n > 0 {
		return fmt.Errorf("%d problem(s) found", n)
	}
	return nil
}

// --- processes -------------------------------------------------------------

// minerNames are process names of common Linux miners and botnets.
var minerNames = []string{
	"xmrig", "xmr-stak", "xmrig-notls", "minerd", "cpuminer", "cpuminer-multi", "ccminer", "nbminer", "t-rex",
	"lolminer", "phoenixminer", "gminer", "kinsing", "kdevtmpfsi", "kthreaddi", "kworkerds", "sysupdate",
	"networkservice", "sysguard", "dbused", "watchbog", "tsunami", "mirai", "xmr",
}

var minerArgsRe = regexp.MustCompile(`(?i)stratum\+(tcp|ssl)://|--donate-level|--cpu-max-threads-hint|cryptonight|randomx`)

// tempDirs are where malware usually drops its programs.
var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/"}

func inTemp(p string) bool {
	for _, d := range tempDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// proc is one process from ps.
type proc struct {
	PID   int
	User  string
	CPU   float64
	Secs  int
	Comm  string
	Args  string
	Exe   string // /proc/<pid>/exe target
	Gone  bool   // the binary was deleted after start
	Memfd bool   // runs from an anonymous memory file
}

// ParsePS parses `ps -eo pid=,user=,pcpu=,etimes=,comm=,args=`.
func ParsePS(out string) []proc {
	var ps []proc
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(f[2], 64)
		secs, _ := strconv.Atoi(f[3])
		ps = append(ps, proc{PID: pid, User: f[1], CPU: cpu, Secs: secs, Comm: f[4], Args: strings.Join(f[5:], " ")})
	}
	return ps
}

// ParseExeLinks parses `find /proc -maxdepth 2 -name exe -printf '%p\t%l\n'`.
func ParseExeLinks(out string) map[int]string {
	m := map[int]string{}
	for _, l := range strings.Split(out, "\n") {
		p, target, ok := strings.Cut(l, "\t")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(p, "/proc/"), "/exe"))
		if err == nil && target != "" {
			m[pid] = target
		}
	}
	return m
}

func (h *host) processChecks() {
	out, err := h.query("ps", "-eo", "pid=,user=,pcpu=,etimes=,comm=,args=")
	if err != nil {
		h.add(catProc, "Processes", check.Skip, "cannot list processes (ps)", nil, "")
		return
	}
	ps := ParsePS(out)
	links, _ := h.query("find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-name", "exe", "-printf", `%p\t%l\n`)
	exe := ParseExeLinks(links)
	for i := range ps {
		t := exe[ps[i].PID]
		if strings.HasSuffix(t, " (deleted)") {
			t = strings.TrimSuffix(t, " (deleted)")
			ps[i].Memfd = strings.HasPrefix(t, "/memfd:")
			ps[i].Gone = !ps[i].Memfd
		}
		ps[i].Exe = t
	}
	ProcessChecks(h.r, ps, func(p string) bool { return sys.Exists(h.s, p) })
}

// ProcessChecks judges the process list. exists reports whether a path
// still exists (to tell a deleted program from an updated one).
func ProcessChecks(r *check.Report, ps []proc, exists func(string) bool) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catProc, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}
	desc := func(p proc) string {
		a := p.Args
		if len(a) > 120 {
			a = a[:120] + "..."
		}
		return fmt.Sprintf("pid %d  %s  %s", p.PID, p.User, a)
	}
	var miners, temp, deleted, memfd, restart, hot []string
	self := os.Getpid()
	for _, p := range ps {
		if strings.HasPrefix(p.Args, "[") || p.PID == self { // kernel thread, server-init itself
			continue
		}
		name := strings.ToLower(p.Comm)
		argv0 := strings.ToLower(baseName(strings.Fields(p.Args + " x")[0]))
		if slices.Contains(minerNames, name) || slices.Contains(minerNames, argv0) || minerArgsRe.MatchString(p.Args) {
			miners = append(miners, desc(p))
		}
		switch {
		case p.Memfd && !strings.Contains(p.Exe, "runc") && p.Comm != "runc":
			memfd = append(memfd, desc(p)+"  ("+p.Exe+")")
		case inTemp(p.Exe):
			temp = append(temp, desc(p)+"  ("+p.Exe+")")
		case p.Gone && exists(p.Exe):
			restart = append(restart, desc(p))
		case p.Gone:
			deleted = append(deleted, desc(p)+"  ("+p.Exe+")")
		}
		if p.CPU >= 80 && p.Secs >= 600 {
			hot = append(hot, fmt.Sprintf("%.0f%% CPU for %s  %s", p.CPU, (time.Duration(p.Secs)*time.Second).String(), desc(p)))
		}
	}
	fix := "note the pid and path, kill it, remove the file and find how it got in (cron, systemd, SSH keys below)"
	if len(miners) > 0 {
		add("Known miners and bots", check.Fail, "processes look like crypto miners or botnet clients", miners, fix)
	} else {
		add("Known miners and bots", check.OK, "none found", nil, "")
	}
	if len(temp) > 0 {
		add("Programs running from temp directories", check.Fail, "normal software never runs from /tmp or /dev/shm", temp, fix)
	} else {
		add("Programs running from temp directories", check.OK, "none", nil, "")
	}
	if len(memfd) > 0 {
		add("Programs running from memory", check.Fail, "no file on disk (memfd), a common way to hide malware", memfd, fix)
	}
	if len(deleted) > 0 {
		add("Programs whose file was deleted", check.Warn, "the program deleted itself after it started", deleted, fix)
	}
	if len(restart) > 0 {
		add("Outdated programs still running", check.Info, "updated on disk but not restarted (needrestart / reboot)", restart, "")
	}
	if len(hot) > 0 {
		add("High CPU load", check.Warn, "busy for more than 10 minutes; fine for a known job, suspicious otherwise", hot, "")
	} else {
		add("High CPU load", check.OK, "no process keeps the CPU busy", nil, "")
	}
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// --- network ---------------------------------------------------------------

// poolPorts are the usual stratum ports of mining pools.
var poolPorts = []int{3333, 4444, 5555, 6666, 7777, 14433, 14444, 45560, 45700}

func (h *host) connectionChecks() {
	out, err := h.query("ss", "-H", "-tnp", "state", "established")
	if err != nil {
		h.add(catNet, "Connections", check.Skip, "cannot list connections (ss)", nil, "")
		return
	}
	var pools []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		peer := f[3]
		i := strings.LastIndex(peer, ":")
		if i < 0 {
			continue
		}
		if port, err := strconv.Atoi(peer[i+1:]); err == nil && slices.Contains(poolPorts, port) {
			pools = append(pools, strings.Join(f[2:], "  "))
		}
	}
	if len(pools) > 0 {
		h.add(catNet, "Connections to mining pool ports", check.Warn, "outgoing connections to ports mining pools use", pools,
			"look up the remote address and the process")
	} else {
		h.add(catNet, "Connections to mining pool ports", check.OK, "none", nil, "")
	}
}

// --- persistence -----------------------------------------------------------

// badPatterns are command fragments typical for droppers and backdoors.
var badPatterns = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(curl|wget)\b[^#\n]*\|\s*(ba|da|z)?sh\b`), "downloads and runs a script"},
	{regexp.MustCompile(`base64\s+(-d|--decode)\b[^#\n]*\|\s*(ba|da|z)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64`), "runs base64-hidden code"},
	{regexp.MustCompile(`/dev/(tcp|udp)/`), "opens a raw network connection (reverse shell)"},
	{regexp.MustCompile(`\b(nc|ncat|netcat)\b[^#\n]*\s-(e|c)\s`), "netcat with a shell (reverse shell)"},
	{regexp.MustCompile(`\b(python3?|perl)\b[^#\n]*socket[^#\n]*(subprocess|exec|pty)`), "script reverse shell"},
	// a temp-dir program in command position: after ; & | or a shell, in
	// a systemd Exec*= line, or as the command of a cron line
	{regexp.MustCompile(`(^|[;&|]|\b(sh|bash|exec|nohup|setsid)\s|Exec[A-Za-z]*=[-@+!:]*)\s*(/tmp|/var/tmp|/dev/shm)/\S+`), "runs something from a temp directory"},
	{regexp.MustCompile(`^(@\w+|[\d*/,-]+(\s+[\d*/,-]+){4})(\s+[a-z_][a-z0-9_-]*)?\s+(/tmp|/var/tmp|/dev/shm)/\S+`), "runs something from a temp directory"},
}

var keyCommandRe = regexp.MustCompile(`command="[^"]*(curl|wget|/tmp/|/dev/shm/|base64)`)

// Suspicious returns why line looks malicious ("" if it does not).
func Suspicious(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	for _, p := range badPatterns {
		if p.re.MatchString(t) {
			return p.what
		}
	}
	return ""
}

func (h *host) scanFiles(patterns []string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, pat := range patterns {
		files, _ := h.s.Glob(pat)
		for _, f := range files {
			if seen[f] {
				continue
			}
			seen[f] = true
			for i, l := range strings.Split(h.read(f), "\n") {
				if why := Suspicious(l); why != "" {
					l = strings.TrimSpace(l)
					if len(l) > 140 {
						l = l[:140] + "..."
					}
					hits = append(hits, fmt.Sprintf("%s:%d %s: %s", f, i+1, why, l))
				}
			}
		}
	}
	return hits
}

func (h *host) persistenceChecks() {
	type group struct {
		title    string
		patterns []string
	}
	for _, g := range []group{
		{"Cron jobs", []string{"/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*",
			"/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*", "/etc/anacrontab"}},
		{"systemd services and timers", []string{"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
			"/etc/systemd/system/*/*.conf", "/usr/local/lib/systemd/system/*.service", "/run/systemd/system/*.service",
			"/root/.config/systemd/user/*.service", "/home/*/.config/systemd/user/*.service", "/etc/rc.local"}},
		{"Shell startup files", []string{"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/environment",
			"/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/home/*/.bashrc", "/home/*/.profile", "/home/*/.bash_profile"}},
	} {
		if hits := h.scanFiles(g.patterns); len(hits) > 0 {
			h.add(catPersist, g.title, check.Fail, "commands that look like a backdoor or a dropper", hits,
				"check every line; remove what you did not add yourself")
		} else {
			h.add(catPersist, g.title, check.OK, "nothing suspicious", nil, "")
		}
	}

	preload := lines(h.read("/etc/ld.so.preload"))
	if len(preload) > 0 {
		h.add(catPersist, "/etc/ld.so.preload", check.Fail, "libraries forced into every program, a classic rootkit trick", preload,
			"check the libraries; an empty or missing /etc/ld.so.preload is normal")
	} else {
		h.add(catPersist, "/etc/ld.so.preload", check.OK, "empty", nil, "")
	}

	var mods []string
	for _, l := range strings.Split(h.read("/proc/modules"), "\n") {
		name, _, _ := strings.Cut(l, " ")
		if slices.Contains([]string{"diamorphine", "reptile", "reptile_module", "suterusu", "adore", "kovid", "rootfoo"}, strings.ToLower(name)) {
			mods = append(mods, name)
		}
	}
	if len(mods) > 0 {
		h.add(catPersist, "Kernel rootkits", check.Fail, "known rootkit modules are loaded", mods, "reinstall the server: a kernel rootkit cannot be trusted to be removed")
	}
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// --- SSH keys --------------------------------------------------------------

func (h *host) keyChecks() {
	files, _ := h.s.Glob("/home/*/.ssh/authorized_keys*")
	root, _ := h.s.Glob("/root/.ssh/authorized_keys*")
	files = append(root, files...)
	var keys, bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "authorized_keys2") {
			bad = append(bad, f+": authorized_keys2 is obsolete and a favorite hiding place")
		}
		for _, k := range lines(h.read(f)) {
			fields := strings.Fields(k)
			comment := ""
			for i, w := range fields {
				if strings.HasPrefix(w, "ssh-") || strings.HasPrefix(w, "ecdsa-") || strings.HasPrefix(w, "sk-") {
					if i+2 < len(fields) {
						comment = strings.Join(fields[i+2:], " ")
					}
					if strings.HasPrefix(w, "ssh-dss") {
						bad = append(bad, f+": DSA key (insecure) "+comment)
					}
					break
				}
			}
			if comment == "" {
				comment = "(no comment)"
			}
			keys = append(keys, f+": "+comment)
			if keyCommandRe.MatchString(k) {
				bad = append(bad, f+": key with a suspicious command= option")
			}
		}
	}
	if len(bad) > 0 {
		h.add(catFiles, "SSH keys", check.Fail, "suspicious entries", append(bad, keys...), "remove the keys you do not know")
	} else {
		h.add(catFiles, "SSH keys", check.Info, fmt.Sprintf("%d key(s) can log in; remove any you do not recognize", len(keys)), keys, "")
	}
}

// --- temp dirs -------------------------------------------------------------

func (h *host) tempChecks() {
	out, err := h.query("find", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-maxdepth", "4", "-type", "f",
		"-size", "-20M", "-perm", "/111", "-print")
	if err != nil && out == "" {
		return
	}
	var elf []string
	st := check.Warn
	for _, f := range lines(out) {
		b, err := h.s.ReadFile(f)
		if err != nil || len(b) < 4 || string(b[:4]) != "\x7fELF" {
			continue
		}
		elf = append(elf, f)
		if strings.HasPrefix(f, "/dev/shm/") || strings.Contains(f, "/.") {
			st = check.Fail
		}
	}
	if len(elf) > 0 {
		h.add(catFiles, "Programs in temp directories", st, "compiled programs in /tmp, /var/tmp or /dev/shm", elf,
			"check them (file, sha256sum on virustotal.com) and delete what you do not know")
	} else {
		h.add(catFiles, "Programs in temp directories", check.OK, "none", nil, "")
	}
}

// --- package integrity -----------------------------------------------------

// systemDirs hold programs and libraries; a changed file there is serious.
var systemDirs = []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/"}

// ParseDpkgVerify returns the changed non-config files of `dpkg --verify`.
func ParseDpkgVerify(out string) (system, other []string) {
	for _, l := range strings.Split(out, "\n") {
		if len(l) < 13 || strings.HasPrefix(l, "missing") {
			continue
		}
		attrs := l[:9]
		rest := strings.TrimLeft(l[9:], " ")
		if strings.HasPrefix(rest, "c ") { // config file, changing it is normal
			continue
		}
		if len(attrs) < 3 || attrs[2] != '5' { // checksum unchanged
			continue
		}
		p := strings.TrimSpace(rest)
		isSys := false
		for _, d := range systemDirs {
			if strings.HasPrefix(p, d) {
				isSys = true
			}
		}
		if isSys {
			system = append(system, p)
		} else {
			other = append(other, p)
		}
	}
	return system, other
}

// ParseDiversions returns the diverted paths of `dpkg-divert --list`
// ("diversion of /usr/bin/man to /usr/bin/man.REAL by ubuntu-minimal").
func ParseDiversions(out string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(l, "diversion of ")
		if !ok {
			continue
		}
		p, _, _ := strings.Cut(rest, " to ")
		m[strings.TrimSpace(p)] = true
	}
	return m
}

func (h *host) packageChecks() {
	if !sys.Has(h.s, "dpkg") {
		return
	}
	// dpkg --verify exits non-zero when it finds changes; the output counts.
	out, _ := h.query("dpkg", "--verify")
	system, other := ParseDpkgVerify(out)
	// diverted files (e.g. /usr/bin/man in minimized Ubuntu images) are
	// replaced on purpose
	div, _ := h.query("dpkg-divert", "--list")
	diverted := ParseDiversions(div)
	system = slices.DeleteFunc(system, func(p string) bool { return diverted[p] })
	other = slices.DeleteFunc(other, func(p string) bool { return diverted[p] })
	switch {
	case len(system) > 0:
		h.add(catFiles, "Changed system programs", check.Fail, "files of installed packages differ from the package (possible trojan)",
			system, "reinstall the package: apt install --reinstall $(dpkg -S <file> | cut -d: -f1)")
	default:
		h.add(catFiles, "Changed system programs", check.OK, "all programs match their packages", nil, "")
	}
	if len(other) > 0 {
		h.add(catFiles, "Changed package files", check.Info, "other package files differ (often harmless)", other, "")
	}
}
