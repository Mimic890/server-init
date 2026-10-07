// Package sysctl tunes the kernel: BBR congestion control with fq, network
// hardening, a swap file and vm.swappiness, all in one sysctl.d drop-in.
package sysctl

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// Files written by the module.
const (
	DropIn      = "/etc/sysctl.d/99-server-init.conf"
	ModulesLoad = "/etc/modules-load.d/server-init.conf"
	SwapFile    = "/swapfile"
	Fstab       = "/etc/fstab"
)

var swapRe = regexp.MustCompile(`^([1-9][0-9]*)([MG])$`)

// Module is the sysctl module.
type Module struct {
	swapMade bool
}

// New returns the sysctl module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "sysctl" }
func (*Module) Name() string { return "Kernel and swap" }
func (*Module) Description() string {
	return "BBR + fq, network hardening, swap file, vm.swappiness"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.Sysctl
	swappiness := strconv.Itoa(a.Swappiness)
	if a.SwapSize == "" && !hasSwap(env.Sys) {
		a.SwapSize = "2G"
	}
	if env.Quick {
		return nil
	}
	return []*huh.Group{
		huh.NewGroup(
			huh.NewConfirm().
				Title("Use BBR congestion control with the fq qdisc?").
				Description("Better throughput and latency on lossy or long-distance links.").
				Value(&a.BBR),
			huh.NewConfirm().
				Title("Apply network hardening?").
				Description("Reverse path filter, no ICMP redirects, no source routing, SYN cookies.").
				Value(&a.Hardening),
			huh.NewInput().
				Title("Swap file size").
				DescriptionFunc(func() string {
					if hasSwap(env.Sys) {
						return "Swap already exists, nothing is created."
					}
					return "e.g. 1G or 2G; 0 = no swap file. Helps small servers survive memory peaks."
				}, nil).
				Value(&a.SwapSize).
				Validate(func(s string) error {
					if s != "" && s != "0" && !swapRe.MatchString(s) {
						return errors.New("e.g. 512M or 2G, or 0")
					}
					return nil
				}),
			huh.NewInput().
				Title("vm.swappiness").
				Description("0-100. Low values keep programs in RAM longer; 10 suits servers.").
				Value(&swappiness).
				Validate(func(s string) error {
					n, err := strconv.Atoi(s)
					if err != nil || n < 0 || n > 100 {
						return errors.New("0-100")
					}
					a.Swappiness = n
					return nil
				}),
		),
	}
}

func hasSwap(s sys.System) bool {
	lines := strings.Split(strings.TrimSpace(sys.ReadString(s, "/proc/swaps")), "\n")
	return len(lines) > 1
}

func swapActive(s sys.System, path string) bool {
	for _, l := range strings.Split(sys.ReadString(s, "/proc/swaps"), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == path {
			return true
		}
	}
	return false
}

// bbrAvailable reports whether the kernel has BBR (built in, loaded or as a
// module on disk).
func bbrAvailable(ctx context.Context, s sys.System) bool {
	if strings.Contains(sys.ReadString(s, "/proc/sys/net/ipv4/tcp_available_congestion_control"), "bbr") {
		return true
	}
	rel, err := s.Query(ctx, "uname", "-r")
	if err != nil {
		return false
	}
	m, _ := s.Glob("/lib/modules/" + strings.TrimSpace(rel) + "/kernel/net/ipv4/tcp_bbr.ko*")
	return len(m) > 0
}

// strictRP reports whether strict reverse path filtering is safe: VPN/mesh
// interfaces (WireGuard, Tailscale, ...) route asymmetrically and need the
// loose mode.
func strictRP(env *module.Env) bool {
	if len(env.Answers.UFW.Interfaces) > 0 && env.Selected("ufw") {
		return false
	}
	ifaces, _ := env.Sys.Glob("/sys/class/net/*")
	for _, i := range ifaces {
		n := i[strings.LastIndex(i, "/")+1:]
		for _, p := range []string{"wg", "tailscale", "tun", "zt", "nebula"} {
			if strings.HasPrefix(n, p) {
				return false
			}
		}
	}
	return true
}

// Params are the inputs of the drop-in.
type Params struct {
	BBR        bool
	Hardening  bool
	StrictRP   bool
	Swappiness int
}

// Render renders /etc/sysctl.d/99-server-init.conf.
func Render(p Params) string {
	var b strings.Builder
	b.WriteString("# Managed by server-init\n")
	if p.BBR {
		b.WriteString("\n# BBR congestion control with the fq qdisc\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n")
	}
	if p.Hardening {
		rp, why := 1, "strict"
		if !p.StrictRP {
			rp, why = 2, "loose: VPN/mesh interfaces route asymmetrically"
		}
		fmt.Fprintf(&b, `
# Reverse path filter (%s)
net.ipv4.conf.all.rp_filter = %d
net.ipv4.conf.default.rp_filter = %d

# No ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# No source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Do not log martian packets (noise on public servers)
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
`, why, rp, rp)
	}
	fmt.Fprintf(&b, "\n# Swap usage\nvm.swappiness = %d\n", p.Swappiness)
	return b.String()
}

func (m *Module) params(ctx context.Context, env *module.Env) (Params, bool) {
	a := env.Answers.Sysctl
	bbr := a.BBR && bbrAvailable(ctx, env.Sys)
	return Params{BBR: bbr, Hardening: a.Hardening, StrictRP: strictRP(env), Swappiness: a.Swappiness}, a.BBR && !bbr
}

// swapBytes converts "2G" to bytes.
func swapBytes(size string) (uint64, bool) {
	m := swapRe.FindStringSubmatch(size)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.ParseUint(m[1], 10, 64)
	if m[2] == "G" {
		return n << 30, true
	}
	return n << 20, true
}

func (m *Module) wantSwap(env *module.Env) bool {
	s := env.Answers.Sysctl.SwapSize
	return s != "" && s != "0" && !swapActive(env.Sys, SwapFile) && !hasSwap(env.Sys)
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	a := env.Answers.Sysctl
	if a.Swappiness < 0 || a.Swappiness > 100 {
		return p, fmt.Errorf("sysctl.swappiness %d: use 0-100", a.Swappiness)
	}
	if a.SwapSize != "" && a.SwapSize != "0" && !swapRe.MatchString(a.SwapSize) {
		return p, fmt.Errorf("sysctl.swap_size %q: use e.g. 2G", a.SwapSize)
	}
	params, noBBR := m.params(ctx, env)
	if noBBR {
		p.Note("this kernel has no BBR: congestion control is left as it is")
	}
	if params.Hardening && !params.StrictRP {
		p.Note("VPN/mesh interfaces found: reverse path filter in loose mode (2)")
	}
	p.PlanFile(env.Sys, DropIn, Render(params), 0o644, "kernel settings "+DropIn)
	if params.BBR {
		p.PlanFile(env.Sys, ModulesLoad, "tcp_bbr\n", 0o644, "load tcp_bbr at boot ("+ModulesLoad+")")
	}
	if m.wantSwap(env) {
		n, _ := swapBytes(a.SwapSize)
		if free := env.Facts.FreeDiskMB << 20; free > 0 && n+1<<30 > free {
			return p, fmt.Errorf("swap file of %s does not fit: %d MB free on /", a.SwapSize, env.Facts.FreeDiskMB)
		}
		p.Add(module.KindFile, SwapFile, "swap file %s of %s (+ %s entry)", SwapFile, a.SwapSize, Fstab)
	} else if a.SwapSize != "" && a.SwapSize != "0" && hasSwap(env.Sys) && !swapActive(env.Sys, SwapFile) {
		p.Add(module.KindInfo, "swap", "swap already exists, no swap file created")
	}
	return p, nil
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	a := env.Answers.Sysctl
	params, _ := m.params(ctx, env)
	if params.BBR {
		if _, err := env.PutFile(ModulesLoad, "tcp_bbr\n", 0o644); err != nil {
			return err
		}
		if !strings.Contains(sys.ReadString(env.Sys, "/proc/sys/net/ipv4/tcp_available_congestion_control"), "bbr") {
			if _, err := env.Exec(ctx, "modprobe", "tcp_bbr"); err != nil {
				return fmt.Errorf("loading tcp_bbr: %w", err)
			}
		}
	}
	if m.wantSwap(env) {
		if err := m.makeSwap(ctx, env, a.SwapSize); err != nil {
			return err
		}
	}
	if want := Render(params); sys.ReadString(env.Sys, DropIn) != want {
		// Recorded first: on rollback the file is removed, then reloaded.
		if err := env.Undo("reload sysctl", "sysctl", "--system"); err != nil {
			return err
		}
		if _, err := env.PutFile(DropIn, want, 0o644); err != nil {
			return err
		}
		if out, err := env.Exec(ctx, "sysctl", "-p", DropIn); err != nil {
			// The file still applies at boot; containers refuse some keys.
			env.Warnf("some settings could not be applied now: %s", strings.TrimSpace(out))
		}
	}
	return nil
}

func (m *Module) makeSwap(ctx context.Context, env *module.Env, size string) error {
	n, _ := swapBytes(size)
	// Recorded first so the rollback runs swapoff before deleting the file.
	if err := env.Undo("remove swap file", "rm", "-f", SwapFile); err != nil {
		return err
	}
	if _, err := env.Exec(ctx, "fallocate", "-l", strconv.FormatUint(n, 10), SwapFile); err != nil {
		// fallocate files are not valid swap on some filesystems; dd always is
		if _, err := env.Exec(ctx, "dd", "if=/dev/zero", "of="+SwapFile, "bs=1M", "count="+strconv.FormatUint(n>>20, 10), "status=none"); err != nil {
			return err
		}
	}
	if err := env.Sys.Chmod(SwapFile, 0o600); err != nil {
		return err
	}
	if _, err := env.Exec(ctx, "mkswap", SwapFile); err != nil {
		return err
	}
	if _, err := env.EditFile(Fstab, 0o644, func(c string) string {
		return sys.SetBlock(c, "swap", sys.MarkedBlock("swap", SwapFile+" none swap sw 0 0"), "")
	}); err != nil {
		return err
	}
	if err := env.Undo("swapoff", "swapoff", SwapFile); err != nil {
		return err
	}
	if _, err := env.Exec(ctx, "swapon", SwapFile); err != nil {
		return err
	}
	m.swapMade = true
	env.Infof("swap file %s (%s) active", SwapFile, size)
	return nil
}

func (m *Module) Rollback(ctx context.Context, env *module.Env) error { return env.Rollback(ctx) }

func (m *Module) Report(env *module.Env) []module.ReportLine {
	if !m.swapMade {
		return nil
	}
	return []module.ReportLine{{Label: "Swap", Value: fmt.Sprintf("%s (%s), swappiness %d", SwapFile, env.Answers.Sysctl.SwapSize, env.Answers.Sysctl.Swappiness)}}
}
