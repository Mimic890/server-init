// Package ufw sets up the host firewall: deny incoming, allow outgoing, SSH
// with rate limiting, optional web ports and trusted interfaces, and the
// DOCKER-USER fix so published container ports cannot bypass ufw.
package ufw

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/ssh"
	"github.com/mimic890/server-init/internal/sys"
)

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,15}$`)

// Module is the ufw module.
type Module struct {
	ifaces  string // form input
	enabled bool   // for the report
	skipped string
}

// New returns the ufw module. It also closes the rules of old SSH ports
// when `server-init ssh finalize` runs.
func New() *Module {
	m := &Module{}
	ssh.OnFinalize = append(ssh.OnFinalize, m.dropOldSSHRules)
	return m
}

func (*Module) ID() string   { return "ufw" }
func (*Module) Name() string { return "Firewall (ufw)" }
func (*Module) Description() string {
	return "deny incoming, rate-limited SSH, optional 80/443, Docker cannot bypass ufw"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.UFW
	m.ifaces = strings.Join(a.Interfaces, " ")
	return []*huh.Group{
		huh.NewGroup(
			huh.NewConfirm().
				Title("Allow HTTP (80/tcp)?").
				Description("Only needed for a web server on this host.").
				Value(&a.AllowHTTP),
			huh.NewConfirm().
				Title("Allow HTTPS (443/tcp)?").
				Description("Only needed for a web server on this host.").
				Value(&a.AllowHTTPS),
			huh.NewInput().
				Title("Trusted interfaces (optional)").
				Description("All traffic on these interfaces is allowed, e.g. a mesh VPN: tailscale0 wg0. Space separated, empty = none.").
				Value(&m.ifaces).
				Validate(func(s string) error {
					f := strings.Fields(strings.ReplaceAll(s, ",", " "))
					for _, i := range f {
						if !ifaceRe.MatchString(i) {
							return fmt.Errorf("%q is not an interface name", i)
						}
					}
					a.Interfaces = f
					return nil
				}),
			huh.NewConfirm().
				Title("Stop Docker from bypassing ufw?").
				Description("Docker publishes ports past ufw. This adds DOCKER-USER rules to /etc/ufw/after.rules; allow a container port with: ufw route allow proto tcp from any to any port 80").
				Value(&a.DockerFix),
		),
	}
}

// sshPorts are the ports the SSH rule must cover: the port the ssh module
// configures (or the current ones), plus old ports still waiting for
// `ssh finalize`.
func sshPorts(env *module.Env) []int {
	var ports []int
	if env.Selected("ssh") && env.Answers.SSH.Port != 0 {
		ports = []int{env.Answers.SSH.Port}
	} else {
		ports = slices.Clone(env.Facts.SSHPorts)
	}
	for _, p := range ssh.PendingPorts(env.Sys) {
		if !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	return ports
}

func wantedRules(env *module.Env) []Rule {
	a := env.Answers.UFW
	var rules []Rule
	for _, p := range sshPorts(env) {
		rules = append(rules, limitRule(p, "SSH"))
	}
	if a.AllowHTTP {
		rules = append(rules, allowRule(80, "HTTP"))
	}
	if a.AllowHTTPS {
		rules = append(rules, allowRule(443, "HTTPS"))
	}
	for _, i := range a.Interfaces {
		rules = append(rules, ifaceRule(i))
	}
	return rules
}

type status struct {
	installed bool
	active    bool
	rules     []Rule
	input     string // DEFAULT_INPUT_POLICY
	output    string
	ipv6      bool
}

func readStatus(ctx context.Context, s sys.System) status {
	st := status{installed: sys.Has(s, "ufw")}
	def := sys.ReadString(s, DefaultFile)
	st.input = defaultValue(def, "DEFAULT_INPUT_POLICY")
	st.output = defaultValue(def, "DEFAULT_OUTPUT_POLICY")
	st.ipv6 = defaultValue(def, "IPV6") != "no"
	if !st.installed {
		return st
	}
	if out, err := s.Query(ctx, "ufw", "status"); err == nil {
		st.active = strings.Contains(out, "Status: active")
	}
	if out, err := s.Query(ctx, "ufw", "show", "added"); err == nil {
		st.rules = ParseAdded(out)
	}
	return st
}

func defaultValue(content, key string) string {
	for _, l := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// foreignFirewall returns why ufw must not be touched ("" = fine).
func foreignFirewall(ctx context.Context, s sys.System, st status) string {
	if sys.UnitActive(ctx, s, "firewalld") {
		return "firewalld is active: ufw is not set up (two firewall managers would fight). Keep firewalld or disable it first."
	}
	if st.active {
		return ""
	}
	if sys.Has(s, "iptables") {
		if out, err := s.Query(ctx, "iptables", "-S", "INPUT"); err == nil &&
			(strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT")) {
			return "custom iptables rules with a DROP/REJECT policy are active: ufw is not set up so they are not broken."
		}
	}
	if sys.Has(s, "nft") {
		if out, err := s.Query(ctx, "nft", "list", "ruleset"); err == nil && strings.Contains(out, "policy drop") &&
			!strings.Contains(out, "ufw-") {
			return "custom nftables rules with a drop policy are active: ufw is not set up so they are not broken."
		}
	}
	return ""
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	a := env.Answers.UFW
	for _, i := range a.Interfaces {
		if !ifaceRe.MatchString(i) {
			return p, fmt.Errorf("ufw.trusted_interfaces: %q is not an interface name", i)
		}
		if !sys.Exists(env.Sys, "/sys/class/net/"+i) {
			p.Note("interface %s does not exist (yet); the rule is added anyway", i)
		}
	}
	st := readStatus(ctx, env.Sys)
	if why := foreignFirewall(ctx, env.Sys, st); why != "" {
		m.skipped = why
		p.Note("%s", why)
		return p, nil
	}
	if !st.installed {
		p.Add(module.KindPackage, "ufw", "install ufw")
	}
	if st.input != "DROP" {
		p.Add(module.KindCommand, "default-in", "default policy: deny incoming")
	}
	if st.output != "ACCEPT" {
		p.Add(module.KindCommand, "default-out", "default policy: allow outgoing")
	}
	for _, r := range wantedRules(env) {
		if !slices.Contains(st.rules, r) {
			p.Add(module.KindCommand, string(r), "ufw %s", r)
		}
	}
	for _, r := range staleSSHRules(st.rules, sshPorts(env)) {
		p.Add(module.KindCommand, string(r), "remove old rule: ufw %s", r)
	}
	for _, port := range env.Facts.SSHPorts {
		if !slices.Contains(sshPorts(env), port) {
			for _, r := range st.rules {
				if strings.HasPrefix(string(r), "allow "+strconv.Itoa(port)) && !strings.Contains(string(r), Comment) {
					p.Note("rule `ufw %s` for the old SSH port is kept; remove it when you no longer need it: ufw %s", r, strings.Join(r.DeleteArgs(), " "))
				}
			}
		}
	}
	if a.DockerFix {
		cur := sys.ReadString(env.Sys, AfterRules)
		if !HasDockerBlock(cur) {
			c, _ := module.FileChange(env.Sys, AfterRules, WithDockerBlock(cur, false), 0o640, "DOCKER-USER rules in "+AfterRules+" (Docker cannot bypass ufw)")
			if cur == "" {
				c.Diff = "" // the file comes with the ufw package
			}
			p.Changes = append(p.Changes, c)
		}
		if st.ipv6 && sys.Exists(env.Sys, After6Rules) && !HasDockerBlock(sys.ReadString(env.Sys, After6Rules)) {
			p.Add(module.KindFile, After6Rules, "DOCKER-USER rules in %s (IPv6)", After6Rules)
		}
	}
	if !st.active {
		p.Risky(module.KindService, "enable", "enable ufw (only after the SSH rule for port(s) %v is in place)", sshPorts(env))
	}
	return p, nil
}

// staleSSHRules are SSH rules server-init added for ports that are no
// longer SSH ports.
func staleSSHRules(rules []Rule, ports []int) []Rule {
	var stale []Rule
	for _, r := range rules {
		s := string(r)
		if !strings.Contains(s, "SSH "+Comment) && !strings.Contains(s, "SSH ("+Comment+")") {
			continue
		}
		keep := false
		for _, p := range ports {
			if strings.Contains(s, " "+strconv.Itoa(p)+"/tcp") {
				keep = true
			}
		}
		if !keep {
			stale = append(stale, r)
		}
	}
	return stale
}

func (m *Module) Apply(ctx context.Context, env *module.Env, p module.Plan) error {
	if m.skipped != "" {
		return nil
	}
	st := readStatus(ctx, env.Sys)
	if !st.installed {
		if err := sys.AptUpdate(ctx, env.Sys); err != nil {
			return err
		}
		if err := env.Install(ctx, "ufw"); err != nil {
			return err
		}
		st = readStatus(ctx, env.Sys)
	}
	run := func(args ...string) error {
		_, err := env.Exec(ctx, "ufw", args...)
		return err
	}
	if st.input != "DROP" {
		if err := run("default", "deny", "incoming"); err != nil {
			return err
		}
		if err := env.Undo("restore incoming policy", "ufw", "default", policyWord(st.input), "incoming"); err != nil {
			return err
		}
	}
	if st.output != "ACCEPT" {
		if err := run("default", "allow", "outgoing"); err != nil {
			return err
		}
		if err := env.Undo("restore outgoing policy", "ufw", "default", policyWord(st.output), "outgoing"); err != nil {
			return err
		}
	}
	for _, r := range wantedRules(env) {
		if slices.Contains(st.rules, r) {
			continue
		}
		if err := run(r.Args()...); err != nil {
			return err
		}
		env.Infof("ufw %s", r)
		if err := env.Undo("remove rule", append([]string{"ufw"}, r.DeleteArgs()...)...); err != nil {
			return err
		}
	}
	for _, r := range staleSSHRules(st.rules, sshPorts(env)) {
		if err := run(r.DeleteArgs()...); err != nil {
			return err
		}
		env.Infof("removed old rule: ufw %s", r)
	}
	if env.Answers.UFW.DockerFix {
		if _, err := env.EditFile(AfterRules, 0o640, func(old string) string { return WithDockerBlock(old, false) }); err != nil {
			return err
		}
		if st.ipv6 && sys.Exists(env.Sys, After6Rules) {
			if _, err := env.EditFile(After6Rules, 0o640, func(old string) string { return WithDockerBlock(old, true) }); err != nil {
				return err
			}
		}
	}

	// Never enable without the SSH rule: check what ufw really has now.
	now := readStatus(ctx, env.Sys)
	for _, port := range sshPorts(env) {
		if !slices.Contains(now.rules, limitRule(port, "SSH")) {
			return fmt.Errorf("SSH rule for port %d is missing, ufw is NOT enabled", port)
		}
	}
	if !now.active {
		if err := run("--force", "enable"); err != nil {
			return err
		}
		if err := env.Undo("disable ufw", "ufw", "--force", "disable"); err != nil {
			return err
		}
		env.Infof("ufw enabled")
	} else if err := run("reload"); err != nil {
		return err
	}
	m.enabled = true
	return nil
}

func policyWord(p string) string {
	switch p {
	case "ACCEPT":
		return "allow"
	case "REJECT":
		return "reject"
	}
	return "deny"
}

// dropOldSSHRules runs after `ssh finalize` closed the old SSH ports.
func (m *Module) dropOldSSHRules(ctx context.Context, env *module.Env, port int) error {
	if !sys.Has(env.Sys, "ufw") {
		return nil
	}
	st := readStatus(ctx, env.Sys)
	var errs []error
	for _, r := range staleSSHRules(st.rules, []int{port}) {
		if _, err := env.Exec(ctx, "ufw", r.DeleteArgs()...); err != nil {
			errs = append(errs, err)
			continue
		}
		env.Infof("ufw: removed %s", r)
	}
	return errors.Join(errs...)
}

func (m *Module) Rollback(ctx context.Context, env *module.Env) error {
	err := env.Rollback(ctx)
	if sys.Has(env.Sys, "ufw") {
		if out, qerr := env.Sys.Query(ctx, "ufw", "status"); qerr == nil && strings.Contains(out, "Status: active") {
			_, rerr := env.Exec(ctx, "ufw", "reload")
			err = errors.Join(err, rerr)
		}
	}
	return err
}

func (m *Module) Report(env *module.Env) []module.ReportLine {
	if m.skipped != "" {
		return []module.ReportLine{{Label: "Firewall", Value: m.skipped, Warn: true}}
	}
	if !m.enabled {
		return nil
	}
	ports := sshPorts(env)
	lines := []module.ReportLine{{Label: "Firewall", Value: fmt.Sprintf("ufw active, SSH %v rate-limited, check with: ufw status verbose", ports)}}
	if env.Answers.UFW.DockerFix {
		lines = append(lines, module.ReportLine{Label: "Docker ports", Value: "published ports are blocked; allow one with: ufw route allow proto tcp from any to any port <container-port>"})
	}
	return lines
}
