// Package fail2ban installs fail2ban like ssh-setup.sh did: an aggressive
// sshd jail on the real SSH port (systemd backend), optional recidive, a
// permanent all-ports blacklist jail, and whitelist/blacklist files managed
// with `server-init f2b ...`.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/ssh"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

var timeRe = regexp.MustCompile(`^[1-9][0-9]*[smhdw]?$`)

// Module is the fail2ban module.
type Module struct {
	extra   string // form input
	running bool
}

// New returns the fail2ban module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "fail2ban" }
func (*Module) Name() string { return "fail2ban" }
func (*Module) Description() string {
	return "ban brute-force IPs (sshd, recidive), permanent blacklist, whitelist"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.Fail2ban
	retry := fmt.Sprint(a.MaxRetry)
	m.extra = strings.Join(a.Whitelist, " ")
	client := env.Facts.ClientIP
	groups := []*huh.Group{
		huh.NewGroup(
			huh.NewInput().
				Title("maxretry - failed attempts before a ban").
				Description("fail2ban reads the SSH log and bans IPs that fail to log in too often.").
				Value(&retry).
				Validate(func(s string) error {
					var n int
					if _, err := fmt.Sscan(s, &n); err != nil || n < 1 || n > 999 {
						return errors.New("enter a number from 1 to 999")
					}
					a.MaxRetry = n
					return nil
				}),
			huh.NewInput().
				Title("findtime - window in which failures are counted").
				Description("Time values accept s, m, h, d, w (e.g. 10m, 1h, 1w).").
				Value(&a.FindTime).
				Validate(validTime(false)),
			huh.NewInput().
				Title("bantime - how long an IP stays banned").
				Description("e.g. 1h; -1 = permanent.").
				Value(&a.BanTime).
				Validate(validTime(true)),
			huh.NewConfirm().
				Title("Enable recidive (repeat offenders, 1 week ban)?").
				Description("An IP banned 3 times in a day is banned for a whole week.").
				Value(&a.Recidive),
		),
	}
	if client != "" {
		groups = append(groups, huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Whitelist your current IP (%s)?", client)).
				Description("Whitelisted IPs are never banned, so you cannot ban yourself. aggressive mode can ban a client that offers many keys.").
				Value(&a.WhitelistClient),
		))
	}
	groups = append(groups, huh.NewGroup(
		huh.NewInput().
			Title("More IPs/CIDRs to whitelist").
			Description("Space separated, empty = none. Example: 203.0.113.0/24 2001:db8::1").
			Value(&m.extra).
			Validate(func(s string) error {
				f := strings.Fields(strings.ReplaceAll(s, ",", " "))
				for _, ip := range f {
					if !sys.ValidIPOrCIDR(ip) {
						return fmt.Errorf("not a valid IP/CIDR: %s", ip)
					}
				}
				a.Whitelist = f
				return nil
			}),
	))
	return groups
}

func validTime(allowPermanent bool) func(string) error {
	return func(s string) error {
		if allowPermanent && s == "-1" {
			return nil
		}
		if !timeRe.MatchString(s) {
			return errors.New("example: 10m (s, m, h, d, w)")
		}
		return nil
	}
}

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

// whitelist is the existing list (manual additions are kept) plus the
// answers and the legacy ssh-setup.sh list.
func whitelist(env *module.Env) []string {
	a := env.Answers.Fail2ban
	list := ParseList(sys.ReadString(env.Sys, WhitelistList))
	add := func(ip string) {
		if ip != "" && !slices.Contains(list, ip) {
			list = append(list, ip)
		}
	}
	if a.WhitelistClient {
		add(env.Facts.ClientIP)
	}
	for _, ip := range a.Whitelist {
		add(ip)
	}
	for _, ip := range ParseList(sys.ReadString(env.Sys, legacyWhitelist)) {
		add(ip)
	}
	return list
}

func blacklist(env *module.Env) []string {
	list := ParseList(sys.ReadString(env.Sys, BlacklistList))
	for _, ip := range ParseList(sys.ReadString(env.Sys, legacyBlacklist)) {
		if !slices.Contains(list, ip) {
			list = append(list, ip)
		}
	}
	return list
}

func (m *Module) files(env *module.Env) map[string]string {
	a := env.Answers.Fail2ban
	return map[string]string{
		JailFile: RenderJail(JailParams{Ports: sshPorts(env), MaxRetry: a.MaxRetry, FindTime: a.FindTime,
			BanTime: a.BanTime, Recidive: a.Recidive}),
		WhitelistJail: RenderWhitelist(whitelist(env)),
		DBConf:        RenderDBConf(),
		FilterFile:    RenderFilter(),
	}
}

var fileOrder = []string{JailFile, WhitelistJail, DBConf, FilterFile}

func (m *Module) validate(env *module.Env) error {
	a := env.Answers.Fail2ban
	if a.MaxRetry < 1 {
		return errors.New("fail2ban.maxretry must be at least 1")
	}
	if !timeRe.MatchString(a.FindTime) {
		return fmt.Errorf("fail2ban.findtime %q: use e.g. 10m", a.FindTime)
	}
	if a.BanTime != "-1" && !timeRe.MatchString(a.BanTime) {
		return fmt.Errorf("fail2ban.bantime %q: use e.g. 1h or -1", a.BanTime)
	}
	for _, ip := range a.Whitelist {
		if !sys.ValidIPOrCIDR(ip) {
			return fmt.Errorf("fail2ban.whitelist: %q is not an IP/CIDR", ip)
		}
	}
	return nil
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	if err := m.validate(env); err != nil {
		return p, err
	}
	if miss := sys.MissingPkgs(ctx, env.Sys, "fail2ban", "python3-systemd"); len(miss) > 0 {
		p.Add(module.KindPackage, "fail2ban", "install %s", strings.Join(miss, " "))
	}
	for _, f := range legacyFiles {
		p.PlanRemove(env.Sys, f, "remove "+f+" (taken over from ssh-setup.sh)")
	}
	files := m.files(env)
	for _, f := range fileOrder {
		p.PlanFile(env.Sys, f, files[f], 0o644, f)
	}
	p.PlanFile(env.Sys, WhitelistList, RenderList(whitelist(env)), 0o600, "whitelist "+WhitelistList)
	if bl := blacklist(env); len(bl) > 0 {
		p.PlanFile(env.Sys, BlacklistList, RenderList(bl), 0o600, "blacklist "+BlacklistList)
	}
	if !sys.UnitEnabled(ctx, env.Sys, "fail2ban") || !sys.UnitActive(ctx, env.Sys, "fail2ban") {
		p.Add(module.KindService, "fail2ban", "enable and start fail2ban")
	}
	if !p.Empty() {
		p.Add(module.KindInfo, "ports", "sshd jail watches port(s) %v (aggressive mode, systemd journal)", sshPorts(env))
	}
	return p, nil
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	if miss := sys.MissingPkgs(ctx, env.Sys, "fail2ban", "python3-systemd"); len(miss) > 0 {
		if err := sys.AptUpdate(ctx, env.Sys); err != nil {
			return err
		}
		pkgs := miss
		if !sys.Has(env.Sys, "nft") && !sys.Has(env.Sys, "iptables") {
			pkgs = append(pkgs, "nftables")
		}
		if err := env.Install(ctx, pkgs...); err != nil {
			return err
		}
	}
	wasEnabled := sys.UnitEnabled(ctx, env.Sys, "fail2ban")
	for _, f := range legacyFiles {
		if _, err := env.RemoveFile(f); err != nil {
			return err
		}
	}
	if err := env.Sys.MkdirAll(state.ConfDir, 0o700); err != nil {
		return err
	}
	if _, err := env.PutFile(WhitelistList, RenderList(whitelist(env)), 0o600); err != nil {
		return err
	}
	if _, err := env.PutFile(BlacklistList, RenderList(blacklist(env)), 0o600); err != nil {
		return err
	}
	if !sys.Exists(env.Sys, BlacklistLog) {
		if _, err := env.PutFile(BlacklistLog, "", 0o640); err != nil {
			return err
		}
	}
	files := m.files(env)
	for _, f := range fileOrder {
		if _, err := env.PutFile(f, files[f], 0o644); err != nil {
			return err
		}
	}
	if _, err := env.Exec(ctx, "fail2ban-client", "-t"); err != nil {
		return fmt.Errorf("fail2ban rejected the configuration (fail2ban-client -t): %w", err)
	}
	if err := sys.Systemctl(ctx, env.Sys, "enable", "fail2ban"); err != nil {
		return err
	}
	if !wasEnabled {
		if err := env.Undo("disable fail2ban", "systemctl", "disable", "--now", "fail2ban"); err != nil {
			return err
		}
	}
	if err := sys.Systemctl(ctx, env.Sys, "restart", "fail2ban"); err != nil {
		return err
	}
	if !waitReady(ctx, env.Sys) {
		return errors.New("fail2ban did not start, check: systemctl status fail2ban")
	}
	if _, err := env.Sys.Query(ctx, "fail2ban-client", "status", "sshd"); err != nil {
		return fmt.Errorf("sshd jail is not active: %w", err)
	}
	syncBlacklist(ctx, env)
	m.running = true
	env.Infof("fail2ban is running, sshd jail active on port(s) %v", sshPorts(env))
	return nil
}

// pollInterval is the wait between fail2ban readiness checks.
var pollInterval = time.Second

func waitReady(ctx context.Context, s sys.System) bool {
	for range 15 {
		if _, err := s.Query(ctx, "fail2ban-client", "ping"); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
	return false
}

// syncBlacklist bans every blacklisted IP again (bans live in the fail2ban
// database; this restores them if it was lost).
func syncBlacklist(ctx context.Context, env *module.Env) {
	for _, ip := range ParseList(sys.ReadString(env.Sys, BlacklistList)) {
		_, _ = env.Sys.Run(ctx, sys.Command("fail2ban-client", "set", BlacklistJail, "banip", ip))
	}
}

func (m *Module) Rollback(ctx context.Context, env *module.Env) error {
	err := env.Rollback(ctx)
	if sys.UnitActive(ctx, env.Sys, "fail2ban") {
		err = errors.Join(err, sys.Systemctl(ctx, env.Sys, "restart", "fail2ban"))
	}
	return err
}

func (m *Module) Report(env *module.Env) []module.ReportLine {
	if !m.running {
		return nil
	}
	return []module.ReportLine{
		{Label: "fail2ban", Value: fmt.Sprintf("sshd jail on port(s) %v: %d failures in %s -> ban %s",
			sshPorts(env), env.Answers.Fail2ban.MaxRetry, env.Answers.Fail2ban.FindTime, env.Answers.Fail2ban.BanTime)},
		{Label: "Manage bans", Value: "server-init f2b status | unban <ip> | whitelist add <ip> | blacklist add <ip>"},
	}
}
