// Package system does the basic host setup: package upgrade, hostname,
// timezone, locale, NTP, security-only unattended-upgrades and a few base
// packages.
package system

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// OptionalPackages are offered in the form.
var OptionalPackages = []string{"curl", "git", "htop", "btop", "neovim", "fish", "zellij", "ncdu", "jq", "unzip"}

var (
	hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	localeRe   = regexp.MustCompile(`^[A-Za-z]+(_[A-Za-z]+)?(\.[A-Za-z0-9-]+)?(@[a-z]+)?$`)
	timeRe     = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	pkgRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	tzRe       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$`)
)

const zoneinfo = "/usr/share/zoneinfo"

const (
	localeFile = "/etc/default/locale"
	localeGen  = "/etc/locale.gen"
)

// Module is the system module.
type Module struct {
	zellij  bool
	applied bool
}

// New returns the system module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "system" }
func (*Module) Name() string { return "System basics" }
func (*Module) Description() string {
	return "upgrade, hostname, timezone, locale, NTP, security auto-updates, base packages"
}

// Prepare fills hostname, timezone and locale with the current values.
func (m *Module) Prepare(ctx context.Context, env *module.Env) error {
	a := &env.Answers.System
	if a.Hostname == "" {
		a.Hostname = currentHostname(env)
	}
	if a.Timezone == "" {
		a.Timezone = currentTimezone(ctx, env.Sys)
	}
	if a.Locale == "" {
		a.Locale = currentLocale(env.Sys)
	}
	return nil
}

func currentHostname(env *module.Env) string {
	if h := strings.TrimSpace(sys.ReadString(env.Sys, "/etc/hostname")); h != "" {
		return h
	}
	return env.Facts.Hostname
}

func currentTimezone(ctx context.Context, s sys.System) string {
	if out, err := s.Query(ctx, "timedatectl", "show", "-p", "Timezone", "--value"); err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	if tz := strings.TrimSpace(sys.ReadString(s, "/etc/timezone")); tz != "" {
		return tz
	}
	return "Etc/UTC"
}

func currentLocale(s sys.System) string {
	for _, l := range strings.Split(sys.ReadString(s, localeFile), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "LANG="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "C.UTF-8"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.System
	var pkgOpts []huh.Option[string]
	for _, p := range OptionalPackages {
		pkgOpts = append(pkgOpts, huh.NewOption(p, p).Selected(slices.Contains(a.Packages, p)))
	}
	return []*huh.Group{
		huh.NewGroup(
			huh.NewConfirm().
				Title("Upgrade all packages now (apt full-upgrade)?").
				Description("Recommended on a fresh server. A kernel update needs a reboot afterwards.").
				Value(&a.Upgrade),
			huh.NewInput().
				Title("Hostname").
				Description("Name of this server, e.g. web1 or web1.example.com.").
				Value(&a.Hostname).
				Validate(func(s string) error {
					if !hostnameRe.MatchString(s) || len(s) > 253 {
						return errors.New("lowercase letters, digits, '-' and '.' only")
					}
					return nil
				}),
			huh.NewInput().
				Title("Timezone").
				Description("e.g. Etc/UTC, Europe/Berlin, America/New_York. UTC is a good default for servers.").
				Value(&a.Timezone).
				Validate(func(s string) error { return validTimezone(env.Sys, s) }),
			huh.NewInput().
				Title("Locale").
				Description("System language, e.g. C.UTF-8 or en_US.UTF-8.").
				Suggestions([]string{"C.UTF-8", "en_US.UTF-8", "en_GB.UTF-8", "de_DE.UTF-8", "ru_RU.UTF-8"}).
				Value(&a.Locale).
				Validate(func(s string) error {
					if !localeRe.MatchString(s) {
						return errors.New("e.g. en_US.UTF-8")
					}
					return nil
				}),
			huh.NewConfirm().
				Title("Keep the clock in sync (NTP, systemd-timesyncd)?").
				Description("TLS, logs and fail2ban need a correct clock.").
				Value(&a.NTP),
		).Title("Basics"),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Install security updates automatically?").
				Description("unattended-upgrades, limited to the security repositories.").
				Value(&a.UnattendedUpgrades),
			huh.NewConfirm().
				Title("Reboot automatically when an update needs it?").
				Description("Only when a reboot is required (e.g. kernel), at the time below.").
				Value(&a.AutoReboot),
			huh.NewInput().
				Title("Reboot time (HH:MM, server time)").
				Value(&a.AutoRebootTime).
				Validate(func(s string) error {
					if !timeRe.MatchString(s) {
						return errors.New("e.g. 04:00")
					}
					return nil
				}),
		).Title("Automatic updates"),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Base packages").
				Description("zellij is not packaged by Debian/Ubuntu: it comes from its GitHub release (sha256 checked).").
				Options(pkgOpts...).
				Value(&a.Packages).
				Height(len(pkgOpts) + 4),
		),
	}
}

func validTimezone(s sys.System, tz string) error {
	if !tzRe.MatchString(tz) || strings.Contains(tz, "..") {
		return errors.New("e.g. Etc/UTC or Europe/Berlin")
	}
	if !sys.Exists(s, zoneinfo) {
		return nil // tzdata is installed by Apply
	}
	st, err := s.Stat("/usr/share/zoneinfo/" + tz)
	if err != nil || st.IsDir() {
		return fmt.Errorf("unknown timezone %q", tz)
	}
	return nil
}

func normLocale(l string) string {
	return strings.ToLower(strings.ReplaceAll(l, "-", ""))
}

func localeAvailable(ctx context.Context, s sys.System, l string) bool {
	if strings.HasPrefix(l, "C.") || l == "C" || l == "POSIX" {
		return true
	}
	out, err := s.Query(ctx, "locale", "-a")
	if err != nil {
		return false
	}
	for _, x := range strings.Fields(out) {
		if normLocale(x) == normLocale(l) {
			return true
		}
	}
	return false
}

func ntpOn(ctx context.Context, s sys.System) bool {
	out, err := s.Query(ctx, "timedatectl", "show", "-p", "NTP", "--value")
	return err == nil && strings.TrimSpace(out) == "yes"
}

// inContainer reports whether the host is a container (the clock belongs
// to the host system there and timesyncd refuses to run).
func inContainer(ctx context.Context, s sys.System) bool {
	_, err := s.Query(ctx, "systemd-detect-virt", "--container", "--quiet")
	return err == nil
}

// otherTimeDaemon returns a running NTP daemon that is not timesyncd.
func otherTimeDaemon(ctx context.Context, s sys.System) string {
	for _, u := range []string{"chrony", "chronyd", "ntp", "ntpsec", "openntpd"} {
		if sys.UnitActive(ctx, s, u) {
			return u
		}
	}
	return ""
}

func aptCandidate(ctx context.Context, s sys.System, pkg string) bool {
	out, err := s.Query(ctx, "apt-cache", "policy", pkg)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Candidate:"); ok {
			v = strings.TrimSpace(v)
			return v != "" && v != "(none)"
		}
	}
	return false
}

// upgradable parses `apt-get -s full-upgrade`: "N upgraded, M newly installed".
func upgradable(ctx context.Context, s sys.System) int {
	out, err := s.Query(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "full-upgrade")
	if err != nil {
		return 0
	}
	return ParseUpgraded(out)
}

// ParseUpgraded returns the number of packages apt would upgrade or install.
func ParseUpgraded(out string) int {
	for _, l := range strings.Split(out, "\n") {
		var up, inst int
		if n, _ := fmt.Sscanf(strings.TrimSpace(l), "%d upgraded, %d newly installed", &up, &inst); n == 2 {
			return up + inst
		}
	}
	return 0
}

type pkgPlan struct {
	apt         []string
	zellij      bool
	unavailable []string
}

func (m *Module) planPackages(ctx context.Context, env *module.Env) pkgPlan {
	var pp pkgPlan
	for _, p := range env.Answers.System.Packages {
		switch {
		case p == "zellij":
			if !sys.Has(env.Sys, "zellij") && !sys.Exists(env.Sys, zellijBin) && !aptCandidate(ctx, env.Sys, p) {
				pp.zellij = true
			} else if !sys.Has(env.Sys, "zellij") && !sys.Exists(env.Sys, zellijBin) {
				pp.apt = append(pp.apt, p)
			}
		case sys.PkgInstalled(ctx, env.Sys, p):
		case aptCandidate(ctx, env.Sys, p):
			pp.apt = append(pp.apt, p)
		default:
			pp.unavailable = append(pp.unavailable, p)
		}
	}
	return pp
}

func (m *Module) validate(env *module.Env) error {
	a := env.Answers.System
	if !hostnameRe.MatchString(a.Hostname) {
		return fmt.Errorf("system.hostname %q is not valid", a.Hostname)
	}
	if err := validTimezone(env.Sys, a.Timezone); err != nil {
		return fmt.Errorf("system.timezone: %w", err)
	}
	if !localeRe.MatchString(a.Locale) {
		return fmt.Errorf("system.locale %q is not valid", a.Locale)
	}
	if a.AutoReboot && !timeRe.MatchString(a.AutoRebootTime) {
		return fmt.Errorf("system.auto_reboot_time %q: use HH:MM", a.AutoRebootTime)
	}
	for _, p := range a.Packages {
		if !pkgRe.MatchString(p) {
			return fmt.Errorf("system.packages: %q is not a package name", p)
		}
	}
	return nil
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	if err := m.validate(env); err != nil {
		return p, err
	}
	a := env.Answers.System
	if a.Upgrade {
		if n := upgradable(ctx, env.Sys); n > 0 {
			p.Risky(module.KindPackage, "upgrade", "apt update + full-upgrade (%d packages per the current package lists)", n)
		}
	}
	if old := currentHostname(env); old != a.Hostname {
		p.Add(module.KindCommand, "hostname", "hostname: %s -> %s", old, a.Hostname)
	}
	if !strings.Contains(sys.ReadString(env.Sys, HostsFile), "127.0.1.1\t"+a.Hostname+"\n") {
		p.Add(module.KindFile, HostsFile, "%s: 127.0.1.1 %s", HostsFile, a.Hostname)
	}
	if old := currentTimezone(ctx, env.Sys); old != a.Timezone {
		if !sys.Exists(env.Sys, zoneinfo) {
			p.Add(module.KindPackage, "tzdata", "install tzdata")
		}
		p.Add(module.KindCommand, "timezone", "timezone: %s -> %s", old, a.Timezone)
	}
	if old := currentLocale(env.Sys); old != a.Locale {
		p.Add(module.KindFile, localeFile, "locale: %s -> %s", old, a.Locale)
	}
	if !localeAvailable(ctx, env.Sys, a.Locale) {
		p.Add(module.KindCommand, "locale-gen", "generate locale %s", a.Locale)
	}
	if a.NTP {
		if d := otherTimeDaemon(ctx, env.Sys); d != "" {
			p.Note("%s keeps the clock in sync already; systemd-timesyncd is not set up", d)
		} else if inContainer(ctx, env.Sys) {
			p.Note("running in a container: the clock belongs to the host, NTP is not set up")
		} else if !sys.PkgInstalled(ctx, env.Sys, "systemd-timesyncd") || !ntpOn(ctx, env.Sys) {
			p.Add(module.KindService, "ntp", "time sync with systemd-timesyncd (timedatectl set-ntp true)")
		}
	}
	if a.UnattendedUpgrades {
		if !sys.PkgInstalled(ctx, env.Sys, "unattended-upgrades") {
			p.Add(module.KindPackage, "unattended-upgrades", "install unattended-upgrades")
		}
		p.PlanFile(env.Sys, AutoUpgrades, RenderAutoUpgrades(), 0o644, "daily package lists and upgrades ("+AutoUpgrades+")")
		p.PlanFile(env.Sys, Unattended, RenderUnattended(env.Facts.OSID, a.AutoReboot, a.AutoRebootTime), 0o644,
			"security updates only"+map[bool]string{true: ", reboot at " + a.AutoRebootTime + " if needed", false: ""}[a.AutoReboot]+" ("+Unattended+")")
	}
	pp := m.planPackages(ctx, env)
	if len(pp.apt) > 0 {
		p.Add(module.KindPackage, "packages", "install %s", strings.Join(pp.apt, " "))
	}
	if pp.zellij {
		p.Add(module.KindPackage, "zellij", "install zellij %s from the GitHub release (sha256 verified)", zellijBin)
	}
	for _, u := range pp.unavailable {
		p.Note("package %s is not available in the configured repositories, skipped", u)
	}
	return p, nil
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	a := env.Answers.System
	if err := sys.AptUpdate(ctx, env.Sys); err != nil {
		return err
	}
	if a.Upgrade {
		env.Infof("upgrading packages (apt full-upgrade), this can take a while")
		args := []string{"full-upgrade", "-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
		if _, err := env.Exec(ctx, "apt-get", args...); err != nil {
			return err
		}
	}
	if old := currentHostname(env); old != a.Hostname {
		if _, err := env.Exec(ctx, "hostnamectl", "set-hostname", a.Hostname); err != nil {
			return err
		}
		if err := env.Undo("restore hostname", "hostnamectl", "set-hostname", old); err != nil {
			return err
		}
		env.Infof("hostname set to %s", a.Hostname)
	}
	if _, err := env.EditFile(HostsFile, 0o644, func(c string) string { return SetHostsName(c, a.Hostname) }); err != nil {
		return err
	}
	if old := currentTimezone(ctx, env.Sys); old != a.Timezone {
		if !sys.Exists(env.Sys, zoneinfo) {
			if err := env.Install(ctx, "tzdata"); err != nil {
				return err
			}
			if err := validTimezone(env.Sys, a.Timezone); err != nil {
				return err
			}
		}
		if _, err := env.Exec(ctx, "timedatectl", "set-timezone", a.Timezone); err != nil {
			return err
		}
		if err := env.Undo("restore timezone", "timedatectl", "set-timezone", old); err != nil {
			return err
		}
		env.Infof("timezone set to %s", a.Timezone)
	}
	if err := m.applyLocale(ctx, env); err != nil {
		return err
	}
	if a.NTP && otherTimeDaemon(ctx, env.Sys) == "" && !inContainer(ctx, env.Sys) {
		if err := env.Install(ctx, "systemd-timesyncd"); err != nil {
			return err
		}
		if !ntpOn(ctx, env.Sys) {
			if _, err := env.Exec(ctx, "timedatectl", "set-ntp", "true"); err != nil {
				env.Warnf("time sync not enabled: %v", err)
			} else if err := env.Undo("disable NTP", "timedatectl", "set-ntp", "false"); err != nil {
				return err
			}
		}
	}
	if a.UnattendedUpgrades {
		if err := env.Install(ctx, "unattended-upgrades"); err != nil {
			return err
		}
		if _, err := env.PutFile(AutoUpgrades, RenderAutoUpgrades(), 0o644); err != nil {
			return err
		}
		if _, err := env.PutFile(Unattended, RenderUnattended(env.Facts.OSID, a.AutoReboot, a.AutoRebootTime), 0o644); err != nil {
			return err
		}
	}
	pp := m.planPackages(ctx, env)
	if err := env.Install(ctx, pp.apt...); err != nil {
		return err
	}
	if pp.zellij {
		bin, err := downloadZellij(ctx)
		if err != nil {
			env.Warnf("zellij not installed: %v", err)
		} else {
			if _, err := env.PutFile(zellijBin, string(bin), 0o755); err != nil {
				return err
			}
			m.zellij = true
			env.Infof("installed zellij to %s", zellijBin)
		}
	}
	m.applied = true
	return nil
}

func (m *Module) applyLocale(ctx context.Context, env *module.Env) error {
	l := env.Answers.System.Locale
	if !localeAvailable(ctx, env.Sys, l) {
		if err := env.Install(ctx, "locales"); err != nil {
			return err
		}
		if env.Facts.OSID == "ubuntu" {
			if _, err := env.Exec(ctx, "locale-gen", l); err != nil {
				return err
			}
		} else {
			charset := "UTF-8"
			if _, cs, ok := strings.Cut(l, "."); ok {
				charset = strings.ToUpper(cs)
			}
			line := l + " " + charset
			if _, err := env.EditFile(localeGen, 0o644, func(c string) string { return enableLocale(c, line) }); err != nil {
				return err
			}
			if _, err := env.Exec(ctx, "locale-gen"); err != nil {
				return err
			}
		}
		env.Infof("generated locale %s", l)
	}
	if currentLocale(env.Sys) != l {
		if _, err := env.EditFile(localeFile, 0o644, func(c string) string { return setLang(c, l) }); err != nil {
			return err
		}
		env.Infof("LANG=%s (new logins)", l)
	}
	return nil
}

// enableLocale uncomments (or adds) a line of /etc/locale.gen.
func enableLocale(content, line string) string {
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "#"))
		if t == line {
			lines[i] = line
			return strings.Join(lines, "\n")
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

func setLang(content, l string) string {
	lines := strings.Split(content, "\n")
	for i, x := range lines {
		if strings.HasPrefix(strings.TrimSpace(x), "LANG=") {
			lines[i] = "LANG=" + l
			return strings.Join(lines, "\n")
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "LANG=" + l + "\n"
}

func (m *Module) Rollback(ctx context.Context, env *module.Env) error { return env.Rollback(ctx) }

func (m *Module) Report(env *module.Env) []module.ReportLine {
	if !m.applied {
		return nil
	}
	a := env.Answers.System
	lines := []module.ReportLine{
		{Label: "Hostname", Value: a.Hostname},
		{Label: "Timezone / locale", Value: a.Timezone + " / " + a.Locale},
	}
	if a.UnattendedUpgrades {
		v := "security updates daily"
		if a.AutoReboot {
			v += ", automatic reboot at " + a.AutoRebootTime + " when needed"
		}
		lines = append(lines, module.ReportLine{Label: "Auto updates", Value: v})
	}
	if sys.Exists(env.Sys, "/var/run/reboot-required") {
		lines = append(lines, module.ReportLine{Label: "Reboot", Value: "an update needs a reboot: run `reboot` when convenient", Warn: true})
	}
	return lines
}
