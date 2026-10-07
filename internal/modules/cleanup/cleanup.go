// Package cleanup removes what a server does not need (snapd, cloud-init,
// popularity-contest, Ubuntu's MOTD news), cleans apt and caps the journal.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// Files written by the module.
const (
	JournaldDropIn = "/etc/systemd/journald.conf.d/server-init.conf"
	NoSnapdPin     = "/etc/apt/preferences.d/server-init-no-snapd"
	MotdNews       = "/etc/default/motd-news"
)

var sizeRe = regexp.MustCompile(`^[1-9][0-9]*[KMGT]?$`)

// Module is the cleanup module.
type Module struct{}

// New returns the cleanup module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "cleanup" }
func (*Module) Name() string { return "Cleanup" }
func (*Module) Description() string {
	return "remove snapd/cloud-init/popularity-contest, MOTD ads, apt autoremove, journal size"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.Cleanup
	if env.Quick {
		return nil
	}
	return []*huh.Group{
		huh.NewGroup(
			huh.NewConfirm().
				Title("Remove snapd?").
				Description("Removes all snaps too, and pins snapd so apt does not bring it back. Skip if you use snaps (e.g. lxd).").
				Value(&a.RemoveSnapd),
			huh.NewConfirm().
				Title("Remove cloud-init?").
				Description("Only needed for the first boot on most providers. Keep it if your provider re-applies network or keys on reboot.").
				Value(&a.RemoveCloudInit),
			huh.NewConfirm().
				Title("Remove popularity-contest?").
				Description("Sends a list of installed packages to Debian/Ubuntu once a week.").
				Value(&a.RemovePopcon),
			huh.NewConfirm().
				Title("Disable MOTD news (Ubuntu)?").
				Description("Stops fetching advertising news into the login message (motd-news).").
				Value(&a.DisableMotdNews),
		).Title("Remove"),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Remove unused packages and the apt cache?").
				Description("apt autoremove --purge and apt clean.").
				Value(&a.Autoremove),
			huh.NewInput().
				Title("Maximum journal size on disk").
				Description("journald SystemMaxUse, e.g. 200M or 1G. Empty = keep the default (10% of the disk).").
				Value(&a.JournaldMaxUse).
				Validate(func(s string) error {
					if s != "" && !sizeRe.MatchString(s) {
						return errors.New("e.g. 200M or 1G")
					}
					return nil
				}),
		).Title("Tidy up"),
	}
}

// RenderJournald renders the journald drop-in.
func RenderJournald(size string) string {
	return "# Managed by server-init\n[Journal]\nSystemMaxUse=" + size + "\n"
}

// RenderNoSnapd pins snapd away so apt never installs it again.
func RenderNoSnapd() string {
	return "# Managed by server-init: never install snapd again\nPackage: snapd\nPin: release a=*\nPin-Priority: -10\n"
}

// DisableMotd sets ENABLED=0 in /etc/default/motd-news.
func DisableMotd(content string) string {
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "ENABLED=") {
			lines[i] = "ENABLED=0"
		}
	}
	return strings.Join(lines, "\n")
}

func (m *Module) purgeList(ctx context.Context, env *module.Env) []string {
	a := env.Answers.Cleanup
	var pkgs []string
	for _, c := range []struct {
		on  bool
		pkg string
	}{{a.RemoveSnapd, "snapd"}, {a.RemoveCloudInit, "cloud-init"}, {a.RemovePopcon, "popularity-contest"}} {
		if c.on && sys.PkgInstalled(ctx, env.Sys, c.pkg) {
			pkgs = append(pkgs, c.pkg)
		}
	}
	return pkgs
}

func autoremoveCount(ctx context.Context, s sys.System) int {
	out, err := s.Query(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "autoremove", "--purge")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(out, "\n") {
		var up, inst, rm int
		if n, _ := fmt.Sscanf(strings.TrimSpace(l), "%d upgraded, %d newly installed, %d to remove", &up, &inst, &rm); n == 3 {
			return rm
		}
	}
	return 0
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	a := env.Answers.Cleanup
	if a.JournaldMaxUse != "" && !sizeRe.MatchString(a.JournaldMaxUse) {
		return p, fmt.Errorf("cleanup.journald_max_use %q: use e.g. 200M", a.JournaldMaxUse)
	}
	for _, pkg := range m.purgeList(ctx, env) {
		p.Risky(module.KindPackage, pkg, "purge %s", pkg)
		if pkg == "snapd" {
			if out, err := env.Sys.Query(ctx, "snap", "list"); err == nil {
				if snaps := strings.Split(strings.TrimSpace(out), "\n"); len(snaps) > 1 {
					p.Note("snapd removes these snaps too: %s", snapNames(snaps[1:]))
				}
			}
		}
	}
	if a.RemoveSnapd {
		p.PlanFile(env.Sys, NoSnapdPin, RenderNoSnapd(), 0o644, "keep snapd from coming back ("+NoSnapdPin+")")
	}
	if a.DisableMotdNews && sys.Exists(env.Sys, MotdNews) {
		cur := sys.ReadString(env.Sys, MotdNews)
		p.PlanFile(env.Sys, MotdNews, DisableMotd(cur), 0o644, "MOTD news off")
		if sys.UnitEnabled(ctx, env.Sys, "motd-news.timer") {
			p.Add(module.KindService, "motd-news.timer", "disable motd-news.timer")
		}
	}
	if a.Autoremove {
		if n := autoremoveCount(ctx, env.Sys); n > 0 {
			p.Add(module.KindPackage, "autoremove", "apt autoremove --purge (%d packages)", n)
		}
		if debs, _ := env.Sys.Glob("/var/cache/apt/archives/*.deb"); len(debs) > 0 {
			p.Add(module.KindCommand, "clean", "apt clean (%d cached .deb files)", len(debs))
		}
	}
	if a.JournaldMaxUse != "" {
		p.PlanFile(env.Sys, JournaldDropIn, RenderJournald(a.JournaldMaxUse), 0o644, "journal limited to "+a.JournaldMaxUse)
	}
	return p, nil
}

func snapNames(lines []string) string {
	var names []string
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	return strings.Join(names, ", ")
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	a := env.Answers.Cleanup
	if pkgs := m.purgeList(ctx, env); len(pkgs) > 0 {
		env.Infof("purging %s", strings.Join(pkgs, " "))
		if err := sys.AptPurge(ctx, env.Sys, pkgs...); err != nil {
			return err
		}
	}
	if a.RemoveSnapd {
		if _, err := env.PutFile(NoSnapdPin, RenderNoSnapd(), 0o644); err != nil {
			return err
		}
		for _, d := range []string{"/snap", "/var/snap", "/var/lib/snapd"} {
			if sys.Exists(env.Sys, d) && !sys.PkgInstalled(ctx, env.Sys, "snapd") {
				_ = env.Sys.RemoveAll(d)
			}
		}
	}
	if a.DisableMotdNews && sys.Exists(env.Sys, MotdNews) {
		if _, err := env.EditFile(MotdNews, 0o644, DisableMotd); err != nil {
			return err
		}
		if sys.UnitEnabled(ctx, env.Sys, "motd-news.timer") {
			if err := sys.Systemctl(ctx, env.Sys, "disable", "--now", "motd-news.timer"); err != nil {
				return err
			}
			if err := env.Undo("enable motd-news.timer", "systemctl", "enable", "--now", "motd-news.timer"); err != nil {
				return err
			}
		}
	}
	if a.Autoremove {
		if _, err := env.Exec(ctx, "apt-get", "autoremove", "--purge", "-y", "-q"); err != nil {
			return err
		}
		if _, err := env.Exec(ctx, "apt-get", "clean"); err != nil {
			return err
		}
	}
	if want := RenderJournald(a.JournaldMaxUse); a.JournaldMaxUse != "" && sys.ReadString(env.Sys, JournaldDropIn) != want {
		// Recorded first: the rollback replays in reverse, so journald is
		// restarted after the drop-in is gone.
		if err := env.Undo("restart journald", "systemctl", "restart", "systemd-journald"); err != nil {
			return err
		}
		if _, err := env.PutFile(JournaldDropIn, want, 0o644); err != nil {
			return err
		}
		if err := sys.Systemctl(ctx, env.Sys, "restart", "systemd-journald"); err != nil {
			return err
		}
	}
	return nil
}

// Rollback restores the files and timers; purged packages stay removed.
func (m *Module) Rollback(ctx context.Context, env *module.Env) error { return env.Rollback(ctx) }
