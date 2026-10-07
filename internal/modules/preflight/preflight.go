// Package preflight checks that the host can be set up safely. It always
// runs first; the /etc backup itself is made by the runner right before the
// first change.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

// LegacyDropIn is the drop-in written by the original ssh-setup.sh.
const LegacyDropIn = "/etc/ssh/sshd_config.d/00-ssh-setup.conf"

// Module is the preflight module.
type Module struct{}

// New returns the preflight module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "preflight" }
func (*Module) Name() string { return "Preflight" }
func (*Module) Description() string {
	return "root, OS, systemd, disk, internet; backup of /etc before any change"
}
func (*Module) Required() bool { return true }

func (*Module) Form(*module.Env) []*huh.Group { return nil }

// Problems returns the reasons the setup cannot run (blocking) and the
// warnings shown in the summary.
func Problems(ctx context.Context, env *module.Env) (blocking, warnings []string) {
	f := env.Facts
	if !f.IsRoot && !env.Sys.DryRun() {
		blocking = append(blocking, "run as root (sudo server-init)")
	}
	if !f.Systemd {
		blocking = append(blocking, "systemd is required")
	}
	if f.FreeDiskMB < facts.MinFreeDiskMB {
		blocking = append(blocking, fmt.Sprintf("only %d MB free on / (need %d MB)", f.FreeDiskMB, facts.MinFreeDiskMB))
	}
	if !f.OSSupported {
		warnings = append(warnings, fmt.Sprintf("%s is not tested; server-init targets Debian 12+ and Ubuntu 24.04+", f.OSPretty))
	}
	if !f.Internet {
		warnings = append(warnings, "package mirrors are not reachable: installing packages will fail")
	}
	for _, tool := range []string{"ss", "systemctl", "dpkg-query", "apt-get"} {
		if !sys.Has(env.Sys, tool) {
			blocking = append(blocking, tool+" not found")
		}
	}
	if sys.Exists(env.Sys, LegacyDropIn) {
		warnings = append(warnings, "ssh-setup.sh configuration found: the ssh and fail2ban modules take it over (its files are backed up and replaced)")
	}
	return blocking, warnings
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	blocking, warnings := Problems(ctx, env)
	for _, w := range warnings {
		p.Note("%s", w)
	}
	dirs := make([]string, 0, len(state.SnapshotDirs))
	for _, d := range state.SnapshotDirs {
		dirs = append(dirs, filepath.Base(d))
	}
	p.Add(module.KindInfo, env.Run.Dir, "before the first change: back up /etc/{%s} to %s/", strings.Join(dirs, ","), env.Run.Dir)
	if len(blocking) > 0 {
		return p, errors.New(strings.Join(blocking, "; "))
	}
	return p, nil
}

// Apply has nothing to do: the plan only holds information.
func (*Module) Apply(context.Context, *module.Env, module.Plan) error { return nil }

// Rollback has nothing to undo; the global --rollback restores the backup.
func (*Module) Rollback(context.Context, *module.Env) error { return nil }
