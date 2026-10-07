// Package runner drives modules through Prepare -> Check -> Apply and
// reports progress as events. The TUI and the plain (--config) mode both use
// it.
package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

// Status of one module during apply.
type Status int

const (
	Pending Status = iota
	Running
	Done
	Unchanged // plan was empty
	Failed
	NotRun // an earlier module failed
)

func (s Status) String() string {
	return [...]string{"pending", "running", "done", "unchanged", "failed", "not run"}[s]
}

// Event is sent while applying.
type Event interface{ event() }

// ModuleStarted is sent before a module is applied.
type ModuleStarted struct{ ID string }

// ModuleFinished is sent after a module.
type ModuleFinished struct {
	ID     string
	Status Status
	Err    error
}

func (ModuleStarted) event()  {}
func (ModuleFinished) event() {}

// Runner applies a set of modules.
type Runner struct {
	Env     *module.Env
	Modules []module.Module
	Events  func(Event)
}

// New returns a runner for mods.
func New(env *module.Env, mods []module.Module) *Runner {
	r := &Runner{Env: env, Modules: mods}
	env.Selected = func(id string) bool {
		return slices.ContainsFunc(r.Modules, func(m module.Module) bool { return m.ID() == id })
	}
	return r
}

func (r *Runner) emit(e Event) {
	if r.Events != nil {
		r.Events(e)
	}
}

// Env returns the environment of one module.
func (r *Runner) EnvFor(m module.Module) *module.Env { return r.Env.For(m.ID()) }

// Prepare lets modules fill host-dependent defaults.
func (r *Runner) Prepare(ctx context.Context) error {
	for _, m := range r.Modules {
		if p, ok := m.(module.Preparer); ok {
			if err := p.Prepare(ctx, r.EnvFor(m)); err != nil {
				return fmt.Errorf("%s: %w", m.ID(), err)
			}
		}
	}
	return nil
}

// Check computes the plan of every module.
func (r *Runner) Check(ctx context.Context) ([]module.Plan, error) {
	plans := make([]module.Plan, 0, len(r.Modules))
	var errs []error
	for _, m := range r.Modules {
		p, err := m.Check(ctx, r.EnvFor(m))
		p.Module = m.ID()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.Name(), err))
		}
		plans = append(plans, p)
	}
	return plans, errors.Join(errs...)
}

// NothingToDo reports whether all plans are empty.
func NothingToDo(plans []module.Plan) bool {
	for _, p := range plans {
		if !p.Empty() {
			return false
		}
	}
	return true
}

// Apply applies the modules in order. Each module is checked again right
// before it runs, because earlier modules may have changed the host. The
// first failure stops the run.
func (r *Runner) Apply(ctx context.Context, plans []module.Plan) error {
	if NothingToDo(plans) {
		for _, m := range r.Modules {
			r.emit(ModuleFinished{ID: m.ID(), Status: Unchanged})
		}
		return nil
	}
	if err := r.Env.Run.Snapshot(); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	r.Env.Log.Info("backup of /etc saved", "dir", r.Env.Run.Dir)

	var failed error
	for _, m := range r.Modules {
		if failed != nil {
			r.emit(ModuleFinished{ID: m.ID(), Status: NotRun})
			continue
		}
		r.emit(ModuleStarted{ID: m.ID()})
		env := r.EnvFor(m)
		p, err := m.Check(ctx, env)
		p.Module = m.ID()
		if err == nil && p.Empty() {
			env.Infof("already applied")
			r.emit(ModuleFinished{ID: m.ID(), Status: Unchanged})
			continue
		}
		if err == nil {
			err = m.Apply(ctx, env, p)
		}
		if err != nil {
			env.Log.Error(err.Error())
			failed = fmt.Errorf("%s: %w", m.Name(), err)
			r.emit(ModuleFinished{ID: m.ID(), Status: Failed, Err: err})
			continue
		}
		env.Infof("done")
		r.emit(ModuleFinished{ID: m.ID(), Status: Done})
	}
	if failed == nil {
		r.saveAnswers()
	}
	return failed
}

func (r *Runner) saveAnswers() {
	a := *r.Env.Answers
	a.Modules = nil
	for _, m := range r.Modules {
		a.Modules = append(a.Modules, m.ID())
	}
	b, err := config.Marshal(&a)
	if err != nil {
		return
	}
	if err := r.Env.Sys.MkdirAll(state.ConfDir, 0o700); err == nil {
		_ = r.Env.Sys.WriteFile(state.Answers, b, 0o600)
	}
}

// Report collects the final report lines of all modules.
func (r *Runner) Report() map[string][]module.ReportLine {
	out := map[string][]module.ReportLine{}
	for _, m := range r.Modules {
		if rep, ok := m.(module.Reporter); ok {
			if lines := rep.Report(r.EnvFor(m)); len(lines) > 0 {
				out[m.ID()] = lines
			}
		}
	}
	return out
}

// Rollback undoes the given modules in reverse apply order.
func (r *Runner) Rollback(ctx context.Context) error {
	var errs []error
	for _, m := range slices.Backward(r.Modules) {
		env := r.EnvFor(m)
		env.Infof("rolling back")
		if err := m.Rollback(ctx, env); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.ID(), err))
		}
	}
	return errors.Join(errs...)
}

// RestoreLatestBackup is the global --rollback: put the /etc snapshot of the
// latest run back and restart the affected services.
func RestoreLatestBackup(ctx context.Context, env *module.Env) error {
	dir := state.LatestRunDir(env.Sys)
	if dir == "" {
		return errors.New("no backup found in " + state.StateDir)
	}
	if err := state.RestoreSnapshot(env.Sys, dir, env.Infof); err != nil {
		return err
	}
	s := env.Sys
	var errs []error
	// The socket drop-in lives outside the snapshot dirs and would keep the
	// new SSH port on socket-activated systems.
	_ = s.Remove("/etc/systemd/system/ssh.socket.d/server-init.conf")
	if err := sys.DaemonReload(ctx, s); err != nil {
		errs = append(errs, err)
	}
	if sys.UnitActive(ctx, s, "ssh.socket") {
		errs = append(errs, sys.Systemctl(ctx, s, "restart", "ssh.socket"))
	}
	if err := sys.Systemctl(ctx, s, "restart", "ssh.service"); err != nil {
		errs = append(errs, sys.Systemctl(ctx, s, "restart", "sshd.service"))
	}
	if sys.UnitActive(ctx, s, "ufw") {
		_, err := s.Run(ctx, sys.Command("ufw", "reload"))
		errs = append(errs, err)
	}
	if sys.UnitActive(ctx, s, "fail2ban") {
		errs = append(errs, sys.Systemctl(ctx, s, "restart", "fail2ban"))
	}
	_, err := s.Run(ctx, sys.Command("sysctl", "--system"))
	errs = append(errs, err)
	env.Infof("restored backup %s", dir)
	return errors.Join(errs...)
}
