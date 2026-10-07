// Package moduletest has a configurable fake module for runner and TUI
// tests.
package moduletest

import (
	"context"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
)

// Fake is a module whose behaviour is set by its fields.
type Fake struct {
	IDValue   string
	Changes   []module.Change
	ApplyErr  error
	CheckErr  error
	Questions func(env *module.Env) []*huh.Group
	Applied   int
	Rolled    int
	Lines     []module.ReportLine
	OnApply   func(env *module.Env)
}

func (f *Fake) ID() string          { return f.IDValue }
func (f *Fake) Name() string        { return "Fake " + f.IDValue }
func (f *Fake) Description() string { return "fake module " + f.IDValue }

func (f *Fake) Form(env *module.Env) []*huh.Group {
	if f.Questions == nil {
		return nil
	}
	return f.Questions(env)
}

func (f *Fake) Check(context.Context, *module.Env) (module.Plan, error) {
	if f.Applied > 0 {
		return module.Plan{}, f.CheckErr // idempotent: nothing left after apply
	}
	return module.Plan{Changes: f.Changes}, f.CheckErr
}

func (f *Fake) Apply(_ context.Context, env *module.Env, _ module.Plan) error {
	if f.ApplyErr != nil {
		return f.ApplyErr
	}
	if f.OnApply != nil {
		f.OnApply(env)
	}
	env.Infof("applied %s", f.IDValue)
	f.Applied++
	return nil
}

func (f *Fake) Rollback(context.Context, *module.Env) error { f.Rolled++; return nil }

func (f *Fake) Report(*module.Env) []module.ReportLine { return f.Lines }

// Change returns a single file change.
func Change(target string) []module.Change {
	return []module.Change{{Kind: module.KindFile, Target: target, Summary: "write " + target}}
}
