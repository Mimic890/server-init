package module

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

// Env is everything a module needs. The runner gives every module its own
// copy (own Journal and Log).
type Env struct {
	Answers *config.Answers
	Facts   *facts.Facts
	Sys     sys.System
	Run     *state.Run
	Journal *state.Journal
	Prompt  Prompter
	Log     *slog.Logger
	// Selected reports whether another module takes part in this run (ssh
	// asks whether ufw will run, for example).
	Selected func(id string) bool
	// Quick is set by the full setup: forms ask only the essential
	// questions, everything else keeps the recommended answer.
	Quick bool
}

// For returns a copy of env bound to one module.
func (e *Env) For(id string) *Env {
	c := *e
	c.Journal = state.NewJournal(e.Sys, id)
	if e.Log != nil {
		c.Log = e.Log.With("module", id)
	} else {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Prompt == nil {
		c.Prompt = AutoPrompter{}
	}
	if c.Selected == nil {
		c.Selected = func(string) bool { return false }
	}
	return &c
}

// Advanced returns a group hide func for questions the full setup skips.
// hide is the group's own condition and may be nil.
func (e *Env) Advanced(hide func() bool) func() bool {
	quick := e.Quick
	return func() bool { return quick || hide != nil && hide() }
}

// Infof logs a user-visible progress line.
func (e *Env) Infof(format string, args ...any) { e.Log.Info(fmt.Sprintf(format, args...)) }

// Warnf logs a user-visible warning.
func (e *Env) Warnf(format string, args ...any) { e.Log.Warn(fmt.Sprintf(format, args...)) }

// FileChange compares path with the wanted content and returns the change
// (with diff) or false when the file is already right.
func FileChange(s sys.System, path, content string, perm fs.FileMode, summary string) (Change, bool) {
	old, err := s.ReadFile(path)
	if err == nil && string(old) == content {
		if st, err := s.Stat(path); err == nil && st.Mode().Perm() == perm {
			return Change{}, false
		}
		return Change{Kind: KindFile, Target: path, Summary: fmt.Sprintf("%s (chmod %04o)", summary, perm)}, true
	}
	return Change{Kind: KindFile, Target: path, Summary: summary, Diff: sys.Diff(path, string(old), content)}, true
}

// PlanFile adds a file change to p when needed and reports whether it did.
func (p *Plan) PlanFile(s sys.System, path, content string, perm fs.FileMode, summary string) bool {
	c, ok := FileChange(s, path, content, perm, summary)
	if ok {
		p.Changes = append(p.Changes, c)
	}
	return ok
}

// PlanRemove adds a removal when path exists.
func (p *Plan) PlanRemove(s sys.System, path, summary string) bool {
	if !sys.Exists(s, path) {
		return false
	}
	p.Changes = append(p.Changes, Change{Kind: KindFile, Target: path, Summary: summary,
		Diff: sys.Diff(path, sys.ReadString(s, path), "")})
	return true
}

// PutFile makes path contain content with mode perm. The previous version is
// backed up and journaled first. It reports whether anything changed.
func (e *Env) PutFile(path, content string, perm fs.FileMode) (bool, error) {
	old, err := e.Sys.ReadFile(path)
	exists := err == nil
	if exists && string(old) == content {
		if st, err := e.Sys.Stat(path); err == nil && st.Mode().Perm() != perm {
			return true, e.Sys.Chmod(path, perm)
		}
		return false, nil
	}
	if err := e.remember(path, exists); err != nil {
		return false, err
	}
	if err := e.Sys.WriteFile(path, []byte(content), perm); err != nil {
		return false, err
	}
	e.Log.Debug("wrote file", "path", path)
	return true, nil
}

// EditFile rewrites path through edit (used for the few main configs without
// a drop-in directory). A missing file is passed as "".
func (e *Env) EditFile(path string, perm fs.FileMode, edit func(old string) string) (bool, error) {
	old := sys.ReadString(e.Sys, path)
	if st, err := e.Sys.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	return e.PutFile(path, edit(old), perm)
}

// RemoveFile deletes path (after a backup). It reports whether it existed.
func (e *Env) RemoveFile(path string) (bool, error) {
	if !sys.Exists(e.Sys, path) {
		return false, nil
	}
	if !e.Journal.Knows(path) {
		b, err := e.Run.BackupFile(path)
		if err != nil {
			return false, err
		}
		if err := e.Journal.Add(state.Entry{Op: state.OpRemove, Path: path, Backup: b}); err != nil {
			return false, err
		}
	}
	return true, e.Sys.Remove(path)
}

func (e *Env) remember(path string, exists bool) error {
	if e.Journal.Knows(path) {
		return nil // the original is already preserved
	}
	if !exists {
		return e.Journal.Add(state.Entry{Op: state.OpCreate, Path: path})
	}
	b, err := e.Run.BackupFile(path)
	if err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return e.Journal.Add(state.Entry{Op: state.OpModify, Path: path, Backup: b})
}

// Exec runs a changing command and logs it.
func (e *Env) Exec(ctx context.Context, name string, args ...string) (string, error) {
	c := sys.Command(name, args...)
	e.Log.Debug("exec", "cmd", c.String())
	return e.Sys.Run(ctx, c)
}

// Undo records a command that Rollback must run.
func (e *Env) Undo(note string, cmd ...string) error {
	return e.Journal.Add(state.Entry{Op: state.OpUndo, Undo: cmd, Note: note})
}

// Install installs the missing packages from pkgs and journals them.
func (e *Env) Install(ctx context.Context, pkgs ...string) error {
	miss := sys.MissingPkgs(ctx, e.Sys, pkgs...)
	if len(miss) == 0 {
		return nil
	}
	e.Infof("installing %v", miss)
	if err := sys.AptInstall(ctx, e.Sys, miss...); err != nil {
		return err
	}
	return e.Journal.Add(state.Entry{Op: state.OpPackage, Packages: miss})
}

// Rollback is the default module rollback: replay the journal.
func (e *Env) Rollback(ctx context.Context) error {
	return e.Journal.Replay(ctx, e.Infof)
}
