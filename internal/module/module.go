// Package module defines the Module interface every setup step implements,
// the Plan it produces and the Env it runs in.
package module

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/huh/v2"
)

// Module is one setup step (ssh, ufw, ...).
//
// Lifecycle: Prepare (optional) -> Form (TUI only) -> Check -> summary ->
// Apply -> Report (optional). Rollback undoes everything the module did.
type Module interface {
	ID() string
	Name() string
	Description() string
	// Form returns the questions, bound to env.Answers. Nil = no questions.
	Form(env *Env) []*huh.Group
	// Check computes what Apply would change. An empty plan means the module
	// is already applied. Check must not change the host.
	Check(ctx context.Context, env *Env) (Plan, error)
	// Apply makes the changes of p.
	Apply(ctx context.Context, env *Env, p Plan) error
	// Rollback undoes what Apply did (normally env.Journal.Replay plus
	// service restarts).
	Rollback(ctx context.Context, env *Env) error
}

// Preparer fills answers that depend on the host (random port, client IP,
// current hostname, ...) before the questions are shown.
type Preparer interface {
	Prepare(ctx context.Context, env *Env) error
}

// Reporter contributes lines to the final report.
type Reporter interface {
	Report(env *Env) []ReportLine
}

// Required modules always run and cannot be unselected (preflight).
type Required interface {
	Required() bool
}

// ReportLine is one line of the final report.
type ReportLine struct {
	Label string
	Value string
	Warn  bool // highlighted (e.g. "open the port in your provider firewall")
}

// ChangeKind classifies a change for the summary screen.
type ChangeKind string

const (
	KindFile    ChangeKind = "file"
	KindPackage ChangeKind = "package"
	KindService ChangeKind = "service"
	KindCommand ChangeKind = "command"
	KindUser    ChangeKind = "user"
	KindInfo    ChangeKind = "info" // shown, but nothing to do by itself
)

// Change is one planned change.
type Change struct {
	Kind    ChangeKind
	Target  string // path, package, unit, user
	Summary string // one line for the summary screen
	Diff    string // unified diff for files
	Risky   bool   // highlighted in the summary
}

// Plan is the list of changes of one module.
type Plan struct {
	Module  string
	Changes []Change
	// Notes are warnings shown in the summary that are not changes
	// (e.g. "firewalld is active, ufw module skipped").
	Notes []string
}

// Empty reports whether the plan has nothing to do. Info entries do not
// count.
func (p Plan) Empty() bool {
	for _, c := range p.Changes {
		if c.Kind != KindInfo {
			return false
		}
	}
	return true
}

// Add appends a change.
func (p *Plan) Add(kind ChangeKind, target, format string, args ...any) {
	p.Changes = append(p.Changes, Change{Kind: kind, Target: target, Summary: fmt.Sprintf(format, args...)})
}

// Risky appends a highlighted change.
func (p *Plan) Risky(kind ChangeKind, target, format string, args ...any) {
	p.Changes = append(p.Changes, Change{Kind: kind, Target: target, Summary: fmt.Sprintf(format, args...), Risky: true})
}

// Note appends a warning.
func (p *Plan) Note(format string, args ...any) {
	p.Notes = append(p.Notes, fmt.Sprintf(format, args...))
}

// Has reports whether the plan contains a change for target.
func (p Plan) Has(target string) bool {
	for _, c := range p.Changes {
		if c.Target == target && c.Kind != KindInfo {
			return true
		}
	}
	return false
}

// String renders the plan as plain text (dry-run output, logs).
func (p Plan) String() string {
	var b strings.Builder
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "  ! %s\n", n)
	}
	if p.Empty() {
		b.WriteString("  already applied, nothing to do\n")
	}
	for _, c := range p.Changes {
		mark := "-"
		if c.Risky {
			mark = "*"
		}
		fmt.Fprintf(&b, "  %s %s\n", mark, c.Summary)
		if c.Diff != "" {
			for _, l := range strings.Split(strings.TrimRight(c.Diff, "\n"), "\n") {
				b.WriteString("      " + l + "\n")
			}
		}
	}
	return b.String()
}

// LoginCheck describes the "log in from a second terminal" step of the SSH
// module.
type LoginCheck struct {
	Command    string        // ssh -p 2222 admin@203.0.113.1
	Timeout    time.Duration // after it, the watchdog rolls back
	PrivateKey string        // shown once when the key was generated with "show"
	KeyPath    string
}

// Prompter is how a module talks to the user while Apply is running.
type Prompter interface {
	// Interactive is false for --config runs without a terminal user.
	Interactive() bool
	// ConfirmLogin shows the login instructions and waits until the user
	// types yes (true), something else (false) or the timeout expires
	// (false).
	ConfirmLogin(ctx context.Context, c LoginCheck) (bool, error)
	// Confirm asks a yes/no question.
	Confirm(ctx context.Context, question string, def bool) (bool, error)
}

// AutoPrompter answers without a user (non-interactive runs).
type AutoPrompter struct{}

func (AutoPrompter) Interactive() bool { return false }

func (AutoPrompter) ConfirmLogin(context.Context, LoginCheck) (bool, error) {
	return false, fmt.Errorf("login confirmation needs an interactive terminal")
}

func (AutoPrompter) Confirm(_ context.Context, _ string, def bool) (bool, error) { return def, nil }
