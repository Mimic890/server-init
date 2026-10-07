package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/mimic890/server-init/internal/module"
)

// loginRequestMsg opens the "log in from a second terminal" dialog.
type loginRequestMsg struct {
	check    module.LoginCheck
	deadline time.Time
	reply    chan bool
}

// confirmRequestMsg opens a yes/no dialog.
type confirmRequestMsg struct {
	question string
	def      bool
	reply    chan bool
}

// Prompter shows dialogs inside the running TUI. Modules call it from the
// apply goroutine; it blocks until the user answers.
type Prompter struct {
	send func(tea.Msg)
}

func (p *Prompter) Interactive() bool { return true }

func (p *Prompter) ConfirmLogin(ctx context.Context, c module.LoginCheck) (bool, error) {
	reply := make(chan bool, 1)
	deadline := time.Now().Add(c.Timeout)
	p.send(loginRequestMsg{check: c, deadline: deadline, reply: reply})
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	select {
	case ok := <-reply:
		return ok, nil
	case <-ctx.Done():
		p.send(closeModalMsg{})
		return false, nil
	}
}

func (p *Prompter) Confirm(ctx context.Context, q string, def bool) (bool, error) {
	reply := make(chan bool, 1)
	p.send(confirmRequestMsg{question: q, def: def, reply: reply})
	select {
	case ok := <-reply:
		return ok, nil
	case <-ctx.Done():
		p.send(closeModalMsg{})
		return def, ctx.Err()
	}
}

type closeModalMsg struct{}
