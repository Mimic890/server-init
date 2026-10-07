package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"

	"github.com/mimic890/server-init/internal/log"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/runner"
)

// PlainOptions configure the non-interactive mode (--config).
type PlainOptions struct {
	Options
	Modules []module.Module
	Yes     bool // apply without asking
	Out     io.Writer
	In      io.Reader
}

// RunPlain runs without the full-screen UI: print the plan, apply, print
// the report. It returns the process exit code.
func RunPlain(ctx context.Context, o PlainOptions) int {
	out := o.Out
	if out == nil {
		out = os.Stdout
	}
	p := func(format string, args ...any) { _, _ = lipgloss.Fprintf(out, format, args...) }

	f := o.Env.Facts
	p("%s %s\n", sBold.Render("server-init"), sDim.Render(o.Version))
	p("OS: %s  SSH port(s): %v  client IP: %s\n\n", f.OSPretty, f.SSHPorts, orDash(f.ClientIP))
	if !f.IsRoot && !o.DryRun {
		p("%s\n", sErr.Render("Run as root (sudo server-init ...)."))
		return 1
	}
	if !f.Systemd {
		p("%s\n", sErr.Render("systemd is required."))
		return 1
	}
	if o.Env.Prompt == nil {
		o.Env.Prompt = module.AutoPrompter{}
	}

	r := runner.New(o.Env, o.Modules)
	if err := r.Prepare(ctx); err != nil {
		p("%s\n", sErr.Render(err.Error()))
		return 1
	}
	plans, err := r.Check(ctx)
	p("%s\n\n%s", sTitle.Render("Planned changes"), renderPlans(o.Modules, plans))
	if err != nil {
		p("%s\n", sErr.Render("Cannot continue:\n"+err.Error()))
		return 1
	}
	if o.DryRun {
		p("%s\n", sWarn.Render("Dry run: nothing was changed."))
		return 0
	}
	if runner.NothingToDo(plans) {
		p("%s\n", sOK.Render("Everything is already applied."))
		return 0
	}
	if !o.Yes {
		in := o.In
		if in == nil {
			in = os.Stdin
		}
		if fd, ok := in.(interface{ Fd() uintptr }); !ok || !term.IsTerminal(fd.Fd()) {
			p("%s\n", sErr.Render("No terminal to confirm the changes. Re-run with --yes to apply them."))
			return 1
		}
		p("%s ", sBold.Render("Apply these changes? [y/N]"))
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			p("Aborted. Nothing was changed.\n")
			return 0
		}
	}

	status := map[string]runner.Status{}
	errs := map[string]error{}
	if o.Sink != nil {
		o.Sink.Set(func(l log.Line) {
			msg := l.Msg
			switch {
			case l.Level >= slog.LevelError:
				msg = sErr.Render(msg)
			case l.Level >= slog.LevelWarn:
				msg = sWarn.Render(msg)
			}
			p("  %s %s\n", sDim.Render(fmt.Sprintf("%-9s", l.Module)), msg)
		})
		defer o.Sink.Set(nil)
	}
	r.Events = func(e runner.Event) {
		switch e := e.(type) {
		case runner.ModuleStarted:
			status[e.ID] = runner.Running
			p("%s %s\n", sTitle.Render("==>"), e.ID)
		case runner.ModuleFinished:
			status[e.ID] = e.Status
			if e.Err != nil {
				errs[e.ID] = e.Err
			}
		}
	}
	runErr := r.Apply(ctx, plans)
	p("\n%s", RenderReport(o.Modules, status, errs, r.Report(), runErr, o.LogPath))
	if runErr != nil {
		return 1
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// PrintReport prints the final report of a TUI run to w (colors are
// dropped when w is not a terminal).
func PrintReport(w io.Writer, res Result) {
	_, _ = lipgloss.Fprint(w, RenderReport(res.Modules, res.Status, res.Errs, res.Report, res.Err, "/var/log/server-init.log"))
}
