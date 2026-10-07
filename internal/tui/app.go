// Package tui is the interactive front end: main menu (server info) ->
// full setup, custom setup (module picker) or manage -> per-module forms ->
// summary -> apply -> report.
package tui

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/log"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/runner"
)

type screen int

const (
	scrMenu screen = iota
	scrManage
	scrAction
	scrPicker
	scrForms
	scrChecking
	scrSummary
	scrApply
	scrReport
)

// Options configure a TUI run.
type Options struct {
	Version  string
	Registry *module.Registry
	Env      *module.Env
	DryRun   bool
	Only     []string // preselected modules (--only)
	Commands map[string]Command
	Sink     *log.Sink
	LogPath  string
}

// Result is what happened, for the caller to print after the TUI exits.
type Result struct {
	Plans   []module.Plan
	Applied bool
	Err     error
	Report  map[string][]module.ReportLine
	Modules []module.Module
	Status  map[string]runner.Status
	Errs    map[string]error
}

type (
	preparedMsg struct{ err error }
	checkedMsg  struct {
		plans []module.Plan
		err   error
	}
	eventMsg     struct{ ev runner.Event }
	logMsg       struct{ line log.Line }
	applyDoneMsg struct{ err error }
	tickMsg      time.Time
)

// App is the root Bubble Tea model.
type App struct {
	opts   Options
	runner *runner.Runner
	send   func(tea.Msg)
	ctx    context.Context

	screen        screen
	width, height int
	menu          *menu
	manage        *menu
	act           *action
	flow          flow

	picker   *huh.Form
	selected []string

	forms   []*moduleForm
	formIdx int

	plans    []module.Plan
	checkErr error
	vp       viewport.Model
	applyBtn bool // focus on "Apply" (default: Cancel)

	status  map[string]runner.Status
	errs    map[string]error
	spin    spinner.Model
	logs    []string
	logVP   viewport.Model
	follow  bool
	applied bool
	runErr  error
	modal   *modal
	notice  string

	report map[string][]module.ReportLine
	result Result
}

type moduleForm struct {
	mod  module.Module
	form *huh.Form
}

// New builds the model. send must deliver messages to the running program
// (set by Run).
func New(ctx context.Context, opts Options) *App {
	a := &App{
		opts:   opts,
		ctx:    ctx,
		runner: runner.New(opts.Env, nil),
		status: map[string]runner.Status{},
		errs:   map[string]error{},
		spin:   spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(sTitle)),
		vp:     viewport.New(),
		logVP:  viewport.New(),
		follow: true,
		width:  100,
		height: 30,
	}
	a.vp.SoftWrap = true
	a.logVP.SoftWrap = true
	a.menu = a.mainMenu()
	for _, m := range opts.Registry.All() {
		if module.IsRequired(m) {
			continue
		}
		if len(opts.Only) == 0 || slices.Contains(opts.Only, m.ID()) {
			a.selected = append(a.selected, m.ID())
		}
	}
	return a
}

// Run starts the TUI and blocks until it exits.
func Run(ctx context.Context, opts Options) (Result, error) {
	a := New(ctx, opts)
	p := tea.NewProgram(a, tea.WithContext(ctx))
	a.send = p.Send
	opts.Env.Prompt = &Prompter{send: p.Send}
	if opts.Sink != nil {
		opts.Sink.Set(func(l log.Line) { p.Send(logMsg{l}) })
		defer opts.Sink.Set(nil)
	}
	_, err := p.Run()
	a.result.Modules = a.runner.Modules
	a.result.Status = a.status
	a.result.Errs = a.errs
	return a.result, err
}

func (a *App) Init() tea.Cmd { return nil }

func (a *App) blocking() []string {
	f := a.opts.Env.Facts
	var b []string
	if !f.IsRoot && !a.opts.DryRun {
		b = append(b, "run as root (sudo server-init)")
	}
	if !f.Systemd {
		b = append(b, "systemd is required")
	}
	return b
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.layout()
	case logMsg:
		a.addLog(msg.line)
		if a.screen == scrAction && a.act != nil && a.act.running {
			a.act.out = append(a.act.out, msg.line.Msg)
		}
		return a, nil
	case loginRequestMsg:
		a.modal = newLoginModal(msg)
		return a, tickCmd()
	case confirmRequestMsg:
		a.modal = newConfirmModal(msg)
		return a, nil
	case closeModalMsg:
		a.modal = nil
		return a, nil
	case preparedMsg:
		if msg.err != nil {
			a.checkErr = msg.err
			a.screen = scrSummary
			a.renderSummary()
			return a, nil
		}
		a.buildForms()
		return a, a.openForm(0)
	case tickMsg:
		if a.modal != nil && a.modal.login {
			return a, tickCmd()
		}
		return a, nil
	case tea.KeyPressMsg:
		if a.modal != nil {
			if a.modal.key(msg) {
				a.modal = nil
			}
			return a, nil
		}
		if msg.String() == "ctrl+c" {
			if a.screen == scrApply && !a.applied {
				a.notice = "Apply is running - ctrl+c is disabled so the server is not left half-configured."
				return a, nil
			}
			return a, tea.Quit
		}
	}

	switch a.screen {
	case scrMenu:
		a.notice = ""
		return a.updateMenu(a.menu, msg)
	case scrManage:
		a.notice = ""
		return a.updateMenu(a.manage, msg)
	case scrAction:
		return a.updateAction(msg)
	case scrPicker:
		return a.updatePicker(msg)
	case scrForms:
		return a.updateForms(msg)
	case scrChecking:
		return a.updateChecking(msg)
	case scrSummary:
		return a.updateSummary(msg)
	case scrApply:
		return a.updateApply(msg)
	case scrReport:
		if k, ok := msg.(tea.KeyPressMsg); ok {
			switch k.String() {
			case "q", "enter", "esc":
				return a, tea.Quit
			}
			var cmd tea.Cmd
			a.vp, cmd = a.vp.Update(msg)
			return a, cmd
		}
	}
	return a, nil
}

// --- picker ----------------------------------------------------------------

func (a *App) startPicker() tea.Cmd {
	var opts []huh.Option[string]
	for _, m := range a.opts.Registry.All() {
		if module.IsRequired(m) {
			continue
		}
		label := fmt.Sprintf("%-10s %s", m.ID(), sDim.Render(m.Description()))
		opts = append(opts, huh.NewOption(label, m.ID()).Selected(slices.Contains(a.selected, m.ID())))
	}
	a.picker = huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title("Modules to run").
			Description("space toggles, enter continues. Modules always run in a safe order.").
			Options(opts...).
			Value(&a.selected).
			// huh v2.0.3 sizes a MultiSelect without counting the description
			Height(len(opts) + 4),
	)).WithTheme(formTheme()).WithShowHelp(true)
	a.flow = flowCustom
	a.opts.Env.Quick = false
	a.screen = scrPicker
	return a.picker.Init()
}

func (a *App) updatePicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		a.screen = scrMenu
		return a, nil
	}
	m, cmd := a.picker.Update(msg)
	a.picker = m.(*huh.Form)
	switch a.picker.State {
	case huh.StateAborted:
		return a, tea.Quit
	case huh.StateCompleted:
		mods, err := a.opts.Registry.Select(a.selected)
		if err != nil {
			a.checkErr = err
			return a, nil
		}
		if len(a.selected) == 0 {
			// only required modules: nothing useful to do, ask again
			return a, a.startPicker()
		}
		a.runner.Modules = mods
		a.forms, a.plans, a.checkErr = nil, nil, nil
		return a, a.prepare()
	}
	return a, cmd
}

func (a *App) prepare() tea.Cmd {
	r := a.runner
	ctx := a.ctx
	return func() tea.Msg { return preparedMsg{err: r.Prepare(ctx)} }
}

// --- forms -----------------------------------------------------------------

func (a *App) buildForms() {
	a.forms = nil
	for _, m := range a.runner.Modules {
		groups := m.Form(a.runner.EnvFor(m))
		if len(groups) == 0 {
			continue
		}
		f := huh.NewForm(groups...).WithTheme(formTheme()).WithShowHelp(true)
		a.forms = append(a.forms, &moduleForm{mod: m, form: f})
	}
}

func (a *App) openForm(i int) tea.Cmd {
	if i >= len(a.forms) {
		return a.check()
	}
	if i < 0 {
		return a.back()
	}
	a.formIdx = i
	mf := a.forms[i]
	if mf.form.State != huh.StateNormal {
		// re-open a finished form: rebuild it, answers are kept in Env
		mf.form = huh.NewForm(mf.mod.Form(a.runner.EnvFor(mf.mod))...).WithTheme(formTheme()).WithShowHelp(true)
	}
	a.screen = scrForms
	return mf.form.Init()
}

func (a *App) updateForms(msg tea.Msg) (tea.Model, tea.Cmd) {
	if len(a.forms) == 0 || a.formIdx >= len(a.forms) {
		return a, nil
	}
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		return a, a.openForm(a.formIdx - 1)
	}
	mf := a.forms[a.formIdx]
	m, cmd := mf.form.Update(msg)
	mf.form = m.(*huh.Form)
	switch mf.form.State {
	case huh.StateAborted:
		return a, tea.Quit
	case huh.StateCompleted:
		return a, a.openForm(a.formIdx + 1)
	}
	return a, cmd
}

// --- check / summary -------------------------------------------------------

func (a *App) check() tea.Cmd {
	a.screen = scrChecking
	r := a.runner
	ctx := a.ctx
	return tea.Batch(a.spin.Tick, func() tea.Msg {
		plans, err := r.Check(ctx)
		return checkedMsg{plans: plans, err: err}
	})
}

func (a *App) updateChecking(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case checkedMsg:
		a.plans, a.checkErr = msg.plans, msg.err
		a.result.Plans = msg.plans
		a.applyBtn = false
		a.screen = scrSummary
		a.renderSummary()
		return a, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		return a, cmd
	}
	return a, nil
}

func (a *App) canApply() bool {
	return a.checkErr == nil && !a.opts.DryRun && !runner.NothingToDo(a.plans)
}

func (a *App) updateSummary(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		var cmd tea.Cmd
		a.vp, cmd = a.vp.Update(msg)
		return a, cmd
	}
	switch k.String() {
	case "esc":
		if len(a.forms) > 0 {
			return a, a.openForm(len(a.forms) - 1)
		}
		return a, a.back()
	case "q":
		return a, tea.Quit
	case "n":
		return a, a.back()
	case "left", "right", "tab", "shift+tab", "h", "l":
		if a.canApply() {
			a.applyBtn = !a.applyBtn
		}
		return a, nil
	case "y":
		if a.canApply() {
			return a, a.startApply()
		}
		return a, nil
	case "enter":
		if a.canApply() && a.applyBtn {
			return a, a.startApply()
		}
		return a, a.back()
	}
	var cmd tea.Cmd
	a.vp, cmd = a.vp.Update(msg)
	return a, cmd
}

// --- apply -----------------------------------------------------------------

func (a *App) startApply() tea.Cmd {
	a.screen = scrApply
	for _, m := range a.runner.Modules {
		a.status[m.ID()] = runner.Pending
	}
	send := a.send
	a.runner.Events = func(e runner.Event) {
		if send != nil {
			send(eventMsg{e})
		}
	}
	r, ctx, plans := a.runner, a.ctx, a.plans
	a.layout()
	return tea.Batch(a.spin.Tick, func() tea.Msg {
		return applyDoneMsg{err: r.Apply(ctx, plans)}
	})
}

func (a *App) updateApply(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case eventMsg:
		switch e := msg.ev.(type) {
		case runner.ModuleStarted:
			a.status[e.ID] = runner.Running
		case runner.ModuleFinished:
			a.status[e.ID] = e.Status
			if e.Err != nil {
				a.errs[e.ID] = e.Err
			}
		}
		return a, nil
	case applyDoneMsg:
		a.applied = true
		a.runErr = msg.err
		a.result.Applied = true
		a.result.Err = msg.err
		a.report = a.runner.Report()
		a.result.Report = a.report
		a.notice = ""
		return a, nil
	case spinner.TickMsg:
		if a.applied {
			return a, nil
		}
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		return a, cmd
	case tea.KeyPressMsg:
		if a.applied {
			switch msg.String() {
			case "enter", "r":
				a.screen = scrReport
				a.renderReport()
				return a, nil
			case "q":
				return a, tea.Quit
			}
		}
		switch msg.String() {
		case "end", "G":
			a.follow = true
			a.logVP.GotoBottom()
			return a, nil
		}
		var cmd tea.Cmd
		a.logVP, cmd = a.logVP.Update(msg)
		a.follow = a.logVP.AtBottom()
		return a, cmd
	}
	return a, nil
}

func (a *App) addLog(l log.Line) {
	prefix := ""
	if l.Module != "" {
		prefix = sDim.Render(fmt.Sprintf("%-9s", l.Module)) + " "
	}
	msg := l.Msg
	switch {
	case l.Level >= slog.LevelError:
		msg = sErr.Render(msg)
	case l.Level >= slog.LevelWarn:
		msg = sWarn.Render(msg)
	}
	a.logs = append(a.logs, sDim.Render(l.Time.Format("15:04:05"))+" "+prefix+msg)
	if len(a.logs) > 2000 {
		a.logs = a.logs[len(a.logs)-2000:]
	}
	a.logVP.SetContentLines(a.logs)
	if a.follow {
		a.logVP.GotoBottom()
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// layout resizes the viewports for the current screen.
func (a *App) layout() {
	h := max(a.height-6, 5)
	a.vp.SetWidth(a.width)
	a.vp.SetHeight(h)
	// left box: listWidth incl. padding + 2 border; gap 1; right box: content
	// + 2 padding + 2 border
	lw := a.width - (listWidth + 2) - 1 - 4
	if a.width < 80 {
		lw = a.width - 4
		h = max(a.height-len(a.runner.Modules)-8, 5)
	}
	a.logVP.SetWidth(max(lw, 20))
	a.logVP.SetHeight(h)
	if a.follow {
		a.logVP.GotoBottom()
	}
}

const listWidth = 28
