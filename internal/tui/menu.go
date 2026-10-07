package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/mimic890/server-init/internal/audit"
	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/ssh"
	"github.com/mimic890/server-init/internal/scan"
	"github.com/mimic890/server-init/internal/sys"
)

// menuItem is one entry of a menu. A disabled item shows why.
type menuItem struct {
	title    string
	desc     string
	disabled string
	run      func(a *App) tea.Cmd
}

// menu is a vertical list with a cursor.
type menu struct {
	items []menuItem
	cur   int
}

func (m *menu) key(k string) {
	switch k {
	case "up", "k", "shift+tab":
		m.cur = (m.cur + len(m.items) - 1) % len(m.items)
	case "down", "j", "tab":
		m.cur = (m.cur + 1) % len(m.items)
	case "home", "g":
		m.cur = 0
	case "end", "G":
		m.cur = len(m.items) - 1
	default:
		// 1-9 jump to an item
		if len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
			if i := int(k[0] - '1'); i < len(m.items) {
				m.cur = i
			}
		}
	}
}

func (m *menu) view() string {
	w := 0
	for _, it := range m.items {
		w = max(w, len(it.title))
	}
	var b strings.Builder
	for i, it := range m.items {
		desc := it.desc
		if it.disabled != "" {
			desc = it.disabled
		}
		title := fmt.Sprintf("%-*s", w, it.title)
		switch {
		case i == m.cur && it.disabled == "":
			b.WriteString(sTitle.Render("› "+title) + "  " + desc + "\n")
		case i == m.cur:
			b.WriteString(sTitle.Render("› ") + sDim.Render(title+"  "+desc) + "\n")
		case it.disabled != "":
			b.WriteString(sDim.Render("  "+title+"  "+desc) + "\n")
		default:
			b.WriteString("  " + sBold.Render(title) + "  " + sDim.Render(desc) + "\n")
		}
	}
	return b.String()
}

// flow is what the module screens (questions, summary, apply) were opened
// for; esc on the first screen goes back to where it started.
type flow int

const (
	flowFull flow = iota
	flowCustom
	flowManage
)

func (a *App) mainMenu() *menu {
	m := &menu{items: []menuItem{
		{title: "Full setup", desc: "everything with recommended settings, only a few questions",
			run: func(a *App) tea.Cmd { return a.startSetup(flowFull, nil) }},
		{title: "Custom setup", desc: "choose the modules and answer every question",
			run: func(a *App) tea.Cmd { return a.startPicker() }},
		{title: "Security audit", desc: "check SSH, accounts, ports, firewall, updates, web server; changes nothing",
			run: func(a *App) tea.Cmd { return a.runAudit() }},
		{title: "Malware scan", desc: "look for miners, backdoors and rootkit tricks; optional ClamAV",
			run: func(a *App) tea.Cmd { return a.startScan() }},
		{title: "Manage", desc: "SSH, admin user, firewall, fail2ban",
			run: func(a *App) tea.Cmd { a.openManage(); return nil }},
		{title: "Quit", desc: "", run: func(*App) tea.Cmd { return tea.Quit }},
	}}
	if len(a.blocking()) > 0 {
		last := len(m.items) - 1
		for i := range m.items[:last] {
			m.items[i].disabled = "unavailable"
		}
		m.cur = last
	} else if len(a.opts.Only) > 0 {
		m.cur = 1
	}
	return m
}

func (a *App) manageMenu() *menu {
	f2b := ""
	if !sys.Has(a.opts.Env.Sys, "fail2ban-client") {
		f2b = "fail2ban is not installed - set it up first"
	}
	items := []menuItem{
		{title: "SSH", desc: "port, key, login user, limits",
			run: func(a *App) tea.Cmd { return a.startSetup(flowManage, []string{"ssh"}) }},
		{title: "Admin user", desc: "create the admin, sudo, root password",
			run: func(a *App) tea.Cmd { return a.startSetup(flowManage, []string{"users"}) }},
		{title: "Firewall", desc: "ufw: web ports, trusted interfaces, Docker",
			run: func(a *App) tea.Cmd { return a.startSetup(flowManage, []string{"ufw"}) }},
		{title: "fail2ban settings", desc: "ban limits, whitelist",
			run: func(a *App) tea.Cmd { return a.startSetup(flowManage, []string{"fail2ban"}) }},
		{title: "fail2ban status", desc: "jails, banned IPs, whitelist and blacklist", disabled: f2b,
			run: func(a *App) tea.Cmd { return a.runAction("fail2ban status", "f2b", []string{"status"}) }},
		{title: "Ban / unban an IP", desc: "unban, whitelist or blacklist an address", disabled: f2b,
			run: func(a *App) tea.Cmd { return a.startIPAction() }},
	}
	if p := ssh.PendingPorts(a.opts.Env.Sys); len(p) > 0 {
		items = append(items, menuItem{title: "Close old SSH port", desc: fmt.Sprintf("port(s) %v still open from a --config run", p),
			run: func(a *App) tea.Cmd { return a.runAction("Close old SSH port", "ssh", []string{"finalize"}) }})
	}
	items = append(items, menuItem{title: "Back", run: func(a *App) tea.Cmd { a.screen = scrMenu; return nil }})
	return &menu{items: items}
}

func (a *App) openManage() {
	cur := 0
	if a.manage != nil {
		cur = a.manage.cur
	}
	a.manage = a.manageMenu()
	a.manage.cur = min(cur, len(a.manage.items)-1)
	a.screen = scrManage
}

// updateMenu handles the main and the manage menu.
func (a *App) updateMenu(m *menu, msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return a, nil
	}
	switch k.String() {
	case "q":
		return a, tea.Quit
	case "esc":
		if a.screen == scrManage {
			a.screen = scrMenu
			return a, nil
		}
		return a, tea.Quit
	case "enter", "space":
		it := m.items[m.cur]
		if it.disabled != "" {
			return a, nil
		}
		return a, it.run(a)
	}
	m.key(k.String())
	return a, nil
}

// --- actions: management commands with captured output --------------------

// action is a management command (fail2ban, ssh finalize) run from the
// manage menu; an optional form asks for its arguments first.
type action struct {
	title string
	form  *huh.Form
	args  func() []string
	cmd   string
	// run replaces cmd: it writes its result to out
	run func(ctx context.Context, out io.Writer) error
	// report: the result replaces the progress lines
	report   bool
	fromMain bool
	running  bool
	done     bool
	out      []string
	err      error
}

type actionDoneMsg struct {
	out string
	err error
}

func (a *App) runAction(title, cmd string, args []string) tea.Cmd {
	a.act = &action{title: title, cmd: cmd, args: func() []string { return args }}
	a.screen = scrAction
	return a.execAction()
}

func (a *App) execAction() tea.Cmd {
	act := a.act
	act.running = true
	ctx := a.ctx
	if act.run != nil {
		run := act.run
		return tea.Batch(a.spin.Tick, func() tea.Msg {
			var buf bytes.Buffer
			err := run(ctx, &buf)
			return actionDoneMsg{out: buf.String(), err: err}
		})
	}
	fn := a.opts.Commands[act.cmd]
	env, args := a.opts.Env.For(act.cmd), act.args()
	return tea.Batch(a.spin.Tick, func() tea.Msg {
		if fn == nil {
			return actionDoneMsg{err: fmt.Errorf("command %q is not available", act.cmd)}
		}
		var buf bytes.Buffer
		err := fn(ctx, env, args, &buf)
		return actionDoneMsg{out: buf.String(), err: err}
	})
}

// startIPAction asks what to do with which address, then runs `f2b`.
func (a *App) startIPAction() tea.Cmd {
	var op, ip string
	op = "unban"
	needsIP := func() bool { return op != "unban-all" }
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What to do").
				Options(
					huh.NewOption("Unban an IP", "unban"),
					huh.NewOption("Unban everyone", "unban-all"),
					huh.NewOption("Whitelist an IP (never banned)", "whitelist add"),
					huh.NewOption("Remove an IP from the whitelist", "whitelist del"),
					huh.NewOption("Blacklist an IP (banned on all ports, permanently)", "blacklist add"),
					huh.NewOption("Remove an IP from the blacklist", "blacklist del"),
				).
				Value(&op),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("IP address or CIDR").
				Description("e.g. 203.0.113.7 or 203.0.113.0/24").
				Value(&ip).
				Validate(func(s string) error {
					if !sys.ValidIPOrCIDR(strings.TrimSpace(s)) {
						return errors.New("not a valid IP or CIDR")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return !needsIP() }),
	).WithTheme(formTheme()).WithShowHelp(true)
	a.act = &action{title: "Ban / unban an IP", cmd: "f2b", form: form, args: func() []string {
		args := strings.Fields(op)
		if needsIP() {
			args = append(args, strings.TrimSpace(ip))
		}
		return args
	}}
	a.screen = scrAction
	return form.Init()
}

func (a *App) updateAction(msg tea.Msg) (tea.Model, tea.Cmd) {
	act := a.act
	switch msg := msg.(type) {
	case actionDoneMsg:
		act.running, act.done, act.err = false, true, msg.err
		if act.report {
			act.out = nil
		}
		if out := strings.TrimRight(msg.out, "\n"); out != "" {
			act.out = append(act.out, strings.Split(out, "\n")...)
		}
		a.layout()
		a.vp.SetContentLines(act.out)
		if act.report {
			a.vp.GotoTop() // the score is on the first line
		} else {
			a.vp.GotoBottom()
		}
		return a, nil
	case spinner.TickMsg:
		if !act.running {
			return a, nil
		}
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		return a, cmd
	case tea.KeyPressMsg:
		switch {
		case act.done && (msg.String() == "enter" || msg.String() == "esc"):
			a.actionBack()
			return a, nil
		case act.done && msg.String() == "q":
			return a, tea.Quit
		case act.form != nil && !act.running && !act.done && msg.String() == "esc":
			a.actionBack()
			return a, nil
		}
	}
	if act.form != nil && !act.running && !act.done {
		m, cmd := act.form.Update(msg)
		act.form = m.(*huh.Form)
		switch act.form.State {
		case huh.StateAborted:
			a.actionBack()
			return a, nil
		case huh.StateCompleted:
			return a, a.execAction()
		}
		return a, cmd
	}
	if act.done {
		var cmd tea.Cmd
		a.vp, cmd = a.vp.Update(msg)
		return a, cmd
	}
	return a, nil
}

// actionBack returns to the menu the action was started from.
func (a *App) actionBack() {
	if a.act.fromMain {
		a.screen = scrMenu
		return
	}
	a.openManage()
}

func (a *App) viewAction() string {
	act := a.act
	head := sHeader.Render(act.title) + "\n\n"
	switch {
	case act.form != nil && !act.running && !act.done:
		return head + act.form.View() + "\n" + sHelp.Render("esc back")
	case act.running:
		return head + a.spin.View() + " running...\n" + strings.Join(tail(act.out, max(a.height-6, 3)), "\n")
	}
	foot := sOK.Render("Done.")
	if act.report {
		foot = sHelp.Render(fmt.Sprintf("↑/↓ pgup/pgdn scroll (%3.0f%%)", a.vp.ScrollPercent()*100))
	}
	if act.err != nil {
		foot = sErr.Render("Failed: " + act.err.Error())
	}
	return head + a.vp.View() + "\n" + foot + "  " + sHelp.Render("enter back · q quit")
}

// startSetup opens the questions of a set of modules (nil = all).
func (a *App) startSetup(f flow, ids []string) tea.Cmd {
	mods, err := a.opts.Registry.Select(ids)
	if err != nil {
		a.notice = err.Error()
		return nil
	}
	a.flow = f
	a.opts.Env.Quick = f == flowFull
	a.runner.Modules = mods
	a.forms, a.plans, a.checkErr = nil, nil, nil
	return a.prepare()
}

// back returns to the screen the current setup flow started from.
func (a *App) back() tea.Cmd {
	switch a.flow {
	case flowCustom:
		return a.startPicker()
	case flowManage:
		a.openManage()
	default:
		a.screen = scrMenu
	}
	return nil
}

// Command is a `server-init <name> ...` subcommand (modules.Commands).
type Command = func(ctx context.Context, env *module.Env, args []string, out io.Writer) error

func tail(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

// reportStyles colors audit and scan reports.
var reportStyles = check.Styles{
	OK: style(sOK), Info: style(sTitle), Warn: style(sWarn), Fail: style(sErr), Dim: style(sDim), Bold: style(sHeader),
}

func style(st lipgloss.Style) func(string) string {
	return func(s string) string { return st.Render(s) }
}

// runAudit runs the security audit and shows the report.
func (a *App) runAudit() tea.Cmd {
	s := a.opts.Env.Sys
	a.act = &action{title: "Security audit", report: true, fromMain: true, run: func(ctx context.Context, out io.Writer) error {
		check.Render(out, audit.Run(ctx, s), reportStyles)
		return nil
	}}
	a.screen = scrAction
	return a.execAction()
}

// startScan asks for the scan depth, then runs the malware scan.
func (a *App) startScan() tea.Cmd {
	mode := "quick"
	clam := "Built-in checks + ClamAV antivirus (installs clamav, downloads ~300 MB of signatures, needs ~1 GB RAM)"
	if sys.Has(a.opts.Env.Sys, "clamscan") {
		clam = "Built-in checks + ClamAV antivirus (installed)"
	}
	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Scan depth").
			Description("The built-in checks look for miners, programs in temp directories, backdoors in cron, systemd and\n"+
				"shell startup files, rootkit tricks, unknown SSH keys and changed system programs. They only read.").
			Options(
				huh.NewOption("Built-in checks (1-3 minutes)", "quick"),
				huh.NewOption(clam, "clamav"),
			).
			Value(&mode),
	)).WithTheme(formTheme()).WithShowHelp(true)
	env := a.opts.Env.For("scan")
	a.act = &action{title: "Malware scan", form: form, report: true, fromMain: true,
		run: func(ctx context.Context, out io.Writer) error {
			r := scan.Run(ctx, env.Sys, scan.Options{ClamAV: mode == "clamav", Progress: func(s string) { env.Infof("%s", s) }})
			check.Render(out, r, reportStyles)
			return nil
		}}
	a.screen = scrAction
	return form.Init()
}
