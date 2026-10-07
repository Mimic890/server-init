package tui

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/module/moduletest"
	"github.com/mimic890/server-init/internal/runner"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func testApp(t *testing.T, f *facts.Facts, mods ...module.Module) *App {
	h := systest.New(t)
	env := &module.Env{
		Answers: config.Default(),
		Facts:   f,
		Sys:     h,
		Run:     state.NewRun(h, time.Unix(0, 0).UTC()),
		Log:     slog.New(slog.DiscardHandler),
	}
	a := New(context.Background(), Options{Version: "test", Registry: module.NewRegistry(mods...), Env: env})
	a.runner.Modules = mods
	a.screen = scrChecking
	return a
}

func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	}
	return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
}

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func okFacts() *facts.Facts {
	return &facts.Facts{IsRoot: true, Systemd: true, OSSupported: true, OSPretty: "Debian 12", SSHPorts: []int{22}, FreeDiskMB: 9000}
}

func TestMenuBlocksWithoutRoot(t *testing.T) {
	f := okFacts()
	f.IsRoot = false
	a := testApp(t, f)
	a.screen = scrMenu
	a.menu = a.mainMenu()
	if !strings.Contains(a.View().Content, "run as root") {
		t.Fatal("missing root warning")
	}
	a.menu.cur = 1
	a.Update(key("enter"))
	if a.screen != scrMenu {
		t.Fatal("must not continue without root")
	}
	a.opts.DryRun = true
	a.menu = a.mainMenu()
	a.menu.cur = 1
	a.Update(key("enter"))
	if a.screen != scrPicker || a.flow != flowCustom {
		t.Fatal("dry run works without root")
	}
	a.Update(key("esc"))
	if a.screen != scrMenu {
		t.Fatal("esc in the picker must return to the menu")
	}
}

func TestMenuServerInfo(t *testing.T) {
	f := okFacts()
	f.Hostname, f.ServerIP, f.CPUs, f.MemTotalMB, f.DiskMB = "web1", "203.0.113.5", 2, 4096, 40960
	f.Uptime = 50 * time.Hour
	a := testApp(t, f)
	a.screen = scrMenu
	v := a.View().Content
	for _, want := range []string{"web1", "Debian 12", "203.0.113.5", "2 vCPU", "RAM 4.0 GB", "of 40.0 GB", "up 2d 2h", "SSH port 22",
		"Full setup", "Custom setup", "Security audit", "Malware scan", "Manage"} {
		if !strings.Contains(v, want) {
			t.Errorf("menu misses %q:\n%s", want, v)
		}
	}
}

func TestFullSetupUsesQuickForms(t *testing.T) {
	m := &moduletest.Fake{IDValue: "x"}
	a := testApp(t, okFacts(), m)
	a.screen = scrMenu
	a.menu.cur = 0
	_, cmd := a.Update(key("enter"))
	if cmd == nil || a.flow != flowFull || !a.opts.Env.Quick {
		t.Fatal("full setup must start in quick mode")
	}
	a.Update(cmd()) // preparedMsg -> forms (none) -> check
	if a.screen != scrChecking {
		t.Fatalf("screen = %v", a.screen)
	}
	a.Update(checkedMsg{plans: []module.Plan{{Module: "x"}}})
	a.Update(key("esc"))
	if a.screen != scrMenu {
		t.Fatal("esc in the summary of the full setup must return to the menu")
	}
	a.menu.cur = 1
	a.Update(key("enter"))
	if a.screen != scrPicker || a.opts.Env.Quick {
		t.Fatal("custom setup must ask every question")
	}
}

func TestManageAction(t *testing.T) {
	var got []string
	a := testApp(t, okFacts())
	a.opts.Commands = map[string]Command{"f2b": func(_ context.Context, _ *module.Env, args []string, out io.Writer) error {
		got = args
		_, _ = io.WriteString(out, "Unbanned 203.0.113.7\n")
		return nil
	}}
	a.screen = scrMenu
	a.menu.cur = 4
	a.Update(key("enter"))
	if a.screen != scrManage {
		t.Fatal("manage menu not opened")
	}
	cmd := a.runAction("test", "f2b", []string{"unban", "203.0.113.7"})
	for _, msg := range runBatch(cmd) {
		if _, ok := msg.(actionDoneMsg); ok {
			a.Update(msg)
		}
	}
	if !a.act.done || strings.Join(got, " ") != "unban 203.0.113.7" {
		t.Fatalf("done=%v args=%v", a.act.done, got)
	}
	if !strings.Contains(a.View().Content, "Unbanned 203.0.113.7") {
		t.Fatalf("output not shown:\n%s", a.View().Content)
	}
	a.Update(key("enter"))
	if a.screen != scrManage {
		t.Fatal("enter after an action must return to the manage menu")
	}
	a.Update(key("esc"))
	if a.screen != scrMenu {
		t.Fatal("esc in the manage menu must return to the main menu")
	}
}

func TestSummaryDefaultsToCancel(t *testing.T) {
	m := &moduletest.Fake{IDValue: "x", Changes: moduletest.Change("/etc/x")}
	a := testApp(t, okFacts(), m)
	a.Update(checkedMsg{plans: []module.Plan{{Module: "x", Changes: m.Changes}}})
	if a.screen != scrSummary || a.applyBtn {
		t.Fatal("summary must open with Cancel focused")
	}
	if !strings.Contains(a.vp.GetContent(), "write /etc/x") {
		t.Fatalf("summary content:\n%s", a.vp.GetContent())
	}
	_, cmd := a.Update(key("enter"))
	if isQuit(cmd) || a.screen != scrMenu || m.Applied != 0 {
		t.Fatal("enter on the default button must go back to the menu without applying")
	}
}

func TestSummaryApplyAndReport(t *testing.T) {
	m := &moduletest.Fake{IDValue: "x", Changes: moduletest.Change("/etc/x"),
		Lines: []module.ReportLine{{Label: "SSH port", Value: "2222"}}}
	a := testApp(t, okFacts(), m)
	var sent []tea.Msg
	a.send = func(msg tea.Msg) { sent = append(sent, msg) }
	a.Update(checkedMsg{plans: []module.Plan{{Module: "x", Changes: m.Changes}}})
	a.Update(key("right"))
	if !a.applyBtn {
		t.Fatal("right must focus Apply")
	}
	_, cmd := a.Update(key("enter"))
	if a.screen != scrApply || cmd == nil {
		t.Fatal("apply not started")
	}
	// run the batched commands: the apply goroutine result is one of them
	msgs := runBatch(cmd)
	for _, s := range sent {
		a.Update(s)
	}
	for _, msg := range msgs {
		a.Update(msg)
	}
	if m.Applied != 1 || !a.applied || a.status["x"] != runner.Done {
		t.Fatalf("applied=%d done=%v status=%v", m.Applied, a.applied, a.status)
	}
	a.Update(key("enter"))
	if a.screen != scrReport || !strings.Contains(a.vp.GetContent(), "2222") {
		t.Fatalf("report:\n%s", a.vp.GetContent())
	}
}

func TestDryRunSummaryCannotApply(t *testing.T) {
	m := &moduletest.Fake{IDValue: "x", Changes: moduletest.Change("/etc/x")}
	a := testApp(t, okFacts(), m)
	a.opts.DryRun = true
	a.Update(checkedMsg{plans: []module.Plan{{Module: "x", Changes: m.Changes}}})
	a.Update(key("y"))
	if a.screen != scrSummary || m.Applied != 0 {
		t.Fatal("dry run must never apply")
	}
}

func TestCheckErrorBlocksApply(t *testing.T) {
	m := &moduletest.Fake{IDValue: "x", Changes: moduletest.Change("/etc/x")}
	a := testApp(t, okFacts(), m)
	a.Update(checkedMsg{plans: []module.Plan{{Module: "x"}}, err: errors.New("bad port")})
	a.Update(key("y"))
	if a.screen != scrSummary || !strings.Contains(a.vp.GetContent(), "bad port") {
		t.Fatal("check error must be shown and block apply")
	}
}

func TestLoginModal(t *testing.T) {
	a := testApp(t, okFacts())
	a.screen = scrApply
	reply := make(chan bool, 1)
	a.Update(loginRequestMsg{check: module.LoginCheck{Command: "ssh -p 2222 admin@host", Timeout: time.Minute},
		deadline: time.Now().Add(time.Minute), reply: reply})
	if a.modal == nil || !strings.Contains(a.View().Content, "ssh -p 2222 admin@host") {
		t.Fatal("modal not shown")
	}
	for _, k := range []string{"y", "e", "x", "backspace", "s"} {
		a.Update(key(k))
	}
	a.Update(key("enter"))
	if a.modal != nil || !<-reply {
		t.Fatal("typing yes must confirm")
	}

	a.Update(loginRequestMsg{check: module.LoginCheck{Command: "ssh"}, deadline: time.Now().Add(time.Minute), reply: reply})
	a.Update(key("n"))
	a.Update(key("enter"))
	if <-reply {
		t.Fatal("anything but yes must reject")
	}
}

func TestCtrlCDisabledDuringApply(t *testing.T) {
	a := testApp(t, okFacts())
	a.screen = scrApply
	_, cmd := a.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if isQuit(cmd) || a.notice == "" {
		t.Fatal("ctrl+c must not quit while applying")
	}
}

// runBatch executes a command tree and returns the leaf messages.
func runBatch(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if b, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range b {
			out = append(out, runBatch(c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func TestAuditFromMenu(t *testing.T) {
	a := testApp(t, okFacts())
	a.screen = scrMenu
	a.menu.cur = 2
	_, cmd := a.Update(key("enter"))
	if a.screen != scrAction || a.act == nil || !a.act.report {
		t.Fatal("audit not started")
	}
	for _, msg := range runBatch(cmd) {
		if _, ok := msg.(actionDoneMsg); ok {
			a.Update(msg)
		}
	}
	if !a.act.done || !strings.Contains(a.vp.GetContent(), "Security audit") {
		t.Fatalf("report not shown:\n%s", a.vp.GetContent())
	}
	a.Update(key("esc"))
	if a.screen != scrMenu {
		t.Fatal("esc after the audit must return to the main menu")
	}
}

func TestScanAsksDepth(t *testing.T) {
	a := testApp(t, okFacts())
	a.screen = scrMenu
	a.menu.cur = 3
	a.Update(key("enter"))
	if a.screen != scrAction || a.act.form == nil || !strings.Contains(a.View().Content, "Built-in checks") {
		t.Fatalf("scan depth form not shown:\n%s", a.View().Content)
	}
	a.Update(key("esc"))
	if a.screen != scrMenu {
		t.Fatal("esc in the scan form must return to the main menu")
	}
}
