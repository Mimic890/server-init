package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/runner"
)

func (a *App) View() tea.View {
	var content string
	switch {
	case a.modal != nil && a.modal.login:
		content = a.modal.view(a.width)
	case a.modal != nil:
		content = overlay(a.modal.view(a.width), a.width, a.height)
	default:
		content = a.header() + "\n" + a.body()
	}
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "server-init"
	return v
}

func (a *App) header() string {
	title := sBold.Render("server-init") + sDim.Render(" "+a.opts.Version)
	if a.opts.DryRun {
		title += " " + sWarn.Render("[dry run]")
	}
	switch a.screen {
	case scrMenu, scrManage, scrAction:
		return title + "\n"
	}
	steps := []string{"Questions", "Summary", "Apply", "Report"}
	cur := map[screen]int{scrForms: 0, scrChecking: 1, scrSummary: 1, scrApply: 2, scrReport: 3}[a.screen]
	if a.flow == flowCustom {
		steps = append([]string{"Modules"}, steps...)
		cur++
		if a.screen == scrPicker {
			cur = 0
		}
	}
	parts := make([]string, len(steps))
	for i, s := range steps {
		switch {
		case i == cur:
			parts[i] = sTitle.Render(s)
		case i < cur:
			parts[i] = s
		default:
			parts[i] = sDim.Render(s)
		}
	}
	name := map[flow]string{flowFull: "Full setup", flowCustom: "Custom setup", flowManage: "Manage"}[a.flow]
	return title + "  " + sHeader.Render(name) + "  " + strings.Join(parts, sDim.Render(" › ")) + "\n"
}

func (a *App) body() string {
	switch a.screen {
	case scrMenu:
		return a.viewMenu(a.menu, "")
	case scrManage:
		return a.viewMenu(a.manage, "Manage")
	case scrAction:
		return a.viewAction()
	case scrPicker:
		return a.picker.View()
	case scrForms:
		if a.formIdx < len(a.forms) {
			mf := a.forms[a.formIdx]
			head := sHeader.Render(fmt.Sprintf("%s (%d/%d)", mf.mod.Name(), a.formIdx+1, len(a.forms))) +
				"  " + sDim.Render(mf.mod.Description())
			return head + "\n\n" + mf.form.View() + "\n" + sHelp.Render("esc back · ctrl+c quit")
		}
		return a.spin.View() + " preparing..."
	case scrChecking:
		return a.spin.View() + " checking what needs to change..."
	case scrSummary:
		return a.vp.View() + "\n" + a.summaryFooter()
	case scrApply:
		return a.viewApply()
	case scrReport:
		return a.vp.View() + "\n" + sHelp.Render("↑/↓ scroll · enter/q quit")
	}
	return ""
}

// serverInfo is the box at the top of the main menu.
func (a *App) serverInfo() string {
	f := a.opts.Env.Facts
	dot := sDim.Render(" · ")
	name := f.Hostname
	if name == "" {
		name = "server"
	}
	osName := f.OSPretty
	if !f.OSSupported {
		osName = sWarn.Render(osName + " (not tested: targets Debian 12+ / Ubuntu 24.04+)")
	}
	lines := []string{sBold.Render(name) + dot + osName}

	var hw []string
	if f.ServerIP != "" {
		hw = append(hw, "IP "+f.ServerIP)
	}
	if f.CPUs > 0 {
		hw = append(hw, fmt.Sprintf("%d vCPU", f.CPUs))
	}
	if f.MemTotalMB > 0 {
		hw = append(hw, fmt.Sprintf("RAM %s", gb(f.MemTotalMB)))
	}
	disk := fmt.Sprintf("disk %s free", gb(f.FreeDiskMB))
	if f.DiskMB > 0 {
		disk = fmt.Sprintf("disk %s free of %s", gb(f.FreeDiskMB), gb(f.DiskMB))
	}
	if f.FreeDiskMB < facts.MinFreeDiskMB {
		disk = sWarn.Render(disk)
	}
	hw = append(hw, disk)
	if f.Uptime > 0 {
		hw = append(hw, "up "+uptime(f.Uptime))
	}
	lines = append(lines, strings.Join(hw, dot))

	ports := make([]string, len(f.SSHPorts))
	for i, p := range f.SSHPorts {
		ports[i] = fmt.Sprint(p)
	}
	conn := "SSH port " + strings.Join(ports, ", ")
	if f.SSHSocket {
		conn += sDim.Render(" (socket)")
	}
	if f.ClientIP != "" {
		conn += dot + "your IP " + f.ClientIP
	}
	if !f.Internet {
		conn += dot + sWarn.Render("package mirrors not reachable")
	}
	lines = append(lines, conn)
	w := 0
	for _, l := range lines {
		w = max(w, lipgloss.Width(l))
	}
	return sBox.Width(min(w+4, max(a.width, 40))).Render(strings.Join(lines, "\n"))
}

func (a *App) viewMenu(m *menu, title string) string {
	var b strings.Builder
	b.WriteString(a.serverInfo() + "\n\n")
	if title != "" {
		b.WriteString(sHeader.Render(title) + "\n\n")
	}
	b.WriteString(m.view())
	for _, x := range a.blocking() {
		b.WriteString("\n" + sErr.Render("Cannot continue: "+x))
	}
	if a.notice != "" {
		b.WriteString("\n" + sWarn.Render(a.notice) + "\n")
	}
	if a.screen == scrMenu && len(a.blocking()) == 0 {
		b.WriteString("\n" + sDim.Render("Nothing is changed until you confirm the summary.") + "\n")
	}
	help := "↑/↓ choose · enter open · q quit"
	if a.screen == scrManage {
		help = "↑/↓ choose · enter open · esc back · q quit"
	}
	return b.String() + "\n" + sHelp.Render(help)
}

func gb(mb uint64) string {
	if mb < 1024 {
		return fmt.Sprintf("%d MB", mb)
	}
	return fmt.Sprintf("%.1f GB", float64(mb)/1024)
}

func uptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// renderSummary fills the viewport with all planned changes.
func (a *App) renderSummary() {
	a.layout()
	var b strings.Builder
	if a.checkErr != nil {
		b.WriteString(sErr.Render("Cannot continue:") + "\n")
		for _, l := range strings.Split(a.checkErr.Error(), "\n") {
			b.WriteString(sErr.Render("  "+l) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(renderPlans(a.runner.Modules, a.plans))
	a.vp.SetContent(b.String())
	a.vp.GotoTop()
}

func renderPlans(mods []module.Module, plans []module.Plan) string {
	var b strings.Builder
	for i, p := range plans {
		name := p.Module
		if i < len(mods) {
			name = mods[i].Name()
		}
		state := ""
		if p.Empty() && len(p.Changes) == 0 {
			state = sDim.Render("  already applied")
		}
		b.WriteString(sHeader.Render("▸ "+name) + state + "\n")
		for _, n := range p.Notes {
			b.WriteString("  " + sWarn.Render(iconWarn+" "+n) + "\n")
		}
		for _, c := range p.Changes {
			line := "  • " + c.Summary
			switch {
			case c.Risky:
				line = sWarn.Render("  ★ " + c.Summary)
			case c.Kind == module.KindInfo:
				line = sDim.Render("  " + c.Summary)
			}
			b.WriteString(line + "\n")
			if c.Diff != "" {
				b.WriteString(renderDiff(c.Diff))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderDiff(d string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(d, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
			l = sDim.Render(l)
		case strings.HasPrefix(l, "+"):
			l = sOK.Render(l)
		case strings.HasPrefix(l, "-"):
			l = sErr.Render(l)
		case strings.HasPrefix(l, "@@"):
			l = sDim.Render(l)
		}
		b.WriteString("      " + l + "\n")
	}
	return b.String()
}

func (a *App) summaryFooter() string {
	scroll := sHelp.Render(fmt.Sprintf("↑/↓ pgup/pgdn scroll (%3.0f%%) · esc back", a.vp.ScrollPercent()*100))
	switch {
	case a.checkErr != nil:
		return scroll + "\n" + sHelp.Render("enter back · q quit")
	case a.opts.DryRun:
		return scroll + "\n" + sWarn.Render("Dry run: nothing was changed.") + " " + sHelp.Render("enter back · q quit")
	case runner.NothingToDo(a.plans):
		return scroll + "\n" + sOK.Render("Everything is already applied.") + " " + sHelp.Render("enter back · q quit")
	}
	apply, cancel := sButton.Render("Apply"), sButtonF.Render("Cancel")
	if a.applyBtn {
		apply, cancel = sButtonF.Render("Apply"), sButton.Render("Cancel")
	}
	return scroll + "\n" + sBold.Render("Apply these changes?") + "  " + apply + " " + cancel +
		"  " + sHelp.Render("←/→ choose · enter confirm · y apply · n back")
}

func statusIcon(s runner.Status, spin string) string {
	switch s {
	case runner.Running:
		return spin
	case runner.Done:
		return sOK.Render(iconOK)
	case runner.Unchanged:
		return sOK.Render(iconSkip)
	case runner.Failed:
		return sErr.Render(iconFail)
	case runner.NotRun:
		return sDim.Render("-")
	}
	return sDim.Render("·")
}

func (a *App) viewApply() string {
	var list strings.Builder
	for _, m := range a.runner.Modules {
		st := a.status[m.ID()]
		name := m.Name()
		if st == runner.Unchanged || st == runner.NotRun {
			name = sDim.Render(name)
		}
		fmt.Fprintf(&list, "%s %s\n", statusIcon(st, a.spin.View()), name)
	}
	left := sBox.Width(listWidth).Render(strings.TrimRight(list.String(), "\n"))
	right := sBox.Render(a.logVP.View())
	var main string
	if a.width < 80 {
		main = lipgloss.JoinVertical(lipgloss.Left, left, right)
	} else {
		main = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}
	foot := sHelp.Render("↑/↓ scroll log · G follow · " + iconOK + " done  • no change  " + iconFail + " failed")
	if a.applied {
		if a.runErr != nil {
			foot = sErr.Render("Failed: "+a.runErr.Error()) + "\n" + sHelp.Render("enter report · q quit")
		} else {
			foot = sOK.Render("All done.") + " " + sHelp.Render("enter report · q quit")
		}
	}
	if a.notice != "" {
		foot = sWarn.Render(a.notice) + "\n" + foot
	}
	return main + "\n" + foot
}

func (a *App) renderReport() {
	a.layout()
	a.vp.SetContent(RenderReport(a.runner.Modules, a.status, a.errs, a.report, a.runErr, a.opts.LogPath))
	a.vp.GotoTop()
}

// RenderReport renders the final report (also used by the plain mode).
func RenderReport(mods []module.Module, status map[string]runner.Status, errs map[string]error,
	report map[string][]module.ReportLine, runErr error, logPath string) string {
	var b strings.Builder
	if runErr != nil {
		b.WriteString(sErr.Render("Setup stopped with an error: "+runErr.Error()) + "\n\n")
	} else {
		b.WriteString(sOK.Render("Setup finished.") + "\n\n")
	}
	for _, m := range mods {
		st, ok := status[m.ID()]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "%s %-22s %s\n", statusIcon(st, "…"), m.Name(), sDim.Render(st.String()))
		if err := errs[m.ID()]; err != nil {
			b.WriteString(sErr.Render("    "+err.Error()) + "\n")
		}
	}
	b.WriteString("\n")
	ids := make([]string, 0, len(report))
	for _, m := range mods {
		if _, ok := report[m.ID()]; ok {
			ids = append(ids, m.ID())
		}
	}
	for _, id := range ids {
		for _, l := range report[id] {
			v := l.Value
			if l.Warn {
				v = sWarn.Render(v)
			}
			if l.Label == "" {
				fmt.Fprintf(&b, "  %s\n", v)
			} else {
				fmt.Fprintf(&b, "  %s %s\n", label(sBold.Render(l.Label)), v)
			}
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "  %s %s\n", label(sBold.Render("Log file")), logPath)
	fmt.Fprintf(&b, "  %s %s\n", label(sBold.Render("Undo everything")), "server-init --rollback")
	fmt.Fprintf(&b, "  %s %s\n", label(sBold.Render("Undo one module")), "server-init --rollback <module>")
	return b.String()
}

// label right-pads a styled report label to a fixed column.
func label(s string) string {
	const width = 22
	if w := lipgloss.Width(s); w < width {
		return s + strings.Repeat(" ", width-w)
	}
	return s
}
