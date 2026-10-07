package tui

import (
	"fmt"
	"strings"

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
	steps := []string{"Preflight", "Modules", "Questions", "Summary", "Apply", "Report"}
	cur := map[screen]int{scrWelcome: 0, scrPicker: 1, scrForms: 2, scrChecking: 3, scrSummary: 3, scrApply: 4, scrReport: 5}[a.screen]
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
	title := sBold.Render("server-init") + sDim.Render(" "+a.opts.Version)
	if a.opts.DryRun {
		title += " " + sWarn.Render("[dry run]")
	}
	return title + "  " + strings.Join(parts, sDim.Render(" › ")) + "\n"
}

func (a *App) body() string {
	switch a.screen {
	case scrWelcome:
		return a.viewWelcome()
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

func check(ok bool) string {
	if ok {
		return sOK.Render(iconOK)
	}
	return sErr.Render(iconFail)
}

func (a *App) viewWelcome() string {
	f := a.opts.Env.Facts
	var b strings.Builder
	b.WriteString(sHeader.Render("Initial setup and hardening for Debian 12+ / Ubuntu 24.04+") + "\n\n")
	row := func(icon, label, value string) {
		fmt.Fprintf(&b, "  %s %-14s %s\n", icon, label, value)
	}
	osIcon := sOK.Render(iconOK)
	osNote := ""
	if !f.OSSupported {
		osIcon = sWarn.Render(iconWarn)
		osNote = sWarn.Render("  (not tested: targets Debian 12+ / Ubuntu 24.04+)")
	}
	row(osIcon, "OS", f.OSPretty+osNote)
	row(check(f.IsRoot), "root", map[bool]string{true: "yes", false: "no"}[f.IsRoot])
	row(check(f.Systemd), "systemd", map[bool]string{true: "running", false: "not found"}[f.Systemd])
	diskOK := f.FreeDiskMB >= facts.MinFreeDiskMB
	row(check(diskOK), "free disk", fmt.Sprintf("%.1f GB on /", float64(f.FreeDiskMB)/1024))
	inet := sOK.Render(iconOK)
	if !f.Internet {
		inet = sWarn.Render(iconWarn)
	}
	row(inet, "internet", map[bool]string{true: "reachable", false: "package mirrors not reachable"}[f.Internet])
	ports := make([]string, len(f.SSHPorts))
	for i, p := range f.SSHPorts {
		ports[i] = fmt.Sprint(p)
	}
	sock := ""
	if f.SSHSocket {
		sock = sDim.Render("  (socket activation)")
	}
	row(sDim.Render(iconSkip), "SSH port(s)", strings.Join(ports, ", ")+sock)
	client := f.ClientIP
	if client == "" {
		client = sDim.Render("unknown (not an SSH session)")
	}
	row(sDim.Render(iconSkip), "your IP", client)
	row(sDim.Render(iconSkip), "hostname", f.Hostname)
	b.WriteString("\n")
	if bl := a.blocking(); len(bl) > 0 {
		for _, x := range bl {
			b.WriteString(sErr.Render("  cannot continue: "+x) + "\n")
		}
		b.WriteString("\n" + sHelp.Render("q quit"))
		return b.String()
	}
	b.WriteString(sDim.Render("  Nothing is changed until you confirm the summary.") + "\n")
	b.WriteString(sDim.Render("  Keep your current SSH session open during the whole run.") + "\n\n")
	b.WriteString(sHelp.Render("enter continue · q quit"))
	return b.String()
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
		return scroll + "\n" + sHelp.Render("q quit")
	case a.opts.DryRun:
		return scroll + "\n" + sWarn.Render("Dry run: nothing was changed.") + " " + sHelp.Render("enter/q quit")
	case runner.NothingToDo(a.plans):
		return scroll + "\n" + sOK.Render("Everything is already applied.") + " " + sHelp.Render("enter/q quit")
	}
	apply, cancel := sButton.Render("Apply"), sButtonF.Render("Cancel")
	if a.applyBtn {
		apply, cancel = sButtonF.Render("Apply"), sButton.Render("Cancel")
	}
	return scroll + "\n" + sBold.Render("Apply these changes?") + "  " + apply + " " + cancel +
		"  " + sHelp.Render("←/→ choose · enter confirm · y apply · n cancel")
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
		if st == runner.Unchanged {
			name = sDim.Render(name + " (no change)")
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
	foot := sHelp.Render("↑/↓ scroll log · G follow")
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
