package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// modal is a dialog shown on top of the apply screen.
type modal struct {
	login    bool
	title    string
	body     string
	deadline time.Time
	input    string
	def      bool
	reply    chan bool
}

func newLoginModal(m loginRequestMsg) *modal {
	var b strings.Builder
	if m.check.PrivateKey != "" {
		b.WriteString("Your new PRIVATE key. Copy everything, including the BEGIN/END lines,\n")
		b.WriteString("to a file on your PC and run: chmod 600 <file>\n\n")
		b.WriteString(m.check.PrivateKey)
		if !strings.HasSuffix(m.check.PrivateKey, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	} else if m.check.KeyPath != "" {
		fmt.Fprintf(&b, "Private key is on the server: %s (download it, e.g. with scp)\n\n", m.check.KeyPath)
	}
	b.WriteString("Open a NEW terminal (keep this one open!) and connect:\n\n")
	b.WriteString("  " + sOK.Render(m.check.Command) + "\n\n")
	b.WriteString("Type " + sBold.Render("yes") + " and press enter when the new login works.\n")
	b.WriteString("Anything else, or no answer in time, rolls the SSH configuration back.")
	return &modal{login: true, title: "Test the new SSH login", body: b.String(), deadline: m.deadline, reply: m.reply}
}

func newConfirmModal(m confirmRequestMsg) *modal {
	return &modal{title: "Question", body: m.question, def: m.def, reply: m.reply}
}

// key handles a key press and reports whether the dialog is finished.
func (m *modal) key(k tea.KeyPressMsg) bool {
	if !m.login {
		switch strings.ToLower(k.String()) {
		case "y":
			m.reply <- true
			return true
		case "n", "esc":
			m.reply <- false
			return true
		case "enter":
			m.reply <- m.def
			return true
		}
		return false
	}
	switch k.String() {
	case "enter":
		m.reply <- strings.EqualFold(strings.TrimSpace(m.input), "yes")
		return true
	case "backspace":
		if m.input != "" {
			m.input = m.input[:len(m.input)-1]
		}
	case "ctrl+u":
		m.input = ""
	default:
		if k.Text != "" && len(m.input) < 16 {
			m.input += k.Text
		}
	}
	return false
}

func (m *modal) view(width int) string {
	var b strings.Builder
	b.WriteString(sTitle.Render(m.title) + "\n\n")
	b.WriteString(m.body + "\n\n")
	if m.login {
		left := max(time.Until(m.deadline).Round(time.Second), 0)
		b.WriteString(sWarn.Render(fmt.Sprintf("Time left: %s", left)) + "\n")
		b.WriteString("> " + m.input + "█")
	} else {
		hint := "y/N"
		if m.def {
			hint = "Y/n"
		}
		b.WriteString(sHelp.Render(hint))
	}
	if m.login {
		// No border: the private key must be copyable line by line.
		return b.String()
	}
	w := min(max(width-4, 40), 100)
	return sModal.Width(w).Render(b.String())
}

// overlay centers the dialog on the screen (the background is replaced, the
// terminal is small and the dialog is the only thing that matters).
func overlay(dialog string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, dialog)
}
