package tui

import (
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// ANSI colors follow the user's terminal palette (light and dark themes).
var (
	cAccent = lipgloss.Color("12")
	cOK     = lipgloss.Color("10")
	cWarn   = lipgloss.Color("11")
	cErr    = lipgloss.Color("9")
	cDim    = lipgloss.Color("8")

	sTitle   = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sHeader  = lipgloss.NewStyle().Bold(true)
	sOK      = lipgloss.NewStyle().Foreground(cOK)
	sWarn    = lipgloss.NewStyle().Foreground(cWarn)
	sErr     = lipgloss.NewStyle().Foreground(cErr)
	sDim     = lipgloss.NewStyle().Foreground(cDim)
	sBold    = lipgloss.NewStyle().Bold(true)
	sBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cDim).Padding(0, 1)
	sModal   = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(cWarn).Padding(1, 2)
	sButton  = lipgloss.NewStyle().Padding(0, 2).Foreground(cDim)
	sButtonF = lipgloss.NewStyle().Padding(0, 2).Bold(true).Reverse(true)
	sHelp    = lipgloss.NewStyle().Foreground(cDim)
)

func formTheme() huh.Theme { return huh.ThemeFunc(huh.ThemeCharm) }

const (
	iconOK   = "✓"
	iconFail = "✗"
	iconWarn = "!"
	iconSkip = "•"
)
