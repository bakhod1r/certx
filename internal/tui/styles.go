package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/bakhod1r/certx/internal/discovery"
)

var (
	accent  = lipgloss.AdaptiveColor{Light: "#5A4FCF", Dark: "#9D8CFF"}
	muted   = lipgloss.AdaptiveColor{Light: "#6B6B6B", Dark: "#8A8A8A"}
	green   = lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#3FB950"}
	yellow  = lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#D29922"}
	red     = lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#F85149"}
	selBg   = lipgloss.AdaptiveColor{Light: "#E8E5FF", Dark: "#2E2A4F"}
	onAccnt = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#1B1530"}

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(accent)
	mutedStyle   = lipgloss.NewStyle().Foreground(muted)
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(muted)
	selStyle     = lipgloss.NewStyle().Background(selBg).Bold(true)
	tabActive    = lipgloss.NewStyle().Bold(true).Foreground(onAccnt).Background(accent).Padding(0, 1)
	tabInactive  = lipgloss.NewStyle().Foreground(muted).Padding(0, 1)
	sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(accent).MarginTop(1)
	labelStyle   = lipgloss.NewStyle().Foreground(muted).Width(12)
	okStyle      = lipgloss.NewStyle().Foreground(green)
	warnStyle    = lipgloss.NewStyle().Foreground(yellow)
	errStyle     = lipgloss.NewStyle().Foreground(red)
)

func statusStyle(s discovery.Status) lipgloss.Style {
	switch s {
	case discovery.StatusOK:
		return okStyle
	case discovery.StatusNoTLS:
		return mutedStyle
	case discovery.StatusSelfSigned, discovery.StatusExpiring, discovery.StatusBadChain:
		return warnStyle
	default:
		return errStyle
	}
}

func statusLabel(s discovery.Status) string {
	icon := "✖"
	switch s {
	case discovery.StatusOK:
		icon = "✔"
	case discovery.StatusNoTLS:
		icon = "○"
	case discovery.StatusSelfSigned, discovery.StatusBadChain:
		icon = "◐"
	case discovery.StatusExpiring:
		icon = "⚠"
	}
	return icon + " " + string(s)
}

// cell truncates s to width w and pads it with spaces.
func cell(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	if pad := w - ansi.StringWidth(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

func rcell(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	if pad := w - ansi.StringWidth(s); pad > 0 {
		s = strings.Repeat(" ", pad) + s
	}
	return s
}
