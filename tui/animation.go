package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// TickMsg is sent periodically for animations
type TickMsg time.Time

// ProgressPollMsg is sent to poll for processing progress
type ProgressPollMsg struct{}

// tickCmd returns a command that sends periodic tick messages
func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// checkProcessingCompleteCmd checks if processing is complete
func checkProcessingCompleteCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return ProgressPollMsg{}
	})
}