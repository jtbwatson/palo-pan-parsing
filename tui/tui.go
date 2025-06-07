package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// Run starts the TUI application
func Run() error {
	// Create the model
	m := NewModel()

	// Create the program with alt screen and mouse support to fully isolate TUI
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	// Start the program
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	// Handle any final state
	if finalModel, ok := finalModel.(Model); ok {
		if finalModel.err != nil {
			fmt.Printf("Application ended with error: %v\n", finalModel.err)
			os.Exit(1)
		}
	}

	return nil
}
