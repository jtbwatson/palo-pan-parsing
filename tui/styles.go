package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors - Bubble Tea guide color scheme
	primaryColor   = lipgloss.Color("#347aeb") // Blue
	secondaryColor = lipgloss.Color("#636363") // Gray
	// accentColor    = lipgloss.Color("#06B6D4")  // Cyan (unused, kept for future use)
	successColor = lipgloss.Color("#69d194") // Light Green
	warningColor = lipgloss.Color("#F5E6A8") // Pale Yellow
	errorColor   = lipgloss.Color("#f54242") // Red
	mutedColor   = lipgloss.Color("#636363") // Gray
	textColor    = lipgloss.Color("#FFFDF5") // White
	inputTextColor = lipgloss.Color("#F5E6A8") // Pale Yellow

	// Base styles
	// baseStyle = lipgloss.NewStyle().
	//	Padding(1, 2).
	//	Border(lipgloss.RoundedBorder()).
	//	BorderForeground(secondaryColor) // unused, kept for future use

	// Box container - cleaner style (will be dynamically sized)
	boxStyle = lipgloss.NewStyle().
			Padding(2, 3).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(secondaryColor).
			Align(lipgloss.Left)

	// Title styles - cleaner, less flashy
	titleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			PaddingBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(textColor).
			PaddingBottom(1)

	// Menu styles
	choiceStyle = lipgloss.NewStyle()

	selectedStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	// Input styles - clean, no messy borders
	// inputStyle = lipgloss.NewStyle().
	//	Foreground(textColor).
	//	Background(lipgloss.Color("#374151")).
	//	Padding(0, 1) // unused, kept for future use

	// Simple input with just background highlight
	inputFieldStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	// User input text style
	inputTextStyle = lipgloss.NewStyle().
			Foreground(inputTextColor).
			Bold(true)

	// Placeholder text style
	placeholderStyle = lipgloss.NewStyle().
				Foreground(mutedColor).
				Italic(true)

	// Status styles
	successStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)

	errorTitleStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true).
			PaddingBottom(1)

	// Highlight style
	highlightStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	// Help text
	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	// Session summary styles
	sessionActionStyle = lipgloss.NewStyle().
				Foreground(primaryColor).
				Italic(true)

	sessionStatusStyle = lipgloss.NewStyle().
				Foreground(textColor)

	sessionSuccessValueStyle = lipgloss.NewStyle().
					Foreground(successColor).
					Bold(true)

	sessionWarningValueStyle = lipgloss.NewStyle().
					Foreground(warningColor).
					Bold(true)

	sessionErrorValueStyle = lipgloss.NewStyle().
				Foreground(errorColor).
				Bold(true)

	sessionNeutralValueStyle = lipgloss.NewStyle().
					Foreground(textColor)

	// Progress styles
	// progressBarStyle = lipgloss.NewStyle().
	//	Foreground(successColor) // unused, kept for future use

	// progressTextStyle = lipgloss.NewStyle().
	//	Foreground(secondaryColor) // unused, kept for future use
)
