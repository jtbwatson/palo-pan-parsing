package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors - Professional blue/purple theme
	primaryColor   = lipgloss.Color("#7C3AED")  // Purple
	secondaryColor = lipgloss.Color("#3B82F6")  // Blue 
	accentColor    = lipgloss.Color("#06B6D4")  // Cyan
	successColor   = lipgloss.Color("#10B981")  // Green
	warningColor   = lipgloss.Color("#F59E0B")  // Amber
	errorColor     = lipgloss.Color("#EF4444")  // Red
	mutedColor     = lipgloss.Color("#6B7280")  // Gray
	textColor      = lipgloss.Color("#F9FAFB")  // Light gray
	
	// Base styles
	baseStyle = lipgloss.NewStyle().
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor)
	
	// Box container - cleaner style
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
	inputStyle = lipgloss.NewStyle().
		Foreground(textColor).
		Background(lipgloss.Color("#374151")).
		Padding(0, 1)
	
	// Simple input with just background highlight
	inputFieldStyle = lipgloss.NewStyle().
		Foreground(secondaryColor).
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
	
	// Progress styles
	progressBarStyle = lipgloss.NewStyle().
		Foreground(successColor)
	
	progressTextStyle = lipgloss.NewStyle().
		Foreground(secondaryColor)
)