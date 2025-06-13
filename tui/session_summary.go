package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderOutputSummary generates the content for the right pane with scrolling
func (m Model) renderOutputSummary() string {
	var s strings.Builder

	// Title for the output summary pane
	s.WriteString(highlightStyle.Render("Session Summary") + "\n\n")

	if len(m.outputSummary) == 0 {
		s.WriteString(helpStyle.Render("No operations completed yet.\n\nAnalysis results and operations\nwill appear here as you\nprogress through the workflow."))
	} else {
		// Calculate visible area (approximate based on height)
		visibleLines := m.height - 8 // Account for borders, padding, title
		if visibleLines < 5 {
			visibleLines = 5
		}

		// Apply scroll offset
		startIdx := m.outputScrollOffset
		endIdx := startIdx + visibleLines

		if startIdx >= len(m.outputSummary) {
			startIdx = len(m.outputSummary) - 1
			if startIdx < 0 {
				startIdx = 0
			}
		}

		if endIdx > len(m.outputSummary) {
			endIdx = len(m.outputSummary)
		}

		// Render visible lines
		for i := startIdx; i < endIdx; i++ {
			if i < len(m.outputSummary) {
				s.WriteString(m.outputSummary[i])
				if i < endIdx-1 {
					s.WriteString("\n")
				}
			}
		}

		// Add scroll indicator if content is scrollable
		if len(m.outputSummary) > visibleLines {
			s.WriteString("\n\n" + helpStyle.Render("PgUp/PgDn, Ctrl+U/D, or mouse wheel to scroll"))
		}
	}

	return s.String()
}

// addToOutputSummary adds an item to the output summary
func (m *Model) addToOutputSummary(item string) {
	m.outputSummary = append(m.outputSummary, item)
}

// clearOutputSummary clears the output summary
func (m *Model) clearOutputSummary() {
	m.outputSummary = []string{}
	m.outputScrollOffset = 0
}

// formatSessionAction formats an action description with italic styling
func formatSessionAction(action string) string {
	return sessionActionStyle.Render(action)
}

// formatSessionStatus formats a status line with key: value format and intelligent coloring
func formatSessionStatus(key, value string) string {
	keyStyled := sessionStatusStyle.Render(key + ": ")
	valueStyled := determineValueStyle(key, value).Render(value)
	return keyStyled + valueStyled
}

// determineValueStyle intelligently determines the appropriate style for a status value
func determineValueStyle(key, value string) lipgloss.Style {
	// Convert to lowercase for easier comparison
	lowerKey := strings.ToLower(key)
	lowerValue := strings.ToLower(value)

	// Handle special cases first before pattern matching
	switch lowerKey {
	case "redundant addresses", "address groups":
		// Redundant addresses and address groups should always be warning colored
		return sessionWarningValueStyle
	case "target address":
		// Target addresses should be success colored (actual address names)
		return sessionSuccessValueStyle
	case "file", "targets":
		// File names and target addresses should be warning colored
		return sessionWarningValueStyle
	case "files generated", "cleanup commands", "group commands":
		// Non-zero counts should be success colored
		if lowerValue != "0" && lowerValue != "" {
			return sessionSuccessValueStyle
		}
	}

	// Success indicators (green)
	successPatterns := []string{
		"complete", "completed", "success", "successful", "found", "generated", "created", "finished",
	}
	for _, pattern := range successPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionSuccessValueStyle
		}
	}

	// Error indicators (red)
	errorPatterns := []string{
		"error", "failed", "failure", "not found", "missing", "invalid", "corrupt",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionErrorValueStyle
		}
	}

	// Warning indicators (yellow)
	warningPatterns := []string{
		"warning", "partial", "limited", "timeout", "retry", "skipped",
	}
	for _, pattern := range warningPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionWarningValueStyle
		}
	}

	// Additional special logic for remaining keys
	switch lowerKey {
	case "total references", "addresses", "address groups":
		// Numbers and "Found" should be success colored
		if lowerValue == "found" || (lowerValue != "0" && lowerValue != "") {
			return sessionSuccessValueStyle
		}
	}

	// Default neutral styling
	return sessionNeutralValueStyle
}

// addFormattedAction adds a formatted action to the output summary
func (m *Model) addFormattedAction(action string) {
	m.addToOutputSummary(formatSessionAction(action))
}

// addFormattedStatus adds a formatted status line to the output summary
func (m *Model) addFormattedStatus(key, value string) {
	m.addToOutputSummary(formatSessionStatus(key, value))
}

// addFormattedStatusIndented adds a formatted status line with indentation
func (m *Model) addFormattedStatusIndented(key, value string) {
	m.addToOutputSummary("  " + formatSessionStatus(key, value))
}

// addFormattedMapping adds a formatted address mapping line
func (m *Model) addFormattedMapping(source, target string) {
	sourceStyled := sessionNeutralValueStyle.Render(source)
	arrowStyled := sessionStatusStyle.Render(" → ")
	targetStyled := sessionSuccessValueStyle.Render(target)
	m.addToOutputSummary("  " + sourceStyled + arrowStyled + targetStyled)
}

// addFormattedLine adds a formatted line by parsing key: value pairs
func (m *Model) addFormattedLine(line string, indented bool) {
	line = strings.TrimSpace(line)
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if indented {
				m.addFormattedStatusIndented(key, value)
			} else {
				m.addFormattedStatus(key, value)
			}
			return
		}
	}
	// Fallback for lines that don't match key:value format
	if indented {
		m.addToOutputSummary("  " + line)
	} else {
		m.addToOutputSummary(line)
	}
}