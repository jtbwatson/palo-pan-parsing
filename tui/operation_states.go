package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Operation status state handlers
func (m Model) updateOperationStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "enter", "esc", " ":
		// Any key returns to post-analysis menu
		m.state = StatePostAnalysis
		m.operationMessage = ""
	}

	return m, nil
}

func (m Model) viewOperationStatus() string {
	var s strings.Builder

	title := titleStyle.Render("Operation Status")
	s.WriteString(title + "\n\n")

	if m.operationMessage != "" {
		if strings.Contains(m.operationMessage, "No operations selected") {
			s.WriteString(warningStyle.Render(m.operationMessage) + "\n\n")
		} else {
			// Show success message
			s.WriteString(successStyle.Render("✅ "+m.operationMessage) + "\n\n")

			// Show detailed operation summary if available
			if m.lastOperationType != "" {
				s.WriteString(highlightStyle.Render("Operation: ") + m.lastOperationType + "\n\n")

				// Show configuration file if available
				if m.lastConfigFile != "" {
					s.WriteString(highlightStyle.Render("Configuration File: ") + m.lastConfigFile + "\n\n")
				}

				// Show addresses analyzed if available
				if len(m.lastAddresses) > 0 {
					s.WriteString(highlightStyle.Render("Addresses: ") + strings.Join(m.lastAddresses, ", ") + "\n\n")
				}

				// Show address mappings if available (for address group operations)
				if len(m.lastAddressMappings) > 0 {
					s.WriteString(highlightStyle.Render("Address Mappings:") + "\n")
					for source, target := range m.lastAddressMappings {
						s.WriteString("  " + source + " → " + target + "\n")
					}
					s.WriteString("\n")
				}

				if m.lastOperationSummary != "" {
					s.WriteString(highlightStyle.Render("Summary:") + "\n")

					// Process summary line by line for proper indentation and wrapping
					summaryLines := strings.Split(strings.TrimSpace(m.lastOperationSummary), "\n")
					for _, line := range summaryLines {
						line = strings.TrimSpace(line)
						if line != "" {
							// Handle long lines by wrapping them
							maxLineLength := 80
							if m.width > 0 {
								maxLineLength = m.width - 20 // Leave room for indentation and borders
								if maxLineLength < 40 {
									maxLineLength = 40
								}
							}

							if len(line) <= maxLineLength {
								if strings.HasPrefix(line, "•") || strings.HasPrefix(line, "-") {
									s.WriteString("  " + line + "\n")
								} else if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
									s.WriteString(line + "\n")
								} else {
									s.WriteString("  " + line + "\n")
								}
							} else {
								// Wrap long lines
								wrapped := m.wrapText(line, maxLineLength)
								for i, wrappedLine := range wrapped {
									if i == 0 {
										if strings.HasPrefix(line, "•") || strings.HasPrefix(line, "-") {
											s.WriteString("  " + wrappedLine + "\n")
										} else if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
											s.WriteString(wrappedLine + "\n")
										} else {
											s.WriteString("  " + wrappedLine + "\n")
										}
									} else {
										s.WriteString("    " + wrappedLine + "\n") // Extra indent for continuation
									}
								}
							}
						}
					}
					s.WriteString("\n")
				}

				if len(m.lastFilesGenerated) > 0 {
					s.WriteString(highlightStyle.Render("Files Generated:") + "\n")
					for _, file := range m.lastFilesGenerated {
						// Show just the filename without redundant outputs/ prefix
						cleanFile := strings.TrimPrefix(file, "outputs/")
						s.WriteString("  📄 " + cleanFile + "\n")
					}
					s.WriteString("\n")
				}
			}
		}
	}

	s.WriteString(helpStyle.Render("Press any key to return to Additional Options menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Completion state handlers
func (m Model) updateCompleted(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "enter", "esc", " ":
		// Return to main menu for new analysis
		m.state = StateMenu
		// Clear session data for fresh start
		m.clearOutputSummary()
		m.addresses = []string{}
		m.logFile = ""
		m.fileInput = ""
		m.addressInput = ""
		m.showRightPane = false
	}

	return m, nil
}

func (m Model) viewCompleted() string {
	var s strings.Builder

	// Responsive header based on terminal width
	if m.width >= 60 {
		// Full-width header for larger terminals
		headerBox := `
╔════════════════════════════════════════════════════════╗
║                                                        ║
║                ALL OPERATIONS COMPLETED                ║
║                                                        ║
╚════════════════════════════════════════════════════════╝`
		s.WriteString(successStyle.Render(headerBox))
	} else if m.width >= 45 {
		// Compact header for medium terminals
		compactHeader := `
╔═══════════════════════════════════════╗
║                                       ║
║        OPERATIONS COMPLETED           ║
║                                       ║
╚═══════════════════════════════════════╝`
		s.WriteString(successStyle.Render(compactHeader))
	} else {
		// Minimal header for very small terminals
		minimalHeader := `
┌─────────────────────────────┐
│                             │
│     OPERATIONS COMPLETE     │
│                             │
└─────────────────────────────┘`
		s.WriteString(successStyle.Render(minimalHeader))
	}

	s.WriteString("\n\n")

	// Main title
	summaryMsg := titleStyle.Render("Analysis Complete")
	s.WriteString(summaryMsg + "\n\n")

	// Stats summary
	totalFiles := len(m.lastFilesGenerated)
	if totalFiles > 0 {
		fileWord := "files"
		if totalFiles == 1 {
			fileWord = "file"
		}
		statsMsg := fmt.Sprintf("Generated %d output %s in the outputs/ directory", totalFiles, fileWord)
		s.WriteString(successStyle.Render(statsMsg) + "\n")
		
		// List all generated files
		for _, file := range m.lastFilesGenerated {
			// Show just the filename without redundant outputs/ prefix
			cleanFile := strings.TrimPrefix(file, "outputs/")
			s.WriteString("  • " + cleanFile + "\n")
		}
		s.WriteString("\n")
	}

	if len(m.addresses) > 0 {
		addressMsg := fmt.Sprintf("Analyzed %d address object(s): %s", len(m.addresses), strings.Join(m.addresses, ", "))
		s.WriteString(highlightStyle.Render(addressMsg) + "\n")
	}

	if m.logFile != "" {
		fileMsg := fmt.Sprintf("Configuration file: %s", m.logFile)
		s.WriteString(sessionStatusStyle.Render(fileMsg) + "\n\n")
	}

	// Action prompt
	s.WriteString(highlightStyle.Render("Press Enter to start a new analysis, or q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Error state handlers
func (m Model) updateError(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		// Reset error state
		m.err = nil
		m.fileInput = ""
		m.addressInput = ""
		m.addresses = nil
	}

	return m, nil
}

func (m Model) viewError() string {
	var s strings.Builder

	title := errorTitleStyle.Render("Error")
	s.WriteString(title + "\n\n")

	if m.err != nil {
		s.WriteString(errorStyle.Render(m.err.Error()) + "\n\n")
	}

	s.WriteString(helpStyle.Render("Esc to return to menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}