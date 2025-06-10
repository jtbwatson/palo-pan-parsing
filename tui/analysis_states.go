package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Processing state
func (m Model) viewProcessing() string {
	var s strings.Builder

	title := titleStyle.Render("Processing Configuration...")
	s.WriteString(title + "\n\n")

	s.WriteString("Analyzing: " + highlightStyle.Render(strings.Join(m.addresses, ", ")) + "\n")
	s.WriteString("File: " + highlightStyle.Render(m.logFile) + "\n\n")

	// Animated progress indicator
	dots := strings.Repeat(".", m.processingDots)
	spaces := strings.Repeat(" ", 3-m.processingDots)
	progressText := "Working" + dots + spaces
	s.WriteString(progressText + "\n\n")

	// Progress bar (if we have progress)
	if m.progress > 0 {
		s.WriteString(m.progressBar.ViewAs(m.progress) + "\n")
		percentage := int(m.progress * 100)
		s.WriteString(fmt.Sprintf("Progress: %d%%\n\n", percentage))
	} else {
		s.WriteString("Initializing analysis...\n\n")
	}

	s.WriteString(helpStyle.Render("Please wait while we analyze your configuration..."))

	return m.renderWithDynamicWidth(s.String())
}

// Results state handlers
func (m Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		// Reset for next analysis
		m.fileInput = ""
		m.addressInput = ""
		m.addresses = nil
		m.results = ""
	}

	return m, nil
}

func (m Model) viewResults() string {
	var s strings.Builder

	title := titleStyle.Render("Analysis Complete")
	s.WriteString(title + "\n\n")

	s.WriteString("Analysis results have been generated:\n\n")

	if len(m.addresses) == 1 {
		filename := m.addresses[0] + "_results.yml"
		s.WriteString("📄 " + highlightStyle.Render("outputs/"+filename) + "\n")
	} else {
		s.WriteString("📄 Multiple result files generated in " + highlightStyle.Render("outputs/") + " directory\n")
		for _, addr := range m.addresses {
			s.WriteString("   • " + addr + "_results.yml\n")
		}
	}

	s.WriteString("\n" + successStyle.Render("✅ Configuration analysis completed successfully!") + "\n\n")

	s.WriteString(helpStyle.Render("Esc to return to menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Post-analysis state handlers
func (m Model) updatePostAnalysis(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateResults
	case "up", "k":
		for {
			if m.cursor > 0 {
				m.cursor--
				// Skip separator lines
				if m.postAnalysisChoices[m.cursor] != "---" {
					break
				}
			} else {
				break
			}
		}
	case "down", "j":
		for {
			if m.cursor < len(m.postAnalysisChoices)-1 {
				m.cursor++
				// Skip separator lines
				if m.postAnalysisChoices[m.cursor] != "---" {
					break
				}
			} else {
				break
			}
		}
	case " ": // Spacebar toggles selection
		choice := m.postAnalysisChoices[m.cursor]
		// Only allow selection of operation choices, not separators or action items
		if choice == "Generate Address Group Commands" || choice == "Generate Cleanup Commands" {
			// Toggle current selection
			m.postAnalysisSelected[m.cursor] = !m.postAnalysisSelected[m.cursor]
			
			// Implement mutual exclusion - if this operation is now selected, deselect the other
			if m.postAnalysisSelected[m.cursor] {
				for i, otherChoice := range m.postAnalysisChoices {
					if i != m.cursor && (otherChoice == "Generate Address Group Commands" || otherChoice == "Generate Cleanup Commands") {
						m.postAnalysisSelected[i] = false
					}
				}
			}
		}
	case "enter":
		choice := m.postAnalysisChoices[m.cursor]
		switch choice {
		case "Execute Selected Operation":
			return m.executeSelectedOperations()
		case "No Additional Operations":
			return m.showComprehensiveAnalysisSummary()
		case "Return to Main Menu":
			m.state = StateMenu
			// Reset for next analysis
			m.fileInput = ""
			m.addressInput = ""
			m.addresses = nil
			m.results = ""
			m.cursor = 0
			m.postAnalysisSelected = make(map[int]bool)
			// Clear operation details
			m.lastOperationType = ""
			m.lastOperationSummary = ""
			m.lastFilesGenerated = nil
			// Reset right pane
			m.showRightPane = false
			m.clearOutputSummary()
		}
	}

	return m, nil
}

func (m Model) viewPostAnalysis() string {
	var s strings.Builder

	title := titleStyle.Render("Additional Options")
	s.WriteString(title + "\n")

	s.WriteString("Analysis complete! Select operation to perform:\n\n")

	// Menu options with checkboxes
	for i, choice := range m.postAnalysisChoices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}

		// Handle different types of items
		if choice == "---" {
			s.WriteString("  ────────────────────────────────\n")
			continue
		}

		var line string

		if choice == "Generate Address Group Commands" || choice == "Generate Cleanup Commands" {
			// Selectable operations with consistent spacing
			var checkbox string
			if m.postAnalysisSelected[i] {
				checkbox = "[✓]"
			} else {
				checkbox = "[ ]"
			}

			var displayChoice string
			if m.cursor == i {
				displayChoice = selectedStyle.Render(choice)
			} else {
				displayChoice = choiceStyle.Render(choice)
			}

			line = cursor + " " + checkbox + " " + displayChoice

			// Add description below selectable operations
			var description string
			switch choice {
			case "Generate Address Group Commands":
				description = "Add a new address to the same groups as an existing address"
			case "Generate Cleanup Commands":
				description = "Remove redundant address objects and optimize configuration"
			}

			s.WriteString(line + "\n")
			if description != "" {
				s.WriteString("       " + helpStyle.Render(description) + "\n")
			}
			continue
		} else {
			// Action items (Execute, No Additional Options, Return to Menu) - align with checkbox text
			var displayChoice string
			if m.cursor == i {
				displayChoice = selectedStyle.Render(choice)
			} else {
				displayChoice = choiceStyle.Render(choice)
			}

			// cursor(2) + checkbox(4) + space(1) = 7 total characters to align with
			line = cursor + "   • " + displayChoice // 5 spaces to align properly
		}

		s.WriteString(line + "\n")
	}

	s.WriteString("\n" + helpStyle.Render("↑/↓ navigate • Space to select • Enter to execute • Esc to go back"))

	return m.renderWithDynamicWidth(s.String())
}

// Source address selection state handlers
func (m Model) updateSelectSourceAddress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StatePostAnalysis
		m.pendingCommands = nil // Clear pending commands when canceling
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.addressesWithGroups)-1 {
			m.cursor++
		}
	case " ": // Spacebar to toggle selection
		if m.cursor < len(m.addressesWithGroups) {
			m.selectedSourceAddresses[m.cursor] = !m.selectedSourceAddresses[m.cursor]
		}
	case "enter":
		// Build queue of selected addresses for individual processing
		m.addressProcessingQueue = []string{}
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				m.addressProcessingQueue = append(m.addressProcessingQueue, m.addressesWithGroups[i])
			}
		}

		if len(m.addressProcessingQueue) > 0 {
			// Start processing the first address
			m.currentProcessingIndex = 0
			m.addressNameMappings = make(map[string]string) // Reset mappings
			m.addressIPMappings = make(map[string]string)   // Reset IP mappings
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		}
	}

	return m, nil
}

func (m Model) viewSelectSourceAddress() string {
	var s strings.Builder

	title := titleStyle.Render("Select Source Addresses")
	s.WriteString(title + "\n\n")

	s.WriteString("Multiple addresses have address groups. Select which ones to use as sources:\n\n")

	for i, address := range m.addressesWithGroups {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}

		// Checkbox indicator (matching post-analysis style)
		var checkbox string
		if m.selectedSourceAddresses[i] {
			checkbox = "[✓]"
		} else {
			checkbox = "[ ]"
		}

		line := cursor + " " + checkbox + " " + address
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			s.WriteString(choiceStyle.Render(line) + "\n")
		}
	}

	// Show count of selected items
	selectedCount := 0
	for _, selected := range m.selectedSourceAddresses {
		if selected {
			selectedCount++
		}
	}

	s.WriteString("\n" + helpStyle.Render(fmt.Sprintf("Selected: %d | ↑/↓ to navigate, Space to toggle, Enter to continue, Esc to go back", selectedCount)))

	return m.renderWithDynamicWidth(s.String())
}