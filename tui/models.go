package tui

import (
	"fmt"
	"strings"

	"palo-pan-parsing/processor"

	tea "github.com/charmbracelet/bubbletea"
)

// AppState represents the current state of the application
type AppState int

const (
	StateMenu AppState = iota
	StateFileInput
	StateAddressInput
	StateProcessing
	StateResults
	StatePostAnalysis
	StateSelectSourceAddress
	StateNewAddressInput
	StateOperationStatus
	StateError
)

// Model represents the main TUI model
type Model struct {
	state  AppState
	width  int
	height int

	// Input fields
	logFile         string
	addresses       []string
	addressInput    string
	fileInput       string
	newAddressInput string

	// Address group generation
	addressesWithGroups   []string
	selectedSourceAddress string

	// Pending operations
	pendingCommands []tea.Cmd

	// Processing
	progress float64

	// Results
	results           string
	analysisResults   map[string]any
	hasAddressGroups  bool
	hasRedundantAddrs bool
	operationMessage  string

	// Error handling
	err error

	// UI components
	cursor               int
	selected             map[int]struct{}
	choices              []string
	postAnalysisChoices  []string
	postAnalysisSelected map[int]bool // Track which post-analysis options are selected
}

// NewModel creates a new TUI model
func NewModel() Model {
	return Model{
		state:                StateMenu,
		selected:             make(map[int]struct{}),
		choices:              []string{"Analyze Configuration File", "Exit"},
		postAnalysisSelected: make(map[int]bool),
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch m.state {
		case StateMenu:
			return m.updateMenu(msg)
		case StateFileInput:
			return m.updateFileInput(msg)
		case StateAddressInput:
			return m.updateAddressInput(msg)
		case StateResults:
			return m.updateResults(msg)
		case StatePostAnalysis:
			return m.updatePostAnalysis(msg)
		case StateSelectSourceAddress:
			return m.updateSelectSourceAddress(msg)
		case StateNewAddressInput:
			return m.updateNewAddressInput(msg)
		case StateOperationStatus:
			return m.updateOperationStatus(msg)
		case StateError:
			return m.updateError(msg)
		}

	case ProcessResult:
		return m.handleProcessResult(msg)
	}

	return m, nil
}

// View implements tea.Model
func (m Model) View() string {
	switch m.state {
	case StateMenu:
		return m.viewMenu()
	case StateFileInput:
		return m.viewFileInput()
	case StateAddressInput:
		return m.viewAddressInput()
	case StateProcessing:
		return m.viewProcessing()
	case StateResults:
		return m.viewResults()
	case StatePostAnalysis:
		return m.viewPostAnalysis()
	case StateSelectSourceAddress:
		return m.viewSelectSourceAddress()
	case StateNewAddressInput:
		return m.viewNewAddressInput()
	case StateOperationStatus:
		return m.viewOperationStatus()
	case StateError:
		return m.viewError()
	}

	return ""
}

// Menu state handlers
func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.choices)-1 {
			m.cursor++
		}
	case "enter", " ":
		switch m.cursor {
		case 0: // Analyze Configuration File
			m.state = StateFileInput
			m.fileInput = "default.log"
		case 1: // Exit
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m Model) viewMenu() string {
	var s strings.Builder

	// Header
	title := titleStyle.Render("PAN Configuration Log Parser (Go Edition)")
	subtitle := subtitleStyle.Render("Advanced Palo Alto Networks Configuration Analysis")

	s.WriteString(title + "\n")
	s.WriteString(subtitle + "\n")

	// Menu options with descriptions
	descriptions := []string{
		"Search for address objects and analyze their usage across configuration",
		"Exit the application",
	}

	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
			choice = selectedStyle.Render(choice)
		} else {
			choice = choiceStyle.Render(choice)
		}
		s.WriteString(cursor + " " + choice + "\n")
		// Add description immediately below each option with proper indentation
		if i < len(descriptions) {
			s.WriteString("   " + helpStyle.Render(descriptions[i]) + "\n")
		}
		s.WriteString("\n") // Extra spacing between option groups
	}

	s.WriteString(helpStyle.Render("Use ↑/↓ to navigate, Enter to select, q to quit"))

	return boxStyle.Render(s.String())
}

// File input state handlers
func (m Model) updateFileInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
	case "enter":
		if m.fileInput != "" {
			m.logFile = m.fileInput
			m.state = StateAddressInput
		}
	case "backspace":
		if len(m.fileInput) > 0 {
			m.fileInput = m.fileInput[:len(m.fileInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.fileInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewFileInput() string {
	var s strings.Builder

	title := titleStyle.Render("Configuration File Selection")
	s.WriteString(title + "\n")

	s.WriteString("Enter the path to your PAN configuration file:\n")
	s.WriteString(helpStyle.Render("Supports both local files and full file paths") + "\n\n")

	// Clean input styling - just highlight the text, no messy boxes
	displayText := m.fileInput
	if displayText == "" {
		displayText = "default.log"
	}
	cursor := "█"

	s.WriteString("File: " + inputFieldStyle.Render(displayText) + cursor + "\n\n")

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return boxStyle.Render(s.String())
}

// Address input state handlers
func (m Model) updateAddressInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateFileInput
	case "enter":
		if m.addressInput != "" {
			// Parse comma-separated addresses
			addresses := strings.Split(m.addressInput, ",")
			m.addresses = make([]string, 0, len(addresses))
			for _, addr := range addresses {
				if trimmed := strings.TrimSpace(addr); trimmed != "" {
					m.addresses = append(m.addresses, trimmed)
				}
			}
			if len(m.addresses) > 0 {
				// Start processing
				m.state = StateProcessing
				return m, processFileCmd(m.logFile, m.addresses)
			}
		}
	case "backspace":
		if len(m.addressInput) > 0 {
			m.addressInput = m.addressInput[:len(m.addressInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.addressInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewAddressInput() string {
	var s strings.Builder

	title := titleStyle.Render("Address Object Selection")
	s.WriteString(title + "\n")

	s.WriteString("Enter address object name(s) to analyze:\n")
	s.WriteString(helpStyle.Render("Use commas to separate multiple addresses (e.g., web1,db1,server2)") + "\n\n")

	// Clean input styling - just highlight the text, no messy boxes
	displayText := m.addressInput
	cursor := "█"
	if displayText == "" {
		// Show placeholder when empty
		s.WriteString("Address(es): " + cursor + "\n\n")
	} else {
		s.WriteString("Address(es): " + inputFieldStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString("Configuration file: " + highlightStyle.Render(m.logFile) + "\n\n")

	s.WriteString(helpStyle.Render("Enter to analyze, Esc to go back, Ctrl+C to quit"))

	return boxStyle.Render(s.String())
}

// Processing state
func (m Model) viewProcessing() string {
	var s strings.Builder

	title := titleStyle.Render("Processing Configuration...")
	s.WriteString(title + "\n\n")

	s.WriteString("Analyzing: " + highlightStyle.Render(strings.Join(m.addresses, ", ")) + "\n")
	s.WriteString("File: " + highlightStyle.Render(m.logFile) + "\n\n")

	// Simple progress indicator
	progress := "Working"
	for range int(m.progress*3) % 4 {
		progress += "."
	}
	s.WriteString(progress + "\n\n")

	s.WriteString(helpStyle.Render("Please wait while we analyze your configuration..."))

	return boxStyle.Render(s.String())
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

	return boxStyle.Render(s.String())
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
			m.postAnalysisSelected[m.cursor] = !m.postAnalysisSelected[m.cursor]
		}
	case "enter":
		choice := m.postAnalysisChoices[m.cursor]
		switch choice {
		case "Execute Selected Operations":
			return m.executeSelectedOperations()
		case "Return to Main Menu":
			m.state = StateMenu
			// Reset for next analysis
			m.fileInput = ""
			m.addressInput = ""
			m.addresses = nil
			m.results = ""
			m.cursor = 0
			m.postAnalysisSelected = make(map[int]bool)
		}
	}

	return m, nil
}

// executeSelectedOperations runs all selected operations in sequence
func (m Model) executeSelectedOperations() (Model, tea.Cmd) {
	var cmds []tea.Cmd
	var selectedOps []string
	var needsAddressInput bool

	for i, choice := range m.postAnalysisChoices {
		if m.postAnalysisSelected[i] {
			selectedOps = append(selectedOps, choice)
			switch choice {
			case "Generate Address Group Commands":
				// This operation requires new address name input
				needsAddressInput = true
			case "Generate Cleanup Commands":
				if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
					if configFile, ok := m.analysisResults["configFile"].(string); ok {
						if addresses, ok := m.analysisResults["addresses"].([]string); ok {
							// Generate cleanup commands for all addresses that have redundant addresses
							for _, address := range addresses {
								if _, exists := proc.Results[address]; exists {
									itemsDict := proc.FormatResults(address)
									if len(itemsDict.RedundantAddresses) > 0 {
										cmds = append(cmds, generateCleanupCmd(proc, configFile, address))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// If Generate Address Group Commands is selected, handle address selection
	if needsAddressInput {
		// Store any other pending commands to execute after address input
		m.pendingCommands = cmds

		if len(m.addressesWithGroups) == 1 {
			// Only one address has groups, go directly to new address input
			m.selectedSourceAddress = m.addressesWithGroups[0]
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		} else if len(m.addressesWithGroups) > 1 {
			// Multiple addresses have groups, let user choose
			m.state = StateSelectSourceAddress
			m.cursor = 0
		} else {
			// No addresses with groups (shouldn't happen)
			m.operationMessage = "No addresses with address groups found"
			m.state = StateOperationStatus
		}
		return m, nil
	}

	if len(cmds) == 0 {
		// No operations selected - show message and stay in current state
		m.operationMessage = "No operations selected. Use Space to select operations first."
		m.state = StateOperationStatus
		return m, nil
	}

	// Set status message for operations being executed
	if len(selectedOps) == 1 {
		m.operationMessage = "Executing: " + selectedOps[0]
	} else {
		m.operationMessage = "Executing " + strings.Join(selectedOps, " and ")
	}
	m.state = StateOperationStatus

	// If only one command, execute it directly
	if len(cmds) == 1 {
		return m, cmds[0]
	}

	// For multiple commands, we need to batch them
	return m, tea.Batch(cmds...)
}

func (m Model) viewPostAnalysis() string {
	var s strings.Builder

	title := titleStyle.Render("Additional Options")
	s.WriteString(title + "\n")

	s.WriteString("Analysis complete! Select operations to perform:\n\n")

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
			// Action items (Execute, Return to Menu) - align with checkbox text
			var displayChoice string
			if m.cursor == i {
				displayChoice = selectedStyle.Render(choice)
			} else {
				displayChoice = choiceStyle.Render(choice)
			}

			// cursor(2) + checkbox(4) + space(1) = 7 total characters to align with
			line = cursor + "      " + displayChoice // 6 spaces to align properly
		}

		s.WriteString(line + "\n")
	}

	s.WriteString("\n" + helpStyle.Render("↑/↓ navigate • Space to select • Enter to execute • Esc to go back"))

	return boxStyle.Render(s.String())
}

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
	s.WriteString(title + "\n")

	if m.operationMessage != "" {
		if strings.Contains(m.operationMessage, "No operations selected") {
			s.WriteString(warningStyle.Render(m.operationMessage) + "\n\n")
		} else {
			s.WriteString(m.operationMessage + "\n\n")
		}
	}

	s.WriteString(helpStyle.Render("Press any key to return to Additional Options menu, q to quit"))

	return boxStyle.Render(s.String())
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

	return boxStyle.Render(s.String())
}

// New address input state handlers
func (m Model) updateNewAddressInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StatePostAnalysis
		m.newAddressInput = ""
		m.pendingCommands = nil // Clear pending commands when canceling
	case "enter":
		if m.newAddressInput != "" {
			// Generate address group commands with the new name
			if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
				if m.selectedSourceAddress != "" {
					m.state = StateOperationStatus
					m.operationMessage = "Executing selected operations..."

					// Create address group command
					addressGroupCmd := generateAddressGroupCmdWithName(proc, m.selectedSourceAddress, m.newAddressInput)

					// If we have pending commands, execute them all together
					if len(m.pendingCommands) > 0 {
						// Add the address group command to pending commands
						allCmds := append([]tea.Cmd{addressGroupCmd}, m.pendingCommands...)
						m.pendingCommands = nil // Clear pending commands
						return m, tea.Batch(allCmds...)
					} else {
						// Just execute the address group command
						return m, addressGroupCmd
					}
				}
			}
		}
	case "backspace":
		if len(m.newAddressInput) > 0 {
			m.newAddressInput = m.newAddressInput[:len(m.newAddressInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.newAddressInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewNewAddressInput() string {
	var s strings.Builder

	title := titleStyle.Render("New Address Name")
	s.WriteString(title + "\n")

	if m.selectedSourceAddress != "" {
		s.WriteString(fmt.Sprintf("Source address: %s\n", highlightStyle.Render(m.selectedSourceAddress)))
	}
	s.WriteString("Enter the name for the new address object:\n")
	s.WriteString("(This will be added to the same groups as the source address)\n\n")

	// Clean input styling
	displayText := m.newAddressInput
	cursor := "█"
	if displayText == "" {
		s.WriteString("New Address Name: " + placeholderStyle.Render("my-new-address") + "\n\n")
	} else {
		s.WriteString("New Address Name: " + inputFieldStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return boxStyle.Render(s.String())
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
	case "enter":
		if m.cursor < len(m.addressesWithGroups) {
			m.selectedSourceAddress = m.addressesWithGroups[m.cursor]
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		}
	}

	return m, nil
}

func (m Model) viewSelectSourceAddress() string {
	var s strings.Builder

	title := titleStyle.Render("Select Source Address")
	s.WriteString(title + "\n\n")

	s.WriteString("Multiple addresses have address groups. Select which one to use as the source:\n\n")

	for i, address := range m.addressesWithGroups {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}

		if i == m.cursor {
			s.WriteString(selectedStyle.Render(cursor+address) + "\n")
		} else {
			s.WriteString(choiceStyle.Render(cursor+address) + "\n")
		}
	}

	s.WriteString("\n" + helpStyle.Render("↑/↓ to navigate, Enter to select, Esc to go back, Ctrl+C to quit"))

	return boxStyle.Render(s.String())
}
