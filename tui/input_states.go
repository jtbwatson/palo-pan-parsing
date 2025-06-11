package tui

import (
	"fmt"
	"strings"

	"palo-pan-parsing/utils"

	tea "github.com/charmbracelet/bubbletea"
)

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
			// Don't pre-populate fileInput - leave empty for placeholder
		case 1: // Find Duplicate Addresses in Device Group
			m.state = StateFileInput
			// Set a flag to indicate we're in device group mode
			m.deviceGroupInput = "DEVICE_GROUP_MODE"
		case 2: // Exit
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
		"Scan a specific device group for duplicate address objects with same IP",
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

	return m.renderWithDynamicWidth(s.String())
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
		} else {
			m.logFile = "default.log" // Use default when field is empty
		}
		// Enable right pane and add initial summary
		m.showRightPane = true
		// Calculate pane sizes immediately if we have width
		if m.width > 0 {
			m.leftPaneWidth = int(float64(m.width) * 0.6)    // 60% for left pane
			m.rightPaneWidth = m.width - m.leftPaneWidth - 1 // 40% for right pane (minus 1 for separator)
		}
		m.clearOutputSummary()
		
		// Check if we're in device group mode
		if m.deviceGroupInput == "DEVICE_GROUP_MODE" {
			m.addFormattedAction("Device Group Duplicate Scan Started")
			m.addFormattedStatusIndented("File", m.logFile)
			m.state = StateDeviceGroupInput
			m.deviceGroupInput = "" // Clear the flag
		} else {
			m.addFormattedAction("Configuration Analysis Started")
			m.addFormattedStatusIndented("File", m.logFile)
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

	// Clean input styling with placeholder support
	cursor := "█"

	if m.fileInput == "" {
		// Show placeholder text when field is empty
		s.WriteString(inputFieldStyle.Render("File: ") + placeholderStyle.Render("default.log") + cursor + "\n\n")
	} else {
		// Show actual input text
		s.WriteString(inputFieldStyle.Render("File: ") + inputTextStyle.Render(m.fileInput) + cursor + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
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
				// Add to output summary
				m.addFormattedAction("Processing Started")
				m.addFormattedStatusIndented("Targets", strings.Join(m.addresses, ", "))

				// Start processing
				m.state = StateProcessing
				m.processingDots = 0
				return m, tea.Batch(
					processFileCmd(m.logFile, m.addresses),
					tickCmd(),
				)
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
		s.WriteString(inputFieldStyle.Render("Address(es): ") + inputTextStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString("Configuration file: " + highlightStyle.Render(m.logFile) + "\n\n")

	s.WriteString(helpStyle.Render("Enter to analyze, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Device group input state handlers
func (m Model) updateDeviceGroupInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		m.deviceGroupInput = ""
	case "enter":
		// Start device group discovery instead of direct processing
		m.addFormattedAction("Discovering Device Groups")
		return m, m.startDeviceGroupDiscovery()
	case "backspace":
		if len(m.deviceGroupInput) > 0 {
			m.deviceGroupInput = m.deviceGroupInput[:len(m.deviceGroupInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.deviceGroupInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewDeviceGroupInput() string {
	var s strings.Builder

	title := titleStyle.Render("Device Group Discovery")
	s.WriteString(title + "\n")

	s.WriteString(helpStyle.Render("The tool will scan your configuration file to discover all device groups,\n"))
	s.WriteString(helpStyle.Render("then let you select which one to analyze for duplicate address objects.\n\n"))

	s.WriteString(inputFieldStyle.Render("Configuration file: ") + inputTextStyle.Render(m.logFile) + "\n\n")

	s.WriteString(successStyle.Render("Ready to scan for device groups!") + "\n\n")

	s.WriteString(helpStyle.Render("Enter to discover device groups, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Device group selection state handlers
func (m Model) updateDeviceGroupSelection(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.discoveredDeviceGroups)-1 {
			m.cursor++
		}
	case "enter", " ":
		if m.cursor < len(m.discoveredDeviceGroups) {
			m.selectedDeviceGroup = m.discoveredDeviceGroups[m.cursor]
			m.addFormattedStatusIndented("Selected Device Group", m.selectedDeviceGroup)
			m.addFormattedAction("Starting Duplicate Address Scan")
			m.state = StateProcessing // Transition to processing state
			return m, m.startDeviceGroupDuplicateScan()
		}
	}

	return m, nil
}

func (m Model) viewDeviceGroupSelection() string {
	var s strings.Builder

	title := titleStyle.Render("Select Device Group")
	s.WriteString(title + "\n")

	s.WriteString(helpStyle.Render(fmt.Sprintf("Found %d device groups. Select one to scan for duplicate address objects:\n\n", len(m.discoveredDeviceGroups))))

	// Display device groups as selectable list
	for i, dg := range m.discoveredDeviceGroups {
		if m.cursor == i {
			s.WriteString(selectedStyle.Render(fmt.Sprintf("> %s", dg)) + "\n")
		} else {
			s.WriteString(choiceStyle.Render(fmt.Sprintf("  %s", dg)) + "\n")
		}
	}

	s.WriteString("\n" + helpStyle.Render("Use ↑/↓ to navigate, Enter to select, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
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
		// Clear address mappings when canceling
		m.addressNameMappings = make(map[string]string)
		m.addressIPMappings = make(map[string]string)
	case "enter":
		if m.newAddressInput != "" {
			// Move to IP address input state
			m.state = StateIPAddressInput
			m.ipAddressInput = ""
			m.ipValidationError = ""
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

	// Show current address being processed and progress
	if len(m.addressProcessingQueue) > 0 && m.currentProcessingIndex < len(m.addressProcessingQueue) {
		currentAddress := m.addressProcessingQueue[m.currentProcessingIndex]
		progress := "(" + "1" + " of " + "1" + ")" // Simplified for now

		s.WriteString("Processing address " + progress + ": " + highlightStyle.Render(currentAddress) + "\n")
		s.WriteString("Enter the name for the new address object:\n")
		s.WriteString("(This will be added to the same groups as " + currentAddress + ")\n\n")
	} else {
		// Fallback for single address (backward compatibility)
		selectedAddresses := []string{}
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				selectedAddresses = append(selectedAddresses, m.addressesWithGroups[i])
			}
		}

		if len(selectedAddresses) > 0 {
			s.WriteString("Source address: " + highlightStyle.Render(selectedAddresses[0]) + "\n")
		}
		s.WriteString("Enter the name for the new address object:\n")
		s.WriteString("(This will be added to the same groups as the source address)\n\n")
	}

	// Clean input styling
	displayText := m.newAddressInput
	cursor := "█"
	if displayText == "" {
		s.WriteString("New Address Name: " + placeholderStyle.Render("my-new-address") + "\n\n")
	} else {
		s.WriteString(inputFieldStyle.Render("New Address Name: ") + inputTextStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// IP address input state handlers
func (m Model) updateIPAddressInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateNewAddressInput
		m.ipAddressInput = ""
		m.ipValidationError = ""
	case "enter":
		if m.ipAddressInput != "" {
			// Validate IP address format
			if err := utils.ValidateIPAddress(m.ipAddressInput); err != nil {
				m.ipValidationError = err.Error()
				return m, nil
			}

			// Clear any previous validation error
			m.ipValidationError = ""

			// Normalize IP address (add default CIDR if missing)
			normalizedIP, err := utils.NormalizeIPAddress(m.ipAddressInput)
			if err != nil {
				m.ipValidationError = err.Error()
				return m, nil
			}
			m.ipAddressInput = normalizedIP

			// Save the current address mapping and IP address
			if len(m.addressProcessingQueue) > 0 && m.currentProcessingIndex < len(m.addressProcessingQueue) {
				currentAddress := m.addressProcessingQueue[m.currentProcessingIndex]
				m.addressNameMappings[currentAddress] = m.newAddressInput
				m.addressIPMappings[currentAddress] = normalizedIP

				// Move to next address or finish processing
				m.currentProcessingIndex++
				if m.currentProcessingIndex < len(m.addressProcessingQueue) {
					// More addresses to process, continue to next one
					m.newAddressInput = ""
					m.ipAddressInput = ""
					m.ipValidationError = ""
					m.state = StateNewAddressInput
				} else {
					// All addresses processed, generate commands for all mappings
					return m.generateAllAddressGroupCommandsWithMappings()
				}
			} else {
				// Fallback for single address (backward compatibility)
				return m.generateSingleAddressGroupCommandWithIP()
			}
		}
	case "backspace":
		if len(m.ipAddressInput) > 0 {
			m.ipAddressInput = m.ipAddressInput[:len(m.ipAddressInput)-1]
			// Clear validation error when user starts typing
			m.ipValidationError = ""
		}
	default:
		if len(msg.String()) == 1 {
			m.ipAddressInput += msg.String()
			// Clear validation error when user starts typing
			m.ipValidationError = ""
		}
	}

	return m, nil
}

func (m Model) viewIPAddressInput() string {
	var s strings.Builder

	title := titleStyle.Render("IP Address Input")
	s.WriteString(title + "\n")

	// Show current address being processed
	if len(m.addressProcessingQueue) > 0 && m.currentProcessingIndex < len(m.addressProcessingQueue) {
		currentAddress := m.addressProcessingQueue[m.currentProcessingIndex]
		progress := "(" + "1" + " of " + "1" + ")" // Simplified for now

		s.WriteString("Processing address " + progress + ": " + highlightStyle.Render(currentAddress) + "\n")
		s.WriteString("New address name: " + highlightStyle.Render(m.newAddressInput) + "\n")
		s.WriteString("Enter the IP address for the new address object:\n\n")
	} else {
		// Fallback for single address
		s.WriteString("New address name: " + highlightStyle.Render(m.newAddressInput) + "\n")
		s.WriteString("Enter the IP address for the new address object:\n\n")
	}

	// Clean input styling
	displayText := m.ipAddressInput
	cursor := "█"
	if displayText == "" {
		s.WriteString("IP Address: " + placeholderStyle.Render("192.168.1.100/32") + "\n\n")
	} else {
		s.WriteString(inputFieldStyle.Render("IP Address: ") + inputTextStyle.Render(displayText) + cursor + "\n\n")
	}

	// Show validation error if present
	if m.ipValidationError != "" {
		s.WriteString(errorStyle.Render("⚠ "+m.ipValidationError) + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}