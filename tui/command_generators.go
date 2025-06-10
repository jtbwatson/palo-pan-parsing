package tui

import (
	"fmt"
	"strings"

	"palo-pan-parsing/processor"

	tea "github.com/charmbracelet/bubbletea"
)

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
			m.selectedSourceAddresses = make(map[int]bool)
			m.selectedSourceAddresses[0] = true
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		} else if len(m.addressesWithGroups) > 1 {
			// Multiple addresses have groups, let user choose
			m.state = StateSelectSourceAddress
			m.cursor = 0
			// Clear any previous selections
			m.selectedSourceAddresses = make(map[int]bool)
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

	// Reset accumulated operation details before starting new operations
	// (Only reset for the operation status display, not the session summary)
	m.lastOperationType = ""
	m.lastOperationSummary = ""
	m.lastFilesGenerated = nil
	m.lastAddressMappings = nil

	// Set status message for operations being executed
	if len(selectedOps) == 1 {
		m.operationMessage = "Executing: " + selectedOps[0]
	} else {
		m.operationMessage = "Executing " + strings.Join(selectedOps, " and ")
	}
	m.state = StateOperationStatus

	// Execute commands (sequentially if multiple, to ensure all results are captured)
	if len(cmds) == 1 {
		return m, cmds[0]
	} else if len(cmds) > 1 {
		// For multiple commands, execute the first one and store the rest for sequential execution
		m.pendingCommands = cmds[1:] // Store remaining commands
		return m, cmds[0]            // Execute first command
	}

	return m, nil
}

// showComprehensiveAnalysisSummary displays a comprehensive summary of the analysis
func (m Model) showComprehensiveAnalysisSummary() (Model, tea.Cmd) {
	// Create comprehensive summary from analysis results
	if analysisResults, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		if addresses, ok := m.analysisResults["addresses"].([]string); ok {
			if configFile, ok := m.analysisResults["configFile"].(string); ok {
				// Store comprehensive analysis summary
				m.lastOperationType = "Analysis Summary"
				m.lastConfigFile = configFile
				m.lastAddresses = addresses

				// Generate comprehensive summary
				var summaryBuilder strings.Builder
				summaryBuilder.WriteString(fmt.Sprintf("Configuration File: %s\n", configFile))
				summaryBuilder.WriteString(fmt.Sprintf("Addresses Analyzed: %s\n", strings.Join(addresses, ", ")))

				// Count total findings
				totalMatches := 0
				addressGroupCount := 0
				redundantAddressCount := 0
				var allFiles []string

				for _, address := range addresses {
					if result, exists := analysisResults.Results[address]; exists {
						totalMatches += len(result.MatchingLines)
					}

					// Check for additional analysis results
					itemsDict := analysisResults.FormatResults(address)
					addressGroupCount += len(itemsDict.AddressGroups)
					redundantAddressCount += len(itemsDict.RedundantAddresses)

					// Add result file
					resultFile := fmt.Sprintf("%s_results.yml", address)
					allFiles = append(allFiles, resultFile)
				}

				summaryBuilder.WriteString(fmt.Sprintf("Total Configuration References: %d\n", totalMatches))
				if addressGroupCount > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("Address Groups Found: %d\n", addressGroupCount))
				}
				if redundantAddressCount > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("Redundant Addresses Found: %d", redundantAddressCount))
				}

				m.lastOperationSummary = summaryBuilder.String()
				m.lastFilesGenerated = allFiles
				m.operationMessage = "Analysis completed successfully!"
				m.state = StateCompleted
				return m, nil
			}
		}
	}

	// Fallback if analysis results not available
	m.lastOperationType = "Analysis Summary"
	m.lastOperationSummary = "Analysis completed - see result files for details"
	m.operationMessage = "Analysis completed successfully!"
	m.state = StateCompleted
	return m, nil
}

// generateAllAddressGroupCommands generates commands for all address mappings
func (m Model) generateAllAddressGroupCommands() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		newModel := m
		newModel.state = StateOperationStatus
		newModel.operationMessage = fmt.Sprintf("Executing operations for %d address mappings...", len(m.addressNameMappings))

		// Create a sequential command to process all mappings
		cmd := generateSequentialAddressGroupCommands(proc, m.addressNameMappings, m.pendingCommands)
		return newModel, cmd
	}

	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group commands"
	return newModel, nil
}

// generateSingleAddressGroupCommand generates command for single address (backward compatibility)
func (m Model) generateSingleAddressGroupCommand() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		var sourceAddress string

		// Find the selected source address
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				sourceAddress = m.addressesWithGroups[i]
				break
			}
		}

		if sourceAddress != "" {
			cmd := generateAddressGroupCmdWithName(proc, sourceAddress, m.newAddressInput)
			newModel := m
			newModel.state = StateOperationStatus
			newModel.operationMessage = "Executing address group operation..."

			// If we have pending commands, execute them all together
			if len(m.pendingCommands) > 0 {
				// Add the address group command to pending commands
				allCmds := append([]tea.Cmd{cmd}, m.pendingCommands...)
				newModel.pendingCommands = nil // Clear pending commands
				return newModel, tea.Batch(allCmds...)
			} else {
				// Just execute the address group command
				return newModel, cmd
			}
		}
	}

	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group command"
	return newModel, nil
}

// generateAllAddressGroupCommandsWithIP generates commands for all address mappings with IP addresses
func (m Model) generateAllAddressGroupCommandsWithIP() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		newModel := m
		newModel.state = StateOperationStatus
		newModel.operationMessage = fmt.Sprintf("Executing operations for %d address mappings...", len(m.addressNameMappings))

		// Create a sequential command to process all mappings with IP address
		cmd := generateSequentialAddressGroupCommandsWithIP(proc, m.addressNameMappings, m.ipAddressInput, m.pendingCommands)
		return newModel, cmd
	}

	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group commands with IP"
	return newModel, nil
}

// generateAllAddressGroupCommandsWithMappings generates commands for all address mappings with separate IP mappings
func (m Model) generateAllAddressGroupCommandsWithMappings() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		newModel := m
		newModel.state = StateOperationStatus
		newModel.operationMessage = fmt.Sprintf("Executing operations for %d address mappings...", len(m.addressNameMappings))

		// Create a sequential command to process all mappings with separate IP mappings
		cmd := generateSequentialAddressGroupCommandsWithMappings(proc, m.addressNameMappings, m.addressIPMappings, m.pendingCommands)
		return newModel, cmd
	}
	
	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group commands with mappings"
	return newModel, nil
}

// generateSingleAddressGroupCommandWithIP generates command for single address with IP
func (m Model) generateSingleAddressGroupCommandWithIP() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		var sourceAddress string

		// Find the selected source address
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				sourceAddress = m.addressesWithGroups[i]
				break
			}
		}

		if sourceAddress != "" {
			cmd := generateAddressGroupCmdWithNameAndIP(proc, sourceAddress, m.newAddressInput, m.ipAddressInput)
			newModel := m
			newModel.state = StateOperationStatus
			newModel.operationMessage = "Executing address group operation..."

			// If we have pending commands, execute them all together
			if len(m.pendingCommands) > 0 {
				// Add the address group command to pending commands
				allCmds := append([]tea.Cmd{cmd}, m.pendingCommands...)
				newModel.pendingCommands = nil // Clear pending commands
				return newModel, tea.Batch(allCmds...)
			} else {
				// Just execute the address group command
				return newModel, cmd
			}
		}
	}

	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group command with IP"
	return newModel, nil
}