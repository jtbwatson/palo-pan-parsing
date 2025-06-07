package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"palo-pan-parsing/processor"
	"palo-pan-parsing/utils"
)

// ProcessResult represents the result of file processing
type ProcessResult struct {
	Success           bool
	Error             error
	Addresses         []string
	AddressesWithGroups []string
	HasAddressGroups  bool
	HasRedundantAddrs bool
	Processor         *processor.PANLogProcessor
	ConfigFile        string
	OperationComplete bool  // Flag to indicate operation completed, stay in post-analysis
}

// ProcessProgressMsg represents progress updates during processing
type ProcessProgressMsg struct {
	Progress float64
	Message  string
}

// processFileCmd creates a command to process the configuration file
func processFileCmd(logFile string, addresses []string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		// Create processor in silent mode for TUI
		panProcessor := processor.NewPANLogProcessor()
		panProcessor.Silent = true
		
		// Process file silently (no stdout output)
		if err := panProcessor.ProcessFileSinglePass(logFile, addresses); err != nil {
			return ProcessResult{
				Success: false,
				Error:   err,
			}
		}
		
		var hasAddressGroups, hasRedundantAddrs bool
		var addressesWithGroups []string
		
		// Generate results for each address
		for _, address := range addresses {
			result, exists := panProcessor.Results[address]
			if !exists || len(result.MatchingLines) == 0 {
				continue
			}
			
			// Format results
			itemsDict := panProcessor.FormatResults(address)
			
			// Check for address groups and redundant addresses
			if len(itemsDict.AddressGroups) > 0 {
				hasAddressGroups = true
				addressesWithGroups = append(addressesWithGroups, address)
			}
			if len(itemsDict.RedundantAddresses) > 0 {
				hasRedundantAddrs = true
			}
			
			// Generate output file
			outputFile := fmt.Sprintf("%s_results.yml", address)
			err := utils.WriteResults(outputFile, address, result.MatchingLines, itemsDict)
			if err != nil {
				return ProcessResult{
					Success: false,
					Error:   fmt.Errorf("error writing results for %s: %w", address, err),
				}
			}
		}
		
		return ProcessResult{
			Success:           true,
			Addresses:         addresses,
			AddressesWithGroups: addressesWithGroups,
			HasAddressGroups:  hasAddressGroups,
			HasRedundantAddrs: hasRedundantAddrs,
			Processor:         panProcessor,
			ConfigFile:        logFile,
		}
	})
}

// Handle process result in the model
func (m Model) handleProcessResult(result ProcessResult) (Model, tea.Cmd) {
	if result.Success {
		// If this is just an operation completion, return to post-analysis
		if result.OperationComplete {
			// Operation completed successfully, return to post-analysis menu
			m.operationMessage = "Operation completed successfully!"
			m.state = StateOperationStatus
			return m, nil
		}
		
		// This is the initial analysis result
		m.hasAddressGroups = result.HasAddressGroups
		m.hasRedundantAddrs = result.HasRedundantAddrs
		m.addressesWithGroups = result.AddressesWithGroups
		
		// Set up post-analysis choices with separators for execution
		m.postAnalysisChoices = []string{}
		if result.HasAddressGroups {
			m.postAnalysisChoices = append(m.postAnalysisChoices, "Generate Address Group Commands")
		}
		if result.HasRedundantAddrs {
			m.postAnalysisChoices = append(m.postAnalysisChoices, "Generate Cleanup Commands")
		}
		m.postAnalysisChoices = append(m.postAnalysisChoices, "---") // Separator
		m.postAnalysisChoices = append(m.postAnalysisChoices, "Execute Selected Operations")
		m.postAnalysisChoices = append(m.postAnalysisChoices, "Return to Main Menu")
		
		// Reset selections and cursor
		m.postAnalysisSelected = make(map[int]bool)
		m.cursor = 0
		// Make sure cursor starts on a non-separator item
		for m.cursor < len(m.postAnalysisChoices) && m.postAnalysisChoices[m.cursor] == "---" {
			m.cursor++
		}
		
		// Store processor for later use
		m.analysisResults = map[string]interface{}{
			"processor":   result.Processor,
			"configFile":  result.ConfigFile,
			"addresses":   result.Addresses,
		}
		
		if len(m.postAnalysisChoices) > 1 {
			m.state = StatePostAnalysis
		} else {
			m.state = StateResults
		}
	} else {
		m.state = StateError
		m.err = result.Error
	}
	return m, nil
}

// generateAddressGroupCmd creates a command to generate address group commands
func generateAddressGroupCmd(proc *processor.PANLogProcessor, address string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		itemsDict := proc.FormatResults(address)
		if len(itemsDict.AddressGroups) == 0 {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no address groups found for %s", address),
			}
		}
		
		// Generate commands (simplified - you might want a new address name input)
		newAddressName := address + "-new"
		outputFile := fmt.Sprintf("%s_add_to_groups_commands.yml", address)
		
		// Generate commands
		var commands []string
		for _, group := range itemsDict.AddressGroups {
			if group.Context == "shared" {
				commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddressName))
			} else {
				commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddressName))
			}
		}
		
		err := utils.WriteAddressGroupCommands(outputFile, address, newAddressName, commands, itemsDict.AddressGroups)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing address group commands: %w", err),
			}
		}
		
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
		}
	})
}

// generateAddressGroupCmdWithName creates a command to generate address group commands with custom name
func generateAddressGroupCmdWithName(proc *processor.PANLogProcessor, address, newAddressName string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		itemsDict := proc.FormatResults(address)
		if len(itemsDict.AddressGroups) == 0 {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no address groups found for %s", address),
			}
		}
		
		outputFile := fmt.Sprintf("%s_add_to_groups_commands.yml", newAddressName)
		
		// Generate commands
		var commands []string
		for _, group := range itemsDict.AddressGroups {
			if group.Context == "shared" {
				commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddressName))
			} else {
				commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddressName))
			}
		}
		
		err := utils.WriteAddressGroupCommands(outputFile, address, newAddressName, commands, itemsDict.AddressGroups)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing address group commands: %w", err),
			}
		}
		
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
		}
	})
}

// generateCleanupCmd creates a command to generate cleanup commands
func generateCleanupCmd(proc *processor.PANLogProcessor, configFile, address string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		analysis, err := proc.AnalyzeRedundantAddressCleanupWithReparse(configFile, address)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error analyzing cleanup: %w", err),
			}
		}
		
		commands := proc.GenerateCleanupCommands(analysis)
		outputFile := fmt.Sprintf("%s_redundant_cleanup_commands.yml", address)
		
		err = utils.WriteCleanupCommands(outputFile, commands)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing cleanup commands: %w", err),
			}
		}
		
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
		}
	})
}