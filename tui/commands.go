package tui

import (
	"fmt"
	"strings"
	"sync"

	"palo-pan-parsing/processor"
	"palo-pan-parsing/utils"

	tea "github.com/charmbracelet/bubbletea"
)

// ProcessResult represents the result of file processing
type ProcessResult struct {
	Success             bool
	Error               error
	Addresses           []string
	AddressesWithGroups []string
	HasAddressGroups    bool
	HasRedundantAddrs   bool
	Processor           *processor.PANLogProcessor
	ConfigFile          string
	OperationComplete   bool // Flag to indicate operation completed, stay in post-analysis

	// Operation summary details
	OperationType    string            // e.g., "Address Group Commands", "Cleanup Commands"
	OperationSummary string            // Detailed description of what was done
	FilesGenerated   []string          // List of output files created
	CommandCount     int               // Number of commands generated
	AddressMappings  map[string]string // Source -> Target address mappings (for address group operations)
}

// ProcessProgressMsg represents progress updates during processing
type ProcessProgressMsg struct {
	Progress float64
	Message  string
}

// DeviceGroupDiscoveryResult represents the result of device group discovery
type DeviceGroupDiscoveryResult struct {
	Success      bool
	Error        error
	DeviceGroups []string
}

// ProgressPollMsg moved to animation.go to avoid duplication

// Global progress state
var (
	progressMutex    sync.RWMutex
	currentProgress  float64
	processingDone   bool
	processingResult *ProcessResult
)

// updateProgress safely updates the global progress
func updateProgress(progress float64) {
	progressMutex.Lock()
	currentProgress = progress
	progressMutex.Unlock()
}

// getProgress safely gets the current progress
func getProgress() float64 {
	progressMutex.RLock()
	progress := currentProgress
	progressMutex.RUnlock()
	return progress
}

// setProcessingComplete sets the processing as complete with result
func setProcessingComplete(result ProcessResult) {
	progressMutex.Lock()
	processingDone = true
	processingResult = &result
	progressMutex.Unlock()
}

// getProcessingStatus gets the processing status and result
func getProcessingStatus() (bool, *ProcessResult) {
	progressMutex.RLock()
	done := processingDone
	result := processingResult
	progressMutex.RUnlock()
	return done, result
}

// resetProcessingState resets the global processing state
func resetProcessingState() {
	progressMutex.Lock()
	currentProgress = 0.0
	processingDone = false
	processingResult = nil
	progressMutex.Unlock()
}

// processFileCmd creates a command to process the configuration file with real-time progress
func processFileCmd(logFile string, addresses []string) tea.Cmd {
	return func() tea.Msg {
		// Reset progress state
		resetProcessingState()

		// Start processing in a goroutine
		go func() {
			// Create processor in silent mode for TUI
			panProcessor := processor.NewPANLogProcessor()
			panProcessor.Silent = true

			// Set up progress callback to update global state
			panProcessor.ProgressCallback = func(progress float64, message string) {
				updateProgress(progress)
			}

			// Process file silently (no stdout output)
			if err := panProcessor.ProcessFileSinglePass(logFile, addresses); err != nil {
				setProcessingComplete(ProcessResult{
					Success: false,
					Error:   err,
				})
				return
			}

			var hasAddressGroups, hasRedundantAddrs bool
			var addressesWithGroups []string
			var filesGenerated []string

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
					setProcessingComplete(ProcessResult{
						Success: false,
						Error:   fmt.Errorf("error writing results for %s: %w", address, err),
					})
					return
				}
				filesGenerated = append(filesGenerated, outputFile)
			}

			setProcessingComplete(ProcessResult{
				Success:             true,
				Addresses:           addresses,
				AddressesWithGroups: addressesWithGroups,
				HasAddressGroups:    hasAddressGroups,
				HasRedundantAddrs:   hasRedundantAddrs,
				Processor:           panProcessor,
				ConfigFile:          logFile,
				FilesGenerated:      filesGenerated,
			})
		}()

		// Start polling for progress updates
		return ProgressPollMsg{}
	}
}

// Handle process result in the model
func (m Model) handleProcessResult(result ProcessResult) (Model, tea.Cmd) {
	if result.Success {
		// If this is just an operation completion, return to post-analysis
		if result.OperationComplete {
			// Store operation details for the status display (replace for each operation)
			m.operationMessage = "Operation completed successfully!"
			m.lastOperationType = result.OperationType
			m.lastOperationSummary = result.OperationSummary
			// Accumulate files generated across all operations
			m.lastFilesGenerated = append(m.lastFilesGenerated, result.FilesGenerated...)
			m.lastAddressMappings = result.AddressMappings
			m.lastAddresses = result.Addresses
			m.lastConfigFile = result.ConfigFile

			// ALWAYS add to session summary (this should persist across operations)
			completionMessage := result.OperationType + " Complete"
			if result.OperationType == "Address Group Commands" {
				completionMessage = "Address Group Commands Generated"
			} else if result.OperationType == "Cleanup Commands" {
				completionMessage = "Cleanup Commands Generated"
			} else if result.OperationType == "Device Group Duplicate Scan" {
				completionMessage = "Device Group Duplicate Scan Complete"
			}
			m.addFormattedAction(completionMessage)

			// Handle different operation types in session summary
			if result.OperationType == "Cleanup Commands" {
				// Extract cleanup-specific information from summary
				if strings.Contains(result.OperationSummary, "Target Address:") {
					lines := strings.Split(result.OperationSummary, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "Target Address:") {
							m.addFormattedLine(line, true)
						} else if strings.HasPrefix(line, "Redundant Addresses:") {
							m.addFormattedLine(line, true)
						} else if strings.Contains(line, "cleanup commands") {
							m.addFormattedLine(line, true)
						}
					}
				}
			} else {
				// Handle address group commands and other operations
				if len(result.AddressMappings) > 0 {
					for source, target := range result.AddressMappings {
						m.addFormattedMapping(source, target)
					}
				}
			}

			// Show command count if available, otherwise show file count
			if result.CommandCount > 0 {
				commandTypeText := "Commands Generated"
				if result.OperationType == "Address Group Commands" {
					commandTypeText = "Group Commands"
				} else if result.OperationType == "Cleanup Commands" {
					commandTypeText = "Cleanup Commands"
				} else if result.OperationType == "Device Group Duplicate Scan" {
					commandTypeText = "Duplicate Sets Found"
				}
				m.addFormattedStatusIndented(commandTypeText, fmt.Sprintf("%d", result.CommandCount))
			} else if len(result.FilesGenerated) > 0 {
				operationTypeText := "Command Files Generated"
				if result.OperationType == "Address Group Commands" {
					operationTypeText = "Group Command Files"
				} else if result.OperationType == "Cleanup Commands" {
					operationTypeText = "Cleanup Command Files"
				} else if result.OperationType == "Device Group Duplicate Scan" {
					operationTypeText = "Result Files Generated"
				}
				m.addFormattedStatusIndented(operationTypeText, fmt.Sprintf("%d", len(result.FilesGenerated)))
			}

			// Check if there are pending commands to execute
			if len(m.pendingCommands) > 0 {
				// Execute next pending command
				nextCmd := m.pendingCommands[0]
				m.pendingCommands = m.pendingCommands[1:] // Remove the command we're about to execute
				return m, nextCmd
			}

			// All operations completed - show thank you screen
			m.state = StateCompleted
			return m, nil
		}

		// This is the initial analysis result
		m.hasAddressGroups = result.HasAddressGroups
		m.hasRedundantAddrs = result.HasRedundantAddrs
		m.addressesWithGroups = result.AddressesWithGroups
		
		// Store files generated for completion screen
		m.lastFilesGenerated = result.FilesGenerated
		m.lastAddresses = result.Addresses
		m.lastConfigFile = result.ConfigFile

		// Add to output summary
		m.addFormattedAction("Analysis Complete")
		m.addFormattedStatusIndented("Addresses", strings.Join(result.Addresses, ", "))

		// Count total matches
		totalMatches := 0
		if result.Processor != nil {
			for _, address := range result.Addresses {
				if res, exists := result.Processor.Results[address]; exists {
					totalMatches += len(res.MatchingLines)
				}
			}
		}
		m.addFormattedStatusIndented("Total References", fmt.Sprintf("%d", totalMatches))

		if result.HasAddressGroups {
			m.addFormattedStatusIndented("Address Groups", "Found")
		}
		if result.HasRedundantAddrs {
			m.addFormattedStatusIndented("Redundant Addresses", "Found")
		}
		
		// Show files generated count
		if len(result.FilesGenerated) > 0 {
			m.addFormattedStatusIndented("Files Generated", fmt.Sprintf("%d", len(result.FilesGenerated)))
		}

		// Set up post-analysis choices with separators for execution
		m.postAnalysisChoices = []string{}
		if result.HasAddressGroups {
			m.postAnalysisChoices = append(m.postAnalysisChoices, "Generate Address Group Commands")
		}
		if result.HasRedundantAddrs {
			m.postAnalysisChoices = append(m.postAnalysisChoices, "Generate Cleanup Commands")
		}
		m.postAnalysisChoices = append(m.postAnalysisChoices, "---") // Separator
		m.postAnalysisChoices = append(m.postAnalysisChoices, "Execute Selected Operation")
		m.postAnalysisChoices = append(m.postAnalysisChoices, "No Additional Operations")
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
			"processor":  result.Processor,
			"configFile": result.ConfigFile,
			"addresses":  result.Addresses,
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

		outputFile := fmt.Sprintf("%s_copyto_%s.yml", address, newAddressName)

		// Generate commands
		var commands []string
		for _, group := range itemsDict.AddressGroups {
			if group.Context == "shared" {
				commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddressName))
			} else {
				commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddressName))
			}
		}

		err := utils.WriteAddressGroupCommands(outputFile, address, newAddressName, "192.168.1.100/32", commands, itemsDict.AddressGroups)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing address group commands: %w", err),
			}
		}

		// Create detailed summary
		summary := fmt.Sprintf("Generated commands for %d address groups\nAddress Mapping: %s → %s",
			len(itemsDict.AddressGroups), address, newAddressName)

		addressMappings := make(map[string]string)
		addressMappings[address] = newAddressName

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Address Group Commands",
			OperationSummary:  summary,
			FilesGenerated:    []string{outputFile},
			CommandCount:      len(commands),
			AddressMappings:   addressMappings,
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
		outputFile := fmt.Sprintf("%s_cleanup.yml", address)

		err = utils.WriteCleanupCommands(outputFile, commands)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing cleanup commands: %w", err),
			}
		}

		// Create detailed summary
		var summary strings.Builder
		summary.WriteString(fmt.Sprintf("Target Address: %s", commands.TargetAddress))
		if len(commands.RedundantAddresses) > 0 {
			summary.WriteString(fmt.Sprintf("\nRedundant Addresses: %d found", len(commands.RedundantAddresses)))
		}

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Cleanup Commands",
			OperationSummary:  summary.String(),
			FilesGenerated:    []string{outputFile},
			CommandCount:      commands.TotalCommands,
		}
	})
}

// generateSequentialAddressGroupCommands processes address mappings sequentially to avoid file conflicts
func generateSequentialAddressGroupCommands(proc *processor.PANLogProcessor, addressMappings map[string]string, pendingCommands []tea.Cmd) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		var filesGenerated []string
		var totalGroups int
		var processedCount int

		// Process each address mapping sequentially
		for sourceAddress, newAddress := range addressMappings {
			itemsDict := proc.FormatResults(sourceAddress)
			if len(itemsDict.AddressGroups) == 0 {
				continue // Skip addresses with no groups
			}

			outputFile := fmt.Sprintf("%s_copyto_%s.yml", sourceAddress, newAddress)

			// Generate commands
			var commands []string
			for _, group := range itemsDict.AddressGroups {
				if group.Context == "shared" {
					commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddress))
				} else {
					commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddress))
				}
			}

			err := utils.WriteAddressGroupCommands(outputFile, sourceAddress, newAddress, "192.168.1.100/32", commands, itemsDict.AddressGroups)
			if err != nil {
				return ProcessResult{
					Success: false,
					Error:   fmt.Errorf("error writing address group commands for %s: %w", sourceAddress, err),
				}
			}

			filesGenerated = append(filesGenerated, outputFile)
			totalGroups += len(itemsDict.AddressGroups)
			processedCount++
		}

		// Create detailed summary
		var summary strings.Builder
		summary.WriteString(fmt.Sprintf("Processed %d address mappings", processedCount))
		summary.WriteString(fmt.Sprintf("\nGenerated commands for %d address groups", totalGroups))
		if len(addressMappings) > 1 {
			summary.WriteString("\n\nAddress Mappings:")
			for source, target := range addressMappings {
				summary.WriteString(fmt.Sprintf("\n• %s → %s", source, target))
			}
		}

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Address Group Commands",
			OperationSummary:  summary.String(),
			FilesGenerated:    filesGenerated,
			CommandCount:      totalGroups,
			AddressMappings:   addressMappings,
		}
	})
}

// generateAddressGroupCmdWithNameAndIP generates address group commands with IP address input
func generateAddressGroupCmdWithNameAndIP(proc *processor.PANLogProcessor, address, newAddressName, ipAddress string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		itemsDict := proc.FormatResults(address)
		if len(itemsDict.AddressGroups) == 0 {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no address groups found for %s", address),
			}
		}

		outputFile := fmt.Sprintf("%s_copyto_%s.yml", address, newAddressName)

		// Generate commands
		var commands []string
		for _, group := range itemsDict.AddressGroups {
			if group.Context == "shared" {
				commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddressName))
			} else {
				commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddressName))
			}
		}

		err := utils.WriteAddressGroupCommands(outputFile, address, newAddressName, ipAddress, commands, itemsDict.AddressGroups)
		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("error writing address group commands: %w", err),
			}
		}

		// Create detailed summary
		summary := fmt.Sprintf("Generated commands for %d address groups\nAddress Mapping: %s → %s\nIP Address: %s",
			len(itemsDict.AddressGroups), address, newAddressName, ipAddress)

		addressMappings := make(map[string]string)
		addressMappings[address] = newAddressName

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Address Group Commands",
			OperationSummary:  summary,
			FilesGenerated:    []string{outputFile},
			CommandCount:      len(commands),
			AddressMappings:   addressMappings,
		}
	})
}

// generateSequentialAddressGroupCommandsWithIP generates commands for multiple address mappings with IP addresses
func generateSequentialAddressGroupCommandsWithIP(proc *processor.PANLogProcessor, addressMappings map[string]string, ipAddress string, pendingCommands []tea.Cmd) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		var summary strings.Builder
		var filesGenerated []string
		var allAddressMappings = make(map[string]string)
		processedCount := 0
		totalGroups := 0

		summary.WriteString("Sequential Address Group Commands Generation:\n")

		for sourceAddress, newAddress := range addressMappings {
			itemsDict := proc.FormatResults(sourceAddress)
			if len(itemsDict.AddressGroups) == 0 {
				summary.WriteString(fmt.Sprintf("❌ %s: No address groups found\n", sourceAddress))
				continue
			}

			outputFile := fmt.Sprintf("%s_copyto_%s.yml", sourceAddress, newAddress)

			// Generate commands
			var commands []string
			for _, group := range itemsDict.AddressGroups {
				if group.Context == "shared" {
					commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddress))
				} else {
					commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddress))
				}
			}

			err := utils.WriteAddressGroupCommands(outputFile, sourceAddress, newAddress, ipAddress, commands, itemsDict.AddressGroups)
			if err != nil {
				return ProcessResult{
					Success: false,
					Error:   fmt.Errorf("error writing address group commands for %s: %w", sourceAddress, err),
				}
			}

			filesGenerated = append(filesGenerated, outputFile)
			totalGroups += len(itemsDict.AddressGroups)
			processedCount++
			allAddressMappings[sourceAddress] = newAddress

			summary.WriteString(fmt.Sprintf("✅ %s → %s: %d groups processed\n",
				sourceAddress, newAddress, len(itemsDict.AddressGroups)))
		}

		if processedCount == 0 {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no address mappings could be processed"),
			}
		}

		// Execute pending commands if any
		if len(pendingCommands) > 0 {
			summary.WriteString(fmt.Sprintf("\n🔄 Executing %d additional operations...\n", len(pendingCommands)))
			// Execute all pending commands in batch
			go func() {
				for _, cmd := range pendingCommands {
					cmd()
				}
			}()
		}

		summary.WriteString(fmt.Sprintf("\n📊 Summary: %d addresses processed, %d total groups, %d files generated",
			processedCount, totalGroups, len(filesGenerated)))
		summary.WriteString(fmt.Sprintf("\n🌐 IP Address: %s", ipAddress))

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Sequential Address Group Commands",
			OperationSummary:  summary.String(),
			FilesGenerated:    filesGenerated,
			CommandCount:      totalGroups,
			AddressMappings:   allAddressMappings,
		}
	})
}

// generateSequentialAddressGroupCommandsWithMappings generates commands for multiple addresses with separate IP mappings
func generateSequentialAddressGroupCommandsWithMappings(proc *processor.PANLogProcessor, addressMappings map[string]string, ipMappings map[string]string, pendingCommands []tea.Cmd) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		var summary strings.Builder
		var filesGenerated []string
		var allAddressMappings = make(map[string]string)
		processedCount := 0
		totalGroups := 0

		summary.WriteString("Sequential Address Group Commands Generation:\n")

		for sourceAddress, newAddress := range addressMappings {
			itemsDict := proc.FormatResults(sourceAddress)
			if len(itemsDict.AddressGroups) == 0 {
				summary.WriteString(fmt.Sprintf("❌ %s: No address groups found\n", sourceAddress))
				continue
			}

			// Get the IP address for this specific source address
			ipAddress, exists := ipMappings[sourceAddress]
			if !exists {
				summary.WriteString(fmt.Sprintf("❌ %s: No IP address mapping found\n", sourceAddress))
				continue
			}

			outputFile := fmt.Sprintf("%s_copyto_%s.yml", sourceAddress, newAddress)

			// Generate commands
			var commands []string
			for _, group := range itemsDict.AddressGroups {
				if group.Context == "shared" {
					commands = append(commands, fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddress))
				} else {
					commands = append(commands, fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newAddress))
				}
			}

			err := utils.WriteAddressGroupCommands(outputFile, sourceAddress, newAddress, ipAddress, commands, itemsDict.AddressGroups)
			if err != nil {
				return ProcessResult{
					Success: false,
					Error:   fmt.Errorf("error writing address group commands for %s: %w", sourceAddress, err),
				}
			}

			filesGenerated = append(filesGenerated, outputFile)
			totalGroups += len(itemsDict.AddressGroups)
			processedCount++
			allAddressMappings[sourceAddress] = fmt.Sprintf("%s (%s)", newAddress, ipAddress)

			summary.WriteString(fmt.Sprintf("✅ %s → %s (%s): %d groups processed\n",
				sourceAddress, newAddress, ipAddress, len(itemsDict.AddressGroups)))
		}

		if processedCount == 0 {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no address mappings could be processed"),
			}
		}

		// Execute pending commands if any
		if len(pendingCommands) > 0 {
			summary.WriteString(fmt.Sprintf("\n🔄 Executing %d additional operations...\n", len(pendingCommands)))
			// Execute all pending commands in batch
			go func() {
				for _, cmd := range pendingCommands {
					cmd()
				}
			}()
		}

		summary.WriteString(fmt.Sprintf("\n📊 Summary: %d addresses processed, %d total groups, %d files generated",
			processedCount, totalGroups, len(filesGenerated)))

		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Sequential Address Group Commands with Mappings",
			OperationSummary:  summary.String(),
			FilesGenerated:    filesGenerated,
			CommandCount:      totalGroups,
			AddressMappings:   allAddressMappings,
		}
	})
}

// Device group discovery command
func (m Model) startDeviceGroupDiscovery() tea.Cmd {
	return processDeviceGroupDiscoveryCmd(m.logFile)
}

// Device group duplicate scan command
func (m Model) startDeviceGroupDuplicateScan() tea.Cmd {
	return processDeviceGroupDuplicateCmd(m.logFile, m.selectedDeviceGroup)
}

// processDeviceGroupDiscoveryCmd creates a command to discover device groups in a config file
func processDeviceGroupDiscoveryCmd(logFile string) tea.Cmd {
	return func() tea.Msg {
		// Create processor in silent mode for TUI
		panProcessor := processor.NewPANLogProcessor()
		panProcessor.Silent = true

		// Discover device groups
		deviceGroups, err := panProcessor.DiscoverDeviceGroups(logFile)
		
		return DeviceGroupDiscoveryResult{
			Success:      err == nil,
			Error:        err,
			DeviceGroups: deviceGroups,
		}
	}
}

// processDeviceGroupDuplicateCmd creates a command to scan for duplicates in a device group
func processDeviceGroupDuplicateCmd(logFile, deviceGroup string) tea.Cmd {
	return func() tea.Msg {
		// Create processor in silent mode for TUI
		panProcessor := processor.NewPANLogProcessor()
		panProcessor.Silent = true

		// Process device group for duplicates (synchronously to avoid hanging)
		if err := panProcessor.FindDuplicateAddressesInDeviceGroup(logFile, deviceGroup); err != nil {
			return ProcessResult{
				Success: false,
				Error:   err,
			}
		}

		// Check results
		scanResultKey := fmt.Sprintf("device-group-%s-scan", deviceGroup)
		result, exists := panProcessor.Results[scanResultKey]
		
		if !exists {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("no scan results found for device group %s", deviceGroup),
			}
		}

		duplicateCount := len(result.RedundantAddresses)
		
		// Determine the correct message based on duplicates found
		var summary string
		var filesGenerated []string
		var duplicateSets int
		
		if duplicateCount == 0 {
			summary = fmt.Sprintf("Scanned device group '%s' - no duplicate address objects found", deviceGroup)
			duplicateSets = 0
		} else {
			// Count actual sets of duplicates by grouping by IP
			duplicatesByIP := make(map[string]int)
			for _, dup := range result.RedundantAddresses {
				duplicatesByIP[dup.IPNetmask]++
			}
			duplicateSets = len(duplicatesByIP)
			summary = fmt.Sprintf("Scanned device group '%s' and found %d duplicate address objects in %d sets", deviceGroup, duplicateCount, duplicateSets)
			filesGenerated = []string{fmt.Sprintf("%s_duplicates.yml", deviceGroup)}
		}
		
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
			OperationType:     "Device Group Duplicate Scan",
			OperationSummary:  summary,
			FilesGenerated:    filesGenerated,
			CommandCount:      duplicateSets,
		}
	}
}
