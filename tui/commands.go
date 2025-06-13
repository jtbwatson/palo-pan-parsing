package tui

import (
	"fmt"
	"time"

	"palo-pan-parsing/models"
	"palo-pan-parsing/processor"
	"palo-pan-parsing/utils"

	tea "github.com/charmbracelet/bubbletea"
)

// ProcessResult represents the result of file processing - simplified for XML
type ProcessResult struct {
	Success             bool
	Error               error
	Addresses           []string
	AddressesWithGroups []string
	HasAddressGroups    bool
	HasRedundantAddrs   bool
	Result              interface{} // Can be *models.AnalysisResult or *models.MultiAddressResult
	ConfigFile          string
	OperationComplete   bool
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
	Cache        interface{} // Cache for efficient multi-group analysis
}

// Global progress state (simplified)
var (
	globalProgress       float64
	globalProcessingDone bool
	globalResult         *ProcessResult
)

func setProgress(progress float64) {
	globalProgress = progress
}

func getProgress() float64 {
	return globalProgress
}

func setProcessingDone(result ProcessResult) {
	globalProcessingDone = true
	globalResult = &result
}

func getProcessingStatus() (bool, *ProcessResult) {
	return globalProcessingDone, globalResult
}

func resetProcessingState() {
	globalProgress = 0
	globalProcessingDone = false
	globalResult = nil
}

// processFileCmd creates a command to process the configuration file
func processFileCmd(logFile string, addresses []string) tea.Cmd {
	return func() tea.Msg {
		resetProcessingState()
		setProgress(0.1)

		// Create processor with extended timeout
		config := &models.Config{
			LogFile:       logFile,
			Addresses:     addresses,
			Silent:        true, // Run in silent mode for TUI
			Timeout:       10 * time.Minute, // Extended timeout for large files
			BufferSize:    65536,
			MaxWorkers:    4,
			ProgressEvery: 200000, // Fix divide by zero error
		}
		
		// Set single address if only one provided
		if len(addresses) == 1 {
			config.TargetAddress = addresses[0]
		}

		proc := processor.NewProcessor(config)
		setProgress(0.3)

		var result interface{}
		var err error

		// Process based on number of addresses
		if len(addresses) > 1 {
			setProgress(0.5)
			result, err = proc.ProcessMultipleAddresses(logFile, addresses)
		} else {
			setProgress(0.5)
			result, err = proc.ProcessFile(logFile)
		}

		setProgress(0.8)

		if err != nil {
			return ProcessResult{
				Success: false,
				Error:   err,
			}
		}

		// Write results to files
		setProgress(0.9)
		writer := utils.NewYAMLWriter()
		var writeErr error

		switch r := result.(type) {
		case *models.AnalysisResult:
			writeErr = writer.WriteAnalysisResult(r, "outputs")
		case *models.MultiAddressResult:
			writeErr = writer.WriteMultiAddressResult(r, "outputs")
		}

		if writeErr != nil {
			return ProcessResult{
				Success: false,
				Error:   fmt.Errorf("failed to write results: %w", writeErr),
			}
		}

		setProgress(1.0)

		// Determine analysis characteristics
		hasGroups := false
		hasRedundant := false

		switch r := result.(type) {
		case *models.AnalysisResult:
			hasGroups = len(r.AddressGroups) > 0
			hasRedundant = len(r.RedundantAddresses) > 0
		case *models.MultiAddressResult:
			for _, res := range r.Results {
				if len(res.AddressGroups) > 0 {
					hasGroups = true
				}
				if len(res.RedundantAddresses) > 0 {
					hasRedundant = true
				}
			}
		}

		return ProcessResult{
			Success:           true,
			Addresses:         addresses,
			HasAddressGroups:  hasGroups,
			HasRedundantAddrs: hasRedundant,
			Result:            result,
			ConfigFile:        logFile,
			OperationComplete: false,
		}
	}
}

// Device group discovery - simplified for now
func discoverDeviceGroupsCmd(logFile string) tea.Cmd {
	return func() tea.Msg {
		// For now, return empty device groups - this would need full implementation
		return DeviceGroupDiscoveryResult{
			Success:      true,
			DeviceGroups: []string{}, // Empty for now
			Cache:        nil,
		}
	}
}

// Simplified commands that can be expanded later
func generateAddressGroupCommandsCmd(addresses []string, logFile string) tea.Cmd {
	return func() tea.Msg {
		return ProcessResult{
			Success: true,
			OperationComplete: true,
		}
	}
}

func generateCleanupCommandsCmd(addresses []string, logFile string) tea.Cmd {
	return func() tea.Msg {
		return ProcessResult{
			Success: true,
			OperationComplete: true,
		}
	}
}