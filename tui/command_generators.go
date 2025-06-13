package tui

import (
	"fmt"
	"strings"

	"palo-pan-parsing/models"

	tea "github.com/charmbracelet/bubbletea"
)

// Simplified command generators that work with our XML processor

// generateAddressGroupCommands creates commands for adding addresses to groups
func generateAddressGroupCommands(addresses []string, addressMappings map[string]string, ipMappings map[string]string) tea.Cmd {
	return func() tea.Msg {
		// Simplified - just return success for now
		// This would be expanded to actually generate the commands
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
		}
	}
}

// generateCleanupCommands creates commands for cleaning up redundant addresses
func generateCleanupCommands(addresses []string) tea.Cmd {
	return func() tea.Msg {
		// Simplified - just return success for now
		// This would be expanded to actually generate cleanup commands
		return ProcessResult{
			Success:           true,
			OperationComplete: true,
		}
	}
}

// formatResults formats analysis results for display
func formatResults(result interface{}) string {
	var s strings.Builder

	switch r := result.(type) {
	case *models.AnalysisResult:
		s.WriteString(fmt.Sprintf("Target: %s\n", r.TargetAddress))
		s.WriteString(fmt.Sprintf("Processing Time: %s\n", r.ProcessingTime))
		s.WriteString(fmt.Sprintf("Total References: %d\n\n", r.TotalReferences))
		
		s.WriteString("Statistics:\n")
		s.WriteString(fmt.Sprintf("  Address Objects: %d\n", r.Statistics.AddressObjects))
		s.WriteString(fmt.Sprintf("  Security Rules: %d\n", r.Statistics.SecurityRules))
		s.WriteString(fmt.Sprintf("  NAT Rules: %d\n", r.Statistics.NATRules))
		s.WriteString(fmt.Sprintf("  Address Groups: %d\n", r.Statistics.AddressGroups))
		s.WriteString(fmt.Sprintf("  Device Groups: %d\n", r.Statistics.DeviceGroups))
		
		if r.Statistics.RedundantAddresses > 0 {
			s.WriteString(fmt.Sprintf("  Redundant Addresses: %d\n", r.Statistics.RedundantAddresses))
		}

	case *models.MultiAddressResult:
		s.WriteString(fmt.Sprintf("Targets: %s\n", strings.Join(r.Addresses, ", ")))
		s.WriteString(fmt.Sprintf("Processing Time: %s\n\n", r.ProcessingTime))
		
		s.WriteString("Combined Statistics:\n")
		s.WriteString(fmt.Sprintf("  Address Objects: %d\n", r.CombinedStats.AddressObjects))
		s.WriteString(fmt.Sprintf("  Security Rules: %d\n", r.CombinedStats.SecurityRules))
		s.WriteString(fmt.Sprintf("  NAT Rules: %d\n", r.CombinedStats.NATRules))
		s.WriteString(fmt.Sprintf("  Address Groups: %d\n", r.CombinedStats.AddressGroups))
		s.WriteString(fmt.Sprintf("  Device Groups: %d\n", r.CombinedStats.DeviceGroups))
	}

	return s.String()
}