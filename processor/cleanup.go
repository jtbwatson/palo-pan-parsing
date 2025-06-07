package processor

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"palo-pan-parsing/models"
	"palo-pan-parsing/utils"
)

// AnalyzeRedundantAddressCleanup performs deep analysis of redundant addresses for cleanup
func (p *PANLogProcessor) AnalyzeRedundantAddressCleanup(allLines []string, targetAddress string) (*models.CleanupAnalysis, error) {
	redundantAddresses := p.Results[targetAddress].RedundantAddresses
	if len(redundantAddresses) == 0 {
		return nil, fmt.Errorf("no redundant addresses found for %s", targetAddress)
	}

	analysis := &models.CleanupAnalysis{
		TargetAddress:  targetAddress,
		RedundantUsage: make(map[string]*models.RedundantAddressUsage),
	}

	// Determine target address current scope
	analysis.TargetScope, analysis.TargetDG = p.determineTargetScope(allLines, targetAddress)

	// Analyze usage for each redundant address
	allDGsAffected := make(map[string]bool)

	for _, redundant := range redundantAddresses {
		usage := p.analyzeRedundantUsage(allLines, redundant.Name)
		analysis.RedundantUsage[redundant.Name] = usage

		// Track all affected device groups
		for dg := range usage.UsedInDGs {
			allDGsAffected[dg] = true
		}
	}

	analysis.TotalDGsAffected = len(allDGsAffected)

	// Smart scope promotion logic
	analysis.ShouldPromoteToShared = p.shouldPromoteToShared(analysis, allDGsAffected)

	return analysis, nil
}

// determineTargetScope finds where the target address is currently defined
func (p *PANLogProcessor) determineTargetScope(allLines []string, targetAddress string) (scope, deviceGroup string) {
	targetPattern := regexp.MustCompile(fmt.Sprintf(`set\s+(shared|device-group\s+(\S+))\s+address\s+%s\s+ip-netmask`, regexp.QuoteMeta(targetAddress)))

	for _, line := range allLines {
		if matches := targetPattern.FindStringSubmatch(line); matches != nil {
			if matches[1] == "shared" {
				return "shared", ""
			} else {
				return "device-group", matches[2]
			}
		}
	}
	return "unknown", ""
}

// shouldPromoteToShared determines if target should be promoted to shared scope
func (p *PANLogProcessor) shouldPromoteToShared(analysis *models.CleanupAnalysis, allDGsAffected map[string]bool) bool {
	// If target is already in shared scope, always use it
	if analysis.TargetScope == "shared" {
		return false // No promotion needed, already shared
	}

	// If redundant addresses are used in multiple device groups, promote to shared
	if len(allDGsAffected) > 1 {
		return true
	}

	// If target is in different DG than the affected DGs, promote to shared
	if analysis.TargetScope == "device-group" {
		for dg := range allDGsAffected {
			if dg != analysis.TargetDG {
				return true
			}
		}
	}

	return false
}

// analyzeRedundantUsage performs deep analysis of how a redundant address is used
func (p *PANLogProcessor) analyzeRedundantUsage(allLines []string, redundantAddress string) *models.RedundantAddressUsage {
	usage := &models.RedundantAddressUsage{
		Name:          redundantAddress,
		UsedInDGs:     make(map[string]bool),
		AddressGroups: []models.AddressGroup{},
		SecurityRules: make(map[string]string),
		RuleContexts:  make(map[string]string),
		NATRules:      make(map[string]bool),
		ServiceGroups: make(map[string]bool),
	}

	totalLines := len(allLines)
	progressInterval := 300000
	lastProgress := 0

	p.printf("    Analyzing usage of redundant address '%s'...\n", redundantAddress)

	matchCount := 0

	for lineNum, line := range allLines {
		// Progress reporting for large files
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			p.printf("      Scanning line %s/%s (%.0f%%)\n",
				utils.FormatNumber(lineNum), utils.FormatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Skip lines that don't contain the redundant address
		if !strings.Contains(line, redundantAddress) {
			continue
		}

		matchCount++

		// Extract device group from line
		if matches := p.Patterns.DeviceGroup.FindStringSubmatch(line); matches != nil {
			usage.UsedInDGs[matches[1]] = true
		}

		// Extract IP netmask if this is the definition line
		if strings.Contains(line, "ip-netmask") {
			if matches := p.Patterns.IPNetmask.FindStringSubmatch(line); matches != nil && matches[1] == redundantAddress {
				usage.IPNetmask = matches[2]
			}
		}

		// Extract address groups
		if agInfo := p.extractAddressGroup(line); agInfo != nil && strings.Contains(agInfo.Definition, redundantAddress) {
			// Check if already exists
			found := false
			for _, existing := range usage.AddressGroups {
				if existing.Name == agInfo.Name && existing.Context == agInfo.Context && existing.DeviceGroup == agInfo.DeviceGroup {
					found = true
					break
				}
			}
			if !found {
				usage.AddressGroups = append(usage.AddressGroups, *agInfo)
				p.printf("        Found in address group: %s (context: %s)\n", agInfo.Name, agInfo.Context)
			}
		}

		// Extract security rules
		ruleName, context := p.extractSecurityRule(line, redundantAddress)
		if ruleName != "" {
			var deviceGroup string
			if matches := p.Patterns.DeviceGroup.FindStringSubmatch(line); matches != nil {
				deviceGroup = matches[1]
			} else {
				deviceGroup = "Unknown"
			}
			usage.SecurityRules[ruleName] = deviceGroup
			usage.RuleContexts[ruleName] = context
		}

		// Extract NAT rules
		if matches := p.Patterns.NatRule.FindStringSubmatch(line); matches != nil {
			usage.NATRules[matches[1]] = true
		}

		// Extract service groups
		if matches := p.Patterns.ServiceGroup.FindStringSubmatch(line); matches != nil {
			usage.ServiceGroups[matches[1]] = true
		}
	}

	p.printf("      Found %d lines containing '%s'\n", matchCount, redundantAddress)
	return usage
}

// GenerateCleanupCommands creates all commands needed to clean up redundant addresses
func (p *PANLogProcessor) GenerateCleanupCommands(analysis *models.CleanupAnalysis) *models.CleanupCommands {
	commands := &models.CleanupCommands{
		TargetAddress:      analysis.TargetAddress,
		RedundantAddresses: make([]string, 0, len(analysis.RedundantUsage)),
		Commands:           []models.CleanupCommand{},
	}

	// Collect redundant address names
	for name := range analysis.RedundantUsage {
		commands.RedundantAddresses = append(commands.RedundantAddresses, name)
	}

	// Step 1: Create target address in optimal scope if needed
	if analysis.ShouldPromoteToShared {
		commands.Commands = append(commands.Commands, p.generateTargetCreationCommand(analysis))
	}

	// Step 2: Generate removal commands for redundant definitions
	commands.Commands = append(commands.Commands, p.generateDefinitionRemovalCommands(analysis)...)

	// Step 3: Generate replacement commands for address groups
	commands.Commands = append(commands.Commands, p.generateAddressGroupReplacementCommands(analysis)...)

	// Step 4: Generate replacement commands for security rules
	commands.Commands = append(commands.Commands, p.generateSecurityRuleReplacementCommands(analysis)...)

	// Step 5: Generate replacement commands for NAT rules
	commands.Commands = append(commands.Commands, p.generateNATRuleReplacementCommands(analysis)...)

	// Step 6: Generate replacement commands for service groups
	commands.Commands = append(commands.Commands, p.generateServiceGroupReplacementCommands(analysis)...)

	commands.TotalCommands = len(commands.Commands)
	return commands
}

// generateTargetCreationCommand creates command to promote target to shared scope
func (p *PANLogProcessor) generateTargetCreationCommand(analysis *models.CleanupAnalysis) models.CleanupCommand {
	// Get IP netmask from any redundant address (they all have the same IP)
	var ipNetmask string
	for _, usage := range analysis.RedundantUsage {
		if usage.IPNetmask != "" {
			ipNetmask = usage.IPNetmask
			break
		}
	}

	return models.CleanupCommand{
		Type:        "add",
		Command:     fmt.Sprintf("set shared address %s ip-netmask %s", analysis.TargetAddress, ipNetmask),
		Description: fmt.Sprintf("Create %s in shared scope for multi-DG optimization", analysis.TargetAddress),
		Section:     "target_creation",
	}
}

// generateDefinitionRemovalCommands creates commands to remove redundant address definitions
func (p *PANLogProcessor) generateDefinitionRemovalCommands(analysis *models.CleanupAnalysis) []models.CleanupCommand {
	var commands []models.CleanupCommand

	for name, usage := range analysis.RedundantUsage {
		// Check if this redundant address has a device group or is shared
		if len(usage.UsedInDGs) > 0 {
			// Found in device groups - remove from each DG
			for dg := range usage.UsedInDGs {
				command := models.CleanupCommand{
					Type:        "delete",
					Command:     fmt.Sprintf("delete device-group %s address %s", dg, name),
					Description: fmt.Sprintf("Remove redundant address definition %s from %s", name, dg),
					Section:     "definitions",
				}
				commands = append(commands, command)
			}
		} else {
			// Try to find where it's defined based on the original redundant address info
			for targetAddr, result := range p.Results {
				if targetAddr == analysis.TargetAddress {
					for _, redundant := range result.RedundantAddresses {
						if redundant.Name == name {
							if redundant.DeviceGroup == "shared" {
								command := models.CleanupCommand{
									Type:        "delete",
									Command:     fmt.Sprintf("delete shared address %s", name),
									Description: fmt.Sprintf("Remove redundant shared address definition %s", name),
									Section:     "definitions",
								}
								commands = append(commands, command)
							} else {
								command := models.CleanupCommand{
									Type:        "delete",
									Command:     fmt.Sprintf("delete device-group %s address %s", redundant.DeviceGroup, name),
									Description: fmt.Sprintf("Remove redundant address definition %s from %s", name, redundant.DeviceGroup),
									Section:     "definitions",
								}
								commands = append(commands, command)
							}
							break
						}
					}
					break
				}
			}
		}
	}

	return commands
}

// generateAddressGroupReplacementCommands creates commands to replace redundant addresses in address groups
func (p *PANLogProcessor) generateAddressGroupReplacementCommands(analysis *models.CleanupAnalysis) []models.CleanupCommand {
	var commands []models.CleanupCommand

	for redundantName, usage := range analysis.RedundantUsage {
		for _, group := range usage.AddressGroups {
			// Create new member list replacing redundant with target
			newMembers := strings.ReplaceAll(group.Definition, redundantName, analysis.TargetAddress)

			var command string
			if group.Context == "shared" {
				command = fmt.Sprintf("set shared address-group %s static %s", group.Name, newMembers)
			} else {
				command = fmt.Sprintf("set device-group %s address-group %s static %s", group.DeviceGroup, group.Name, newMembers)
			}

			commands = append(commands, models.CleanupCommand{
				Type:        "replace",
				Command:     command,
				Description: fmt.Sprintf("Replace %s with %s in address-group %s", redundantName, analysis.TargetAddress, group.Name),
				Section:     "address_groups",
			})
		}
	}

	return commands
}

// generateSecurityRuleReplacementCommands creates commands to replace redundant addresses in security rules
func (p *PANLogProcessor) generateSecurityRuleReplacementCommands(analysis *models.CleanupAnalysis) []models.CleanupCommand {
	var commands []models.CleanupCommand

	for redundantName, usage := range analysis.RedundantUsage {
		for ruleName, deviceGroup := range usage.SecurityRules {
			context := usage.RuleContexts[ruleName]

			var command string
			if strings.Contains(context, "source") {
				command = fmt.Sprintf("set device-group %s security rules %s source %s", deviceGroup, ruleName, analysis.TargetAddress)
			} else if strings.Contains(context, "destination") {
				command = fmt.Sprintf("set device-group %s security rules %s destination %s", deviceGroup, ruleName, analysis.TargetAddress)
			} else {
				// Generic replacement
				command = fmt.Sprintf("set device-group %s security rules %s source %s", deviceGroup, ruleName, analysis.TargetAddress)
			}

			commands = append(commands, models.CleanupCommand{
				Type:        "replace",
				Command:     command,
				Description: fmt.Sprintf("Replace %s with %s in security rule %s (%s)", redundantName, analysis.TargetAddress, ruleName, context),
				Section:     "security_rules",
			})
		}
	}

	return commands
}

// generateNATRuleReplacementCommands creates commands to replace redundant addresses in NAT rules
func (p *PANLogProcessor) generateNATRuleReplacementCommands(analysis *models.CleanupAnalysis) []models.CleanupCommand {
	var commands []models.CleanupCommand

	for redundantName, usage := range analysis.RedundantUsage {
		for natRule := range usage.NATRules {
			// Note: NAT rule replacement is complex and would need more specific context
			// This is a simplified version - in practice you'd need to determine if it's source/destination NAT
			command := fmt.Sprintf("# NAT rule %s contains %s - manual review required for replacement with %s",
				natRule, redundantName, analysis.TargetAddress)

			commands = append(commands, models.CleanupCommand{
				Type:        "replace",
				Command:     command,
				Description: fmt.Sprintf("Manual review: Replace %s with %s in NAT rule %s", redundantName, analysis.TargetAddress, natRule),
				Section:     "nat_rules",
			})
		}
	}

	return commands
}

// generateServiceGroupReplacementCommands creates commands to replace redundant addresses in service groups
func (p *PANLogProcessor) generateServiceGroupReplacementCommands(analysis *models.CleanupAnalysis) []models.CleanupCommand {
	var commands []models.CleanupCommand

	for redundantName, usage := range analysis.RedundantUsage {
		for serviceGroup := range usage.ServiceGroups {
			// Note: Service groups typically contain services, not addresses
			// This might be a rare case - including for completeness
			command := fmt.Sprintf("# Service group %s references %s - manual review required for replacement with %s",
				serviceGroup, redundantName, analysis.TargetAddress)

			commands = append(commands, models.CleanupCommand{
				Type:        "replace",
				Command:     command,
				Description: fmt.Sprintf("Manual review: Replace %s with %s in service group %s", redundantName, analysis.TargetAddress, serviceGroup),
				Section:     "service_groups",
			})
		}
	}

	return commands
}

// AnalyzeRedundantAddressCleanupWithReparse re-parses the config file and performs cleanup analysis
func (p *PANLogProcessor) AnalyzeRedundantAddressCleanupWithReparse(filePath, targetAddress string) (*models.CleanupAnalysis, error) {
	// Re-read the file into memory for cleanup analysis
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file for cleanup analysis: %w", err)
	}
	defer file.Close()

	p.printf("  Re-reading configuration file for cleanup analysis...\n")

	// Read all lines into memory
	var allLines []string
	scanner := bufio.NewScanner(file)

	// Set a large buffer size for performance with big files
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allLines = append(allLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file for cleanup analysis: %w", err)
	}

	p.printf("  Loaded %s lines for cleanup analysis\n", utils.FormatNumber(len(allLines)))

	// Perform the cleanup analysis
	return p.AnalyzeRedundantAddressCleanup(allLines, targetAddress)
}
