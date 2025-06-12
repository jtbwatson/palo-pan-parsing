package processor

import (
	"strings"

	"palo-pan-parsing/models"
)

type RedundancyAnalyzer struct {
	processor *Processor
}

func NewRedundancyAnalyzer(processor *Processor) *RedundancyAnalyzer {
	return &RedundancyAnalyzer{
		processor: processor,
	}
}

func (ra *RedundancyAnalyzer) FindRedundantAddresses(addressMap map[string]*models.AddressObject) []models.RedundantAddressPair {
	var redundantPairs []models.RedundantAddressPair
	processed := make(map[string]bool)
	
	for sourceName, sourceAddr := range addressMap {
		if processed[sourceName] {
			continue
		}
		
		for targetName, targetAddr := range addressMap {
			if sourceName == targetName || processed[targetName] {
				continue
			}
			
			if sourceAddr.IsRedundantWith(targetAddr) {
				pair := models.RedundantAddressPair{
					SourceAddress:    sourceName,
					DuplicateAddress: targetName,
					IPValue:          sourceAddr.GetIP(),
					SourceScope:      sourceAddr.Scope,
					DuplicateScope:   targetAddr.Scope,
				}
				
				deviceGroups := ra.findAffectedDeviceGroups(sourceName, targetName)
				pair.DeviceGroups = deviceGroups
				
				redundantPairs = append(redundantPairs, pair)
				processed[sourceName] = true
				break
			}
		}
	}
	
	return redundantPairs
}

func (ra *RedundancyAnalyzer) findAffectedDeviceGroups(sourceAddr, targetAddr string) []string {
	deviceGroupSet := make(map[string]bool)
	
	securityRuleMap := ra.processor.GetSecurityRuleMap()
	natRuleMap := ra.processor.GetNATRuleMap()
	groupMap := ra.processor.GetGroupMap()
	
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(sourceAddr) || rule.ContainsAddress(targetAddr) {
			if rule.DeviceGroup != "" {
				deviceGroupSet[rule.DeviceGroup] = true
			}
		}
	}
	
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(sourceAddr) || rule.ContainsAddress(targetAddr) {
			if rule.DeviceGroup != "" {
				deviceGroupSet[rule.DeviceGroup] = true
			}
		}
	}
	
	for _, group := range groupMap {
		if group.HasMember(sourceAddr) || group.HasMember(targetAddr) {
			if group.DeviceGroup != "" {
				deviceGroupSet[group.DeviceGroup] = true
			}
		}
	}
	
	var deviceGroups []string
	for dg := range deviceGroupSet {
		deviceGroups = append(deviceGroups, dg)
	}
	
	return deviceGroups
}

func (ra *RedundancyAnalyzer) GenerateCleanupCommands(redundantPairs []models.RedundantAddressPair) *models.CleanupAnalysis {
	cleanup := &models.CleanupAnalysis{
		RedundantAddresses: redundantPairs,
		ImpactAnalysis:     ra.calculateCleanupImpact(redundantPairs),
		Commands:           models.CleanupCommands{},
		Warnings:          []string{},
	}
	
	cleanup.Commands.RuleUpdates = ra.generateRuleUpdateCommands(redundantPairs)
	cleanup.Commands.GroupUpdates = ra.generateGroupUpdateCommands(redundantPairs)
	cleanup.Commands.ObjectCreation = ra.generateObjectCreationCommands(redundantPairs)
	cleanup.Commands.ObjectDeletion = ra.generateObjectDeletionCommands(redundantPairs)
	
	cleanup.Warnings = ra.generateWarnings(redundantPairs)
	
	return cleanup
}

func (ra *RedundancyAnalyzer) calculateCleanupImpact(redundantPairs []models.RedundantAddressPair) models.CleanupImpact {
	impact := models.CleanupImpact{}
	affectedDeviceGroups := make(map[string]bool)
	
	securityRuleMap := ra.processor.GetSecurityRuleMap()
	natRuleMap := ra.processor.GetNATRuleMap()
	groupMap := ra.processor.GetGroupMap()
	
	for _, pair := range redundantPairs {
		for _, rule := range securityRuleMap {
			if rule.ContainsAddress(pair.SourceAddress) {
				impact.AffectedRules++
				if rule.DeviceGroup != "" {
					affectedDeviceGroups[rule.DeviceGroup] = true
				}
			}
		}
		
		for _, rule := range natRuleMap {
			if rule.ContainsAddress(pair.SourceAddress) {
				impact.AffectedRules++
				if rule.DeviceGroup != "" {
					affectedDeviceGroups[rule.DeviceGroup] = true
				}
			}
		}
		
		for _, group := range groupMap {
			if group.HasMember(pair.SourceAddress) {
				impact.AffectedGroups++
				if group.DeviceGroup != "" {
					affectedDeviceGroups[group.DeviceGroup] = true
				}
			}
		}
		
		for _, dg := range pair.DeviceGroups {
			affectedDeviceGroups[dg] = true
		}
		
		if ra.shouldPromoteScope(pair) {
			impact.ScopeChanges++
		}
	}
	
	for dg := range affectedDeviceGroups {
		impact.DeviceGroups = append(impact.DeviceGroups, dg)
	}
	impact.AffectedDeviceGroups = len(impact.DeviceGroups)
	
	return impact
}

func (ra *RedundancyAnalyzer) shouldPromoteScope(pair models.RedundantAddressPair) bool {
	return len(pair.DeviceGroups) > 1 && 
		   models.IsDeviceGroupScope(pair.DuplicateScope) &&
		   !models.IsSharedScope(pair.DuplicateScope)
}

func (ra *RedundancyAnalyzer) generateRuleUpdateCommands(redundantPairs []models.RedundantAddressPair) []string {
	var commands []string
	
	securityRuleMap := ra.processor.GetSecurityRuleMap()
	natRuleMap := ra.processor.GetNATRuleMap()
	
	for _, pair := range redundantPairs {
		for _, rule := range securityRuleMap {
			if rule.ContainsAddress(pair.SourceAddress) {
				commands = append(commands, ra.generateSecurityRuleUpdateCommand(rule, pair))
			}
		}
		
		for _, rule := range natRuleMap {
			if rule.ContainsAddress(pair.SourceAddress) {
				commands = append(commands, ra.generateNATRuleUpdateCommand(rule, pair))
			}
		}
	}
	
	return commands
}

func (ra *RedundancyAnalyzer) generateSecurityRuleUpdateCommand(rule *models.SecurityRule, pair models.RedundantAddressPair) string {
	baseCommand := ra.buildRuleBasePath("security", rule.DeviceGroup, rule.Name)
	
	contexts := rule.GetAddressContext(pair.SourceAddress)
	var commands []string
	
	for _, context := range contexts {
		cmd := baseCommand + " " + context + " [ edit value " + pair.SourceAddress + " ]"
		cmd += " set value " + pair.DuplicateAddress
		commands = append(commands, cmd)
	}
	
	return strings.Join(commands, "\n")
}

func (ra *RedundancyAnalyzer) generateNATRuleUpdateCommand(rule *models.NATRule, pair models.RedundantAddressPair) string {
	baseCommand := ra.buildRuleBasePath("nat", rule.DeviceGroup, rule.Name)
	
	contexts := rule.GetAddressContext(pair.SourceAddress)
	var commands []string
	
	for _, context := range contexts {
		section := ra.mapNATContextToSection(context)
		cmd := baseCommand + " " + section + " [ edit value " + pair.SourceAddress + " ]"
		cmd += " set value " + pair.DuplicateAddress
		commands = append(commands, cmd)
	}
	
	return strings.Join(commands, "\n")
}

func (ra *RedundancyAnalyzer) generateGroupUpdateCommands(redundantPairs []models.RedundantAddressPair) []string {
	var commands []string
	
	groupMap := ra.processor.GetGroupMap()
	
	for _, pair := range redundantPairs {
		for _, group := range groupMap {
			if group.HasMember(pair.SourceAddress) {
				cmd := ra.generateGroupMemberUpdateCommand(group, pair)
				if cmd != "" {
					commands = append(commands, cmd)
				}
			}
		}
	}
	
	return commands
}

func (ra *RedundancyAnalyzer) generateGroupMemberUpdateCommand(group *models.AddressGroup, pair models.RedundantAddressPair) string {
	basePath := ra.buildGroupBasePath(group.DeviceGroup, group.Name)
	
	deleteCmd := basePath + " static [ delete member " + pair.SourceAddress + " ]"
	addCmd := basePath + " static [ set member " + pair.DuplicateAddress + " ]"
	
	return deleteCmd + "\n" + addCmd
}

func (ra *RedundancyAnalyzer) generateObjectCreationCommands(redundantPairs []models.RedundantAddressPair) []string {
	var commands []string
	addressMap := ra.processor.GetAddressMap()
	
	for _, pair := range redundantPairs {
		if ra.shouldPromoteScope(pair) {
			if targetAddr, exists := addressMap[pair.DuplicateAddress]; exists {
				cmd := ra.generateScopePromotionCommand(targetAddr, "shared")
				if cmd != "" {
					commands = append(commands, cmd)
				}
			}
		}
	}
	
	return commands
}

func (ra *RedundancyAnalyzer) generateScopePromotionCommand(addr *models.AddressObject, newScope string) string {
	if models.IsSharedScope(addr.Scope) {
		return ""
	}
	
	basePath := "set shared address " + addr.Name
	
	if addr.IPNetmask != "" {
		return basePath + " ip-netmask " + addr.IPNetmask
	}
	
	if addr.IPRange != "" {
		return basePath + " ip-range " + addr.IPRange
	}
	
	if addr.FQDN != "" {
		return basePath + " fqdn " + addr.FQDN
	}
	
	return ""
}

func (ra *RedundancyAnalyzer) generateObjectDeletionCommands(redundantPairs []models.RedundantAddressPair) []string {
	var commands []string
	
	for _, pair := range redundantPairs {
		if models.IsSharedScope(pair.SourceScope) {
			commands = append(commands, "delete shared address "+pair.SourceAddress)
		} else {
			deviceGroup := models.ExtractDeviceGroupFromScope(pair.SourceScope)
			if deviceGroup != "" {
				commands = append(commands, "delete device-group "+deviceGroup+" address "+pair.SourceAddress)
			}
		}
	}
	
	return commands
}

func (ra *RedundancyAnalyzer) generateWarnings(redundantPairs []models.RedundantAddressPair) []string {
	var warnings []string
	
	warnings = append(warnings, "WARNING: These commands will modify your PAN configuration.")
	warnings = append(warnings, "WARNING: Test these commands in a non-production environment first.")
	warnings = append(warnings, "WARNING: Ensure you have a configuration backup before proceeding.")
	
	for _, pair := range redundantPairs {
		if len(pair.DeviceGroups) > 1 {
			warnings = append(warnings, "WARNING: Address '"+pair.SourceAddress+"' is used across multiple device groups: "+strings.Join(pair.DeviceGroups, ", "))
		}
	}
	
	return warnings
}

func (ra *RedundancyAnalyzer) buildRuleBasePath(ruleType, deviceGroup, ruleName string) string {
	if deviceGroup != "" {
		return "set device-group " + deviceGroup + " pre-rulebase " + ruleType + " rules " + ruleName
	}
	return "set shared pre-rulebase " + ruleType + " rules " + ruleName
}

func (ra *RedundancyAnalyzer) buildGroupBasePath(deviceGroup, groupName string) string {
	if deviceGroup != "" {
		return "set device-group " + deviceGroup + " address-group " + groupName
	}
	return "set shared address-group " + groupName
}

func (ra *RedundancyAnalyzer) mapNATContextToSection(context string) string {
	switch context {
	case "original-source":
		return "source"
	case "original-destination":
		return "destination"
	case "translated-source":
		return "source-translation"
	case "translated-destination":
		return "destination-translation"
	default:
		return context
	}
}