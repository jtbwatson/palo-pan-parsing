package processor

import (
	"strings"

	"palo-pan-parsing/models"
)

type ScopeAnalyzer struct {
	processor *Processor
}

func NewScopeAnalyzer(processor *Processor) *ScopeAnalyzer {
	return &ScopeAnalyzer{
		processor: processor,
	}
}

func (sa *ScopeAnalyzer) OptimizeScopes(result *models.AnalysisResult) {
	sa.analyzeAddressScopes(result)
	sa.analyzeGroupScopes(result)
	sa.identifyScopeOptimizations(result)
}

func (sa *ScopeAnalyzer) analyzeAddressScopes(result *models.AnalysisResult) {
	addressMap := sa.processor.GetAddressMap()
	
	for _, addr := range addressMap {
		if addr.Scope == "" {
			addr.Scope = sa.inferAddressScope(addr.Name)
		}
	}
}

func (sa *ScopeAnalyzer) analyzeGroupScopes(result *models.AnalysisResult) {
	groupMap := sa.processor.GetGroupMap()
	
	for _, group := range groupMap {
		if group.Scope == "" {
			group.Scope = sa.inferGroupScope(group.Name)
		}
	}
}

func (sa *ScopeAnalyzer) inferAddressScope(addressName string) string {
	deviceGroups := sa.findAddressDeviceGroups(addressName)
	
	if len(deviceGroups) == 0 {
		return "shared"
	}
	
	if len(deviceGroups) == 1 {
		return "device-group:" + deviceGroups[0]
	}
	
	return "shared"
}

func (sa *ScopeAnalyzer) inferGroupScope(groupName string) string {
	deviceGroups := sa.findGroupDeviceGroups(groupName)
	
	if len(deviceGroups) == 0 {
		return "shared"
	}
	
	if len(deviceGroups) == 1 {
		return "device-group:" + deviceGroups[0]
	}
	
	return "shared"
}

func (sa *ScopeAnalyzer) findAddressDeviceGroups(addressName string) []string {
	deviceGroupSet := make(map[string]bool)
	
	securityRuleMap := sa.processor.GetSecurityRuleMap()
	natRuleMap := sa.processor.GetNATRuleMap()
	groupMap := sa.processor.GetGroupMap()
	
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(addressName) && rule.DeviceGroup != "" {
			deviceGroupSet[rule.DeviceGroup] = true
		}
	}
	
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(addressName) && rule.DeviceGroup != "" {
			deviceGroupSet[rule.DeviceGroup] = true
		}
	}
	
	for _, group := range groupMap {
		if group.HasMember(addressName) && group.DeviceGroup != "" {
			deviceGroupSet[group.DeviceGroup] = true
		}
	}
	
	var deviceGroups []string
	for dg := range deviceGroupSet {
		deviceGroups = append(deviceGroups, dg)
	}
	
	return deviceGroups
}

func (sa *ScopeAnalyzer) findGroupDeviceGroups(groupName string) []string {
	deviceGroupSet := make(map[string]bool)
	
	securityRuleMap := sa.processor.GetSecurityRuleMap()
	natRuleMap := sa.processor.GetNATRuleMap()
	
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(groupName) && rule.DeviceGroup != "" {
			deviceGroupSet[rule.DeviceGroup] = true
		}
	}
	
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(groupName) && rule.DeviceGroup != "" {
			deviceGroupSet[rule.DeviceGroup] = true
		}
	}
	
	var deviceGroups []string
	for dg := range deviceGroupSet {
		deviceGroups = append(deviceGroups, dg)
	}
	
	return deviceGroups
}

func (sa *ScopeAnalyzer) identifyScopeOptimizations(result *models.AnalysisResult) {
	addressOptimizations := sa.findAddressScopeOptimizations()
	groupOptimizations := sa.findGroupScopeOptimizations()
	
	var optimizationCommands []string
	optimizationCommands = append(optimizationCommands, addressOptimizations...)
	optimizationCommands = append(optimizationCommands, groupOptimizations...)
	
	if len(optimizationCommands) > 0 {
		result.GroupCommands = append(result.GroupCommands, optimizationCommands...)
	}
}

func (sa *ScopeAnalyzer) findAddressScopeOptimizations() []string {
	var commands []string
	addressMap := sa.processor.GetAddressMap()
	
	for addressName, addr := range addressMap {
		deviceGroups := sa.findAddressDeviceGroups(addressName)
		
		if len(deviceGroups) > 1 && models.IsDeviceGroupScope(addr.Scope) {
			cmd := sa.generateScopePromotionCommand(addr, "shared")
			if cmd != "" {
				commands = append(commands, cmd)
			}
		}
	}
	
	return commands
}

func (sa *ScopeAnalyzer) findGroupScopeOptimizations() []string {
	var commands []string
	groupMap := sa.processor.GetGroupMap()
	
	for groupName, group := range groupMap {
		deviceGroups := sa.findGroupDeviceGroups(groupName)
		
		if len(deviceGroups) > 1 && models.IsDeviceGroupScope(group.Scope) {
			cmd := sa.generateGroupScopePromotionCommand(group, "shared")
			if cmd != "" {
				commands = append(commands, cmd)
			}
		}
	}
	
	return commands
}

func (sa *ScopeAnalyzer) generateScopePromotionCommand(addr *models.AddressObject, newScope string) string {
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

func (sa *ScopeAnalyzer) generateGroupScopePromotionCommand(group *models.AddressGroup, newScope string) string {
	if models.IsSharedScope(group.Scope) {
		return ""
	}
	
	basePath := "set shared address-group " + group.Name
	
	var commands []string
	for _, member := range group.GetAllMembers() {
		commands = append(commands, basePath+" static [ set member "+member+" ]")
	}
	
	if group.DynamicFilter != "" {
		commands = append(commands, basePath+" dynamic filter '"+group.DynamicFilter+"'")
	}
	
	return strings.Join(commands, "\n")
}

func (sa *ScopeAnalyzer) AnalyzeGroupCommandScopes(targetAddress string) *models.GroupCommandAnalysis {
	discoveredGroups := sa.findGroupsContainingAddress(targetAddress)
	scopeAnalysis := sa.analyzeScopeForNewAddress(discoveredGroups)
	
	analysis := &models.GroupCommandAnalysis{
		TargetAddress:    targetAddress,
		DiscoveredGroups: discoveredGroups,
		ScopeAnalysis:    scopeAnalysis,
		Commands:         models.GroupCommands{},
	}
	
	analysis.Commands = sa.generateGroupCommands(targetAddress, discoveredGroups, scopeAnalysis.RecommendedScope)
	
	return analysis
}

func (sa *ScopeAnalyzer) findGroupsContainingAddress(targetAddress string) []models.AddressGroup {
	var groups []models.AddressGroup
	groupMap := sa.processor.GetGroupMap()
	
	for _, group := range groupMap {
		if group.HasMember(targetAddress) {
			groups = append(groups, *group)
		}
	}
	
	return groups
}

func (sa *ScopeAnalyzer) analyzeScopeForNewAddress(groups []models.AddressGroup) models.ScopeOptimization {
	if len(groups) == 0 {
		return models.ScopeOptimization{
			RecommendedScope: "shared",
			Reasoning:        "No existing groups found - defaulting to shared scope",
		}
	}
	
	deviceGroupSet := make(map[string]bool)
	sharedCount := 0
	
	for _, group := range groups {
		if models.IsSharedScope(group.Scope) {
			sharedCount++
		} else if models.IsDeviceGroupScope(group.Scope) {
			deviceGroup := models.ExtractDeviceGroupFromScope(group.Scope)
			if deviceGroup != "" {
				deviceGroupSet[deviceGroup] = true
			}
		}
	}
	
	var deviceGroups []string
	for dg := range deviceGroupSet {
		deviceGroups = append(deviceGroups, dg)
	}
	
	if sharedCount > 0 || len(deviceGroups) > 1 {
		return models.ScopeOptimization{
			RecommendedScope: "shared",
			Reasoning:        "Groups exist in shared scope or multiple device groups - using shared for efficiency",
			DeviceGroups:     deviceGroups,
		}
	}
	
	if len(deviceGroups) == 1 {
		return models.ScopeOptimization{
			RecommendedScope: "device-group:" + deviceGroups[0],
			Reasoning:        "All groups are in the same device group - maintaining scope isolation",
			DeviceGroups:     deviceGroups,
		}
	}
	
	return models.ScopeOptimization{
		RecommendedScope: "shared",
		Reasoning:        "Unable to determine optimal scope - defaulting to shared",
	}
}

func (sa *ScopeAnalyzer) generateGroupCommands(targetAddress string, groups []models.AddressGroup, recommendedScope string) models.GroupCommands {
	commands := models.GroupCommands{}
	
	objectCreationCmd := sa.generateAddressObjectCreationCommand(targetAddress, recommendedScope)
	if objectCreationCmd != "" {
		commands.ObjectCreation = []string{objectCreationCmd}
	}
	
	for _, group := range groups {
		groupUpdateCmd := sa.generateGroupMembershipCommand(group, targetAddress)
		if groupUpdateCmd != "" {
			commands.GroupUpdates = append(commands.GroupUpdates, groupUpdateCmd)
		}
	}
	
	return commands
}

func (sa *ScopeAnalyzer) generateAddressObjectCreationCommand(addressName, scope string) string {
	if models.IsSharedScope(scope) {
		return "set shared address " + addressName + " ip-netmask <IP_ADDRESS>"
	}
	
	deviceGroup := models.ExtractDeviceGroupFromScope(scope)
	if deviceGroup != "" {
		return "set device-group " + deviceGroup + " address " + addressName + " ip-netmask <IP_ADDRESS>"
	}
	
	return ""
}

func (sa *ScopeAnalyzer) generateGroupMembershipCommand(group models.AddressGroup, memberName string) string {
	if models.IsSharedScope(group.Scope) {
		return "set shared address-group " + group.Name + " static [ set member " + memberName + " ]"
	}
	
	deviceGroup := models.ExtractDeviceGroupFromScope(group.Scope)
	if deviceGroup != "" {
		return "set device-group " + deviceGroup + " address-group " + group.Name + " static [ set member " + memberName + " ]"
	}
	
	return ""
}

func (sa *ScopeAnalyzer) GetScopeStatistics() map[string]int {
	stats := make(map[string]int)
	
	addressMap := sa.processor.GetAddressMap()
	groupMap := sa.processor.GetGroupMap()
	
	for _, addr := range addressMap {
		scope := addr.Scope
		if scope == "" {
			scope = "unknown"
		}
		stats["addresses_"+scope]++
	}
	
	for _, group := range groupMap {
		scope := group.Scope
		if scope == "" {
			scope = "unknown"
		}
		stats["groups_"+scope]++
	}
	
	return stats
}

func (sa *ScopeAnalyzer) ValidateScopeConsistency() []string {
	var warnings []string
	
	addressMap := sa.processor.GetAddressMap()
	groupMap := sa.processor.GetGroupMap()
	
	for addressName, addr := range addressMap {
		actualDeviceGroups := sa.findAddressDeviceGroups(addressName)
		expectedScope := sa.inferAddressScope(addressName)
		
		if addr.Scope != expectedScope {
			warning := "Address '" + addressName + "' has scope '" + addr.Scope + "' but should be '" + expectedScope + "' based on usage"
			warnings = append(warnings, warning)
		}
		
		if models.IsDeviceGroupScope(addr.Scope) && len(actualDeviceGroups) > 1 {
			warning := "Address '" + addressName + "' is in device-group scope but used across multiple device groups: " + strings.Join(actualDeviceGroups, ", ")
			warnings = append(warnings, warning)
		}
	}
	
	for groupName, group := range groupMap {
		actualDeviceGroups := sa.findGroupDeviceGroups(groupName)
		expectedScope := sa.inferGroupScope(groupName)
		
		if group.Scope != expectedScope {
			warning := "Group '" + groupName + "' has scope '" + group.Scope + "' but should be '" + expectedScope + "' based on usage"
			warnings = append(warnings, warning)
		}
		
		if models.IsDeviceGroupScope(group.Scope) && len(actualDeviceGroups) > 1 {
			warning := "Group '" + groupName + "' is in device-group scope but used across multiple device groups: " + strings.Join(actualDeviceGroups, ", ")
			warnings = append(warnings, warning)
		}
	}
	
	return warnings
}