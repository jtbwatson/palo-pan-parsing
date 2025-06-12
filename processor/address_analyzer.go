package processor

import (
	"strings"

	"palo-pan-parsing/models"
)

type Analyzer struct {
	config *models.Config
}

func NewAnalyzer(config *models.Config) *Analyzer {
	return &Analyzer{
		config: config,
	}
}

func (a *Analyzer) AnalyzeReferences(
	result *models.AnalysisResult,
	addressMap map[string]*models.AddressObject,
	groupMap map[string]*models.AddressGroup,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) {
	targetAddresses := a.getTargetAddresses(result.TargetAddress)
	
	for _, targetAddr := range targetAddresses {
		a.findDirectReferences(result, targetAddr, securityRuleMap, natRuleMap)
		a.findIndirectReferences(result, targetAddr, groupMap, securityRuleMap, natRuleMap)
	}
}

func (a *Analyzer) AnalyzeGroupMemberships(
	result *models.AnalysisResult,
	groupMap map[string]*models.AddressGroup,
) {
	targetAddresses := a.getTargetAddresses(result.TargetAddress)
	
	for _, targetAddr := range targetAddresses {
		a.findGroupMemberships(result, targetAddr, groupMap)
	}
}

func (a *Analyzer) getTargetAddresses(primaryTarget string) []string {
	if len(a.config.Addresses) > 0 {
		return a.config.Addresses
	}
	return []string{primaryTarget}
}

func (a *Analyzer) findDirectReferences(
	result *models.AnalysisResult,
	targetAddress string,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) {
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(targetAddress) {
			contexts := rule.GetAddressContext(targetAddress)
			for _, context := range contexts {
				ref := models.AddressReference{
					ObjectName:  targetAddress,
					SourceType:  "security_rule",
					SourceName:  rule.Name,
					Context:     context,
					DeviceGroup: rule.DeviceGroup,
					LineNumber:  rule.LineNumber,
				}
				result.DirectReferences = append(result.DirectReferences, ref)
			}
			// Add to direct security rules
			result.DirectSecurityRules = append(result.DirectSecurityRules, *rule)
		}
	}
	
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(targetAddress) {
			contexts := rule.GetAddressContext(targetAddress)
			for _, context := range contexts {
				ref := models.AddressReference{
					ObjectName:  targetAddress,
					SourceType:  "nat_rule",
					SourceName:  rule.Name,
					Context:     context,
					DeviceGroup: rule.DeviceGroup,
					LineNumber:  rule.LineNumber,
				}
				result.DirectReferences = append(result.DirectReferences, ref)
			}
			// Add to direct NAT rules
			result.DirectNATRules = append(result.DirectNATRules, *rule)
		}
	}
}

func (a *Analyzer) findIndirectReferences(
	result *models.AnalysisResult,
	targetAddress string,
	groupMap map[string]*models.AddressGroup,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) {
	containingGroups := a.findContainingGroups(targetAddress, groupMap)
	
	for _, groupName := range containingGroups {
		a.findGroupReferences(result, targetAddress, groupName, securityRuleMap, natRuleMap)
	}
}

func (a *Analyzer) findContainingGroups(targetAddress string, groupMap map[string]*models.AddressGroup) []string {
	var containingGroups []string
	
	for _, group := range groupMap {
		if group.HasMember(targetAddress) {
			containingGroups = append(containingGroups, group.Name)
		}
	}
	
	return containingGroups
}

func (a *Analyzer) findGroupReferences(
	result *models.AnalysisResult,
	targetAddress string,
	groupName string,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) {
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(groupName) {
			contexts := rule.GetAddressContext(groupName)
			for _, context := range contexts {
				ref := models.GroupReference{
					GroupName:    groupName,
					MemberName:   targetAddress,
					SourceType:   "security_rule",
					SourceName:   rule.Name,
					Context:      context,
					DeviceGroup:  rule.DeviceGroup,
					LineNumber:   rule.LineNumber,
				}
				result.IndirectReferences = append(result.IndirectReferences, ref)
			}
			// Add to indirect security rules (avoid duplicates)
			if !a.ruleAlreadyAdded(rule.Name, result.IndirectSecurityRules) {
				result.IndirectSecurityRules = append(result.IndirectSecurityRules, *rule)
			}
		}
	}
	
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(groupName) {
			contexts := rule.GetAddressContext(groupName)
			for _, context := range contexts {
				ref := models.GroupReference{
					GroupName:    groupName,
					MemberName:   targetAddress,
					SourceType:   "nat_rule",
					SourceName:   rule.Name,
					Context:      context,
					DeviceGroup:  rule.DeviceGroup,
					LineNumber:   rule.LineNumber,
				}
				result.IndirectReferences = append(result.IndirectReferences, ref)
			}
			// Add to indirect NAT rules (avoid duplicates)
			if !a.natRuleAlreadyAdded(rule.Name, result.IndirectNATRules) {
				result.IndirectNATRules = append(result.IndirectNATRules, *rule)
			}
		}
	}
}

func (a *Analyzer) findGroupMemberships(
	result *models.AnalysisResult,
	targetAddress string,
	groupMap map[string]*models.AddressGroup,
) {
	for _, group := range groupMap {
		if group.HasMember(targetAddress) {
			membership := models.GroupMembership{
				GroupName:   group.Name,
				MemberName:  targetAddress,
				MemberType:  "address",
				GroupScope:  group.Scope,
				DeviceGroup: group.DeviceGroup,
			}
			
			nestedGroups := a.findNestedGroupsForMember(targetAddress, group.Name, groupMap)
			membership.NestedGroups = nestedGroups
			
			result.GroupMemberships = append(result.GroupMemberships, membership)
		}
	}
}

func (a *Analyzer) findNestedGroupsForMember(
	memberName, groupName string,
	groupMap map[string]*models.AddressGroup,
) []string {
	var nestedGroups []string
	
	for _, group := range groupMap {
		if group.Name != groupName && group.HasMember(groupName) {
			nestedGroups = append(nestedGroups, group.Name)
			
			parentGroups := a.findNestedGroupsForMember(memberName, group.Name, groupMap)
			nestedGroups = append(nestedGroups, parentGroups...)
		}
	}
	
	return nestedGroups
}

func (a *Analyzer) AnalyzeGroupHierarchy(groupMap map[string]*models.AddressGroup) *models.GroupHierarchy {
	hierarchy := &models.GroupHierarchy{
		GroupTree:     make(map[string][]string),
		MembershipMap: make(map[string][]string),
	}
	
	for _, group := range groupMap {
		allMembers := group.GetAllMembers()
		hierarchy.AddGroup(group.Name, allMembers)
	}
	
	hierarchy.CalculateDepth()
	a.identifyRootGroups(hierarchy)
	
	return hierarchy
}

func (a *Analyzer) identifyRootGroups(hierarchy *models.GroupHierarchy) {
	allGroups := make(map[string]bool)
	childGroups := make(map[string]bool)
	
	for groupName := range hierarchy.GroupTree {
		allGroups[groupName] = true
	}
	
	for _, members := range hierarchy.GroupTree {
		for _, member := range members {
			if _, exists := allGroups[member]; exists {
				childGroups[member] = true
			}
		}
	}
	
	for groupName := range allGroups {
		if !childGroups[groupName] {
			hierarchy.RootGroups = append(hierarchy.RootGroups, groupName)
		}
	}
}

func (a *Analyzer) FindCircularReferences(groupMap map[string]*models.AddressGroup) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	
	for groupName := range groupMap {
		if !visited[groupName] {
			if path := a.findCircularDFS(groupName, groupMap, visited, recStack, []string{}); path != nil {
				cycles = append(cycles, path)
			}
		}
	}
	
	return cycles
}

func (a *Analyzer) findCircularDFS(
	groupName string,
	groupMap map[string]*models.AddressGroup,
	visited, recStack map[string]bool,
	path []string,
) []string {
	visited[groupName] = true
	recStack[groupName] = true
	path = append(path, groupName)
	
	group := groupMap[groupName]
	if group == nil {
		recStack[groupName] = false
		return nil
	}
	
	for _, member := range group.GetAllMembers() {
		if _, isGroup := groupMap[member]; isGroup {
			if !visited[member] {
				if cyclePath := a.findCircularDFS(member, groupMap, visited, recStack, path); cyclePath != nil {
					return cyclePath
				}
			} else if recStack[member] {
				cycleStart := -1
				for i, p := range path {
					if p == member {
						cycleStart = i
						break
					}
				}
				if cycleStart != -1 {
					return append(path[cycleStart:], member)
				}
			}
		}
	}
	
	recStack[groupName] = false
	return nil
}

func (a *Analyzer) AnalyzeAddressUsagePatterns(
	addressMap map[string]*models.AddressObject,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) map[string]map[string]int {
	usagePatterns := make(map[string]map[string]int)
	
	for addressName := range addressMap {
		usagePatterns[addressName] = make(map[string]int)
		
		for _, rule := range securityRuleMap {
			contexts := rule.GetAddressContext(addressName)
			for _, context := range contexts {
				usagePatterns[addressName][context]++
			}
		}
		
		for _, rule := range natRuleMap {
			contexts := rule.GetAddressContext(addressName)
			for _, context := range contexts {
				usagePatterns[addressName][context]++
			}
		}
	}
	
	return usagePatterns
}

func (a *Analyzer) FindUnusedAddresses(
	addressMap map[string]*models.AddressObject,
	groupMap map[string]*models.AddressGroup,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) []string {
	var unusedAddresses []string
	usedAddresses := make(map[string]bool)
	
	for _, group := range groupMap {
		for _, member := range group.GetAllMembers() {
			usedAddresses[member] = true
		}
	}
	
	for _, rule := range securityRuleMap {
		for _, addr := range rule.Source {
			usedAddresses[addr] = true
		}
		for _, addr := range rule.Destination {
			usedAddresses[addr] = true
		}
	}
	
	for _, rule := range natRuleMap {
		for _, addr := range rule.OriginalSource {
			usedAddresses[addr] = true
		}
		for _, addr := range rule.OriginalDestination {
			usedAddresses[addr] = true
		}
		for _, addr := range rule.TranslatedSource {
			usedAddresses[addr] = true
		}
		for _, addr := range rule.TranslatedDestination {
			usedAddresses[addr] = true
		}
	}
	
	for addressName := range addressMap {
		if !usedAddresses[addressName] {
			unusedAddresses = append(unusedAddresses, addressName)
		}
	}
	
	return unusedAddresses
}

func (a *Analyzer) AnalyzeScopeDistribution(addressMap map[string]*models.AddressObject) map[string][]string {
	scopeDistribution := make(map[string][]string)
	
	for addressName, address := range addressMap {
		scope := address.Scope
		if scope == "" {
			scope = "unknown"
		}
		
		if models.IsDeviceGroupScope(scope) {
			deviceGroup := models.ExtractDeviceGroupFromScope(scope)
			if deviceGroup != "" {
				scope = "device-group:" + deviceGroup
			}
		}
		
		scopeDistribution[scope] = append(scopeDistribution[scope], addressName)
	}
	
	return scopeDistribution
}

func (a *Analyzer) FindCrossDeviceGroupReferences(
	result *models.AnalysisResult,
	addressMap map[string]*models.AddressObject,
) []models.CrossAddressReference {
	var crossReferences []models.CrossAddressReference
	
	deviceGroupRules := make(map[string][]*models.SecurityRule)
	
	// Add direct security rules
	for i := range result.DirectSecurityRules {
		rule := &result.DirectSecurityRules[i]
		if rule.DeviceGroup != "" {
			deviceGroupRules[rule.DeviceGroup] = append(deviceGroupRules[rule.DeviceGroup], rule)
		}
	}
	
	// Add indirect security rules
	for i := range result.IndirectSecurityRules {
		rule := &result.IndirectSecurityRules[i]
		if rule.DeviceGroup != "" {
			deviceGroupRules[rule.DeviceGroup] = append(deviceGroupRules[rule.DeviceGroup], rule)
		}
	}
	
	for deviceGroup, rules := range deviceGroupRules {
		for _, rule := range rules {
			addresses := append(rule.Source, rule.Destination...)
			for i := 0; i < len(addresses); i++ {
				for j := i + 1; j < len(addresses); j++ {
					addr1, addr2 := addresses[i], addresses[j]
					
					if addr1 != addr2 && a.isTargetAddress(addr1) && a.isTargetAddress(addr2) {
						crossRef := models.CrossAddressReference{
							AddressA:    addr1,
							AddressB:    addr2,
							SharedRule:  rule.Name,
							RuleType:    "security",
							DeviceGroup: deviceGroup,
						}
						crossReferences = append(crossReferences, crossRef)
					}
				}
			}
		}
	}
	
	return crossReferences
}

func (a *Analyzer) isTargetAddress(addressName string) bool {
	if a.config.TargetAddress != "" {
		return addressName == a.config.TargetAddress
	}
	
	for _, target := range a.config.Addresses {
		if addressName == target {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) NormalizeAddressName(name string) string {
	return strings.TrimSpace(strings.Trim(name, "\"'"))
}

func (a *Analyzer) ruleAlreadyAdded(ruleName string, rules []models.SecurityRule) bool {
	for _, rule := range rules {
		if rule.Name == ruleName {
			return true
		}
	}
	return false
}

func (a *Analyzer) natRuleAlreadyAdded(ruleName string, rules []models.NATRule) bool {
	for _, rule := range rules {
		if rule.Name == ruleName {
			return true
		}
	}
	return false
}