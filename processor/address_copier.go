package processor

import (
	"fmt"

	"palo-pan-parsing/models"
)

type AddressCopier struct {
	config *models.Config
}

func NewAddressCopier(config *models.Config) *AddressCopier {
	return &AddressCopier{
		config: config,
	}
}

type AddressCopyRequest struct {
	SourceAddressName string
	NewAddressName    string
	NewIPNetmask      string
	CopyMode          string // "replace" or "add"
}

type AddressCopyResult struct {
	SourceAddress     *models.AddressObject
	NewAddress        *models.AddressObject
	CreateCommands    []string
	UpdateCommands    []string
	GroupMemberships  []models.GroupMembership
	RuleReferences    []models.AddressReference
	Summary           AddressCopySummary
}

type AddressCopySummary struct {
	SourceScope         string
	NewScope            string
	GroupsToUpdate      int
	SecurityRulesToUpdate int
	NATRulesToUpdate    int
	TotalCommands       int
}

func (ac *AddressCopier) AnalyzeAddressCopy(
	request AddressCopyRequest,
	addressMap map[string]*models.AddressObject,
	groupMap map[string]*models.AddressGroup,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) (*AddressCopyResult, error) {
	sourceAddr, exists := addressMap[request.SourceAddressName]
	if !exists {
		return nil, fmt.Errorf("source address '%s' not found in configuration", request.SourceAddressName)
	}

	result := &AddressCopyResult{
		SourceAddress: sourceAddr,
		CreateCommands: []string{},
		UpdateCommands: []string{},
		GroupMemberships: []models.GroupMembership{},
		RuleReferences: []models.AddressReference{},
	}

	// Create new address object with copied settings
	newAddr := ac.createNewAddressObject(sourceAddr, request.NewAddressName, request.NewIPNetmask)
	result.NewAddress = newAddr

	// Find all group memberships
	groupMemberships := ac.findGroupMemberships(request.SourceAddressName, groupMap)
	result.GroupMemberships = groupMemberships

	// Find all rule references
	ruleReferences := ac.findRuleReferences(request.SourceAddressName, securityRuleMap, natRuleMap)
	result.RuleReferences = ruleReferences

	// Generate commands
	ac.generateCreateCommands(result)
	ac.generateUpdateCommands(result, request.CopyMode, groupMap, securityRuleMap, natRuleMap)

	// Generate summary
	result.Summary = ac.generateSummary(result, groupMemberships, ruleReferences)

	return result, nil
}

func (ac *AddressCopier) createNewAddressObject(source *models.AddressObject, newName, newIP string) *models.AddressObject {
	return &models.AddressObject{
		Name:        newName,
		IPNetmask:   newIP,
		IPRange:     "", // Clear IP range since we're setting a specific IP
		FQDN:        "", // Clear FQDN since we're setting an IP
		Scope:       source.Scope,
		DeviceGroup: source.DeviceGroup,
		Description: source.Description,
	}
}

func (ac *AddressCopier) findGroupMemberships(addressName string, groupMap map[string]*models.AddressGroup) []models.GroupMembership {
	var memberships []models.GroupMembership

	for _, group := range groupMap {
		if group.HasMember(addressName) {
			membership := models.GroupMembership{
				GroupName:   group.Name,
				MemberName:  addressName,
				MemberType:  "address",
				GroupScope:  group.Scope,
				DeviceGroup: group.DeviceGroup,
			}
			memberships = append(memberships, membership)
		}
	}

	return memberships
}

func (ac *AddressCopier) findRuleReferences(
	addressName string,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) []models.AddressReference {
	var references []models.AddressReference

	// Find security rule references
	for _, rule := range securityRuleMap {
		if rule.ContainsAddress(addressName) {
			contexts := rule.GetAddressContext(addressName)
			for _, context := range contexts {
				ref := models.AddressReference{
					ObjectName:  addressName,
					SourceType:  "security_rule",
					SourceName:  rule.Name,
					Context:     context,
					DeviceGroup: rule.DeviceGroup,
					LineNumber:  rule.LineNumber,
				}
				references = append(references, ref)
			}
		}
	}

	// Find NAT rule references
	for _, rule := range natRuleMap {
		if rule.ContainsAddress(addressName) {
			contexts := rule.GetAddressContext(addressName)
			for _, context := range contexts {
				ref := models.AddressReference{
					ObjectName:  addressName,
					SourceType:  "nat_rule",
					SourceName:  rule.Name,
					Context:     context,
					DeviceGroup: rule.DeviceGroup,
					LineNumber:  rule.LineNumber,
				}
				references = append(references, ref)
			}
		}
	}

	return references
}

func (ac *AddressCopier) generateCreateCommands(result *AddressCopyResult) {
	newAddr := result.NewAddress
	
	// Determine scope path for command
	var scopePath string
	if newAddr.Scope == "shared" {
		scopePath = "shared"
	} else if newAddr.DeviceGroup != "" {
		scopePath = fmt.Sprintf("device-group %s", newAddr.DeviceGroup)
	} else {
		scopePath = "shared" // Default to shared
	}

	// Create address object command
	createCmd := fmt.Sprintf("set %s address %s ip-netmask %s", 
		scopePath, newAddr.Name, newAddr.IPNetmask)
	result.CreateCommands = append(result.CreateCommands, createCmd)

	// Add description if present
	if newAddr.Description != "" {
		descCmd := fmt.Sprintf("set %s address %s description \"%s\"", 
			scopePath, newAddr.Name, newAddr.Description)
		result.CreateCommands = append(result.CreateCommands, descCmd)
	}
}

func (ac *AddressCopier) generateUpdateCommands(
	result *AddressCopyResult,
	copyMode string,
	groupMap map[string]*models.AddressGroup,
	securityRuleMap map[string]*models.SecurityRule,
	natRuleMap map[string]*models.NATRule,
) {
	newAddrName := result.NewAddress.Name
	sourceAddrName := result.SourceAddress.Name

	// Generate group membership commands
	for _, membership := range result.GroupMemberships {
		group := groupMap[membership.GroupName]
		if group == nil {
			continue
		}

		var scopePath string
		if group.Scope == "shared" {
			scopePath = "shared"
		} else if group.DeviceGroup != "" {
			scopePath = fmt.Sprintf("device-group %s", group.DeviceGroup)
		} else {
			scopePath = "shared"
		}

		// Add new address to group
		addCmd := fmt.Sprintf("set %s address-group %s static %s", 
			scopePath, group.Name, newAddrName)
		result.UpdateCommands = append(result.UpdateCommands, addCmd)

		// If replace mode, remove original address from group
		if copyMode == "replace" {
			removeCmd := fmt.Sprintf("delete %s address-group %s static %s", 
				scopePath, group.Name, sourceAddrName)
			result.UpdateCommands = append(result.UpdateCommands, removeCmd)
		}
	}

	// Generate rule update commands
	for _, ref := range result.RuleReferences {
		if ref.SourceType == "security_rule" {
			rule := securityRuleMap[ref.SourceName]
			if rule != nil {
				ac.generateSecurityRuleUpdateCommands(result, ref, rule, copyMode, newAddrName, sourceAddrName)
			}
		} else if ref.SourceType == "nat_rule" {
			rule := natRuleMap[ref.SourceName]
			if rule != nil {
				ac.generateNATRuleUpdateCommands(result, ref, rule, copyMode, newAddrName, sourceAddrName)
			}
		}
	}
}

func (ac *AddressCopier) generateSecurityRuleUpdateCommands(
	result *AddressCopyResult,
	ref models.AddressReference,
	rule *models.SecurityRule,
	copyMode string,
	newAddrName string,
	sourceAddrName string,
) {
	var scopePath string
	if rule.Scope == "shared" {
		scopePath = "shared"
	} else if rule.DeviceGroup != "" {
		scopePath = fmt.Sprintf("device-group %s", rule.DeviceGroup)
	} else {
		scopePath = "shared"
	}

	rulesetPath := fmt.Sprintf("rulebase security rules")
	
	// Add new address to rule
	addCmd := fmt.Sprintf("set %s %s %s %s %s", 
		scopePath, rulesetPath, rule.Name, ref.Context, newAddrName)
	result.UpdateCommands = append(result.UpdateCommands, addCmd)

	// If replace mode, remove original address from rule
	if copyMode == "replace" {
		removeCmd := fmt.Sprintf("delete %s %s %s %s %s", 
			scopePath, rulesetPath, rule.Name, ref.Context, sourceAddrName)
		result.UpdateCommands = append(result.UpdateCommands, removeCmd)
	}
}

func (ac *AddressCopier) generateNATRuleUpdateCommands(
	result *AddressCopyResult,
	ref models.AddressReference,
	rule *models.NATRule,
	copyMode string,
	newAddrName string,
	sourceAddrName string,
) {
	var scopePath string
	if rule.Scope == "shared" {
		scopePath = "shared"
	} else if rule.DeviceGroup != "" {
		scopePath = fmt.Sprintf("device-group %s", rule.DeviceGroup)
	} else {
		scopePath = "shared"
	}

	rulesetPath := fmt.Sprintf("rulebase nat rules")
	
	// Map context to NAT rule fields
	var natField string
	switch ref.Context {
	case "source":
		natField = "source"
	case "destination":
		natField = "destination"
	case "translated_source":
		natField = "source-translation"
	case "translated_destination":
		natField = "destination-translation"
	default:
		natField = ref.Context
	}

	// Add new address to NAT rule
	addCmd := fmt.Sprintf("set %s %s %s %s %s", 
		scopePath, rulesetPath, rule.Name, natField, newAddrName)
	result.UpdateCommands = append(result.UpdateCommands, addCmd)

	// If replace mode, remove original address from NAT rule
	if copyMode == "replace" {
		removeCmd := fmt.Sprintf("delete %s %s %s %s %s", 
			scopePath, rulesetPath, rule.Name, natField, sourceAddrName)
		result.UpdateCommands = append(result.UpdateCommands, removeCmd)
	}
}

func (ac *AddressCopier) generateSummary(
	result *AddressCopyResult,
	groupMemberships []models.GroupMembership,
	ruleReferences []models.AddressReference,
) AddressCopySummary {
	summary := AddressCopySummary{
		SourceScope: result.SourceAddress.Scope,
		NewScope:    result.NewAddress.Scope,
		GroupsToUpdate: len(groupMemberships),
	}

	// Count rule types
	securityRuleCount := 0
	natRuleCount := 0
	
	for _, ref := range ruleReferences {
		if ref.SourceType == "security_rule" {
			securityRuleCount++
		} else if ref.SourceType == "nat_rule" {
			natRuleCount++
		}
	}

	summary.SecurityRulesToUpdate = securityRuleCount
	summary.NATRulesToUpdate = natRuleCount
	summary.TotalCommands = len(result.CreateCommands) + len(result.UpdateCommands)

	return summary
}

func (ac *AddressCopier) OptimizeScope(
	sourceAddress *models.AddressObject,
	groupMemberships []models.GroupMembership,
) string {
	// If address is used in multiple device groups via groups, promote to shared
	deviceGroups := make(map[string]bool)
	
	for _, membership := range groupMemberships {
		if membership.DeviceGroup != "" {
			deviceGroups[membership.DeviceGroup] = true
		}
	}

	// If used in multiple device groups, promote to shared scope
	if len(deviceGroups) > 1 {
		return "shared"
	}

	// If only used in one device group, keep in that device group
	if len(deviceGroups) == 1 {
		for dg := range deviceGroups {
			return fmt.Sprintf("device-group:%s", dg)
		}
	}

	// Default to source address scope
	return sourceAddress.Scope
}

func ValidateCopyRequest(request AddressCopyRequest) error {
	if request.SourceAddressName == "" {
		return fmt.Errorf("source address name cannot be empty")
	}
	
	if request.NewAddressName == "" {
		return fmt.Errorf("new address name cannot be empty")
	}
	
	if request.NewIPNetmask == "" {
		return fmt.Errorf("new IP/netmask cannot be empty")
	}
	
	if !models.ValidateIPAddress(request.NewIPNetmask) {
		return fmt.Errorf("invalid IP address format: %s", request.NewIPNetmask)
	}
	
	if request.CopyMode != "add" && request.CopyMode != "replace" {
		return fmt.Errorf("copy mode must be 'add' or 'replace'")
	}
	
	return nil
}