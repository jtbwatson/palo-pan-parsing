package processor

import (
	"fmt"
	"regexp"
	"strings"

	"palo-pan-parsing/models"
	"palo-pan-parsing/utils"
)

// findRedundantAddresses finds addresses with same IP netmask
func (p *PANLogProcessor) findRedundantAddresses(ipToAddresses map[string][]models.IPAddress, targetAddresses map[string]bool) {
	for ipNetmask, addrList := range ipToAddresses {
		if len(addrList) > 1 {
			for targetAddr := range targetAddresses {
				// Check if this target address is in the list
				targetFound := false
				for _, addr := range addrList {
					if addr.Name == targetAddr {
						targetFound = true
						break
					}
				}

				if targetFound {
					// Found redundant addresses for this target
					var redundant []models.RedundantAddress
					for _, addr := range addrList {
						if addr.Name != targetAddr {
							// Determine device group
							var dg string
							if strings.HasPrefix(addr.Line, "set shared") {
								dg = "shared"
							} else if matches := regexp.MustCompile(`set\s+device-group\s+(\S+)\s+address`).FindStringSubmatch(addr.Line); matches != nil {
								dg = matches[1]
							} else {
								dg = "Unknown"
							}

							redundant = append(redundant, models.RedundantAddress{
								Name:        addr.Name,
								IPNetmask:   ipNetmask,
								DeviceGroup: dg,
							})
						}
					}
					p.Results[targetAddr].RedundantAddresses = redundant
				}
			}
		}
	}
}

// findIndirectRulesMemory finds security rules that reference address groups containing our addresses (in-memory version)
func (p *PANLogProcessor) findIndirectRulesMemory(allLines []string, addresses []string) {
	// Do a comprehensive scan for ALL address groups containing our target addresses
	// This ensures we don't miss groups that weren't discovered during the initial pass
	groupToAddresses := make(map[string]map[string]bool) // group name -> set of addresses
	allGroups := make(map[string]models.AddressGroup)    // group name -> group info

	// Scan all lines for address groups containing our target addresses
	for _, line := range allLines {
		if agInfo := p.extractAddressGroup(line); agInfo != nil {
			// Check which of our target addresses this group contains
			containedAddresses := make(map[string]bool)
			for _, addr := range addresses {
				if strings.Contains(line, addr) {
					containedAddresses[addr] = true
				}
			}

			// If this group contains any of our addresses, store it
			if len(containedAddresses) > 0 {
				allGroups[agInfo.Name] = *agInfo
				groupToAddresses[agInfo.Name] = containedAddresses
			}
		}
	}

	if len(allGroups) == 0 {
		return
	}

	// Pre-compile all regex patterns for performance
	groupPatterns := make(map[string]*regexp.Regexp)
	for name := range allGroups {
		groupPatterns[name] = regexp.MustCompile(regexp.QuoteMeta(name))
	}

	totalLines := len(allLines)
	progressInterval := 200000 // Less frequent progress reporting
	lastProgress := 0

	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			p.printf("    Analyzing line %s/%s (%.0f%%)\n",
				utils.FormatNumber(lineNum), utils.FormatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Fast pre-filter for security rules
		if !strings.Contains(line, "security") {
			continue
		}
		if !strings.Contains(line, "rules") && !strings.Contains(line, "rule") {
			continue
		}

		// Check if line references any of our address groups
		var matchedGroups []string
		hasMatches := false

		// Pre-filter with fast string search before regex
		for name, pattern := range groupPatterns {
			if idx := strings.Index(line, name); idx != -1 {
				if pattern.MatchString(line) {
					if !hasMatches {
						matchedGroups = make([]string, 0, len(groupPatterns))
						hasMatches = true
					}
					matchedGroups = append(matchedGroups, name)
				}
			}
		}

		if !hasMatches {
			continue
		}

		// Extract rule name and device group
		ruleName, _ := p.extractSecurityRule(line, "")
		if ruleName == "" {
			continue
		}

		var deviceGroup string
		if matches := p.Patterns.DeviceGroup.FindStringSubmatch(line); matches != nil {
			deviceGroup = matches[1]
		} else {
			deviceGroup = "Unknown"
		}

		// Add to results for each relevant address
		for _, groupName := range matchedGroups {
			groupInfo := allGroups[groupName]
			containedAddresses := groupToAddresses[groupName]

			// Add rule to each address contained in this group
			for targetAddr := range containedAddresses {
				// Skip if already in direct rules
				if _, exists := p.Results[targetAddr].DirectRules[ruleName]; exists {
					continue
				}

				p.Results[targetAddr].IndirectRules[ruleName] = deviceGroup

				// Create context
				context := fmt.Sprintf("references address-group '%s' that contains %s", groupName, targetAddr)
				if groupInfo.Context == "shared" {
					context = fmt.Sprintf("references shared address-group '%s' that contains %s", groupName, targetAddr)
				} else if groupInfo.Context == "device-group" {
					context = fmt.Sprintf("references address-group '%s' from device-group '%s' that contains %s",
						groupName, groupInfo.DeviceGroup, targetAddr)
				}

				// Add usage context
				if strings.Contains(line, "destination") {
					destParts := strings.Split(line, "destination")
					if len(destParts) > 1 && strings.Contains(destParts[1], groupName) {
						context += " (in destination)"
					}
				} else if strings.Contains(line, "source") {
					sourceParts := strings.Split(line, "source")
					if len(sourceParts) > 1 && strings.Contains(sourceParts[1], groupName) {
						context += " (in source)"
					}
				}

				p.Results[targetAddr].IndirectRuleContexts[ruleName] = context
			}
		}
	}
}

// findNestedAddressGroupsMemory finds address groups that contain other address groups (in-memory version)
func (p *PANLogProcessor) findNestedAddressGroupsMemory(allLines []string, addresses []string) {
	targetAddresses := make(map[string]bool)
	for _, addr := range addresses {
		targetAddresses[addr] = true
	}

	allAddressGroups := make(map[string]models.GroupMembers)

	totalLines := len(allLines)
	progressInterval := 300000 // Less frequent progress for better performance
	lastProgress := 0

	// Collect ALL address groups and their members from memory
	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			p.printf("    Mapping line %s/%s (%.0f%%)\n",
				utils.FormatNumber(lineNum), utils.FormatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Fast pre-filter for address-group lines
		if !strings.Contains(line, "address-group") {
			continue
		}

		// Check for shared address groups
		if matches := p.Patterns.AddressGroupShared.FindStringSubmatch(line); matches != nil {
			groupName, definition := matches[1], matches[2]
			members := utils.ParseGroupMembers(definition)
			groupInfo := models.AddressGroup{
				Name:       groupName,
				Context:    "shared",
				Definition: definition,
			}
			allAddressGroups[groupName] = models.GroupMembers{
				Info:    groupInfo,
				Members: members,
			}
			continue
		}

		// Check for device group address groups
		if matches := p.Patterns.AddressGroupDevice.FindStringSubmatch(line); matches != nil {
			deviceGroup, groupName, definition := matches[1], matches[2], matches[3]
			members := utils.ParseGroupMembers(definition)
			groupInfo := models.AddressGroup{
				Name:        groupName,
				Context:     "device-group",
				DeviceGroup: deviceGroup,
				Definition:  definition,
			}
			allAddressGroups[groupName] = models.GroupMembers{
				Info:    groupInfo,
				Members: members,
			}
		}
	}

	// Second pass: find nested relationships
	for _, gm := range allAddressGroups {
		// Check if this group contains other groups that contain our target addresses
		relevantForAddresses := make(map[string]bool)

		for _, member := range gm.Members {
			// Check if member is another address group that contains our targets
			if nestedGm, exists := allAddressGroups[member]; exists {
				for _, targetAddr := range addresses {
					for _, nestedMember := range nestedGm.Members {
						if nestedMember == targetAddr {
							relevantForAddresses[targetAddr] = true
						}
					}
				}
			}

			// Also check if member is directly one of our target addresses
			if targetAddresses[member] {
				relevantForAddresses[member] = true
			}
		}

		// Add this group to results for relevant addresses if not already present
		for targetAddr := range relevantForAddresses {
			// Check if already exists
			found := false
			for _, existing := range p.Results[targetAddr].AddressGroups {
				if existing.Name == gm.Info.Name && existing.Context == gm.Info.Context {
					if gm.Info.Context == "device-group" && existing.DeviceGroup == gm.Info.DeviceGroup {
						found = true
						break
					} else if gm.Info.Context == "shared" {
						found = true
						break
					}
				}
			}
			if !found {
				p.Results[targetAddr].AddressGroups = append(p.Results[targetAddr].AddressGroups, gm.Info)
			}
		}
	}
}
