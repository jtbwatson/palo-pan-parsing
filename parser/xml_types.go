package parser

import (
	"strings"

	"palo-pan-parsing/models"
)

type XMLElementConverter struct {
	patterns *models.XMLPatterns
}

func NewXMLElementConverter() *XMLElementConverter {
	return &XMLElementConverter{
		patterns: models.NewXMLPatterns(),
	}
}

func (c *XMLElementConverter) ConvertToAddressObject(event XMLEvent) (*models.AddressObject, error) {
	if event.Type != "address" {
		return nil, nil
	}
	
	addr := &models.AddressObject{
		Name:        event.Name,
		Scope:       event.Scope,
		DeviceGroup: event.DeviceGroup,
	}
	
	if ipNetmask, exists := event.Attributes["ip_netmask"]; exists {
		addr.IPNetmask = ipNetmask
	}
	
	if ipRange, exists := event.Attributes["ip_range"]; exists {
		addr.IPRange = ipRange
	}
	
	if fqdn, exists := event.Attributes["fqdn"]; exists {
		addr.FQDN = fqdn
	}
	
	if description := c.extractDescription(event.Content); description != "" {
		addr.Description = description
	}
	
	return addr, nil
}

func (c *XMLElementConverter) ConvertToAddressGroup(event XMLEvent) (*models.AddressGroup, error) {
	if event.Type != "address_group" {
		return nil, nil
	}
	
	group := &models.AddressGroup{
		Name:        event.Name,
		Scope:       event.Scope,
		DeviceGroup: event.DeviceGroup,
	}
	
	if members, exists := event.Attributes["members"]; exists {
		group.Members = strings.Split(members, ",")
		for i := range group.Members {
			group.Members[i] = strings.TrimSpace(group.Members[i])
		}
	}
	
	if staticMembers := c.extractStaticMembers(event.Content); len(staticMembers) > 0 {
		group.StaticMembers = staticMembers
	}
	
	if dynamicFilter := c.extractDynamicFilter(event.Content); dynamicFilter != "" {
		group.DynamicFilter = dynamicFilter
	}
	
	if description := c.extractDescription(event.Content); description != "" {
		group.Description = description
	}
	
	return group, nil
}

func (c *XMLElementConverter) ConvertToSecurityRule(event XMLEvent) (*models.SecurityRule, error) {
	if event.Type != "security_rule" {
		return nil, nil
	}
	
	rule := &models.SecurityRule{
		Name:        event.Name,
		Scope:       event.Scope,
		DeviceGroup: event.DeviceGroup,
		LineNumber:  event.LineNumber,
	}
	
	rule.From = c.extractZones(event.Content, "from")
	rule.To = c.extractZones(event.Content, "to")
	rule.Source = c.extractAddresses(event.Content, "source")
	rule.Destination = c.extractAddresses(event.Content, "destination")
	rule.Application = c.extractApplications(event.Content)
	rule.Service = c.extractServices(event.Content)
	rule.Action = c.extractAction(event.Content)
	
	if description := c.extractDescription(event.Content); description != "" {
		rule.Description = description
	}
	
	return rule, nil
}

func (c *XMLElementConverter) ConvertToNATRule(event XMLEvent) (*models.NATRule, error) {
	if event.Type != "nat_rule" {
		return nil, nil
	}
	
	rule := &models.NATRule{
		Name:        event.Name,
		Scope:       event.Scope,
		DeviceGroup: event.DeviceGroup,
		LineNumber:  event.LineNumber,
	}
	
	rule.SourceZones = c.extractZones(event.Content, "from")
	rule.DestinationZone = c.extractSingleZone(event.Content, "to")
	rule.OriginalSource = c.extractAddresses(event.Content, "source")
	rule.OriginalDestination = c.extractAddresses(event.Content, "destination")
	rule.TranslatedSource = c.extractTranslatedAddresses(event.Content, "source-translation")
	rule.TranslatedDestination = c.extractTranslatedAddresses(event.Content, "destination-translation")
	rule.Service = c.extractSingleService(event.Content)
	
	if description := c.extractDescription(event.Content); description != "" {
		rule.Description = description
	}
	
	return rule, nil
}

func (c *XMLElementConverter) extractDescription(content string) string {
	descStart := strings.Index(content, "<description>")
	descEnd := strings.Index(content, "</description>")
	
	if descStart != -1 && descEnd != -1 && descEnd > descStart {
		return content[descStart+13 : descEnd]
	}
	return ""
}

func (c *XMLElementConverter) extractStaticMembers(content string) []string {
	var members []string
	
	if strings.Contains(content, "<static>") {
		if matches := c.patterns.Member.FindAllStringSubmatch(content, -1); len(matches) > 0 {
			for _, match := range matches {
				if len(match) > 1 {
					members = append(members, match[1])
				}
			}
		}
	}
	
	return members
}

func (c *XMLElementConverter) extractDynamicFilter(content string) string {
	if strings.Contains(content, "<dynamic>") {
		filterStart := strings.Index(content, "<filter>")
		filterEnd := strings.Index(content, "</filter>")
		if filterStart != -1 && filterEnd != -1 && filterEnd > filterStart {
			return content[filterStart+8 : filterEnd]
		}
	}
	return ""
}

func (c *XMLElementConverter) extractZones(content, sectionName string) []string {
	sectionStart := strings.Index(content, "<"+sectionName+">")
	sectionEnd := strings.Index(content, "</"+sectionName+">")
	
	if sectionStart == -1 || sectionEnd == -1 || sectionEnd <= sectionStart {
		return nil
	}
	
	sectionContent := content[sectionStart:sectionEnd]
	
	var zones []string
	if matches := c.patterns.Member.FindAllStringSubmatch(sectionContent, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				zones = append(zones, match[1])
			}
		}
	}
	
	return zones
}

func (c *XMLElementConverter) extractAddresses(content, sectionName string) []string {
	return c.extractZones(content, sectionName)
}

func (c *XMLElementConverter) extractApplications(content string) []string {
	return c.extractZones(content, "application")
}

func (c *XMLElementConverter) extractServices(content string) []string {
	return c.extractZones(content, "service")
}

func (c *XMLElementConverter) extractAction(content string) string {
	actionStart := strings.Index(content, "<action>")
	actionEnd := strings.Index(content, "</action>")
	
	if actionStart != -1 && actionEnd != -1 && actionEnd > actionStart {
		return content[actionStart+8 : actionEnd]
	}
	
	return "allow"
}

func (c *XMLElementConverter) extractSingleZone(content, sectionName string) string {
	zones := c.extractZones(content, sectionName)
	if len(zones) > 0 {
		return zones[0]
	}
	return ""
}

func (c *XMLElementConverter) extractTranslatedAddresses(content, sectionName string) []string {
	return c.extractZones(content, sectionName)
}

func (c *XMLElementConverter) extractSingleService(content string) string {
	services := c.extractServices(content)
	if len(services) > 0 {
		return services[0]
	}
	return ""
}

type ElementFilter struct {
	TargetAddresses []string
	includedTypes   map[string]bool
}

func NewElementFilter(targetAddresses []string) *ElementFilter {
	return &ElementFilter{
		TargetAddresses: targetAddresses,
		includedTypes: map[string]bool{
			"address":       true,
			"address_group": true,
			"security_rule": true,
			"nat_rule":      true,
		},
	}
}

func (f *ElementFilter) ShouldProcess(event XMLEvent) bool {
	if !f.includedTypes[event.Type] {
		return false
	}
	
	if len(f.TargetAddresses) == 0 {
		return true
	}
	
	// Always process ALL address objects for redundancy analysis
	// Always process address groups, security rules, and NAT rules
	// The analyzer will determine which ones are relevant
	if event.Type == "address" || event.Type == "address_group" || event.Type == "security_rule" || event.Type == "nat_rule" {
		return true
	}
	
	return true
}

func (f *ElementFilter) containsTargetAddress(addressName string) bool {
	for _, target := range f.TargetAddresses {
		if addressName == target {
			return true
		}
	}
	return false
}

func (f *ElementFilter) contentContainsTargetAddress(content string) bool {
	for _, target := range f.TargetAddresses {
		if strings.Contains(content, target) {
			return true
		}
	}
	return false
}

func (f *ElementFilter) SetIncludedTypes(types []string) {
	f.includedTypes = make(map[string]bool)
	for _, t := range types {
		f.includedTypes[t] = true
	}
}