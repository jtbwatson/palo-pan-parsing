package models

import (
	"regexp"
	"strings"
)

type SecurityRule struct {
	Name         string   `json:"name" yaml:"name"`
	From         []string `json:"from" yaml:"from"`
	To           []string `json:"to" yaml:"to"`
	Source       []string `json:"source" yaml:"source"`
	Destination  []string `json:"destination" yaml:"destination"`
	Application  []string `json:"application" yaml:"application"`
	Service      []string `json:"service" yaml:"service"`
	Action       string   `json:"action" yaml:"action"`
	DeviceGroup  string   `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	Scope        string   `json:"scope" yaml:"scope"`
	Description  string   `json:"description,omitempty" yaml:"description,omitempty"`
	LineNumber   int      `json:"line_number" yaml:"line_number"`
}

type NATRule struct {
	Name                string   `json:"name" yaml:"name"`
	SourceZones         []string `json:"source_zones" yaml:"source_zones"`
	DestinationZone     string   `json:"destination_zone" yaml:"destination_zone"`
	OriginalSource      []string `json:"original_source" yaml:"original_source"`
	OriginalDestination []string `json:"original_destination" yaml:"original_destination"`
	TranslatedSource    []string `json:"translated_source" yaml:"translated_source"`
	TranslatedDestination []string `json:"translated_destination" yaml:"translated_destination"`
	Service             string   `json:"service" yaml:"service"`
	DeviceGroup         string   `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	Scope               string   `json:"scope" yaml:"scope"`
	Description         string   `json:"description,omitempty" yaml:"description,omitempty"`
	LineNumber          int      `json:"line_number" yaml:"line_number"`
}

type RuleReference struct {
	RuleName     string `json:"rule_name" yaml:"rule_name"`
	RuleType     string `json:"rule_type" yaml:"rule_type"`
	AddressName  string `json:"address_name" yaml:"address_name"`
	Context      string `json:"context" yaml:"context"`
	DeviceGroup  string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	LineNumber   int    `json:"line_number" yaml:"line_number"`
}

var (
	securityRulePattern = regexp.MustCompile(`<entry name="([^"]+)">.*?</entry>`)
	natRulePattern      = regexp.MustCompile(`<nat>.*?<rules>.*?<entry name="([^"]+)">.*?</entry>.*?</rules>.*?</nat>`)
	sourcePattern       = regexp.MustCompile(`<source>\s*<member>([^<]+)</member>\s*</source>`)
	destinationPattern  = regexp.MustCompile(`<destination>\s*<member>([^<]+)</member>\s*</destination>`)
	addressListPattern  = regexp.MustCompile(`<member>([^<]+)</member>`)
)

func (r *SecurityRule) ContainsAddress(addressName string) bool {
	return containsInSlice(r.Source, addressName) || 
		   containsInSlice(r.Destination, addressName)
}

func (r *SecurityRule) GetAddressContext(addressName string) []string {
	var contexts []string
	
	if containsInSlice(r.Source, addressName) {
		contexts = append(contexts, "source")
	}
	
	if containsInSlice(r.Destination, addressName) {
		contexts = append(contexts, "destination")
	}
	
	return contexts
}

func (r *SecurityRule) ReplaceAddress(oldAddress, newAddress string) bool {
	replaced := false
	
	r.Source = replaceInSlice(r.Source, oldAddress, newAddress)
	if len(r.Source) > 0 {
		replaced = true
	}
	
	r.Destination = replaceInSlice(r.Destination, oldAddress, newAddress)
	if len(r.Destination) > 0 {
		replaced = true
	}
	
	return replaced
}

func (r *NATRule) ContainsAddress(addressName string) bool {
	return containsInSlice(r.OriginalSource, addressName) ||
		   containsInSlice(r.OriginalDestination, addressName) ||
		   containsInSlice(r.TranslatedSource, addressName) ||
		   containsInSlice(r.TranslatedDestination, addressName)
}

func (r *NATRule) GetAddressContext(addressName string) []string {
	var contexts []string
	
	if containsInSlice(r.OriginalSource, addressName) {
		contexts = append(contexts, "original-source")
	}
	
	if containsInSlice(r.OriginalDestination, addressName) {
		contexts = append(contexts, "original-destination")
	}
	
	if containsInSlice(r.TranslatedSource, addressName) {
		contexts = append(contexts, "translated-source")
	}
	
	if containsInSlice(r.TranslatedDestination, addressName) {
		contexts = append(contexts, "translated-destination")
	}
	
	return contexts
}

func (r *NATRule) ReplaceAddress(oldAddress, newAddress string) bool {
	replaced := false
	
	r.OriginalSource = replaceInSlice(r.OriginalSource, oldAddress, newAddress)
	if len(r.OriginalSource) > 0 {
		replaced = true
	}
	
	r.OriginalDestination = replaceInSlice(r.OriginalDestination, oldAddress, newAddress)
	if len(r.OriginalDestination) > 0 {
		replaced = true
	}
	
	r.TranslatedSource = replaceInSlice(r.TranslatedSource, oldAddress, newAddress)
	if len(r.TranslatedSource) > 0 {
		replaced = true
	}
	
	r.TranslatedDestination = replaceInSlice(r.TranslatedDestination, oldAddress, newAddress)
	if len(r.TranslatedDestination) > 0 {
		replaced = true
	}
	
	return replaced
}

func containsInSlice(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func replaceInSlice(slice []string, oldItem, newItem string) []string {
	for i, s := range slice {
		if s == oldItem {
			slice[i] = newItem
		}
	}
	return slice
}

func ExtractAddressesFromRule(ruleContent string) []string {
	var addresses []string
	
	matches := addressListPattern.FindAllStringSubmatch(ruleContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			address := strings.TrimSpace(match[1])
			if address != "" && address != "any" {
				addresses = append(addresses, address)
			}
		}
	}
	
	return addresses
}

func GetRulePatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"security_rule": securityRulePattern,
		"nat_rule":      natRulePattern,
		"source":        sourcePattern,
		"destination":   destinationPattern,
		"address_list":  addressListPattern,
	}
}