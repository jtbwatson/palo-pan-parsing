package models

import "regexp"

// Patterns holds all compiled regex patterns for parsing
type Patterns struct {
	SecurityRuleQuoted    *regexp.Regexp
	SecurityRuleUnquoted  *regexp.Regexp
	SecurityRulesQuoted   *regexp.Regexp
	SecurityRulesUnquoted *regexp.Regexp
	DeviceGroup           *regexp.Regexp
	AddressGroupShared    *regexp.Regexp
	AddressGroupDevice    *regexp.Regexp
	NatRule               *regexp.Regexp
	ServiceGroup          *regexp.Regexp
	IPNetmask             *regexp.Regexp
	AddressByIP           *regexp.Regexp
}

// AddressGroup represents an address group
type AddressGroup struct {
	Name        string `json:"name"`
	Context     string `json:"context"`
	DeviceGroup string `json:"device_group,omitempty"`
	Definition  string `json:"definition"`
}

// RedundantAddress represents a redundant address object
type RedundantAddress struct {
	Name        string `json:"name"`
	IPNetmask   string `json:"ip-netmask"`
	DeviceGroup string `json:"device_group"`
}

// AddressResult holds all analysis results for a single address
type AddressResult struct {
	MatchingLines        []string           `json:"matching_lines"`
	DeviceGroups         map[string]bool    `json:"device_groups"`
	DirectRules          map[string]string  `json:"direct_rules"`
	DirectRuleContexts   map[string]string  `json:"direct_rule_contexts"`
	IndirectRules        map[string]string  `json:"indirect_rules"`
	IndirectRuleContexts map[string]string  `json:"indirect_rule_contexts"`
	AddressGroups        []AddressGroup     `json:"address_groups"`
	NATRules             map[string]bool    `json:"nat_rules"`
	ServiceGroups        map[string]bool    `json:"service_groups"`
	IPNetmask            string             `json:"ip_netmask"`
	RedundantAddresses   []RedundantAddress `json:"redundant_addresses"`
}


// FormattedResults represents the formatted output structure
type FormattedResults struct {
	DeviceGroups          []string           `json:"device_groups"`
	DirectSecurityRules   []string           `json:"direct_security_rules"`
	IndirectSecurityRules []string           `json:"indirect_security_rules"`
	AddressGroups         []AddressGroup     `json:"address_groups"`
	NATRules              []string           `json:"nat_rules"`
	ServiceGroups         []string           `json:"service_groups"`
	RedundantAddresses    []RedundantAddress `json:"redundant_addresses"`
}

// IPAddress represents an IP address with associated line
type IPAddress struct {
	Name string
	Line string
}

// GroupInfo holds group information with associated address
type GroupInfo struct {
	Group   AddressGroup
	Address string
}

// GroupPattern holds compiled pattern with group info
type GroupPattern struct {
	Pattern *regexp.Regexp
	Info    GroupInfo
}

// ReferencedGroup represents a group reference
type ReferencedGroup struct {
	Name string
	Info GroupInfo
}

// GroupMembers holds address group with its members
type GroupMembers struct {
	Info    AddressGroup
	Members []string
}

// RuleContext holds rule name with context information
type RuleContext struct {
	Name    string
	Context string
}

// Config represents configuration from JSON files
type Config struct {
	LogFile     string   `json:"log_file"`
	AddressName []string `json:"address_name"`
}