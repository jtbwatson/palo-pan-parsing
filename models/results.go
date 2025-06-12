package models

import (
	"sort"
	"time"
)

type AnalysisResult struct {
	TargetAddress     string                    `json:"target_address" yaml:"target_address"`
	ConfigFile        string                    `json:"config_file" yaml:"config_file"`
	AnalysisTimestamp time.Time                 `json:"analysis_timestamp" yaml:"analysis_timestamp"`
	ProcessingTime    time.Duration             `json:"processing_time" yaml:"processing_time"`
	TotalReferences   int                       `json:"total_references" yaml:"total_references"`
	
	AddressObjects       []AddressObject           `json:"address_objects" yaml:"address_objects"`
	DirectSecurityRules  []SecurityRule            `json:"direct_security_rules,omitempty" yaml:"direct_security_rules,omitempty"`
	IndirectSecurityRules []SecurityRule           `json:"indirect_security_rules,omitempty" yaml:"indirect_security_rules,omitempty"`
	DirectNATRules       []NATRule                 `json:"direct_nat_rules,omitempty" yaml:"direct_nat_rules,omitempty"`
	IndirectNATRules     []NATRule                 `json:"indirect_nat_rules,omitempty" yaml:"indirect_nat_rules,omitempty"`
	AddressGroups        []AddressGroup            `json:"address_groups" yaml:"address_groups"`
	
	DirectReferences  []AddressReference        `json:"direct_references" yaml:"direct_references"`
	IndirectReferences []GroupReference         `json:"indirect_references" yaml:"indirect_references"`
	GroupMemberships  []GroupMembership         `json:"group_memberships" yaml:"group_memberships"`
	
	RedundantAddresses []RedundantAddressPair   `json:"redundant_addresses,omitempty" yaml:"redundant_addresses,omitempty"`
	CleanupCommands   []string                  `json:"cleanup_commands,omitempty" yaml:"cleanup_commands,omitempty"`
	GroupCommands     []string                  `json:"group_commands,omitempty" yaml:"group_commands,omitempty"`
	
	Statistics        AnalysisStatistics        `json:"statistics" yaml:"statistics"`
	DeviceGroups      []string                  `json:"device_groups" yaml:"device_groups"`
	Scopes            []string                  `json:"scopes" yaml:"scopes"`
}

type AnalysisStatistics struct {
	AddressObjects     int `json:"address_objects" yaml:"address_objects"`
	SecurityRules      int `json:"security_rules" yaml:"security_rules"`
	NATRules          int `json:"nat_rules" yaml:"nat_rules"`
	AddressGroups     int `json:"address_groups" yaml:"address_groups"`
	DirectReferences  int `json:"direct_references" yaml:"direct_references"`
	IndirectReferences int `json:"indirect_references" yaml:"indirect_references"`
	RedundantAddresses int `json:"redundant_addresses" yaml:"redundant_addresses"`
	DeviceGroups      int `json:"device_groups" yaml:"device_groups"`
}

type MultiAddressResult struct {
	Addresses         []string                        `json:"addresses" yaml:"addresses"`
	ConfigFile        string                          `json:"config_file" yaml:"config_file"`
	AnalysisTimestamp time.Time                       `json:"analysis_timestamp" yaml:"analysis_timestamp"`
	ProcessingTime    time.Duration                   `json:"processing_time" yaml:"processing_time"`
	Results           map[string]*AnalysisResult      `json:"results" yaml:"results"`
	CombinedStats     AnalysisStatistics              `json:"combined_statistics" yaml:"combined_statistics"`
	CrossReferences   []CrossAddressReference         `json:"cross_references,omitempty" yaml:"cross_references,omitempty"`
}

type CrossAddressReference struct {
	AddressA    string `json:"address_a" yaml:"address_a"`
	AddressB    string `json:"address_b" yaml:"address_b"`
	SharedRule  string `json:"shared_rule" yaml:"shared_rule"`
	RuleType    string `json:"rule_type" yaml:"rule_type"`
	DeviceGroup string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
}

type CleanupAnalysis struct {
	TargetAddress      string                  `json:"target_address" yaml:"target_address"`
	RedundantAddresses []RedundantAddressPair  `json:"redundant_addresses" yaml:"redundant_addresses"`
	ImpactAnalysis     CleanupImpact           `json:"impact_analysis" yaml:"impact_analysis"`
	Commands           CleanupCommands         `json:"commands" yaml:"commands"`
	Warnings           []string                `json:"warnings" yaml:"warnings"`
}

type CleanupImpact struct {
	AffectedRules      int      `json:"affected_rules" yaml:"affected_rules"`
	AffectedGroups     int      `json:"affected_groups" yaml:"affected_groups"`
	AffectedDeviceGroups int    `json:"affected_device_groups" yaml:"affected_device_groups"`
	ScopeChanges       int      `json:"scope_changes" yaml:"scope_changes"`
	DeviceGroups       []string `json:"device_groups" yaml:"device_groups"`
}

type CleanupCommands struct {
	RuleUpdates    []string `json:"rule_updates" yaml:"rule_updates"`
	GroupUpdates   []string `json:"group_updates" yaml:"group_updates"`
	ObjectCreation []string `json:"object_creation" yaml:"object_creation"`
	ObjectDeletion []string `json:"object_deletion" yaml:"object_deletion"`
}

type GroupCommandAnalysis struct {
	TargetAddress    string            `json:"target_address" yaml:"target_address"`
	DiscoveredGroups []AddressGroup    `json:"discovered_groups" yaml:"discovered_groups"`
	ScopeAnalysis    ScopeOptimization `json:"scope_analysis" yaml:"scope_analysis"`
	Commands         GroupCommands     `json:"commands" yaml:"commands"`
}

type ScopeOptimization struct {
	RecommendedScope string   `json:"recommended_scope" yaml:"recommended_scope"`
	Reasoning        string   `json:"reasoning" yaml:"reasoning"`
	AffectedGroups   []string `json:"affected_groups" yaml:"affected_groups"`
	DeviceGroups     []string `json:"device_groups" yaml:"device_groups"`
}

type GroupCommands struct {
	ObjectCreation []string `json:"object_creation" yaml:"object_creation"`
	GroupUpdates   []string `json:"group_updates" yaml:"group_updates"`
}

func NewAnalysisResult(targetAddress, configFile string) *AnalysisResult {
	return &AnalysisResult{
		TargetAddress:        targetAddress,
		ConfigFile:           configFile,
		AnalysisTimestamp:    time.Now(),
		AddressObjects:       make([]AddressObject, 0),
		DirectSecurityRules:  make([]SecurityRule, 0),
		IndirectSecurityRules: make([]SecurityRule, 0),
		DirectNATRules:       make([]NATRule, 0),
		IndirectNATRules:     make([]NATRule, 0),
		AddressGroups:        make([]AddressGroup, 0),
		DirectReferences:     make([]AddressReference, 0),
		IndirectReferences:   make([]GroupReference, 0),
		GroupMemberships:     make([]GroupMembership, 0),
		RedundantAddresses:   make([]RedundantAddressPair, 0),
		CleanupCommands:      make([]string, 0),
		GroupCommands:        make([]string, 0),
		DeviceGroups:         make([]string, 0),
		Scopes:               make([]string, 0),
	}
}

func (r *AnalysisResult) AddDeviceGroup(deviceGroup string) {
	for _, dg := range r.DeviceGroups {
		if dg == deviceGroup {
			return
		}
	}
	r.DeviceGroups = append(r.DeviceGroups, deviceGroup)
	sort.Strings(r.DeviceGroups)
}

func (r *AnalysisResult) AddScope(scope string) {
	for _, s := range r.Scopes {
		if s == scope {
			return
		}
	}
	r.Scopes = append(r.Scopes, scope)
	sort.Strings(r.Scopes)
}

func (r *AnalysisResult) CalculateStatistics() {
	r.Statistics = AnalysisStatistics{
		AddressObjects:     len(r.AddressObjects),
		SecurityRules:      len(r.DirectSecurityRules) + len(r.IndirectSecurityRules),
		NATRules:          len(r.DirectNATRules) + len(r.IndirectNATRules),
		AddressGroups:     len(r.AddressGroups),
		DirectReferences:  len(r.DirectReferences),
		IndirectReferences: len(r.IndirectReferences),
		RedundantAddresses: len(r.RedundantAddresses),
		DeviceGroups:      len(r.DeviceGroups),
	}
	
	r.TotalReferences = r.Statistics.DirectReferences + r.Statistics.IndirectReferences
}

func (r *AnalysisResult) SortResults() {
	sort.Slice(r.AddressObjects, func(i, j int) bool {
		return r.AddressObjects[i].Name < r.AddressObjects[j].Name
	})
	
	sort.Slice(r.DirectSecurityRules, func(i, j int) bool {
		return r.DirectSecurityRules[i].Name < r.DirectSecurityRules[j].Name
	})
	
	sort.Slice(r.IndirectSecurityRules, func(i, j int) bool {
		return r.IndirectSecurityRules[i].Name < r.IndirectSecurityRules[j].Name
	})
	
	sort.Slice(r.DirectNATRules, func(i, j int) bool {
		return r.DirectNATRules[i].Name < r.DirectNATRules[j].Name
	})
	
	sort.Slice(r.IndirectNATRules, func(i, j int) bool {
		return r.IndirectNATRules[i].Name < r.IndirectNATRules[j].Name
	})
	
	sort.Slice(r.AddressGroups, func(i, j int) bool {
		return r.AddressGroups[i].Name < r.AddressGroups[j].Name
	})
	
	sort.Slice(r.DirectReferences, func(i, j int) bool {
		if r.DirectReferences[i].SourceType == r.DirectReferences[j].SourceType {
			return r.DirectReferences[i].SourceName < r.DirectReferences[j].SourceName
		}
		return r.DirectReferences[i].SourceType < r.DirectReferences[j].SourceType
	})
	
	sort.Slice(r.IndirectReferences, func(i, j int) bool {
		if r.IndirectReferences[i].SourceType == r.IndirectReferences[j].SourceType {
			return r.IndirectReferences[i].SourceName < r.IndirectReferences[j].SourceName
		}
		return r.IndirectReferences[i].SourceType < r.IndirectReferences[j].SourceType
	})
}