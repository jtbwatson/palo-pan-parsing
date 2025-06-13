package utils

import (
	"os"
	"strconv"
	"strings"
	"time"

	"palo-pan-parsing/models"
)

type YAMLWriter struct {
	indent string
}

func NewYAMLWriter() *YAMLWriter {
	return &YAMLWriter{
		indent: "  ",
	}
}

func (w *YAMLWriter) WriteAnalysisResult(result *models.AnalysisResult, outputDir string) error {
	if err := EnsureDirectory(outputDir); err != nil {
		return err
	}
	
	filename := w.generateResultFilename(result.TargetAddress, outputDir)
	content := w.formatAnalysisResult(result)
	
	return w.writeToFile(filename, content)
}

func (w *YAMLWriter) formatAnalysisResult(result *models.AnalysisResult) string {
	var sb strings.Builder
	
	sb.WriteString("# PAN Configuration Analysis Results\n")
	sb.WriteString("# Generated: " + result.AnalysisTimestamp.Format(time.RFC3339) + "\n\n")
	
	sb.WriteString("analysis_info:\n")
	sb.WriteString(w.indent + "target_address: " + result.TargetAddress + "\n")
	sb.WriteString(w.indent + "config_file: " + result.ConfigFile + "\n")
	sb.WriteString(w.indent + "analysis_timestamp: " + result.AnalysisTimestamp.Format(time.RFC3339) + "\n")
	sb.WriteString(w.indent + "processing_time: " + FormatDuration(result.ProcessingTime) + "\n")
	sb.WriteString(w.indent + "total_references: " + strconv.Itoa(result.TotalReferences) + "\n\n")
	
	w.writeStatistics(&sb, result.Statistics)
	
	if len(result.AddressObjects) > 0 {
		w.writeAddressObjects(&sb, result.AddressObjects)
	}
	
	if len(result.DirectReferences) > 0 {
		w.writeDirectReferences(&sb, result.DirectReferences)
	}
	
	if len(result.IndirectReferences) > 0 {
		w.writeIndirectReferences(&sb, result.IndirectReferences)
	}
	
	if len(result.AddressGroups) > 0 {
		w.writeAddressGroups(&sb, result.AddressGroups)
	}
	
	if len(result.GroupMemberships) > 0 {
		w.writeGroupMemberships(&sb, result.GroupMemberships)
	}
	
	if len(result.DirectSecurityRules) > 0 {
		w.writeDirectSecurityRules(&sb, result.DirectSecurityRules)
	}
	
	if len(result.IndirectSecurityRules) > 0 {
		w.writeIndirectSecurityRules(&sb, result.IndirectSecurityRules)
	}
	
	if len(result.RedundantAddresses) > 0 {
		w.writeRedundantAddresses(&sb, result.RedundantAddresses)
	}
	
	if len(result.DeviceGroups) > 0 {
		w.writeDeviceGroups(&sb, result.DeviceGroups)
	}
	
	if len(result.Scopes) > 0 {
		w.writeScopes(&sb, result.Scopes)
	}
	
	return sb.String()
}

func (w *YAMLWriter) writeStatistics(sb *strings.Builder, stats models.AnalysisStatistics) {
	sb.WriteString("statistics:\n")
	sb.WriteString(w.indent + "address_objects: " + strconv.Itoa(stats.AddressObjects) + "\n")
	sb.WriteString(w.indent + "security_rules: " + strconv.Itoa(stats.SecurityRules) + "\n")
	sb.WriteString(w.indent + "nat_rules: " + strconv.Itoa(stats.NATRules) + "\n")
	sb.WriteString(w.indent + "address_groups: " + strconv.Itoa(stats.AddressGroups) + "\n")
	sb.WriteString(w.indent + "direct_references: " + strconv.Itoa(stats.DirectReferences) + "\n")
	sb.WriteString(w.indent + "indirect_references: " + strconv.Itoa(stats.IndirectReferences) + "\n")
	sb.WriteString(w.indent + "redundant_addresses: " + strconv.Itoa(stats.RedundantAddresses) + "\n")
	sb.WriteString(w.indent + "device_groups: " + strconv.Itoa(stats.DeviceGroups) + "\n\n")
}

func (w *YAMLWriter) writeDirectReferences(sb *strings.Builder, refs []models.AddressReference) {
	sb.WriteString("direct_references:\n")
	for _, ref := range refs {
		sb.WriteString(w.indent + "- object_name: " + ref.ObjectName + "\n")
		sb.WriteString(w.indent + "  source_type: " + ref.SourceType + "\n")
		sb.WriteString(w.indent + "  source_name: " + ref.SourceName + "\n")
		sb.WriteString(w.indent + "  context: " + ref.Context + "\n")
		if ref.DeviceGroup != "" {
			sb.WriteString(w.indent + "  device_group: " + ref.DeviceGroup + "\n")
		}
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeIndirectReferences(sb *strings.Builder, refs []models.GroupReference) {
	sb.WriteString("indirect_references:\n")
	for _, ref := range refs {
		sb.WriteString(w.indent + "- group_name: " + ref.GroupName + "\n")
		sb.WriteString(w.indent + "  source_type: " + ref.SourceType + "\n")
		sb.WriteString(w.indent + "  source_name: " + ref.SourceName + "\n")
		sb.WriteString(w.indent + "  context: " + ref.Context + "\n")
		if ref.DeviceGroup != "" {
			sb.WriteString(w.indent + "  device_group: " + ref.DeviceGroup + "\n")
		}
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeDirectSecurityRules(sb *strings.Builder, rules []models.SecurityRule) {
	sb.WriteString("direct_security_rules:\n")
	for _, rule := range rules {
		sb.WriteString(w.indent + rule.Name + ":\n")
		sb.WriteString(w.indent + w.indent + "scope: " + rule.Scope + "\n")
		if rule.DeviceGroup != "" {
			sb.WriteString(w.indent + w.indent + "device_group: " + rule.DeviceGroup + "\n")
		}
		sb.WriteString(w.indent + w.indent + "action: " + rule.Action + "\n")
		
		w.writeNestedStringArray(sb, "from", rule.From)
		w.writeNestedStringArray(sb, "to", rule.To)
		w.writeNestedStringArray(sb, "source", rule.Source)
		w.writeNestedStringArray(sb, "destination", rule.Destination)
		w.writeNestedStringArray(sb, "application", rule.Application)
		w.writeNestedStringArray(sb, "service", rule.Service)
		
		if rule.Description != "" {
			sb.WriteString(w.indent + w.indent + "description: " + rule.Description + "\n")
		}
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeIndirectSecurityRules(sb *strings.Builder, rules []models.SecurityRule) {
	sb.WriteString("indirect_security_rules:\n")
	for _, rule := range rules {
		sb.WriteString(w.indent + rule.Name + ":\n")
		sb.WriteString(w.indent + w.indent + "scope: " + rule.Scope + "\n")
		if rule.DeviceGroup != "" {
			sb.WriteString(w.indent + w.indent + "device_group: " + rule.DeviceGroup + "\n")
		}
		sb.WriteString(w.indent + w.indent + "action: " + rule.Action + "\n")
		
		w.writeNestedStringArray(sb, "from", rule.From)
		w.writeNestedStringArray(sb, "to", rule.To)
		w.writeNestedStringArray(sb, "source", rule.Source)
		w.writeNestedStringArray(sb, "destination", rule.Destination)
		w.writeNestedStringArray(sb, "application", rule.Application)
		w.writeNestedStringArray(sb, "service", rule.Service)
		
		if rule.Description != "" {
			sb.WriteString(w.indent + w.indent + "description: " + rule.Description + "\n")
		}
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeNestedStringArray(sb *strings.Builder, fieldName string, values []string) {
	if len(values) > 0 {
		sb.WriteString(w.indent + w.indent + fieldName + ":\n")
		for _, value := range values {
			sb.WriteString(w.indent + w.indent + "  - " + value + "\n")
		}
	}
}

func (w *YAMLWriter) writeRedundantAddresses(sb *strings.Builder, pairs []models.RedundantAddressPair) {
	sb.WriteString("redundant_addresses:\n")
	for _, pair := range pairs {
		sb.WriteString(w.indent + "- source_address: " + pair.SourceAddress + "\n")
		sb.WriteString(w.indent + "  duplicate_address: " + pair.DuplicateAddress + "\n")
		sb.WriteString(w.indent + "  ip_value: " + pair.IPValue + "\n")
		sb.WriteString(w.indent + "  source_scope: " + pair.SourceScope + "\n")
		sb.WriteString(w.indent + "  duplicate_scope: " + pair.DuplicateScope + "\n")
		w.writeStringArray(sb, "device_groups", pair.DeviceGroups)
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeStringArray(sb *strings.Builder, fieldName string, values []string) {
	if len(values) > 0 {
		sb.WriteString(w.indent + "  " + fieldName + ":\n")
		for _, value := range values {
			sb.WriteString(w.indent + "    - " + value + "\n")
		}
	}
}

// Other required functions (simplified versions)
func (w *YAMLWriter) writeAddressObjects(sb *strings.Builder, addresses []models.AddressObject) {
	sb.WriteString("address_objects:\n")
	for _, addr := range addresses {
		sb.WriteString(w.indent + "- name: " + addr.Name + "\n")
		if addr.IPNetmask != "" {
			sb.WriteString(w.indent + "  ip_netmask: " + addr.IPNetmask + "\n")
		}
		if addr.IPRange != "" {
			sb.WriteString(w.indent + "  ip_range: " + addr.IPRange + "\n")
		}
		if addr.FQDN != "" {
			sb.WriteString(w.indent + "  fqdn: " + addr.FQDN + "\n")
		}
		sb.WriteString(w.indent + "  scope: " + addr.Scope + "\n")
		if addr.DeviceGroup != "" {
			sb.WriteString(w.indent + "  device_group: " + addr.DeviceGroup + "\n")
		}
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeAddressGroups(sb *strings.Builder, groups []models.AddressGroup) {
	sb.WriteString("address_groups:\n")
	for _, group := range groups {
		sb.WriteString(w.indent + "- name: " + group.Name + "\n")
		sb.WriteString(w.indent + "  scope: " + group.Scope + "\n")
		w.writeStringArray(sb, "members", group.Members)
		w.writeStringArray(sb, "static_members", group.StaticMembers)
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeGroupMemberships(sb *strings.Builder, memberships []models.GroupMembership) {
	sb.WriteString("group_memberships:\n")
	for _, membership := range memberships {
		sb.WriteString(w.indent + "- group_name: " + membership.GroupName + "\n")
		sb.WriteString(w.indent + "  member_name: " + membership.MemberName + "\n")
		sb.WriteString(w.indent + "  member_type: " + membership.MemberType + "\n")
		sb.WriteString(w.indent + "  group_scope: " + membership.GroupScope + "\n")
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeDeviceGroups(sb *strings.Builder, groups []string) {
	sb.WriteString("device_groups:\n")
	for _, group := range groups {
		sb.WriteString(w.indent + "- " + group + "\n")
	}
	sb.WriteString("\n")
}

func (w *YAMLWriter) writeScopes(sb *strings.Builder, scopes []string) {
	sb.WriteString("scopes:\n")
	for _, scope := range scopes {
		sb.WriteString(w.indent + "- " + scope + "\n")
	}
	sb.WriteString("\n")
}

// Helper functions
func (w *YAMLWriter) generateResultFilename(targetAddress, outputDir string) string {
	return outputDir + "/" + SanitizeFilename(targetAddress) + "_results.yml"
}

func (w *YAMLWriter) writeToFile(filename, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	_, err = file.WriteString(content)
	return err
}

// WriteGroupCommands writes address group commands in new nested format
func (w *YAMLWriter) WriteGroupCommands(outputFile, originalAddress, newAddressName, ipAddress string, commands []string, addressGroups []models.AddressGroup) error {
	if err := EnsureDirectory("outputs"); err != nil {
		return err
	}
	
	if !strings.HasPrefix(outputFile, "outputs/") {
		outputFile = "outputs/" + outputFile
	}
	
	var sb strings.Builder
	
	sb.WriteString("# PAN Address Group Commands\n")
	sb.WriteString("# Generated: " + time.Now().Format(time.RFC3339) + "\n\n")
	
	sb.WriteString("analysis_info:\n")
	sb.WriteString(w.indent + "original_address: " + originalAddress + "\n")
	sb.WriteString(w.indent + "new_address: " + newAddressName + "\n")
	sb.WriteString(w.indent + "ip_address: " + ipAddress + "\n")
	sb.WriteString(w.indent + "groups_found: " + strconv.Itoa(len(addressGroups)) + "\n")
	sb.WriteString(w.indent + "commands_generated: " + strconv.Itoa(len(commands)) + "\n\n")
	
	w.writeAddressGroups(&sb, addressGroups)
	
	if len(commands) > 0 {
		sb.WriteString("generated_commands:\n")
		for _, cmd := range commands {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	return w.writeToFile(outputFile, sb.String())
}

// WriteCleanupCommands writes cleanup commands in new nested format
func (w *YAMLWriter) WriteCleanupCommands(outputFile string, commands *models.CleanupCommands) error {
	if err := EnsureDirectory("outputs"); err != nil {
		return err
	}
	
	if !strings.HasPrefix(outputFile, "outputs/") {
		outputFile = "outputs/" + outputFile
	}
	
	var sb strings.Builder
	
	sb.WriteString("# PAN Cleanup Commands\n")
	sb.WriteString("# Generated: " + time.Now().Format(time.RFC3339) + "\n\n")
	
	sb.WriteString("cleanup_info:\n")
	sb.WriteString(w.indent + "rule_updates: " + strconv.Itoa(len(commands.RuleUpdates)) + "\n")
	sb.WriteString(w.indent + "group_updates: " + strconv.Itoa(len(commands.GroupUpdates)) + "\n")
	sb.WriteString(w.indent + "object_creation: " + strconv.Itoa(len(commands.ObjectCreation)) + "\n")
	sb.WriteString(w.indent + "object_deletion: " + strconv.Itoa(len(commands.ObjectDeletion)) + "\n\n")
	
	if len(commands.RuleUpdates) > 0 {
		sb.WriteString("rule_updates:\n")
		for _, cmd := range commands.RuleUpdates {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	if len(commands.GroupUpdates) > 0 {
		sb.WriteString("group_updates:\n")
		for _, cmd := range commands.GroupUpdates {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	if len(commands.ObjectCreation) > 0 {
		sb.WriteString("object_creation:\n")
		for _, cmd := range commands.ObjectCreation {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	if len(commands.ObjectDeletion) > 0 {
		sb.WriteString("object_deletion:\n")
		for _, cmd := range commands.ObjectDeletion {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	return w.writeToFile(outputFile, sb.String())
}
// WriteMultiAddressResult writes multiple address analysis results
func (w *YAMLWriter) WriteMultiAddressResult(result *models.MultiAddressResult, outputDir string) error {
	if err := EnsureDirectory(outputDir); err != nil {
		return err
	}
	
	filename := outputDir + "/multiple_addresses_results.yml"
	
	var sb strings.Builder
	
	sb.WriteString("# PAN Multiple Address Analysis Results\n")
	sb.WriteString("# Generated: " + result.AnalysisTimestamp.Format(time.RFC3339) + "\n\n")
	
	sb.WriteString("analysis_info:\n")
	sb.WriteString(w.indent + "addresses: " + strings.Join(result.Addresses, ", ") + "\n")
	sb.WriteString(w.indent + "config_file: " + result.ConfigFile + "\n")
	sb.WriteString(w.indent + "analysis_timestamp: " + result.AnalysisTimestamp.Format(time.RFC3339) + "\n")
	sb.WriteString(w.indent + "processing_time: " + FormatDuration(result.ProcessingTime) + "\n")
	sb.WriteString(w.indent + "addresses_analyzed: " + strconv.Itoa(len(result.Addresses)) + "\n\n")
	
	w.writeMultiAddressStatistics(&sb, result.CombinedStats)
	
	if len(result.Results) > 0 {
		sb.WriteString("individual_results:\n")
		for address, addressResult := range result.Results {
			sb.WriteString(w.indent + address + ":\n")
			sb.WriteString(w.indent + w.indent + "total_references: " + strconv.Itoa(addressResult.TotalReferences) + "\n")
			sb.WriteString(w.indent + w.indent + "direct_references: " + strconv.Itoa(len(addressResult.DirectReferences)) + "\n")
			sb.WriteString(w.indent + w.indent + "indirect_references: " + strconv.Itoa(len(addressResult.IndirectReferences)) + "\n")
			sb.WriteString(w.indent + w.indent + "redundant_addresses: " + strconv.Itoa(len(addressResult.RedundantAddresses)) + "\n")
		}
		sb.WriteString("\n")
	}
	
	if len(result.CrossReferences) > 0 {
		sb.WriteString("cross_references:\n")
		for _, ref := range result.CrossReferences {
			sb.WriteString(w.indent + "- address_a: " + ref.AddressA + "\n")
			sb.WriteString(w.indent + "  address_b: " + ref.AddressB + "\n")
			sb.WriteString(w.indent + "  shared_rule: " + ref.SharedRule + "\n")
			sb.WriteString(w.indent + "  rule_type: " + ref.RuleType + "\n")
			if ref.DeviceGroup != "" {
				sb.WriteString(w.indent + "  device_group: " + ref.DeviceGroup + "\n")
			}
		}
		sb.WriteString("\n")
	}
	
	return w.writeToFile(filename, sb.String())
}

func (w *YAMLWriter) writeMultiAddressStatistics(sb *strings.Builder, stats models.AnalysisStatistics) {
	sb.WriteString("combined_statistics:\n")
	sb.WriteString(w.indent + "address_objects: " + strconv.Itoa(stats.AddressObjects) + "\n")
	sb.WriteString(w.indent + "security_rules: " + strconv.Itoa(stats.SecurityRules) + "\n")
	sb.WriteString(w.indent + "nat_rules: " + strconv.Itoa(stats.NATRules) + "\n")
	sb.WriteString(w.indent + "address_groups: " + strconv.Itoa(stats.AddressGroups) + "\n")
	sb.WriteString(w.indent + "direct_references: " + strconv.Itoa(stats.DirectReferences) + "\n")
	sb.WriteString(w.indent + "indirect_references: " + strconv.Itoa(stats.IndirectReferences) + "\n")
	sb.WriteString(w.indent + "redundant_addresses: " + strconv.Itoa(stats.RedundantAddresses) + "\n")
	sb.WriteString(w.indent + "device_groups: " + strconv.Itoa(stats.DeviceGroups) + "\n\n")
}

// WriteCopyCommands writes address copy commands to YAML file
func (w *YAMLWriter) WriteCopyCommands(
	outputFile string,
	sourceAddr *models.AddressObject,
	newAddr *models.AddressObject,
	createCommands []string,
	updateCommands []string,
	groupMemberships []models.GroupMembership,
	ruleReferences []models.AddressReference,
	summary map[string]int,
) error {
	if err := EnsureDirectory("outputs"); err != nil {
		return err
	}
	
	if !strings.HasPrefix(outputFile, "outputs/") {
		outputFile = "outputs/" + outputFile
	}
	
	var sb strings.Builder
	
	sb.WriteString("# PAN Address Copy Commands\n")
	sb.WriteString("# Generated: " + time.Now().Format(time.RFC3339) + "\n\n")
	
	// Analysis info
	sb.WriteString("copy_info:\n")
	sb.WriteString(w.indent + "source_address: " + sourceAddr.Name + "\n")
	sb.WriteString(w.indent + "source_ip: " + sourceAddr.GetIP() + "\n")
	sb.WriteString(w.indent + "source_scope: " + sourceAddr.Scope + "\n")
	if sourceAddr.DeviceGroup != "" {
		sb.WriteString(w.indent + "source_device_group: " + sourceAddr.DeviceGroup + "\n")
	}
	if sourceAddr.Description != "" {
		sb.WriteString(w.indent + "source_description: \"" + sourceAddr.Description + "\"\n")
	}
	sb.WriteString(w.indent + "new_address: " + newAddr.Name + "\n")
	sb.WriteString(w.indent + "new_ip: " + newAddr.IPNetmask + "\n")
	sb.WriteString(w.indent + "new_scope: " + newAddr.Scope + "\n")
	if newAddr.DeviceGroup != "" {
		sb.WriteString(w.indent + "new_device_group: " + newAddr.DeviceGroup + "\n")
	}
	sb.WriteString("\n")
	
	// Summary
	sb.WriteString("summary:\n")
	if val, exists := summary["groups_to_update"]; exists {
		sb.WriteString(w.indent + "groups_to_update: " + strconv.Itoa(val) + "\n")
	}
	if val, exists := summary["security_rules_to_update"]; exists {
		sb.WriteString(w.indent + "security_rules_to_update: " + strconv.Itoa(val) + "\n")
	}
	if val, exists := summary["nat_rules_to_update"]; exists {
		sb.WriteString(w.indent + "nat_rules_to_update: " + strconv.Itoa(val) + "\n")
	}
	if val, exists := summary["total_commands"]; exists {
		sb.WriteString(w.indent + "total_commands: " + strconv.Itoa(val) + "\n")
	}
	sb.WriteString("\n")
	
	// Commands
	if len(createCommands) > 0 {
		sb.WriteString("step_1_create_objects:\n")
		sb.WriteString(w.indent + "# Create new address object with copied settings\n")
		for _, cmd := range createCommands {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	if len(updateCommands) > 0 {
		sb.WriteString("step_2_update_references:\n")
		sb.WriteString(w.indent + "# Update groups and rules to use new address\n")
		for _, cmd := range updateCommands {
			sb.WriteString(w.indent + "- " + cmd + "\n")
		}
		sb.WriteString("\n")
	}
	
	// Detailed references
	if len(groupMemberships) > 0 {
		sb.WriteString("group_memberships:\n")
		for _, membership := range groupMemberships {
			sb.WriteString(w.indent + "- group_name: " + membership.GroupName + "\n")
			sb.WriteString(w.indent + "  group_scope: " + membership.GroupScope + "\n")
			if membership.DeviceGroup != "" {
				sb.WriteString(w.indent + "  device_group: " + membership.DeviceGroup + "\n")
			}
		}
		sb.WriteString("\n")
	}
	
	if len(ruleReferences) > 0 {
		sb.WriteString("rule_references:\n")
		for _, ref := range ruleReferences {
			sb.WriteString(w.indent + "- rule_name: " + ref.SourceName + "\n")
			sb.WriteString(w.indent + "  rule_type: " + ref.SourceType + "\n")
			sb.WriteString(w.indent + "  context: " + ref.Context + "\n")
			if ref.DeviceGroup != "" {
				sb.WriteString(w.indent + "  device_group: " + ref.DeviceGroup + "\n")
			}
		}
		sb.WriteString("\n")
	}
	
	return w.writeToFile(outputFile, sb.String())
}
