package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ANSI color codes for terminal output
const (
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorYellow    = "\033[33m"
	colorBlue      = "\033[34m"
	colorMagenta   = "\033[35m"
	colorCyan      = "\033[36m"
	colorWhite     = "\033[37m"
)

// Color helper functions
func colorTitle(text string) string     { return colorCyan + colorBold + text + colorReset }
func colorSuccess(text string) string   { return colorGreen + colorBold + text + colorReset }
func colorError(text string) string     { return colorRed + colorBold + text + colorReset }
func colorWarning(text string) string   { return colorYellow + text + colorReset }
func colorInfo(text string) string      { return colorWhite + text + colorReset }
func colorSection(text string) string   { return colorBlue + colorBold + text + colorReset }
func colorHighlight(text string) string { return colorCyan + text + colorReset }
func colorSecondary(text string) string { return colorMagenta + text + colorReset }
func colorDimText(text string) string   { return colorDim + colorWhite + text + colorReset }
func colorListItem(text string) string  { return colorGreen + text + colorReset }

// isWordChar checks if a character is a word character (letter, digit, underscore, hyphen)
func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// Pattern definitions
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

// Compile all regex patterns
func newPatterns() *Patterns {
	return &Patterns{
		SecurityRuleQuoted:    regexp.MustCompile(`security-rule\s+"([^"]+)"`),
		SecurityRuleUnquoted:  regexp.MustCompile(`security-rule\s+(\S+)`),
		SecurityRulesQuoted:   regexp.MustCompile(`security\s+rules\s+"([^"]+)"`),
		SecurityRulesUnquoted: regexp.MustCompile(`security\s+rules\s+(\S+)`),
		DeviceGroup:           regexp.MustCompile(`device-group\s+(\S+)`),
		AddressGroupShared:    regexp.MustCompile(`set\s+shared\s+address-group\s+(\S+)\s+static\s+(.+)`),
		AddressGroupDevice:    regexp.MustCompile(`set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+static\s+(.+)`),
		NatRule:               regexp.MustCompile(`nat-rule\s+(\S+)`),
		ServiceGroup:          regexp.MustCompile(`service-group\s+(\S+)`),
		IPNetmask:             regexp.MustCompile(`set\s+(?:shared|device-group\s+\S+)\s+address\s+(\S+)\s+ip-netmask\s+([\d\.]+/\d+)`),
		AddressByIP:           regexp.MustCompile(`set\s+(?:shared|device-group\s+(\S+))\s+address\s+(\S+)\s+ip-netmask\s+`),
	}
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
	MatchingLines         []string                    `json:"matching_lines"`
	DeviceGroups          map[string]bool             `json:"device_groups"`
	DirectRules           map[string]string           `json:"direct_rules"`
	DirectRuleContexts    map[string]string           `json:"direct_rule_contexts"`
	IndirectRules         map[string]string           `json:"indirect_rules"`
	IndirectRuleContexts  map[string]string           `json:"indirect_rule_contexts"`
	AddressGroups         []AddressGroup              `json:"address_groups"`
	NATRules              map[string]bool             `json:"nat_rules"`
	ServiceGroups         map[string]bool             `json:"service_groups"`
	IPNetmask             string                      `json:"ip_netmask"`
	RedundantAddresses    []RedundantAddress          `json:"redundant_addresses"`
}

// NewAddressResult creates a new initialized AddressResult with pre-allocated capacity
func NewAddressResult() *AddressResult {
	return &AddressResult{
		MatchingLines:         make([]string, 0, 100),        // Pre-allocate for 100 lines
		DeviceGroups:          make(map[string]bool, 10),     // Pre-allocate for 10 device groups
		DirectRules:           make(map[string]string, 50),   // Pre-allocate for 50 rules
		DirectRuleContexts:    make(map[string]string, 50),   // Pre-allocate for 50 contexts
		IndirectRules:         make(map[string]string, 20),   // Pre-allocate for 20 indirect rules
		IndirectRuleContexts:  make(map[string]string, 20),   // Pre-allocate for 20 contexts
		AddressGroups:         make([]AddressGroup, 0, 20),   // Pre-allocate for 20 groups
		NATRules:              make(map[string]bool, 10),     // Pre-allocate for 10 NAT rules
		ServiceGroups:         make(map[string]bool, 10),     // Pre-allocate for 10 service groups
		RedundantAddresses:    make([]RedundantAddress, 0, 5), // Pre-allocate for 5 redundant addresses
	}
}

// PANLogProcessor is the main processor
type PANLogProcessor struct {
	Results  map[string]*AddressResult
	Patterns *Patterns
}

// NewPANLogProcessor creates a new processor instance
func NewPANLogProcessor() *PANLogProcessor {
	return &PANLogProcessor{
		Results:  make(map[string]*AddressResult),
		Patterns: newPatterns(),
	}
}

// ProcessFileSinglePass processes the file once, loading into memory for optimal performance
func (p *PANLogProcessor) ProcessFileSinglePass(filePath string, addresses []string) error {
	addressSet := make(map[string]bool)
	for _, addr := range addresses {
		addressSet[addr] = true
		p.Results[addr] = NewAddressResult()
	}

	ipToAddresses := make(map[string][]IPAddress)

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("error accessing file: %w", err)
	}

	fmt.Printf("  📄 Loading configuration file into memory: %s (%s)\n", 
		colorHighlight(fileInfo.Name()), 
		formatBytes(fileInfo.Size()))

	// Open and read file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	fmt.Println("  🧠 Reading file into memory...")

	// Read all lines into memory
	var allLines []string
	scanner := bufio.NewScanner(file)
	
	// Set a large buffer size for performance with big files
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allLines = append(allLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	totalLines := len(allLines)
	fmt.Printf("  📊 Loaded %s configuration lines into memory\n", 
		colorHighlight(formatNumber(totalLines)))
	fmt.Println("  ⚡ Processing in-memory for maximum performance...")

	// Pre-compile address search patterns for performance
	addressPatterns := make(map[string]*regexp.Regexp)
	for addr := range addressSet {
		// Use word boundaries to avoid partial matches
		addressPatterns[addr] = regexp.MustCompile(`\b` + regexp.QuoteMeta(addr) + `\b`)
	}

	// Process all lines in memory with optimized batch processing
	progressInterval := 250000 // Less frequent progress reporting for better performance
	if totalLines > 5000000 {
		progressInterval = 500000
	}
	lastProgress := 0

	// Use a mutex for thread-safe IP address tracking
	var ipMutex sync.Mutex

	// Process lines in optimized loop
	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			fmt.Printf(colorInfo("    Processing line %s/%s (%.0f%%)\n"), 
				formatNumber(lineNum), formatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Fast early rejection for empty or very short lines
		if len(line) < 10 {
			continue
		}

		// Check for IP netmask definitions first (optimized for common case)
		if strings.Contains(line, "ip-netmask") {
			if matches := p.Patterns.IPNetmask.FindStringSubmatch(line); matches != nil {
				addrName, ipNetmask := matches[1], matches[2]
				if addressSet[addrName] {
					p.Results[addrName].IPNetmask = ipNetmask
				}
				// Track all IP mappings for redundancy detection (thread-safe)
				ipMutex.Lock()
				ipToAddresses[ipNetmask] = append(ipToAddresses[ipNetmask], IPAddress{
					Name: addrName,
					Line: line,
				})
				ipMutex.Unlock()
			}
		}

		// Fast pre-filter: only check detailed patterns if line might contain addresses
		hasAddress := false
		var matchingAddresses []string
		
		// Ultra-optimized address matching - single pass through addresses
		for addr := range addressSet {
			// Fast substring check first
			if idx := strings.Index(line, addr); idx != -1 {
				// Quick boundary check before expensive regex
				lineLen := len(line)
				addrLen := len(addr)
				
				// Check word boundaries manually for common cases
				isWordStart := (idx == 0 || !isWordChar(line[idx-1]))
				isWordEnd := (idx+addrLen >= lineLen || !isWordChar(line[idx+addrLen]))
				
				if isWordStart && isWordEnd {
					if !hasAddress {
						matchingAddresses = make([]string, 0, len(addressSet)) // Pre-allocate capacity
						hasAddress = true
					}
					matchingAddresses = append(matchingAddresses, addr)
				}
			}
		}

		if !hasAddress {
			continue
		}

		// Process line for each matching address
		for _, address := range matchingAddresses {
			p.Results[address].MatchingLines = append(p.Results[address].MatchingLines, line)
			p.extractItemsFromLine(line, address)
		}
	}

	fmt.Println(colorSuccess("  ✅ Initial scan complete"))

	// Process redundant addresses
	fmt.Println(colorInfo("  🔍 Analyzing redundant address objects..."))
	p.findRedundantAddresses(ipToAddresses, addressSet)

	// Find indirect security rules (using in-memory data)
	fmt.Println(colorInfo("  🔗 Discovering indirect security rule relationships..."))
	p.findIndirectRulesMemory(allLines, addresses)

	// Find nested address groups (using in-memory data)
	fmt.Println(colorInfo("  📂 Mapping nested address group hierarchies..."))
	p.findNestedAddressGroupsMemory(allLines, addresses)

	return nil
}

type IPAddress struct {
	Name string
	Line string
}

// extractItemsFromLine extracts all relevant items from a single line
func (p *PANLogProcessor) extractItemsFromLine(line, address string) {
	result := p.Results[address]

	// Cache device group match to avoid multiple regex calls
	var deviceGroupMatch []string
	deviceGroupMatch = p.Patterns.DeviceGroup.FindStringSubmatch(line)
	if deviceGroupMatch != nil {
		result.DeviceGroups[deviceGroupMatch[1]] = true
	}

	// Extract security rules with context (reuse cached device group)
	ruleName, context := p.extractSecurityRule(line, address)
	if ruleName != "" {
		var deviceGroup string
		if deviceGroupMatch != nil {
			deviceGroup = deviceGroupMatch[1]
		} else {
			deviceGroup = "Unknown"
		}
		result.DirectRules[ruleName] = deviceGroup
		result.DirectRuleContexts[ruleName] = context
	}

	// Extract address groups
	if agInfo := p.extractAddressGroup(line); agInfo != nil {
		// Check if this group is already in the list (optimized)
		groupKey := agInfo.Name + "|" + agInfo.Context + "|" + agInfo.DeviceGroup
		found := false
		for _, existing := range result.AddressGroups {
			existingKey := existing.Name + "|" + existing.Context + "|" + existing.DeviceGroup
			if existingKey == groupKey {
				found = true
				break
			}
		}
		if !found {
			result.AddressGroups = append(result.AddressGroups, *agInfo)
		}
	}

	// Extract NAT rules
	if matches := p.Patterns.NatRule.FindStringSubmatch(line); matches != nil {
		result.NATRules[matches[1]] = true
	}

	// Extract service groups
	if matches := p.Patterns.ServiceGroup.FindStringSubmatch(line); matches != nil {
		result.ServiceGroups[matches[1]] = true
	}
}

// extractSecurityRule extracts security rule name and determines context
func (p *PANLogProcessor) extractSecurityRule(line, address string) (string, string) {
	var ruleName string

	// Try different patterns for security rules
	patterns := []*regexp.Regexp{
		p.Patterns.SecurityRuleQuoted,
		p.Patterns.SecurityRuleUnquoted,
		p.Patterns.SecurityRulesQuoted,
		p.Patterns.SecurityRulesUnquoted,
	}

	for _, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(line); matches != nil {
			ruleName = matches[1]
			break
		}
	}

	if ruleName == "" {
		return "", ""
	}

	// Determine context
	context := "references directly"
	if strings.Contains(line, "destination") {
		destParts := strings.Split(line, "destination")
		if len(destParts) > 1 {
			afterDest := destParts[1]
			if sourceParts := strings.Split(afterDest, "source"); len(sourceParts) > 0 {
				if strings.Contains(sourceParts[0], address) {
					context = "contains address in destination"
				}
			}
		}
	} else if strings.Contains(line, "source") {
		sourceParts := strings.Split(line, "source")
		if len(sourceParts) > 1 {
			afterSource := sourceParts[1]
			if destParts := strings.Split(afterSource, "destination"); len(destParts) > 0 {
				if strings.Contains(destParts[0], address) {
					context = "contains address in source"
				}
			}
		}
	} else if strings.Contains(line, "service") {
		serviceParts := strings.Split(line, "service")
		if len(serviceParts) > 1 && strings.Contains(serviceParts[1], address) {
			context = "references address in service field"
		}
	}

	return ruleName, context
}

// extractAddressGroup extracts address group information with context
func (p *PANLogProcessor) extractAddressGroup(line string) *AddressGroup {
	// Check shared address groups
	if matches := p.Patterns.AddressGroupShared.FindStringSubmatch(line); matches != nil {
		return &AddressGroup{
			Name:       matches[1],
			Context:    "shared",
			Definition: matches[2],
		}
	}

	// Check device group address groups
	if matches := p.Patterns.AddressGroupDevice.FindStringSubmatch(line); matches != nil {
		return &AddressGroup{
			Name:        matches[2],
			Context:     "device-group",
			DeviceGroup: matches[1],
			Definition:  matches[3],
		}
	}

	return nil
}

// findRedundantAddresses finds addresses with same IP netmask
func (p *PANLogProcessor) findRedundantAddresses(ipToAddresses map[string][]IPAddress, targetAddresses map[string]bool) {
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
					var redundant []RedundantAddress
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

							redundant = append(redundant, RedundantAddress{
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
	// Collect all address groups from results
	allGroups := make(map[string]GroupInfo)
	for _, addr := range addresses {
		for _, group := range p.Results[addr].AddressGroups {
			allGroups[group.Name] = GroupInfo{
				Group:   group,
				Address: addr,
			}
		}
	}

	if len(allGroups) == 0 {
		return
	}

	// Pre-compile all regex patterns for performance
	groupPatterns := make(map[string]*GroupPattern)
	for name, info := range allGroups {
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		groupPatterns[name] = &GroupPattern{
			Pattern: pattern,
			Info:    info,
		}
	}

	totalLines := len(allLines)
	progressInterval := 200000 // Less frequent progress reporting
	lastProgress := 0

	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			fmt.Printf(colorInfo("    Analyzing line %s/%s (%.0f%%)\n"), 
				formatNumber(lineNum), formatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Fast pre-filter for security rules
		if !strings.Contains(line, "security") {
			continue
		}
		if !strings.Contains(line, "rules") && !strings.Contains(line, "rule") {
			continue
		}

		// Check if line references any of our address groups (optimized)
		var referencedGroups []ReferencedGroup
		hasMatches := false
		
		// Pre-filter with fast string search before regex
		for name, gp := range groupPatterns {
			if idx := strings.Index(line, name); idx != -1 {
				if gp.Pattern.MatchString(line) {
					if !hasMatches {
						referencedGroups = make([]ReferencedGroup, 0, len(groupPatterns))
						hasMatches = true
					}
					referencedGroups = append(referencedGroups, ReferencedGroup{
						Name: name,
						Info: gp.Info,
					})
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
		for _, rg := range referencedGroups {
			targetAddr := rg.Info.Address

			// Skip if already in direct rules
			if _, exists := p.Results[targetAddr].DirectRules[ruleName]; exists {
				continue
			}

			p.Results[targetAddr].IndirectRules[ruleName] = deviceGroup

			// Create context
			context := fmt.Sprintf("references address-group '%s' that contains %s", rg.Name, targetAddr)
			if rg.Info.Group.Context == "shared" {
				context = fmt.Sprintf("references shared address-group '%s' that contains %s", rg.Name, targetAddr)
			} else if rg.Info.Group.Context == "device-group" {
				context = fmt.Sprintf("references address-group '%s' from device-group '%s' that contains %s", 
					rg.Name, rg.Info.Group.DeviceGroup, targetAddr)
			}

			// Add usage context
			if strings.Contains(line, "destination") {
				destParts := strings.Split(line, "destination")
				if len(destParts) > 1 && strings.Contains(destParts[1], rg.Name) {
					context += " (in destination)"
				}
			} else if strings.Contains(line, "source") {
				sourceParts := strings.Split(line, "source")
				if len(sourceParts) > 1 && strings.Contains(sourceParts[1], rg.Name) {
					context += " (in source)"
				}
			}

			p.Results[targetAddr].IndirectRuleContexts[ruleName] = context
		}
	}
}

type GroupInfo struct {
	Group   AddressGroup
	Address string
}

type GroupPattern struct {
	Pattern *regexp.Regexp
	Info    GroupInfo
}

type ReferencedGroup struct {
	Name string
	Info GroupInfo
}

// findNestedAddressGroupsMemory finds address groups that contain other address groups (in-memory version)
func (p *PANLogProcessor) findNestedAddressGroupsMemory(allLines []string, addresses []string) {
	targetAddresses := make(map[string]bool)
	for _, addr := range addresses {
		targetAddresses[addr] = true
	}

	allAddressGroups := make(map[string]GroupMembers)

	totalLines := len(allLines)
	progressInterval := 300000 // Less frequent progress for better performance
	lastProgress := 0

	// Collect ALL address groups and their members from memory
	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			percentage := float64(lineNum) / float64(totalLines) * 100
			fmt.Printf(colorInfo("    Mapping line %s/%s (%.0f%%)\n"), 
				formatNumber(lineNum), formatNumber(totalLines), percentage)
			lastProgress = lineNum
		}

		// Fast pre-filter for address-group lines
		if !strings.Contains(line, "address-group") {
			continue
		}

		// Check for shared address groups
		if matches := p.Patterns.AddressGroupShared.FindStringSubmatch(line); matches != nil {
			groupName, definition := matches[1], matches[2]
			members := parseGroupMembers(definition)
			groupInfo := AddressGroup{
				Name:       groupName,
				Context:    "shared",
				Definition: definition,
			}
			allAddressGroups[groupName] = GroupMembers{
				Info:    groupInfo,
				Members: members,
			}
			continue
		}

		// Check for device group address groups
		if matches := p.Patterns.AddressGroupDevice.FindStringSubmatch(line); matches != nil {
			deviceGroup, groupName, definition := matches[1], matches[2], matches[3]
			members := parseGroupMembers(definition)
			groupInfo := AddressGroup{
				Name:        groupName,
				Context:     "device-group",
				DeviceGroup: deviceGroup,
				Definition:  definition,
			}
			allAddressGroups[groupName] = GroupMembers{
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

type GroupMembers struct {
	Info    AddressGroup
	Members []string
}

// parseGroupMembers parses address group member list from definition string
func parseGroupMembers(definition string) []string {
	// Remove brackets and split by whitespace
	definition = strings.TrimSpace(definition)
	if strings.HasPrefix(definition, "[") && strings.HasSuffix(definition, "]") {
		definition = definition[1 : len(definition)-1]
	}

	// Split and clean up members
	fields := strings.Fields(definition)
	var members []string
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			members = append(members, trimmed)
		}
	}
	return members
}

// formatBytes formats byte size for human readability
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatNumber formats large numbers with commas
func formatNumber(n int) string {
	str := strconv.Itoa(n)
	if len(str) <= 3 {
		return str
	}

	var result []string
	for i, char := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ",")
		}
		result = append(result, string(char))
	}
	return strings.Join(result, "")
}

// main function and CLI setup
func main() {
	var (
		addressFlag  = flag.String("a", "", "Address name to search for (comma-separated for multiple)")
		logfile     = flag.String("l", "default.log", "Path to the log file")
		output      = flag.String("o", "", "Output file name")
		configFile  = flag.String("c", "", "Path to configuration file")
		interactive = flag.Bool("i", false, "Run in interactive mode")
		help        = flag.Bool("h", false, "Show help")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PAN Log Parser Tool - Analyze Palo Alto Networks configuration logs\n\n")
		fmt.Fprintf(os.Stderr, "A high-performance tool for analyzing Palo Alto Networks configuration logs\n")
		fmt.Fprintf(os.Stderr, "to find references to specific IP address objects. Supports both direct and indirect\n")
		fmt.Fprintf(os.Stderr, "references through address groups, security rules, NAT rules, and device groups.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *interactive || (*addressFlag == "" && *configFile == "") {
		runInteractiveMode()
	} else {
		runCommandLineMode(*addressFlag, *logfile, *output, *configFile)
	}
}

func runInteractiveMode() {
	clearScreen()
	printBanner()
	printSectionHeader("Configuration Analysis Setup", "⚙️")
	fmt.Println(colorInfo("  Welcome to the advanced PAN configuration analyzer!"))
	fmt.Println(colorInfo("  This tool will help you discover complex relationships"))
	fmt.Println(colorInfo("  in your Palo Alto Networks configuration logs."))
	printSectionFooter()

	// Get log file
	printSectionHeader("Log File Selection", "📁")
	defaultLog := "default.log"
	configFile := promptInput(fmt.Sprintf("🔍 Enter path to your PAN configuration log [%s]", defaultLog), defaultLog)
	printSectionFooter()

	// Get addresses
	printSectionHeader("Address Object Selection", "🎯")
	fmt.Println(colorInfo("  📝 You can analyze multiple address objects simultaneously"))
	fmt.Println(colorInfo("  📌 For multiple addresses, separate them with commas"))
	fmt.Printf(colorHighlight("  💡 Example: %s\n"), "webserver1,dbserver2,jumphost3")
	fmt.Println()

	var addressInput string
	for addressInput == "" {
		addressInput = promptInput("🔍 Enter address object name(s) to analyze", "")
		if addressInput == "" {
			fmt.Println(colorError("  ❌ At least one address name is required!"))
		}
	}

	addresses := parseAddressList(addressInput)
	printSectionFooter()

	// Run analysis
	printSectionHeader("Configuration Analysis Engine", "🚀")
	fmt.Printf(colorInfo("  📖 Loading configuration file: %s\n"), colorHighlight(configFile))
	fmt.Printf(colorInfo("  🔍 Analyzing %s address object(s): %s\n"), 
		colorHighlight(formatNumber(len(addresses))), 
		colorHighlight(strings.Join(addresses, ", ")))
	fmt.Println(colorInfo("  🧠 Initializing deep relationship analysis..."))

	// Process file once for all addresses
	processor := NewPANLogProcessor()
	if err := processor.ProcessFileSinglePass(configFile, addresses); err != nil {
		fmt.Printf(colorError("Error processing file: %v\n"), err)
		return
	}

	fmt.Println(colorSuccess("  ✅ Deep relationship analysis complete!"))
	printSectionFooter()

	// Process results for each address
	if len(addresses) > 1 {
		printSectionHeader(fmt.Sprintf("Multi-Address Analysis (%d objects)", len(addresses)), "🔄")
		fmt.Printf(colorInfo("  📊 Ready to process: %s\n"), colorHighlight(strings.Join(addresses, ", ")))
		fmt.Println(colorInfo("  📁 Choose your preferred output format:"))
		fmt.Printf(colorInfo("     • %s: Combined report with all results\n"), colorHighlight("Single file"))
		fmt.Printf(colorInfo("     • %s: Individual reports for each address\n"), colorHighlight("Multiple files"))
		fmt.Println()

		useSingleFile := promptInput("🗃️  Use a single combined output file? (y/n)", "n") == "y"
		printSectionFooter()

		if useSingleFile {
			outputFile := "multiple_addresses_results.yml"
			resultsCount := 0
			for _, address := range addresses {
				if ProcessAddress(address, processor, true, outputFile) {
					resultsCount++
				}
			}

			if resultsCount > 0 {
				fmt.Printf(colorSuccess("\nProcessed %s out of %s addresses.\n"), 
					colorHighlight(formatNumber(resultsCount)), 
					colorHighlight(formatNumber(len(addresses))))
				fmt.Printf(colorSuccess("All results written to: %s\n"), colorHighlight(outputFile))
			}
		} else {
			resultsCount := 0
			var outputFiles []string

			for _, address := range addresses {
				if ProcessAddress(address, processor, true, "") {
					resultsCount++
					outputFiles = append(outputFiles, fmt.Sprintf("%s_results.yml", address))
				}
			}

			if resultsCount > 0 {
				fmt.Printf(colorSuccess("\nProcessed %s out of %s addresses.\n"), 
					colorHighlight(formatNumber(resultsCount)), 
					colorHighlight(formatNumber(len(addresses))))
				fmt.Println(colorSuccess("Results written to individual files:"))
				for _, outputFile := range outputFiles {
					fmt.Printf(colorListItem("  - %s\n"), colorHighlight(outputFile))
				}
			}
		}
	} else {
		// Single address
		ProcessAddress(addresses[0], processor, true, "")
	}

	printSectionHeader("Analysis Complete", "🎉")
	fmt.Println(colorSuccess("  🎊 Analysis session completed successfully!"))
	fmt.Println(colorInfo("  💡 Your PAN configuration analysis is ready for review"))
	fmt.Println(colorDimText("  🔧 Tool: PAN Log Parser v2.0 (Go Edition) | Advanced Configuration Analysis"))
	printSectionFooter()
	fmt.Println(colorTitle("\n✨ Thank you for using the PAN Log Parser Tool! ✨"))
}

func runCommandLineMode(addressFlag, logfile, output, configFile string) {
	var config map[string]interface{}
	
	// Read config file if provided
	if configFile != "" {
		if data, err := os.ReadFile(configFile); err == nil {
			json.Unmarshal(data, &config)
		} else {
			fmt.Printf(colorError("Error reading config file: %v\n"), err)
			return
		}
	}

	// Get log file
	if logfile == "" {
		if configLogFile, ok := config["log_file"].(string); ok {
			logfile = configLogFile
		} else {
			logfile = promptInput("Enter log file path [default.log]", "default.log")
		}
	}

	// Get addresses
	var addresses []string
	if addressFlag != "" {
		addresses = parseAddressList(addressFlag)
	} else if configAddr, ok := config["address_name"]; ok {
		switch v := configAddr.(type) {
		case string:
			addresses = parseAddressList(v)
		case []interface{}:
			for _, addr := range v {
				if s, ok := addr.(string); ok {
					addresses = append(addresses, strings.TrimSpace(s))
				}
			}
		}
	} else {
		addressInput := promptInput("Enter the address name (comma-separated for multiple)", "")
		addresses = parseAddressList(addressInput)
	}

	if len(addresses) == 0 {
		fmt.Println(colorError("No addresses specified"))
		return
	}

	fmt.Printf(colorInfo("Loading configuration file: %s\n"), logfile)
	fmt.Printf(colorInfo("Analyzing %d address object(s): %s\n"), len(addresses), strings.Join(addresses, ", "))

	// Process file
	processor := NewPANLogProcessor()
	if err := processor.ProcessFileSinglePass(logfile, addresses); err != nil {
		fmt.Printf(colorError("Error processing file: %v\n"), err)
		return
	}

	// Process results
	if len(addresses) == 1 {
		outputFile := output
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s_results.yml", addresses[0])
		}
		ProcessAddress(addresses[0], processor, false, outputFile)
	} else {
		for _, address := range addresses {
			ProcessAddress(address, processor, false, "")
		}
	}
}

// Configuration structure for JSON config files
type Config struct {
	LogFile     string   `json:"log_file"`
	AddressName []string `json:"address_name"`
}

func promptInput(prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf(colorSection("%s [default: %s]: "), prompt, colorHighlight(defaultValue))
	} else {
		fmt.Printf(colorSection("%s: "), prompt)
	}
	
	var input string
	fmt.Scanln(&input)
	
	if input == "" && defaultValue != "" {
		return defaultValue
	}
	return input
}

func parseAddressList(addressInput string) []string {
	var addresses []string
	for _, addr := range strings.Split(addressInput, ",") {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			addresses = append(addresses, trimmed)
		}
	}
	return addresses
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		fmt.Print("\033[H\033[2J")
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

func printBanner() {
	fmt.Println(colorTitle("    ╔══════════════════════════════════════════════════╗"))
	fmt.Print(colorTitle("    ║  🔥 PAN Log Parser Tool "))
	fmt.Print(colorHighlight("v2.0"))
	fmt.Println(colorTitle("                     ║"))
	fmt.Print(colorTitle("    ║  "))
	fmt.Print(colorInfo("Advanced Palo Alto Networks Configuration       "))
	fmt.Println(colorTitle("║"))
	fmt.Print(colorTitle("    ║  "))
	fmt.Print(colorInfo("Analysis & Address Object Discovery Tool        "))
	fmt.Println(colorTitle("║"))
	fmt.Println(colorTitle("    ╚══════════════════════════════════════════════════╝"))
	fmt.Println(colorDimText("    🚀 Ready to analyze your PAN configurations with precision!"))
	fmt.Println(colorDimText("    📋 Supports nested address groups, security rules & more"))
}

func printSectionHeader(title, icon string) {
	headerContent := fmt.Sprintf("─%s %s", icon, title)
	remainingWidth := 60 - len(headerContent)
	if remainingWidth < 0 {
		remainingWidth = 0
	}
	dashLine := strings.Repeat("─", remainingWidth)
	fmt.Printf(colorSection("┌%s%s┐\n"), headerContent, dashLine)
}

func printSectionFooter() {
	dashLine := strings.Repeat("─", 59)
	fmt.Printf(colorSection("└%s┘\n"), dashLine)
}

// FormattedResults represents the formatted output structure
type FormattedResults struct {
	DeviceGroups                   []string `json:"device_groups"`
	DirectSecurityRules            []string `json:"direct_security_rules"`
	IndirectSecurityRules          []string `json:"indirect_security_rules"`
	AddressGroups                  []AddressGroup `json:"address_groups"`
	NATRules                       []string `json:"nat_rules"`
	ServiceGroups                  []string `json:"service_groups"`
	RedundantAddresses             []RedundantAddress `json:"redundant_addresses"`
}

// FormatResults formats results for a specific address
func (p *PANLogProcessor) FormatResults(address string) *FormattedResults {
	result := p.Results[address]
	
	// Format device groups
	var deviceGroups []string
	for dg := range result.DeviceGroups {
		deviceGroups = append(deviceGroups, dg)
	}
	sort.Strings(deviceGroups)
	
	// Format direct rules
	var directRules []string
	for rule, dg := range result.DirectRules {
		context := result.DirectRuleContexts[rule]
		if context == "" {
			context = "direct reference"
		}
		directRules = append(directRules, fmt.Sprintf("%s (Device Group: %s, %s)", rule, dg, context))
	}
	sort.Strings(directRules)
	
	// Format indirect rules
	var indirectRules []string
	for rule, dg := range result.IndirectRules {
		context := result.IndirectRuleContexts[rule]
		if context == "" {
			context = "indirect reference"
		}
		indirectRules = append(indirectRules, fmt.Sprintf("%s (Device Group: %s, %s)", rule, dg, context))
	}
	sort.Strings(indirectRules)
	
	// Format NAT rules
	var natRules []string
	for rule := range result.NATRules {
		natRules = append(natRules, rule)
	}
	sort.Strings(natRules)
	
	// Format service groups
	var serviceGroups []string
	for sg := range result.ServiceGroups {
		serviceGroups = append(serviceGroups, sg)
	}
	sort.Strings(serviceGroups)
	
	return &FormattedResults{
		DeviceGroups:          deviceGroups,
		DirectSecurityRules:   directRules,
		IndirectSecurityRules: indirectRules,
		AddressGroups:         result.AddressGroups,
		NATRules:              natRules,
		ServiceGroups:         serviceGroups,
		RedundantAddresses:    result.RedundantAddresses,
	}
}

// WriteResults writes results to file in a structured YAML-like format
func WriteResults(outputFile, addressName string, matchingLines []string, itemsDict *FormattedResults) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer file.Close()

	// Enhanced header with metadata
	fmt.Fprintf(file, "# ═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(file, "# 🔥 PAN Log Parser Analysis Report v2.0 (Go Edition)\n")
	fmt.Fprintf(file, "# ═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(file, "# 🎯 Target Address Object: %s\n", addressName)
	fmt.Fprintf(file, "# 📊 Configuration Lines Found: %d\n", len(matchingLines))
	
	totalRelationships := len(itemsDict.DeviceGroups) + len(itemsDict.DirectSecurityRules) + 
		len(itemsDict.IndirectSecurityRules) + len(itemsDict.AddressGroups) + 
		len(itemsDict.NATRules) + len(itemsDict.ServiceGroups) + len(itemsDict.RedundantAddresses)
	fmt.Fprintf(file, "# 🔗 Total Relationships: %d\n", totalRelationships)
	fmt.Fprintf(file, "# ═══════════════════════════════════════════════════════════════\n\n")

	// Matching configuration lines section
	fmt.Fprintf(file, "# 📋 MATCHING CONFIGURATION LINES\n")
	fmt.Fprintf(file, "# Found %d lines containing '%s'\n", len(matchingLines), addressName)
	fmt.Fprintf(file, "---\n\n")

	if len(matchingLines) > 0 {
		for i, line := range matchingLines {
			fmt.Fprintf(file, "  %2d. %s\n", i+1, line)
		}
	} else {
		fmt.Fprintf(file, "  # No matching lines found\n")
	}

	// Category sections with enhanced formatting
	categoryIcons := map[string]string{
		"Device Groups":                        "🏢",
		"Direct Security Rules":                "🛡️",
		"Indirect Security Rules (via Address Groups)": "🔗",
		"Address Groups":                       "📂",
		"NAT Rules":                           "🌐",
		"Service Groups":                      "⚙️",
		"Redundant Addresses":                 "⚠️",
	}

	// Write each category
	writeCategory(file, "Device Groups", categoryIcons["Device Groups"], itemsDict.DeviceGroups)
	writeSecurityRulesCategory(file, "Direct Security Rules", categoryIcons["Direct Security Rules"], itemsDict.DirectSecurityRules)
	writeSecurityRulesCategory(file, "Indirect Security Rules (via Address Groups)", categoryIcons["Indirect Security Rules (via Address Groups)"], itemsDict.IndirectSecurityRules)
	writeAddressGroupsCategory(file, itemsDict.AddressGroups)
	writeCategory(file, "NAT Rules", categoryIcons["NAT Rules"], itemsDict.NATRules)
	writeCategory(file, "Service Groups", categoryIcons["Service Groups"], itemsDict.ServiceGroups)
	writeRedundantAddressesCategory(file, itemsDict.RedundantAddresses)

	// Add footer
	fmt.Fprintf(file, "# ═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(file, "# 🎉 Analysis Complete\n")
	fmt.Fprintf(file, "# Generated by: PAN Log Parser Tool v2.0 (Go Edition)\n")
	fmt.Fprintf(file, "# Advanced Palo Alto Networks Configuration Analysis\n")
	fmt.Fprintf(file, "# ═══════════════════════════════════════════════════════════════\n")

	return nil
}

func writeCategory(file *os.File, category, icon string, items []string) {
	count := len(items)
	fmt.Fprintf(file, "\n# %s %s\n", icon, strings.ToUpper(category))
	fmt.Fprintf(file, "# Found: %d item", count)
	if count != 1 {
		fmt.Fprintf(file, "s")
	}
	fmt.Fprintf(file, "\n---\n")

	if count > 0 {
		for i, item := range items {
			fmt.Fprintf(file, "  📌 %d. %s\n", i+1, item)
		}
	} else {
		fmt.Fprintf(file, "  💭 None discovered\n")
	}
	fmt.Fprintf(file, "\n")
}

func writeSecurityRulesCategory(file *os.File, category, icon string, items []string) {
	count := len(items)
	fmt.Fprintf(file, "\n# %s %s\n", icon, strings.ToUpper(category))
	fmt.Fprintf(file, "# Found: %d item", count)
	if count != 1 {
		fmt.Fprintf(file, "s")
	}
	fmt.Fprintf(file, "\n---\n")

	if count > 0 {
		// Group rules by device group
		rulesByDG := make(map[string][]RuleContext)
		for _, item := range items {
			parts := strings.Split(item, " (Device Group: ")
			if len(parts) == 2 {
				ruleName := parts[0]
				dgPart := parts[1]
				
				// Remove only the final closing parenthesis
				if strings.HasSuffix(dgPart, ")") {
					dgPart = dgPart[:len(dgPart)-1]
				}

				var deviceGroup, context string
				if strings.Contains(dgPart, ", ") {
					dgAndContext := strings.SplitN(dgPart, ", ", 2)
					deviceGroup = dgAndContext[0]
					context = dgAndContext[1]
				} else {
					deviceGroup = dgPart
				}

				rulesByDG[deviceGroup] = append(rulesByDG[deviceGroup], RuleContext{
					Name:    ruleName,
					Context: context,
				})
			}
		}

		// Sort device groups for consistent output
		var deviceGroups []string
		for dg := range rulesByDG {
			deviceGroups = append(deviceGroups, dg)
		}
		sort.Strings(deviceGroups)

		for _, dg := range deviceGroups {
			rules := rulesByDG[dg]
			fmt.Fprintf(file, "  %s:\n", dg)
			for _, rule := range rules {
				if rule.Context != "" {
					fmt.Fprintf(file, "    - %s  # %s\n", rule.Name, rule.Context)
				} else {
					fmt.Fprintf(file, "    - %s\n", rule.Name)
				}
			}
			fmt.Fprintf(file, "\n")
		}
	} else {
		fmt.Fprintf(file, "  💭 None discovered\n")
	}
	fmt.Fprintf(file, "\n")
}

type RuleContext struct {
	Name    string
	Context string
}

func writeAddressGroupsCategory(file *os.File, groups []AddressGroup) {
	count := len(groups)
	fmt.Fprintf(file, "\n# 📂 ADDRESS GROUPS\n")
	fmt.Fprintf(file, "# Found: %d item", count)
	if count != 1 {
		fmt.Fprintf(file, "s")
	}
	fmt.Fprintf(file, "\n---\n")

	if count > 0 {
		for i, group := range groups {
			if group.Context == "shared" {
				fmt.Fprintf(file, "  📂 %d. %s (shared scope):\n", i+1, group.Name)
				fmt.Fprintf(file, "     └─ Command: set shared address-group %s static %s\n", group.Name, group.Definition)
				fmt.Fprintf(file, "     └─ Members: %s\n\n", group.Definition)
			} else {
				fmt.Fprintf(file, "  📂 %d. %s (device-group - %s):\n", i+1, group.Name, group.DeviceGroup)
				fmt.Fprintf(file, "     └─ Command: set device-group %s address-group %s static %s\n", group.DeviceGroup, group.Name, group.Definition)
				fmt.Fprintf(file, "     └─ Members: %s\n\n", group.Definition)
			}
		}
	} else {
		fmt.Fprintf(file, "  💭 None discovered\n")
	}
	fmt.Fprintf(file, "\n")
}

func writeRedundantAddressesCategory(file *os.File, addresses []RedundantAddress) {
	count := len(addresses)
	fmt.Fprintf(file, "\n# ⚠️ REDUNDANT ADDRESSES\n")
	fmt.Fprintf(file, "# Found: %d item", count)
	if count != 1 {
		fmt.Fprintf(file, "s")
	}
	fmt.Fprintf(file, "\n---\n")

	if count > 0 {
		fmt.Fprintf(file, "  ⚠️  Address objects with identical IP configurations:\n\n")
		for i, addr := range addresses {
			fmt.Fprintf(file, "  🔄 %d. %s:\n", i+1, addr.Name)
			fmt.Fprintf(file, "     └─ IP/Netmask: %s\n", addr.IPNetmask)
			fmt.Fprintf(file, "     └─ Scope: %s\n", addr.DeviceGroup)
			fmt.Fprintf(file, "     └─ Note: Same IP as target address - potential duplicate\n\n")
		}
	} else {
		fmt.Fprintf(file, "  💭 None discovered\n")
	}
	fmt.Fprintf(file, "\n")
}

// ProcessAddress processes a single address and generates results
func ProcessAddress(address string, processor *PANLogProcessor, interactiveMode bool, outputOverride string) bool {
	if interactiveMode {
		printSectionHeader(fmt.Sprintf("Analyzing Address Object: %s", address), "🎯")
	}

	result, exists := processor.Results[address]
	if !exists || len(result.MatchingLines) == 0 {
		fmt.Printf(colorWarning("  ⚠️  No matches found for '%s'\n"), address)
		if interactiveMode {
			printSectionFooter()
		}
		return false
	}

	if interactiveMode {
		fmt.Printf(colorSuccess("  ✅ Discovered %s configuration lines\n"), colorHighlight(formatNumber(len(result.MatchingLines))))
		fmt.Println(colorInfo("  📝 Processing relationships and dependencies..."))
	}

	// Format results
	itemsDict := processor.FormatResults(address)

	// Get output file name
	outputFile := outputOverride
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s_results.yml", address)
	}

	if interactiveMode {
		fmt.Printf(colorInfo("  💾 Generating comprehensive report: %s\n"), colorHighlight(outputFile))
	}

	err := WriteResults(outputFile, address, result.MatchingLines, itemsDict)
	if err != nil {
		fmt.Printf(colorError("Error writing results: %v\n"), err)
		return false
	}

	if interactiveMode {
		fmt.Println(colorSuccess("  ✅ Analysis complete! Report generated successfully"))
		printSectionFooter()
		printSectionHeader("Discovery Summary", "📊")
	} else {
		fmt.Printf(colorSuccess("Results written to %s\n"), outputFile)
	}

	// Enhanced summary with icons
	categoryIcons := map[string]string{
		"Device Groups":                        "🏢",
		"Direct Security Rules":                "🛡️",
		"Indirect Security Rules (via Address Groups)": "🔗",
		"Address Groups":                       "📂",
		"NAT Rules":                           "🌐",
		"Service Groups":                      "⚙️",
		"Redundant Addresses":                 "⚠️",
	}

	printResultsSummary("Device Groups", len(itemsDict.DeviceGroups), categoryIcons["Device Groups"])
	printResultsSummary("Direct Security Rules", len(itemsDict.DirectSecurityRules), categoryIcons["Direct Security Rules"])
	printResultsSummary("Indirect Security Rules (via Address Groups)", len(itemsDict.IndirectSecurityRules), categoryIcons["Indirect Security Rules (via Address Groups)"])
	printResultsSummary("Address Groups", len(itemsDict.AddressGroups), categoryIcons["Address Groups"])
	printResultsSummary("NAT Rules", len(itemsDict.NATRules), categoryIcons["NAT Rules"])
	printResultsSummary("Service Groups", len(itemsDict.ServiceGroups), categoryIcons["Service Groups"])
	printResultsSummary("Redundant Addresses", len(itemsDict.RedundantAddresses), categoryIcons["Redundant Addresses"])

	if interactiveMode {
		printSectionFooter()
		totalFindings := len(itemsDict.DeviceGroups) + len(itemsDict.DirectSecurityRules) + 
			len(itemsDict.IndirectSecurityRules) + len(itemsDict.AddressGroups) + 
			len(itemsDict.NATRules) + len(itemsDict.ServiceGroups) + len(itemsDict.RedundantAddresses)
		
		if totalFindings > 0 {
			fmt.Printf(colorSuccess("\n🎉 Analysis revealed %s total configuration items!\n"), colorHighlight(formatNumber(totalFindings)))
			fmt.Printf(colorInfo("📄 Detailed report saved to: %s\n"), colorHighlight(outputFile))
		} else {
			fmt.Println(colorWarning("🤔 No configuration relationships found for this address object."))
		}
	}

	return true
}

func printResultsSummary(category string, count int, icon string) {
	if count > 0 {
		fmt.Printf(colorSuccess("  %s %s: %s found\n"), icon, category, colorHighlight(formatNumber(count)))
	} else {
		fmt.Printf(colorDimText("  %s %s: none found\n"), icon, category)
	}
}