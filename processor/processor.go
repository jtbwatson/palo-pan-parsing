package processor

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"palo-pan-parsing/models"
	"palo-pan-parsing/utils"
)

// PANLogProcessor is the main processor
type PANLogProcessor struct {
	Results          map[string]*models.AddressResult
	Patterns         *models.Patterns
	Silent           bool                  // If true, suppress all output
	ProgressCallback func(float64, string) // Callback for progress updates
}

// NewPatterns creates and compiles all regex patterns
func NewPatterns() *models.Patterns {
	return &models.Patterns{
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

// NewPANLogProcessor creates a new processor instance
func NewPANLogProcessor() *PANLogProcessor {
	return &PANLogProcessor{
		Results:  make(map[string]*models.AddressResult),
		Patterns: NewPatterns(),
		Silent:   false,
	}
}

// printf conditionally prints if not in silent mode
func (p *PANLogProcessor) printf(format string, args ...interface{}) {
	if !p.Silent {
		fmt.Printf(format, args...)
	}
}

// println conditionally prints if not in silent mode
func (p *PANLogProcessor) println(msg string) {
	if !p.Silent {
		fmt.Println(msg)
	}
}

// NewAddressResult creates a new initialized AddressResult with pre-allocated capacity
func NewAddressResult() *models.AddressResult {
	return &models.AddressResult{
		MatchingLines:        make([]string, 0, 100),                // Pre-allocate for 100 lines
		DeviceGroups:         make(map[string]bool, 10),             // Pre-allocate for 10 device groups
		DirectRules:          make(map[string]string, 50),           // Pre-allocate for 50 rules
		DirectRuleContexts:   make(map[string]string, 50),           // Pre-allocate for 50 contexts
		IndirectRules:        make(map[string]string, 20),           // Pre-allocate for 20 indirect rules
		IndirectRuleContexts: make(map[string]string, 20),           // Pre-allocate for 20 contexts
		AddressGroups:        make([]models.AddressGroup, 0, 20),    // Pre-allocate for 20 groups
		NATRules:             make(map[string]bool, 10),             // Pre-allocate for 10 NAT rules
		ServiceGroups:        make(map[string]bool, 10),             // Pre-allocate for 10 service groups
		RedundantAddresses:   make([]models.RedundantAddress, 0, 5), // Pre-allocate for 5 redundant addresses
	}
}

// ProcessFileSinglePass processes the file once, loading into memory for optimal performance
func (p *PANLogProcessor) ProcessFileSinglePass(filePath string, addresses []string) error {
	addressSet := make(map[string]bool)
	for _, addr := range addresses {
		addressSet[addr] = true
		p.Results[addr] = NewAddressResult()
	}

	ipToAddresses := make(map[string][]models.IPAddress)

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("error accessing file: %w", err)
	}

	p.printf("  Loading configuration file into memory: %s (%s)\n",
		fileInfo.Name(),
		utils.FormatBytes(fileInfo.Size()))

	// Open and read file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	p.println("  Reading file into memory...")

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
	p.printf("  Loaded %s configuration lines into memory\n",
		utils.FormatNumber(totalLines))
	p.println("  Processing in-memory for maximum performance...")

	// Note: Using simple substring matching to match Python behavior
	// This ensures addresses like "someserver-rebuild" match when searching for "someserver"

	// Process all lines in memory with optimized batch processing
	progressInterval := 20000 // Very frequent progress reporting for great UX
	if totalLines > 5000000 {
		progressInterval = 40000
	}
	lastProgress := 0

	// Use a mutex for thread-safe IP address tracking
	var ipMutex sync.Mutex

	// Process lines in optimized loop
	for lineNum, line := range allLines {
		// Show progress less frequently for better performance
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			progress := float64(lineNum) / float64(totalLines)
			percentage := progress * 100
			message := fmt.Sprintf("Processing line %s/%s (%.0f%%)",
				utils.FormatNumber(lineNum), utils.FormatNumber(totalLines), percentage)

			// Call progress callback if available
			if p.ProgressCallback != nil {
				p.ProgressCallback(progress, message)
			} else {
				p.printf("    %s\n", message)
			}
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
				ipToAddresses[ipNetmask] = append(ipToAddresses[ipNetmask], models.IPAddress{
					Name: addrName,
					Line: line,
				})
				ipMutex.Unlock()
			}
		}

		// Fast pre-filter: only check detailed patterns if line might contain addresses
		hasAddress := false
		var matchingAddresses []string

		// Fast address matching - simple substring search (matches Python behavior)
		for addr := range addressSet {
			// Simple substring check - matches any occurrence like Python version
			if strings.Contains(line, addr) {
				if !hasAddress {
					matchingAddresses = make([]string, 0, len(addressSet)) // Pre-allocate capacity
					hasAddress = true
				}
				matchingAddresses = append(matchingAddresses, addr)
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

	p.println("  Initial scan complete")

	// Process redundant addresses
	p.println("  Analyzing redundant address objects...")
	p.findRedundantAddresses(ipToAddresses, addressSet)

	// Find indirect security rules (using in-memory data)
	p.println("  Discovering indirect security rule relationships...")
	p.findIndirectRulesMemory(allLines, addresses)

	// Find nested address groups (using in-memory data)
	p.println("  Mapping nested address group hierarchies...")
	p.findNestedAddressGroupsMemory(allLines, addresses)

	return nil
}

// extractItemsFromLine extracts all relevant items from a single line
func (p *PANLogProcessor) extractItemsFromLine(line, address string) {
	result := p.Results[address]

	// Cache device group match to avoid multiple regex calls
	deviceGroupMatch := p.Patterns.DeviceGroup.FindStringSubmatch(line)
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
func (p *PANLogProcessor) extractAddressGroup(line string) *models.AddressGroup {
	// Check shared address groups
	if matches := p.Patterns.AddressGroupShared.FindStringSubmatch(line); matches != nil {
		return &models.AddressGroup{
			Name:       matches[1],
			Context:    "shared",
			Definition: matches[2],
		}
	}

	// Check device group address groups
	if matches := p.Patterns.AddressGroupDevice.FindStringSubmatch(line); matches != nil {
		return &models.AddressGroup{
			Name:        matches[2],
			Context:     "device-group",
			DeviceGroup: matches[1],
			Definition:  matches[3],
		}
	}

	return nil
}

// FormatResults formats results for a specific address
func (p *PANLogProcessor) FormatResults(address string) *models.FormattedResults {
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

	return &models.FormattedResults{
		DeviceGroups:          deviceGroups,
		DirectSecurityRules:   directRules,
		IndirectSecurityRules: indirectRules,
		AddressGroups:         result.AddressGroups,
		NATRules:              natRules,
		ServiceGroups:         serviceGroups,
		RedundantAddresses:    result.RedundantAddresses,
	}
}

// ConfigurationCache holds parsed configuration data for efficient multi-group analysis
type ConfigurationCache struct {
	AllLines           []string
	DeviceGroups       map[string]bool
	HasSharedAddresses bool
	FilePath           string
}

// LoadConfigurationOnce loads and caches configuration file for efficient multi-group analysis
func (p *PANLogProcessor) LoadConfigurationOnce(filePath string) (*ConfigurationCache, error) {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("error accessing file: %w", err)
	}

	p.printf("  Loading configuration file into memory: %s (%s)\n",
		fileInfo.Name(),
		utils.FormatBytes(fileInfo.Size()))

	// Open and read file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	p.println("  Reading file into memory...")

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
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	totalLines := len(allLines)
	p.printf("  Loaded %s configuration lines into memory\n",
		utils.FormatNumber(totalLines))

	// Discover device groups during the initial parse
	deviceGroups := make(map[string]bool)
	hasSharedAddresses := false
	
	deviceGroupPattern := regexp.MustCompile(`device-group\s+(\S+)`)
	sharedPattern := regexp.MustCompile(`set\s+shared\s+address`)

	p.println("  Discovering device groups...")
	for _, line := range allLines {
		// Check for device groups
		if matches := deviceGroupPattern.FindStringSubmatch(line); matches != nil {
			deviceGroupName := matches[1]
			deviceGroups[deviceGroupName] = true
		}
		
		// Check for shared addresses
		if sharedPattern.MatchString(line) {
			hasSharedAddresses = true
		}
	}

	p.printf("  Discovered %d device groups", len(deviceGroups))
	if hasSharedAddresses {
		p.printf(" (plus shared scope)")
	}
	p.println("")

	return &ConfigurationCache{
		AllLines:           allLines,
		DeviceGroups:       deviceGroups,
		HasSharedAddresses: hasSharedAddresses,
		FilePath:           filePath,
	}, nil
}

// FindDuplicateAddressesInDeviceGroupFromCache finds duplicate address objects using cached configuration
func (p *PANLogProcessor) FindDuplicateAddressesInDeviceGroupFromCache(cache *ConfigurationCache, deviceGroup string) error {
	// Initialize result for the device group scan
	scanResultKey := fmt.Sprintf("device-group-%s-scan", deviceGroup)
	p.Results[scanResultKey] = NewAddressResult()

	// Track IP addresses to find duplicates
	ipToAddresses := make(map[string][]models.IPAddress)
	deviceGroupAddresses := make(map[string]bool)

	p.printf("  Analyzing device group '%s' from cached configuration...\n", deviceGroup)

	// Create comprehensive patterns for all address types
	var deviceGroupPatterns, sharedPatterns []*regexp.Regexp
	if deviceGroup == "shared" {
		sharedPatterns = []*regexp.Regexp{
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-netmask\s+([\d\./]+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-range\s+([\d\.\-\s]+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+fqdn\s+(\S+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-wildcard\s+([\d\.\*]+)`),
		}
	} else {
		dgEscaped := regexp.QuoteMeta(deviceGroup)
		deviceGroupPatterns = []*regexp.Regexp{
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-netmask\s+([\d\./]+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-range\s+([\d\.\-\s]+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+fqdn\s+(\S+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-wildcard\s+([\d\.\*]+)`, dgEscaped)),
		}
	}

	// Process cached lines (no file I/O needed!)
	for _, line := range cache.AllLines {
		// Check for address definitions in the target device group or shared using all patterns
		var addrName, addrValue string
		var found bool
		
		// Try all patterns for the target scope
		patterns := deviceGroupPatterns
		if deviceGroup == "shared" {
			patterns = sharedPatterns
		}
		
		for _, pattern := range patterns {
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				addrName, addrValue = matches[1], matches[2]
				found = true
				break
			}
		}
		
		if found {
			deviceGroupAddresses[addrName] = true

			// Track IP mappings for duplicate detection (only for comparable address types)
			// We can only detect duplicates for IP-based addresses, not FQDNs
			if strings.Contains(line, "ip-netmask") || strings.Contains(line, "ip-range") || strings.Contains(line, "ip-wildcard") {
				ipToAddresses[addrValue] = append(ipToAddresses[addrValue], models.IPAddress{
					Name: addrName,
					Line: line,
				})
			}

			// Add to matching lines for debugging
			p.Results[scanResultKey].MatchingLines = append(p.Results[scanResultKey].MatchingLines, line)
		}
	}

	p.printf("  Found %d address objects in device group '%s'\n", len(deviceGroupAddresses), deviceGroup)
	
	// Debug: Show first few address objects found
	if !p.Silent && len(deviceGroupAddresses) > 0 {
		count := 0
		p.printf("  Sample addresses found:\n")
		for addrName := range deviceGroupAddresses {
			if count >= 5 {
				p.printf("    ... and %d more\n", len(deviceGroupAddresses)-5)
				break
			}
			p.printf("    - %s\n", addrName)
			count++
		}
	} else if !p.Silent {
		p.printf("  No address objects found - this could indicate:\n")
		p.printf("    - Device group name doesn't match exactly\n")
		p.printf("    - Address definitions use different format\n")
		p.printf("    - Multi-line address definitions\n")
	}

	// Find duplicates using existing logic
	p.findDuplicatesInDeviceGroup(ipToAddresses, deviceGroupAddresses, deviceGroup, scanResultKey)

	// Write results
	duplicates := p.Results[scanResultKey].RedundantAddresses
	if len(duplicates) > 0 {
		p.printf("  Found %d sets of duplicate addresses\n", len(duplicates))
		return p.writeDuplicateResults(deviceGroup, duplicates, deviceGroupAddresses)
	} else {
		p.printf("  No duplicate addresses found in device group '%s'\n", deviceGroup)
		// Write empty results file for TUI consistency
		return p.writeDuplicateResults(deviceGroup, duplicates, deviceGroupAddresses)
	}
}

// GetAvailableDeviceGroups returns device groups from cached configuration
func (cache *ConfigurationCache) GetAvailableDeviceGroups() []string {
	var result []string
	if cache.HasSharedAddresses {
		result = append(result, "shared")
	}
	for dg := range cache.DeviceGroups {
		result = append(result, dg)
	}
	// Sort for consistent ordering
	if len(result) > 1 && result[0] == "shared" {
		// Keep shared first, sort the rest
		sort.Strings(result[1:])
	} else {
		sort.Strings(result)
	}
	return result
}

// FindDuplicateAddressesInDeviceGroup finds all duplicate address objects within a specific device group (legacy method)
func (p *PANLogProcessor) FindDuplicateAddressesInDeviceGroup(filePath, deviceGroup string) error {
	// Initialize result for the device group scan
	scanResultKey := fmt.Sprintf("device-group-%s-scan", deviceGroup)
	p.Results[scanResultKey] = NewAddressResult()

	// Track IP addresses to find duplicates
	ipToAddresses := make(map[string][]models.IPAddress)
	deviceGroupAddresses := make(map[string]bool)

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("error accessing file: %w", err)
	}

	p.printf("  Loading configuration file into memory: %s (%s)\n",
		fileInfo.Name(),
		utils.FormatBytes(fileInfo.Size()))

	// Open and read file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	p.println("  Reading file into memory...")

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
	p.printf("  Loaded %s configuration lines into memory\n",
		utils.FormatNumber(totalLines))
	p.printf("  Scanning for duplicate addresses in device group '%s'...\n", deviceGroup)

	// Process all lines to find addresses in the specified device group
	progressInterval := 20000
	if totalLines > 5000000 {
		progressInterval = 40000
	}
	lastProgress := 0

	// Create comprehensive patterns for all address types
	var deviceGroupPatterns, sharedPatterns []*regexp.Regexp
	if deviceGroup == "shared" {
		sharedPatterns = []*regexp.Regexp{
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-netmask\s+([\d\./]+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-range\s+([\d\.\-\s]+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+fqdn\s+(\S+)`),
			regexp.MustCompile(`set\s+shared\s+address\s+(\S+)\s+ip-wildcard\s+([\d\.\*]+)`),
		}
	} else {
		dgEscaped := regexp.QuoteMeta(deviceGroup)
		deviceGroupPatterns = []*regexp.Regexp{
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-netmask\s+([\d\./]+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-range\s+([\d\.\-\s]+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+fqdn\s+(\S+)`, dgEscaped)),
			regexp.MustCompile(fmt.Sprintf(`set\s+device-group\s+%s\s+address\s+(\S+)\s+ip-wildcard\s+([\d\.\*]+)`, dgEscaped)),
		}
	}

	for lineNum, line := range allLines {
		// Show progress
		if lineNum > 0 && lineNum%progressInterval == 0 && lineNum != lastProgress {
			progress := float64(lineNum) / float64(totalLines)
			percentage := progress * 100
			message := fmt.Sprintf("Scanning line %s/%s (%.0f%%)",
				utils.FormatNumber(lineNum), utils.FormatNumber(totalLines), percentage)

			if p.ProgressCallback != nil {
				p.ProgressCallback(progress, message)
			} else {
				p.printf("    %s\n", message)
			}
			lastProgress = lineNum
		}

		// Check for address definitions in the target device group or shared using all patterns
		var addrName, addrValue string
		var found bool
		
		// Try all patterns for the target scope
		patterns := deviceGroupPatterns
		if deviceGroup == "shared" {
			patterns = sharedPatterns
		}
		
		for _, pattern := range patterns {
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				addrName, addrValue = matches[1], matches[2]
				found = true
				break
			}
		}
		
		if found {
			deviceGroupAddresses[addrName] = true

			// Track IP mappings for duplicate detection (only for comparable address types)
			// We can only detect duplicates for IP-based addresses, not FQDNs
			if strings.Contains(line, "ip-netmask") || strings.Contains(line, "ip-range") || strings.Contains(line, "ip-wildcard") {
				ipToAddresses[addrValue] = append(ipToAddresses[addrValue], models.IPAddress{
					Name: addrName,
					Line: line,
				})
			}

			// Add to matching lines for debugging
			p.Results[scanResultKey].MatchingLines = append(p.Results[scanResultKey].MatchingLines, line)
		}
	}

	p.printf("  Found %d address objects in device group '%s'\n", len(deviceGroupAddresses), deviceGroup)
	
	// Debug: Show first few address objects found
	if !p.Silent && len(deviceGroupAddresses) > 0 {
		count := 0
		p.printf("  Sample addresses found:\n")
		for addrName := range deviceGroupAddresses {
			if count >= 5 {
				p.printf("    ... and %d more\n", len(deviceGroupAddresses)-5)
				break
			}
			p.printf("    - %s\n", addrName)
			count++
		}
	} else if !p.Silent {
		p.printf("  No address objects found - this could indicate:\n")
		p.printf("    - Device group name doesn't match exactly\n")
		p.printf("    - Address definitions use different format\n")
		p.printf("    - Multi-line address definitions\n")
	}

	// Find duplicates using existing logic
	p.findDuplicatesInDeviceGroup(ipToAddresses, deviceGroupAddresses, deviceGroup, scanResultKey)

	// Write results
	duplicates := p.Results[scanResultKey].RedundantAddresses
	if len(duplicates) > 0 {
		p.printf("  Found %d sets of duplicate addresses\n", len(duplicates))
		return p.writeDuplicateResults(deviceGroup, duplicates, deviceGroupAddresses)
	} else {
		p.printf("  No duplicate addresses found in device group '%s'\n", deviceGroup)
		// Write empty results file for TUI consistency
		return p.writeDuplicateResults(deviceGroup, duplicates, deviceGroupAddresses)
	}
}

// DiscoverDeviceGroups scans a config file and returns all unique device groups found
func (p *PANLogProcessor) DiscoverDeviceGroups(filePath string) ([]string, error) {
	// Open and read file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	deviceGroups := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	// Set a large buffer size for performance
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// Pattern to match device group references
	deviceGroupPattern := regexp.MustCompile(`set\s+device-group\s+(\S+)`)
	sharedPattern := regexp.MustCompile(`set\s+shared\s+address`)

	lineCount := 0
	hasSharedAddresses := false
	
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		
		// Show progress for large files
		if lineCount%100000 == 0 {
			p.printf("  Scanned %s lines for device groups...\n", utils.FormatNumber(lineCount))
		}

		// Check for device groups
		if matches := deviceGroupPattern.FindStringSubmatch(line); matches != nil {
			deviceGroupName := matches[1]
			deviceGroups[deviceGroupName] = true
		}
		
		// Check for shared addresses
		if sharedPattern.MatchString(line) {
			hasSharedAddresses = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Convert to sorted slice and add shared if found
	var result []string
	if hasSharedAddresses {
		result = append(result, "shared")
	}
	for dg := range deviceGroups {
		result = append(result, dg)
	}
	sort.Strings(result)

	p.printf("  Found %d unique device groups", len(deviceGroups))
	if hasSharedAddresses {
		p.printf(" (plus shared scope)")
	}
	p.printf("\n")
	return result, nil
}

// findDuplicatesInDeviceGroup finds duplicates within a specific device group
func (p *PANLogProcessor) findDuplicatesInDeviceGroup(ipToAddresses map[string][]models.IPAddress, deviceGroupAddresses map[string]bool, deviceGroup, resultKey string) {
	for ipNetmask, addrList := range ipToAddresses {
		if len(addrList) > 1 {
			// Found addresses with same IP - these are duplicates
			var duplicates []models.RedundantAddress
			for _, addr := range addrList {
				// Only include addresses from our target device group
				if deviceGroupAddresses[addr.Name] {
					duplicates = append(duplicates, models.RedundantAddress{
						Name:        addr.Name,
						IPNetmask:   ipNetmask,
						DeviceGroup: deviceGroup,
					})
				}
			}
			
			// Add to results if we found duplicates in this device group
			if len(duplicates) > 1 {
				p.Results[resultKey].RedundantAddresses = append(p.Results[resultKey].RedundantAddresses, duplicates...)
			}
		}
	}
}

// writeDuplicateResults writes the duplicate address results to a file
func (p *PANLogProcessor) writeDuplicateResults(deviceGroup string, duplicates []models.RedundantAddress, allAddresses map[string]bool) error {
	outputFile := fmt.Sprintf("outputs/%s_duplicates.yml", deviceGroup)
	
	// Ensure outputs directory exists
	if err := os.MkdirAll("outputs", 0755); err != nil {
		return fmt.Errorf("failed to create outputs directory: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Group duplicates by IP
	duplicatesByIP := make(map[string][]models.RedundantAddress)
	for _, dup := range duplicates {
		duplicatesByIP[dup.IPNetmask] = append(duplicatesByIP[dup.IPNetmask], dup)
	}

	// Write header
	fmt.Fprintf(file, "# Duplicate Address Objects in Device Group: %s\n", deviceGroup)
	fmt.Fprintf(file, "# Generated by PAN Log Parser Tool\n\n")
	fmt.Fprintf(file, "device_group: %s\n", deviceGroup)
	fmt.Fprintf(file, "total_addresses: %d\n", len(allAddresses))
	fmt.Fprintf(file, "duplicate_sets: %d\n\n", len(duplicatesByIP))

	fmt.Fprintln(file, "duplicates:")
	for ipNetmask, dups := range duplicatesByIP {
		fmt.Fprintf(file, "  - ip_netmask: %s\n", ipNetmask)
		fmt.Fprintln(file, "    addresses:")
		for _, dup := range dups {
			fmt.Fprintf(file, "      - %s\n", dup.Name)
		}
		fmt.Fprintln(file)
	}

	return nil
}
