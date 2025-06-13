package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"palo-pan-parsing/models"
	"palo-pan-parsing/processor"
	"palo-pan-parsing/tui"
	"palo-pan-parsing/utils"
)

const (
	version     = "1.0.0"
	defaultOutputDir = "outputs"
)

var (
	showHelp     = flag.Bool("h", false, "Show help information")
	showVersion  = flag.Bool("version", false, "Show version information") 
	logFile      = flag.String("l", "", "Path to PAN configuration file (required)")
	targetAddr   = flag.String("a", "", "Target address name to search for")
	addresses    = flag.String("addresses", "", "Comma-separated list of addresses to search for")
	outputFile   = flag.String("o", "", "Output file path (default: auto-generated in outputs/)")
	outputDir    = flag.String("output-dir", defaultOutputDir, "Output directory for result files")
	configFile   = flag.String("c", "", "JSON configuration file path")
	verbose      = flag.Bool("verbose", false, "Run in classic interactive mode")
	silent       = flag.Bool("silent", false, "Run in silent mode with minimal output")
	tuiMode      = flag.Bool("tui", false, "Run in modern TUI mode (default when no flags provided)")
	workers      = flag.Int("workers", 4, "Number of worker threads for processing")
	bufferSize   = flag.Int("buffer", 65536, "Buffer size for file reading")
	timeout      = flag.Int("timeout", 30, "Timeout in minutes for processing")
	
	// Address copy functionality flags
	copyAddr     = flag.String("copy-address", "", "Source address name to copy settings from")
	newAddrName  = flag.String("new-address", "", "New address name for copied settings")
	newAddrIP    = flag.String("new-ip", "", "New IP/netmask for copied address (e.g., 192.168.1.100/32)")
	copyMode     = flag.String("copy-mode", "add", "Copy mode: 'add' (add new alongside existing) or 'replace' (replace existing)")
)

func main() {
	flag.Parse()
	
	if *showHelp {
		showHelpMessage()
		os.Exit(0)
	}
	
	if *showVersion {
		fmt.Printf("PAN Configuration Parser v%s\n", version)
		os.Exit(0)
	}
	
	config, err := buildConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}
	
	mode := determineRunMode()
	
	// Skip validation for TUI mode and copy mode - they will handle input differently
	if mode != "tui" && mode != "copy" {
		if err := validateConfig(config); err != nil {
			fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
			os.Exit(1)
		}
	}
	
	switch mode {
	case "tui":
		if err := runTUIMode(config); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
	case "interactive":
		if err := runInteractiveMode(config); err != nil {
			fmt.Fprintf(os.Stderr, "Interactive error: %v\n", err)
			os.Exit(1)
		}
	case "cli":
		if err := runCLIMode(config); err != nil {
			fmt.Fprintf(os.Stderr, "CLI error: %v\n", err)
			os.Exit(1)
		}
	case "copy":
		if err := runCopyMode(config); err != nil {
			fmt.Fprintf(os.Stderr, "Copy error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown run mode: %s\n", mode)
		os.Exit(1)
	}
}

func buildConfig() (*models.Config, error) {
	config := models.DefaultConfig
	
	if *logFile != "" {
		config.LogFile = *logFile
	}
	
	if *targetAddr != "" {
		config.TargetAddress = *targetAddr
	}
	
	if *addresses != "" {
		config.Addresses = utils.ParseCommaSeparatedList(*addresses)
	}
	
	if *outputFile != "" {
		config.OutputFile = *outputFile
	}
	
	config.Silent = *silent
	config.Verbose = *verbose
	config.TUI = *tuiMode
	
	if *workers > 0 {
		config.MaxWorkers = *workers
	}
	
	if *bufferSize > 0 {
		config.BufferSize = *bufferSize
	}
	
	if *timeout > 0 {
		config.Timeout = time.Duration(*timeout) * time.Minute
	}
	
	if *configFile != "" {
		if err := loadConfigFromFile(&config, *configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}
	
	return &config, nil
}

func validateConfig(config *models.Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	
	if config.LogFile != "" {
		if err := utils.ValidateFile(config.LogFile); err != nil {
			return fmt.Errorf("log file validation failed: %w", err)
		}
	}
	
	if err := utils.EnsureDirectory(*outputDir); err != nil {
		return fmt.Errorf("output directory creation failed: %w", err)
	}
	
	return nil
}

func determineRunMode() string {
	if flag.NFlag() == 0 {
		return "tui"
	}
	
	// Check for address copy mode first
	if *copyAddr != "" && *newAddrName != "" && *newAddrIP != "" {
		return "copy"
	}
	
	if *tuiMode {
		return "tui"
	}
	
	if *verbose {
		return "interactive"
	}
	
	if *logFile != "" && (*targetAddr != "" || *addresses != "") {
		return "cli"
	}
	
	return "tui"
}

func runTUIMode(config *models.Config) error {
	return tui.Run()
}

func runInteractiveMode(config *models.Config) error {
	fmt.Println("Interactive mode not yet implemented - falling back to CLI mode")
	return runCLIMode(config)
}

func runCLIMode(config *models.Config) error {
	if !config.Silent {
		fmt.Printf("PAN Configuration Parser v%s\n", version)
		fmt.Printf("Processing file: %s\n", config.LogFile)
		
		if config.TargetAddress != "" {
			fmt.Printf("Target address: %s\n", config.TargetAddress)
		}
		
		if len(config.Addresses) > 0 {
			fmt.Printf("Target addresses: %s\n", strings.Join(config.Addresses, ", "))
		}
		
		fmt.Println()
	}
	
	proc := processor.NewProcessor(config)
	
	var result interface{}
	var err error
	
	if len(config.Addresses) > 1 {
		result, err = proc.ProcessMultipleAddresses(config.LogFile, config.Addresses)
	} else {
		result, err = proc.ProcessFile(config.LogFile)
	}
	
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}
	
	if err := writeResults(result, config); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	
	if !config.Silent {
		fmt.Println("Analysis completed successfully!")
		fmt.Printf("Results written to: %s\n", *outputDir)
	}
	
	return nil
}

func writeResults(result interface{}, config *models.Config) error {
	writer := utils.NewYAMLWriter()
	
	switch r := result.(type) {
	case *models.AnalysisResult:
		return writer.WriteAnalysisResult(r, *outputDir)
	case *models.MultiAddressResult:
		return writer.WriteMultiAddressResult(r, *outputDir)
	default:
		return fmt.Errorf("unknown result type: %T", result)
	}
}

func loadConfigFromFile(config *models.Config, filename string) error {
	return fmt.Errorf("config file loading not yet implemented")
}

func showHelpMessage() {
	fmt.Printf("PAN Configuration Parser v%s\n\n", version)
	fmt.Println("A high-performance tool for analyzing Palo Alto Networks configuration files.")
	fmt.Println("Finds references to IP address objects in security rules, NAT rules, and address groups.")
	fmt.Println()
	
	fmt.Println("USAGE:")
	fmt.Println("  pan-parser [OPTIONS]")
	fmt.Println("  pan-parser -l <config_file> -a <address>")
	fmt.Println("  pan-parser -l <config_file> -addresses <addr1,addr2,addr3>")
	fmt.Println("  pan-parser -l <config_file> -copy-address <source> -new-address <name> -new-ip <ip>")
	fmt.Println()
	
	fmt.Println("MODES:")
	fmt.Println("  Default (no flags)    Run in modern TUI mode (recommended)")
	fmt.Println("  --tui                 Run in modern TUI mode explicitly") 
	fmt.Println("  --verbose             Run in classic interactive mode")
	fmt.Println("  Address Copy Mode     Copy all settings from one address to another")
	fmt.Println("  CLI flags             Run in command-line mode")
	fmt.Println()
	
	fmt.Println("OPTIONS:")
	flag.PrintDefaults()
	fmt.Println()
	
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Run in TUI mode (default)")
	fmt.Println("  pan-parser")
	fmt.Println()
	fmt.Println("  # Analyze single address")
	fmt.Println("  pan-parser -l panos.xml -a server1")
	fmt.Println()
	fmt.Println("  # Analyze multiple addresses")
	fmt.Println("  pan-parser -l panos.xml -addresses \"server1,server2,web-server\"")
	fmt.Println()
	fmt.Println("  # Run with custom output directory")
	fmt.Println("  pan-parser -l panos.xml -a server1 -output-dir /tmp/results")
	fmt.Println()
	fmt.Println("  # Run in interactive mode")
	fmt.Println("  pan-parser --verbose")
	fmt.Println()
	fmt.Println("  # Performance tuning for large files")
	fmt.Println("  pan-parser -l large-config.xml -a server1 -workers 8 -buffer 131072")
	fmt.Println()
	fmt.Println("  # Copy address settings (add new address alongside existing)")
	fmt.Println("  pan-parser -l panos.xml -copy-address server1 -new-address server2 -new-ip 192.168.1.100/32")
	fmt.Println()
	fmt.Println("  # Copy address settings (replace existing with new)")
	fmt.Println("  pan-parser -l panos.xml -copy-address server1 -new-address server2 -new-ip 192.168.1.100/32 -copy-mode replace")
	fmt.Println()
	
	fmt.Println("OUTPUT:")
	fmt.Println("  Results are saved to YAML files in the output directory:")
	fmt.Println("  - <address>_results.yml         Main analysis results")
	fmt.Println("  - <address>_cleanup.yml         Redundant address cleanup commands")
	fmt.Println("  - <address>_add_to_groups_commands.yml  Address group commands")
	fmt.Println("  - <address>_copy_commands.yml   Address copy commands")
	fmt.Println("  - multiple_addresses_results.yml      Multi-address analysis")
	fmt.Println()
	
	fmt.Println("PERFORMANCE:")
	fmt.Println("  - Optimized for large Panorama configurations (1M+ lines)")
	fmt.Println("  - Streaming XML processing with configurable buffer sizes")
	fmt.Println("  - Parallel processing with configurable worker pools")
	fmt.Println("  - Memory-efficient design suitable for resource-constrained environments")
	fmt.Println()
	
	fmt.Println("For more information, visit: https://github.com/your-org/palo-pan-parsing")
}

func runCopyMode(config *models.Config) error {
	if *logFile == "" {
		return fmt.Errorf("configuration file (-l) is required for copy mode")
	}
	
	request := processor.AddressCopyRequest{
		SourceAddressName: *copyAddr,
		NewAddressName:    *newAddrName,
		NewIPNetmask:      *newAddrIP,
		CopyMode:          *copyMode,
	}
	
	if err := processor.ValidateCopyRequest(request); err != nil {
		return fmt.Errorf("invalid copy request: %w", err)
	}
	
	if !*silent {
		fmt.Printf("Copying address settings from '%s' to '%s' (%s)\n", *copyAddr, *newAddrName, *newAddrIP)
		fmt.Printf("Copy mode: %s\n", *copyMode)
		fmt.Printf("Analyzing configuration file: %s\n", *logFile)
	}
	
	// Parse the configuration to get all objects but without target filtering
	// We need ALL objects for copy analysis
	tempConfig := *config
	tempConfig.TargetAddress = ""
	tempConfig.Addresses = []string{}
	
	// Create a processor that will give us all objects
	allObjectsProc := processor.NewProcessor(&tempConfig)
	
	// Parse to get all objects in the configuration
	analysisResult, err := allObjectsProc.ProcessFile(*logFile)
	if err != nil {
		return fmt.Errorf("failed to process configuration file: %w", err)
	}
	
	// Build maps for the copier
	addressMap := make(map[string]*models.AddressObject)
	for i := range analysisResult.AddressObjects {
		addr := &analysisResult.AddressObjects[i]
		addressMap[addr.Name] = addr
	}
	
	groupMap := make(map[string]*models.AddressGroup)
	for i := range analysisResult.AddressGroups {
		group := &analysisResult.AddressGroups[i]
		groupMap[group.Name] = group
	}
	
	securityRuleMap := make(map[string]*models.SecurityRule)
	for i := range analysisResult.DirectSecurityRules {
		rule := &analysisResult.DirectSecurityRules[i]
		securityRuleMap[rule.Name] = rule
	}
	for i := range analysisResult.IndirectSecurityRules {
		rule := &analysisResult.IndirectSecurityRules[i]
		securityRuleMap[rule.Name] = rule
	}
	
	natRuleMap := make(map[string]*models.NATRule)
	for i := range analysisResult.DirectNATRules {
		rule := &analysisResult.DirectNATRules[i]
		natRuleMap[rule.Name] = rule
	}
	for i := range analysisResult.IndirectNATRules {
		rule := &analysisResult.IndirectNATRules[i]
		natRuleMap[rule.Name] = rule
	}
	
	// Perform address copy analysis
	copier := processor.NewAddressCopier(config)
	copyResult, err := copier.AnalyzeAddressCopy(request, addressMap, groupMap, securityRuleMap, natRuleMap)
	if err != nil {
		return fmt.Errorf("address copy analysis failed: %w", err)
	}
	
	// Generate output file
	outputFile := fmt.Sprintf("%s_copy_commands.yml", utils.SanitizeFilename(*copyAddr))
	
	// Convert summary to the format expected by WriteCopyCommands
	summary := map[string]int{
		"groups_to_update":         copyResult.Summary.GroupsToUpdate,
		"security_rules_to_update": copyResult.Summary.SecurityRulesToUpdate,
		"nat_rules_to_update":      copyResult.Summary.NATRulesToUpdate,
		"total_commands":           copyResult.Summary.TotalCommands,
	}
	
	writer := utils.NewYAMLWriter()
	if err := writer.WriteCopyCommands(
		outputFile,
		copyResult.SourceAddress,
		copyResult.NewAddress,
		copyResult.CreateCommands,
		copyResult.UpdateCommands,
		copyResult.GroupMemberships,
		copyResult.RuleReferences,
		summary,
	); err != nil {
		return fmt.Errorf("failed to write copy commands: %w", err)
	}
	
	if !*silent {
		fmt.Printf("\nAddress copy analysis complete!\n")
		fmt.Printf("Commands generated: %d\n", copyResult.Summary.TotalCommands)
		fmt.Printf("Groups to update: %d\n", copyResult.Summary.GroupsToUpdate)
		fmt.Printf("Security rules to update: %d\n", copyResult.Summary.SecurityRulesToUpdate)
		fmt.Printf("NAT rules to update: %d\n", copyResult.Summary.NATRulesToUpdate)
		fmt.Printf("Results written to: outputs/%s\n", outputFile)
	}
	
	return nil
}

func init() {
	flag.Usage = func() {
		showHelpMessage()
	}
}