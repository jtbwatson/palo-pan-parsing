package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"palo-pan-parsing/models"
	"palo-pan-parsing/processor"
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
	
	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}
	
	mode := determineRunMode()
	
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
	fmt.Println("TUI mode not yet implemented - falling back to interactive mode")
	return runInteractiveMode(config)
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
	fmt.Println()
	
	fmt.Println("MODES:")
	fmt.Println("  Default (no flags)    Run in modern TUI mode (recommended)")
	fmt.Println("  --tui                 Run in modern TUI mode explicitly") 
	fmt.Println("  --verbose             Run in classic interactive mode")
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
	
	fmt.Println("OUTPUT:")
	fmt.Println("  Results are saved to YAML files in the output directory:")
	fmt.Println("  - <address>_results.yml         Main analysis results")
	fmt.Println("  - <address>_cleanup.yml         Redundant address cleanup commands")
	fmt.Println("  - <address>_add_to_groups_commands.yml  Address group commands")
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

func init() {
	flag.Usage = func() {
		showHelpMessage()
	}
}