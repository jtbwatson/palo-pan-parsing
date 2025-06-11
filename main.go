package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"palo-pan-parsing/models"
	"palo-pan-parsing/processor"
	"palo-pan-parsing/tui"
	"palo-pan-parsing/ui"
	"palo-pan-parsing/utils"
)

// main function and CLI setup
func main() {
	var (
		addressFlag   = flag.String("a", "", "Address name to search for (comma-separated for multiple)")
		logfile       = flag.String("l", "default.log", "Path to the log file")
		outputFlag    = flag.String("o", "", "Output file name")
		configFile    = flag.String("c", "", "Path to configuration file")
		deviceGroup   = flag.String("dg", "", "Device group to scan for duplicate address objects")
		verbose       = flag.Bool("verbose", false, "Run in verbose interactive mode (classic)")
		help          = flag.Bool("h", false, "Show help")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PAN Log Parser Tool - Analyze Palo Alto Networks configuration logs\n\n")
		fmt.Fprintf(os.Stderr, "A high-performance tool for analyzing Palo Alto Networks configuration logs\n")
		fmt.Fprintf(os.Stderr, "to find references to specific IP address objects and detect duplicate addresses.\n")
		fmt.Fprintf(os.Stderr, "Supports both direct and indirect references through address groups, security rules,\n")
		fmt.Fprintf(os.Stderr, "NAT rules, and device groups.\n\n")
		fmt.Fprintf(os.Stderr, "By default, runs in modern TUI mode. Use --verbose for classic interactive mode.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *deviceGroup != "" {
		runDeviceGroupDuplicateMode(*deviceGroup, *logfile, *outputFlag)
	} else if *verbose {
		runInteractiveMode()
	} else if *addressFlag != "" || *configFile != "" {
		runCommandLineMode(*addressFlag, *logfile, *outputFlag, *configFile)
	} else {
		// Default to TUI mode when no specific arguments provided
		runTUIMode()
	}
}

func runDeviceGroupDuplicateMode(deviceGroup, logfile, outputFlag string) {
	fmt.Printf(ui.ColorInfo("Scanning device group '%s' for duplicate address objects...\n"), deviceGroup)
	fmt.Printf(ui.ColorInfo("Loading configuration file: %s\n"), logfile)

	processor := processor.NewPANLogProcessor()
	if err := processor.FindDuplicateAddressesInDeviceGroup(logfile, deviceGroup); err != nil {
		fmt.Printf(ui.ColorError("Error processing file: %v\n"), err)
		return
	}

	// Generate output file name
	outputFile := outputFlag
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s_duplicates.yml", deviceGroup)
	}

	fmt.Printf(ui.ColorSuccess("Duplicate address scan complete for device group '%s'\n"), deviceGroup)
	fmt.Printf(ui.ColorInfo("Results saved to: %s\n"), ui.ColorHighlight("outputs/"+outputFile))
}

func runTUIMode() {
	if err := tui.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func runInteractiveMode() {
	panProcessor := processor.NewPANLogProcessor()
	ui.RunInteractiveMode(panProcessor, func(address string, proc *processor.PANLogProcessor, interactive bool, output string, configFile string) bool {
		return ProcessAddress(address, proc, interactive, output, configFile)
	})
}

func runCommandLineMode(addressFlag, logfile, outputFlag, configFile string) {
	var config map[string]interface{}

	// Read config file if provided
	if configFile != "" {
		if data, err := os.ReadFile(configFile); err == nil {
			json.Unmarshal(data, &config)
		} else {
			fmt.Printf(ui.ColorError("Error reading config file: %v\n"), err)
			return
		}
	}

	// Get log file
	if logfile == "" {
		if configLogFile, ok := config["log_file"].(string); ok {
			logfile = configLogFile
		} else {
			logfile = ui.PromptInput("Enter log file path [default.log]", "default.log")
		}
	}

	// Get addresses
	var addresses []string
	if addressFlag != "" {
		addresses = utils.ParseAddressList(addressFlag)
	} else if configAddr, ok := config["address_name"]; ok {
		switch v := configAddr.(type) {
		case string:
			addresses = utils.ParseAddressList(v)
		case []interface{}:
			for _, addr := range v {
				if s, ok := addr.(string); ok {
					addresses = append(addresses, strings.TrimSpace(s))
				}
			}
		}
	} else {
		addressInput := ui.PromptInput("Enter the address name (comma-separated for multiple)", "")
		addresses = utils.ParseAddressList(addressInput)
	}

	if len(addresses) == 0 {
		fmt.Println(ui.ColorError("No addresses specified"))
		return
	}

	fmt.Printf(ui.ColorInfo("Loading configuration file: %s\n"), logfile)
	fmt.Printf(ui.ColorInfo("Analyzing %d address object(s): %s\n"), len(addresses), strings.Join(addresses, ", "))

	// Process file
	processor := processor.NewPANLogProcessor()
	if err := processor.ProcessFileSinglePass(logfile, addresses); err != nil {
		fmt.Printf(ui.ColorError("Error processing file: %v\n"), err)
		return
	}

	// Process results
	if len(addresses) == 1 {
		outputFile := outputFlag
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s_results.yml", addresses[0])
		}
		ProcessAddress(addresses[0], processor, false, outputFile, logfile)
	} else {
		for _, address := range addresses {
			ProcessAddress(address, processor, false, "", logfile)
		}
	}
}

// ProcessAddress processes a single address and generates results
func ProcessAddress(address string, panProcessor *processor.PANLogProcessor, interactiveMode bool, outputOverride string, configFile string) bool {
	if interactiveMode {
		ui.PrintSectionHeader(fmt.Sprintf("Analyzing Address Object: %s", address))
	}

	result, exists := panProcessor.Results[address]
	if !exists || len(result.MatchingLines) == 0 {
		fmt.Printf(ui.ColorWarning("  WARNING: No matches found for '%s'\n"), address)
		if interactiveMode {
			ui.PrintSectionFooter()
		}
		return false
	}

	if interactiveMode {
		fmt.Printf(ui.ColorSuccess("  Discovered %s configuration lines\n"), ui.ColorHighlight(utils.FormatNumber(len(result.MatchingLines))))
		fmt.Println(ui.ColorInfo("  Processing relationships and dependencies..."))
	}

	// Format results
	itemsDict := panProcessor.FormatResults(address)

	// Get output file name
	outputFile := outputOverride
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s_results.yml", address)
	}

	if interactiveMode {
		fmt.Printf(ui.ColorInfo("  Generating comprehensive report: %s\n"), ui.ColorHighlight("outputs/"+outputFile))
	}

	err := utils.WriteResults(outputFile, address, result.MatchingLines, itemsDict)
	if err != nil {
		fmt.Printf(ui.ColorError("Error writing results: %v\n"), err)
		return false
	}

	if interactiveMode {
		fmt.Println(ui.ColorSuccess("  Analysis complete! Report generated successfully"))
		ui.PrintSectionFooter()
		ui.PrintSectionHeader("Discovery Summary")
	} else {
		fmt.Printf(ui.ColorSuccess("Results written to %s\n"), outputFile)
	}

	// Enhanced summary
	ui.PrintResultsSummary("Device Groups", len(itemsDict.DeviceGroups))
	ui.PrintResultsSummary("Direct Security Rules", len(itemsDict.DirectSecurityRules))
	ui.PrintResultsSummary("Indirect Security Rules (via Address Groups)", len(itemsDict.IndirectSecurityRules))
	ui.PrintResultsSummary("Address Groups", len(itemsDict.AddressGroups))
	ui.PrintResultsSummary("NAT Rules", len(itemsDict.NATRules))
	ui.PrintResultsSummary("Service Groups", len(itemsDict.ServiceGroups))
	ui.PrintResultsSummary("Redundant Addresses", len(itemsDict.RedundantAddresses))

	if interactiveMode {
		ui.PrintSectionFooter()
		totalFindings := len(itemsDict.DeviceGroups) + len(itemsDict.DirectSecurityRules) +
			len(itemsDict.IndirectSecurityRules) + len(itemsDict.AddressGroups) +
			len(itemsDict.NATRules) + len(itemsDict.ServiceGroups) + len(itemsDict.RedundantAddresses)

		if totalFindings > 0 {
			fmt.Printf(ui.ColorSuccess("\nAnalysis revealed %s total configuration items!\n"), ui.ColorHighlight(utils.FormatNumber(totalFindings)))
			fmt.Printf(ui.ColorInfo("Detailed report saved to: %s\n"), ui.ColorHighlight("outputs/"+outputFile))

			// Offer to generate commands for adding new address to discovered groups
			if len(itemsDict.AddressGroups) > 0 {
				ui.PromptAddressGroupCopy(address, itemsDict.AddressGroups, utils.WriteAddressGroupCommands)
			}

			// Offer to generate cleanup commands for redundant addresses
			if len(itemsDict.RedundantAddresses) > 0 {
				ui.PromptRedundantAddressCleanup(
					address,
					itemsDict.RedundantAddresses,
					func(targetAddr string) (*models.CleanupAnalysis, error) {
						return panProcessor.AnalyzeRedundantAddressCleanupWithReparse(configFile, targetAddr)
					},
					panProcessor.GenerateCleanupCommands,
					utils.WriteCleanupCommands,
				)
			}
		} else {
			fmt.Println(ui.ColorWarning("No configuration relationships found for this address object."))
		}
	}

	return true
}
