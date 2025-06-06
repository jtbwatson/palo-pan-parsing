package ui

import (
	"fmt"
	"strings"

	"github.com/jtbwatson/palo-pan-parsing/models"
	"github.com/jtbwatson/palo-pan-parsing/processor"
	"github.com/jtbwatson/palo-pan-parsing/utils"
)

// PromptInput prompts the user for input with a default value
func PromptInput(prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf(ColorSection("%s [default: %s]: "), prompt, ColorHighlight(defaultValue))
	} else {
		fmt.Printf(ColorSection("%s: "), prompt)
	}

	var input string
	fmt.Scanln(&input)

	if input == "" && defaultValue != "" {
		return defaultValue
	}
	return input
}

// RunInteractiveMode runs the interactive mode for the application
func RunInteractiveMode(panProcessor *processor.PANLogProcessor, processAddress func(string, *processor.PANLogProcessor, bool, string) bool) {
	utils.ClearScreen()
	PrintBanner()
	PrintSectionHeader("Configuration Analysis Setup")
	fmt.Println(ColorInfo("  Welcome to the advanced PAN configuration analyzer!"))
	fmt.Println(ColorInfo("  This tool will help you discover complex relationships"))
	fmt.Println(ColorInfo("  in your Palo Alto Networks configuration logs."))
	PrintSectionFooter()

	// Get log file
	PrintSectionHeader("Log File Selection")
	defaultLog := "default.log"
	configFile := PromptInput(fmt.Sprintf("Enter path to your PAN configuration log [%s]", defaultLog), defaultLog)
	PrintSectionFooter()

	// Get addresses
	PrintSectionHeader("Address Object Selection")
	fmt.Println(ColorInfo("  You can analyze multiple address objects simultaneously"))
	fmt.Println(ColorInfo("  For multiple addresses, separate them with commas"))
	fmt.Printf(ColorHighlight("  Example: %s\n"), "webserver1,dbserver2,jumphost3")
	fmt.Println()

	var addressInput string
	for addressInput == "" {
		addressInput = PromptInput("Enter address object name(s) to analyze", "")
		if addressInput == "" {
			fmt.Println(ColorError("  At least one address name is required!"))
		}
	}

	addresses := utils.ParseAddressList(addressInput)
	PrintSectionFooter()

	// Run analysis
	PrintSectionHeader("Configuration Analysis Engine")
	fmt.Printf(ColorInfo("  Loading configuration file: %s\n"), ColorHighlight(configFile))
	fmt.Printf(ColorInfo("  Analyzing %s address object(s): %s\n"),
		ColorHighlight(utils.FormatNumber(len(addresses))),
		ColorHighlight(strings.Join(addresses, ", ")))
	fmt.Println(ColorInfo("  Initializing deep relationship analysis..."))

	// Process file once for all addresses
	if err := panProcessor.ProcessFileSinglePass(configFile, addresses); err != nil {
		fmt.Printf(ColorError("Error processing file: %v\n"), err)
		return
	}

	fmt.Println(ColorSuccess("  Deep relationship analysis complete!"))
	PrintSectionFooter()

	// Process results for each address
	if len(addresses) > 1 {
		PrintSectionHeader(fmt.Sprintf("Multi-Address Analysis (%d objects)", len(addresses)))
		fmt.Printf(ColorInfo("  Ready to process: %s\n"), ColorHighlight(strings.Join(addresses, ", ")))
		fmt.Println(ColorInfo("  Choose your preferred output format:"))
		fmt.Printf(ColorInfo("     • %s: Combined report with all results\n"), ColorHighlight("Single file"))
		fmt.Printf(ColorInfo("     • %s: Individual reports for each address\n"), ColorHighlight("Multiple files"))
		fmt.Println()

		useSingleFile := PromptInput("Use a single combined output file? (y/n)", "n") == "y"
		PrintSectionFooter()

		if useSingleFile {
			outputFile := "multiple_addresses_results.yml"
			resultsCount := 0
			for _, address := range addresses {
				if processAddress(address, panProcessor, true, outputFile) {
					resultsCount++
				}
			}

			if resultsCount > 0 {
				fmt.Printf(ColorSuccess("\nProcessed %s out of %s addresses.\n"),
					ColorHighlight(utils.FormatNumber(resultsCount)),
					ColorHighlight(utils.FormatNumber(len(addresses))))
				fmt.Printf(ColorSuccess("All results written to: %s\n"), ColorHighlight("outputs/"+outputFile))
			}
		} else {
			resultsCount := 0
			var outputFiles []string

			for _, address := range addresses {
				if processAddress(address, panProcessor, true, "") {
					resultsCount++
					outputFiles = append(outputFiles, fmt.Sprintf("outputs/%s_results.yml", address))
				}
			}

			if resultsCount > 0 {
				fmt.Printf(ColorSuccess("\nProcessed %s out of %s addresses.\n"),
					ColorHighlight(utils.FormatNumber(resultsCount)),
					ColorHighlight(utils.FormatNumber(len(addresses))))
				fmt.Println(ColorSuccess("Results written to individual files:"))
				for _, outputFile := range outputFiles {
					fmt.Printf(ColorListItem("  - %s\n"), ColorHighlight(outputFile))
				}
			}
		}
	} else {
		// Single address
		processAddress(addresses[0], panProcessor, true, "")
	}

	PrintSectionHeader("Analysis Complete")
	fmt.Println(ColorSuccess("  Analysis session completed successfully!"))
	fmt.Println(ColorInfo("  Your PAN configuration analysis is ready for review"))
	fmt.Println(ColorDimText("  Tool: PAN Log Parser v2.0 (Go Edition) | Advanced Configuration Analysis"))
	PrintSectionFooter()
	fmt.Println(ColorTitle("\nThank you for using the PAN Log Parser Tool!"))
}

// PromptAddressGroupCopy offers to generate commands for adding a new address to discovered groups
func PromptAddressGroupCopy(originalAddress string, addressGroups []models.AddressGroup, writeCommands func(string, string, string, []string, []models.AddressGroup) error) {
	fmt.Println()
	PrintSectionHeader("Address Group Configuration Helper")
	fmt.Printf(ColorInfo("  Found %s address group(s) containing '%s'\n"),
		ColorHighlight(utils.FormatNumber(len(addressGroups))), originalAddress)
	fmt.Println(ColorInfo("  Would you like to generate commands to add a new address object"))
	fmt.Println(ColorInfo("     to these same groups?"))
	fmt.Println()

	response := PromptInput("Generate add-to-groups commands? (y/n)", "n")
	if response != "y" && response != "Y" {
		PrintSectionFooter()
		return
	}

	var newAddressName string
	for newAddressName == "" {
		newAddressName = PromptInput("Enter new address object name", "")
		if newAddressName == "" {
			fmt.Println(ColorError("  Address name is required!"))
		}
	}

	fmt.Println()
	fmt.Printf(ColorSuccess("  Generating commands to add '%s' to discovered groups...\n"), newAddressName)
	fmt.Println()

	// Generate commands for each address group
	var commands []string
	commandCount := 0
	for _, group := range addressGroups {
		var command string
		if group.Context == "shared" {
			command = fmt.Sprintf("set shared address-group %s static %s", group.Name, newAddressName)
		} else if group.Context == "device-group" {
			command = fmt.Sprintf("set device-group %s address-group %s static %s",
				group.DeviceGroup, group.Name, newAddressName)
		}

		if command != "" {
			commandCount++
			commands = append(commands, command)
		}
	}

	if commandCount > 0 {
		// Write commands to YAML file
		outputFile := fmt.Sprintf("%s_add_to_groups_commands.yml", newAddressName)
		err := writeCommands(outputFile, originalAddress, newAddressName, commands, addressGroups)
		if err != nil {
			fmt.Printf(ColorError("  Error writing commands file: %v\n"), err)
		} else {
			fmt.Println()
			fmt.Printf(ColorSuccess("  Generated %s command(s) successfully!\n"), ColorHighlight(utils.FormatNumber(commandCount)))
			fmt.Printf(ColorInfo("  Commands saved to: %s\n"), ColorHighlight(outputFile))
			fmt.Printf(ColorInfo("  Copy these commands to add '%s' to the same groups as '%s'\n"),
				newAddressName, originalAddress)
		}
	}

	PrintSectionFooter()
}