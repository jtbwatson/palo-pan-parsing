package ui

import (
	"fmt"
	"strings"
)

// ANSI color codes for terminal output
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
)

// Color helper functions
func ColorTitle(text string) string     { return ColorCyan + ColorBold + text + ColorReset }
func ColorSuccess(text string) string   { return ColorGreen + ColorBold + text + ColorReset }
func ColorError(text string) string     { return ColorRed + ColorBold + text + ColorReset }
func ColorWarning(text string) string   { return ColorYellow + text + ColorReset }
func ColorInfo(text string) string      { return ColorWhite + text + ColorReset }
func ColorSection(text string) string   { return ColorBlue + ColorBold + text + ColorReset }
func ColorHighlight(text string) string { return ColorCyan + text + ColorReset }
func ColorSecondary(text string) string { return ColorMagenta + text + ColorReset }
func ColorDimText(text string) string   { return ColorDim + ColorWhite + text + ColorReset }
func ColorListItem(text string) string  { return ColorGreen + text + ColorReset }

// PrintBanner displays the application banner
func PrintBanner() {
	fmt.Println(ColorTitle("    ╔══════════════════════════════════════════════════╗"))
	fmt.Print(ColorTitle("    ║  PAN Log Parser Tool "))
	fmt.Print(ColorHighlight("v2.0"))
	fmt.Println(ColorTitle("                        ║"))
	fmt.Print(ColorTitle("    ║  "))
	fmt.Print(ColorInfo("Advanced Palo Alto Networks Configuration       "))
	fmt.Println(ColorTitle("║"))
	fmt.Print(ColorTitle("    ║  "))
	fmt.Print(ColorInfo("Analysis & Address Object Discovery Tool        "))
	fmt.Println(ColorTitle("║"))
	fmt.Println(ColorTitle("    ╚══════════════════════════════════════════════════╝"))
	fmt.Println(ColorDimText("    Ready to analyze your PAN configurations with precision!"))
	fmt.Println(ColorDimText("    Supports nested address groups, security rules & more"))
}

// PrintSectionHeader prints a formatted section header
func PrintSectionHeader(title string) {
	headerContent := fmt.Sprintf("─ %s", title)
	remainingWidth := 60 - len(headerContent)
	if remainingWidth < 0 {
		remainingWidth = 0
	}
	dashLine := strings.Repeat("─", remainingWidth)
	fmt.Printf(ColorSection("┌%s%s┐\n"), headerContent, dashLine)
}

// PrintSectionFooter prints a formatted section footer
func PrintSectionFooter() {
	dashLine := strings.Repeat("─", 59)
	fmt.Printf(ColorSection("└%s┘\n"), dashLine)
}

// PrintResultsSummary prints a summary of results for a category
func PrintResultsSummary(category string, count int) {
	if count > 0 {
		fmt.Printf(ColorSuccess("  %s: %s found\n"), category, ColorHighlight(fmt.Sprintf("%d", count)))
	} else {
		fmt.Printf(ColorDimText("  %s: none found\n"), category)
	}
}