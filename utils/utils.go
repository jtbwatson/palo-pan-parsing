package utils

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// FormatBytes formats byte size for human readability
func FormatBytes(bytes int64) string {
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

// FormatNumber formats large numbers with commas
func FormatNumber(n int) string {
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

// ParseAddressList parses comma-separated address input into a slice
func ParseAddressList(addressInput string) []string {
	var addresses []string
	for _, addr := range strings.Split(addressInput, ",") {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			addresses = append(addresses, trimmed)
		}
	}
	return addresses
}

// ClearScreen clears the terminal screen
func ClearScreen() {
	if runtime.GOOS == "windows" {
		fmt.Print("\033[H\033[2J")
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

// EnsureOutputsDir creates the outputs directory if it doesn't exist
func EnsureOutputsDir() error {
	outputsDir := "outputs"
	if _, err := os.Stat(outputsDir); os.IsNotExist(err) {
		return os.MkdirAll(outputsDir, 0755)
	}
	return nil
}

// ParseGroupMembers parses address group member list from definition string
func ParseGroupMembers(definition string) []string {
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
