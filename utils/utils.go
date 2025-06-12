package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ipv4Pattern = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$`)
	ipv6Pattern = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$`)
)

func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	
	ip = strings.TrimSpace(ip)
	
	if !strings.Contains(ip, "/") {
		ip += "/32"
	}
	
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	
	return nil
}

func NormalizeIPAddress(ip string) (string, error) {
	if err := ValidateIPAddress(ip); err != nil {
		return "", err
	}
	
	ip = strings.TrimSpace(ip)
	
	if !strings.Contains(ip, "/") {
		if net.ParseIP(ip).To4() != nil {
			ip += "/32"
		} else {
			ip += "/128"
		}
	}
	
	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		return "", err
	}
	
	return ipNet.String(), nil
}

func ValidateFile(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filename)
		}
		return fmt.Errorf("cannot access file %s: %w", filename, err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", filename)
	}
	
	if info.Size() == 0 {
		return fmt.Errorf("file is empty: %s", filename)
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot open file %s: %w", filename, err)
	}
	defer file.Close()
	
	return nil
}

func EnsureDirectory(dirPath string) error {
	if dirPath == "" {
		return fmt.Errorf("directory path cannot be empty")
	}
	
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path for %s: %w", dirPath, err)
	}
	
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", absPath, err)
	}
	
	return nil
}

func FormatDuration(duration time.Duration) string {
	if duration < time.Second {
		return fmt.Sprintf("%d ms", duration.Milliseconds())
	}
	
	if duration < time.Minute {
		return fmt.Sprintf("%.1f sec", duration.Seconds())
	}
	
	if duration < time.Hour {
		return fmt.Sprintf("%.1f min", duration.Minutes())
	}
	
	return fmt.Sprintf("%.1f hrs", duration.Hours())
}

func FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(size)/float64(div), units[exp])
}

func FormatNumber(num int) string {
	if num < 1000 {
		return strconv.Itoa(num)
	}
	
	if num < 1000000 {
		return fmt.Sprintf("%.1fK", float64(num)/1000.0)
	}
	
	if num < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(num)/1000000.0)
	}
	
	return fmt.Sprintf("%.1fB", float64(num)/1000000000.0)
}

func ParseCommaSeparatedList(input string) []string {
	if input == "" {
		return nil
	}
	
	parts := strings.Split(input, ",")
	var result []string
	
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	return result
}

func SanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*]`)
	filename = invalidChars.ReplaceAllString(filename, "_")
	
	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		base := filename[:255-len(ext)]
		filename = base + ext
	}
	
	if filename == "" {
		filename = "unnamed"
	}
	
	return filename
}

func IsValidAddressName(name string) bool {
	if name == "" {
		return false
	}
	
	if len(name) > 127 {
		return false
	}
	
	validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return validNamePattern.MatchString(name)
}

func GetFileInfo(filename string) (map[string]interface{}, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"name":      info.Name(),
		"size":      info.Size(),
		"size_formatted": FormatFileSize(info.Size()),
		"modified":  info.ModTime(),
		"is_dir":    info.IsDir(),
		"readable":  isReadable(filename),
	}, nil
}

func isReadable(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()
	return true
}

func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	
	if maxLength <= 3 {
		return s[:maxLength]
	}
	
	return s[:maxLength-3] + "..."
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func GenerateTimestamp() string {
	return time.Now().Format("2006-01-02_15-04-05")
}

func GenerateOutputFilename(baseName string, extension string) string {
	timestamp := GenerateTimestamp()
	sanitizedName := SanitizeFilename(baseName)
	
	if extension != "" && !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	
	return fmt.Sprintf("%s_%s%s", sanitizedName, timestamp, extension)
}

func ParseBoolFlag(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "1" || value == "yes" || value == "on"
}

func SplitQuotedString(input string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false
	
	for i, char := range input {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				if current.Len() > 0 {
					result = append(result, strings.TrimSpace(current.String()))
					current.Reset()
				}
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
		
		if i == len(input)-1 && current.Len() > 0 {
			result = append(result, strings.TrimSpace(current.String()))
		}
	}
	
	return result
}

func CalculateProgress(current, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(current) / float64(total) * 100.0
}

func FormatProgress(current, total int) string {
	percentage := CalculateProgress(current, total)
	return fmt.Sprintf("%s/%s (%.1f%%)", 
		FormatNumber(current), 
		FormatNumber(total), 
		percentage)
}

func IsWritableDirectory(dirPath string) bool {
	testFile := filepath.Join(dirPath, ".write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

func CleanFilename(filename string) string {
	cleaned := strings.TrimSpace(filename)
	cleaned = strings.Trim(cleaned, "\"'")
	return SanitizeFilename(cleaned)
}