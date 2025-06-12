package models

import (
	"regexp"
	"time"
)

type Config struct {
	LogFile        string        `json:"log_file" yaml:"log_file"`
	OutputFile     string        `json:"output_file" yaml:"output_file"`
	TargetAddress  string        `json:"target_address" yaml:"target_address"`
	Addresses      []string      `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Silent         bool          `json:"silent" yaml:"silent"`
	Verbose        bool          `json:"verbose" yaml:"verbose"`
	TUI            bool          `json:"tui" yaml:"tui"`
	ProgressEvery  int           `json:"progress_every" yaml:"progress_every"`
	BufferSize     int           `json:"buffer_size" yaml:"buffer_size"`
	MaxWorkers     int           `json:"max_workers" yaml:"max_workers"`
	Timeout        time.Duration `json:"timeout" yaml:"timeout"`
}

type XMLPatterns struct {
	AddressEntry       *regexp.Regexp
	AddressGroupEntry  *regexp.Regexp
	SecurityRuleEntry  *regexp.Regexp
	NATRuleEntry       *regexp.Regexp
	DeviceGroupEntry   *regexp.Regexp
	IPNetmask          *regexp.Regexp
	IPRange            *regexp.Regexp
	FQDN              *regexp.Regexp
	Member            *regexp.Regexp
	Source            *regexp.Regexp
	Destination       *regexp.Regexp
	QuotedName        *regexp.Regexp
}

type ProcessingContext struct {
	CurrentDeviceGroup string
	CurrentScope       string
	LineNumber         int
	ChunkNumber        int
	TotalChunks        int
	ProcessingPhase    string
}

type Scope struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	DeviceGroup string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
}

var DefaultConfig = Config{
	ProgressEvery: 200000,
	BufferSize:    65536,
	MaxWorkers:    4,
	Timeout:       30 * time.Minute,
	Silent:        false,
	Verbose:       false,
	TUI:           true,
}

func NewXMLPatterns() *XMLPatterns {
	return &XMLPatterns{
		AddressEntry:      regexp.MustCompile(`<address>\s*<entry name="([^"]+)">`),
		AddressGroupEntry: regexp.MustCompile(`<address-group>\s*<entry name="([^"]+)">`),
		SecurityRuleEntry: regexp.MustCompile(`<security>\s*<rules>\s*<entry name="([^"]+)">`),
		NATRuleEntry:      regexp.MustCompile(`<nat>\s*<rules>\s*<entry name="([^"]+)">`),
		DeviceGroupEntry:  regexp.MustCompile(`<device-group>\s*<entry name="([^"]+)">`),
		IPNetmask:         regexp.MustCompile(`<ip-netmask>([^<]+)</ip-netmask>`),
		IPRange:           regexp.MustCompile(`<ip-range>([^<]+)</ip-range>`),
		FQDN:             regexp.MustCompile(`<fqdn>([^<]+)</fqdn>`),
		Member:           regexp.MustCompile(`<member>([^<]+)</member>`),
		Source:           regexp.MustCompile(`<source>\s*<member>([^<]+)</member>`),
		Destination:      regexp.MustCompile(`<destination>\s*<member>([^<]+)</member>`),
		QuotedName:       regexp.MustCompile(`"([^"]+)"`),
	}
}

func (c *Config) Validate() error {
	if c.LogFile == "" {
		return &ConfigError{Field: "log_file", Message: "log file path is required"}
	}
	
	if c.TargetAddress == "" && len(c.Addresses) == 0 {
		return &ConfigError{Field: "target_address", Message: "target address or addresses list is required"}
	}
	
	if c.ProgressEvery <= 0 {
		c.ProgressEvery = DefaultConfig.ProgressEvery
	}
	
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultConfig.BufferSize
	}
	
	if c.MaxWorkers <= 0 {
		c.MaxWorkers = DefaultConfig.MaxWorkers
	}
	
	if c.Timeout <= 0 {
		c.Timeout = DefaultConfig.Timeout
	}
	
	return nil
}

type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "config error in field '" + e.Field + "': " + e.Message
}

func NewProcessingContext() *ProcessingContext {
	return &ProcessingContext{
		CurrentScope:    "shared",
		LineNumber:      0,
		ChunkNumber:     0,
		TotalChunks:     0,
		ProcessingPhase: "initialization",
	}
}

func (ctx *ProcessingContext) UpdateScope(deviceGroup string) {
	if deviceGroup != "" {
		ctx.CurrentDeviceGroup = deviceGroup
		ctx.CurrentScope = "device-group"
	} else {
		ctx.CurrentDeviceGroup = ""
		ctx.CurrentScope = "shared"
	}
}

func (ctx *ProcessingContext) GetFullScope() string {
	if ctx.CurrentScope == "shared" {
		return "shared"
	}
	return "device-group:" + ctx.CurrentDeviceGroup
}

func IsSharedScope(scope string) bool {
	return scope == "shared"
}

func IsDeviceGroupScope(scope string) bool {
	return scope != "shared" && scope != ""
}

func ExtractDeviceGroupFromScope(scope string) string {
	if IsDeviceGroupScope(scope) && len(scope) > 13 {
		return scope[13:]
	}
	return ""
}