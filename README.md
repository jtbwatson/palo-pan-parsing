# PAN Configuration Parser

A high-performance Go-based command-line tool for analyzing Palo Alto Networks XML configuration files. Quickly find references to specific IP address objects through direct and indirect relationships across security rules, address groups, NAT rules, and device groups.

## Features

- **Fast XML Processing**: Streaming parser optimized for large Panorama configuration files
- **Comprehensive Analysis**: Finds direct and indirect address references through groups and rules
- **Redundant Address Detection**: Identifies duplicate addresses with same IP/netmask
- **Smart Scope Analysis**: Optimizes address placement across device groups and shared scopes
- **Modern TUI Interface**: Terminal user interface with multi-select operations and progress tracking
- **YAML Output**: Clean, structured results without unnecessary quotes or clutter
- **Memory Efficient**: In-memory processing with progress reporting for large files
- **Offline Ready**: All dependencies vendored for air-gapped/offline deployment

## Quick Start

### Installation
```bash
# One-step installation (recommended)
make install

# Manual build
make build
```

### Basic Usage
```bash
# Modern TUI mode (default - recommended)
./pan-parser

# Classic interactive mode
./pan-parser --verbose

# Command line mode
./pan-parser -a linux1 -l config.xml -o results.yml
```

## Output Examples

### Address Analysis Results
```yaml
# linux1_results.yml
analysis_info:
  target_address: linux1
  config_file: panos.xml
  total_references: 2

address_objects:
  - name: linux1
    ip_netmask: 172.16.3.2/32
    scope: shared

direct_security_rules:
  internal-to-linux:
    scope: shared
    action: allow
    from:
      - trust
    to:
      - dmz
    destination:
      - linux1

redundant_addresses:
  - source_address: linux1
    duplicate_address: llinux1
    ip_value: 172.16.3.2/32
```

### Address Group Commands
```yaml
# linux1_add_to_groups_commands.yml
analysis_info:
  original_address: linux1
  new_address: newServer1
  ip_address: 10.0.1.100/32
  groups_found: 2

generated_commands:
  - set shared address newServer1 ip-netmask 10.0.1.100/32
  - set shared address-group web_servers static newServer1
  - set shared address-group production_servers static newServer1
```

## Interface Modes

### 1. Modern TUI (Default)
- **Terminal User Interface**: Professional blue/purple theme with Bubble Tea framework
- **Multi-State Navigation**: 10-state workflow from file input to completion
- **Multi-Select Operations**: Checkbox-based selection for post-analysis actions
- **Real-time Progress**: Background processing with status updates
- **Session Tracking**: Color-coded history with intelligent formatting

### 2. Interactive Mode
```bash
./pan-parser --verbose
```
- **Guided Experience**: Step-by-step prompts with validation
- **Color Output**: Formatted terminal display with status indicators
- **Input Validation**: Real-time checking of file paths and address names

### 3. Command Line Mode
```bash
# Single address analysis
./pan-parser -a server1 -l config.xml

# Multiple addresses
./pan-parser -a "server1,server2,server3" -l config.xml

# Custom output location
./pan-parser -a server1 -l config.xml -o /path/to/results.yml
```

## Architecture

### Core Components
- **Streaming Parser**: Memory-efficient XML processing using Go's standard library
- **Modular Processor**: Concurrent event processing with worker pools
- **Analysis Engine**: Deep relationship analysis across configuration elements
- **Redundancy Analyzer**: Smart duplicate detection with IP matching
- **Scope Optimizer**: Intelligent placement recommendations for efficiency

### Performance Features
- **In-Memory Processing**: Entire configuration loaded for faster analysis
- **Pre-Compiled Regex**: All patterns compiled once at startup
- **Progress Reporting**: Shows progress every 200K-500K elements
- **Concurrent Processing**: Worker pools for parallel event handling
- **Memory Efficient**: Optimized data structures and garbage collection

### File Structure
```
├── main.go                    # CLI interface and orchestration
├── models/                    # Data structures and types
│   ├── address.go            # Address objects and groups
│   ├── rules.go              # Security and NAT rules
│   └── results.go            # Analysis results and statistics
├── processor/                 # Core processing engine
│   ├── processor.go          # Main processing coordination
│   ├── address_analyzer.go   # Relationship analysis
│   └── redundancy_analyzer.go # Duplicate detection
├── parser/                    # XML parsing and conversion
│   ├── xml_reader.go         # Streaming XML processor
│   └── element_converter.go  # XML to model conversion
├── tui/                       # Modern terminal interface
│   ├── tui.go                # TUI application entry
│   ├── models.go             # State management
│   └── styles.go             # Visual styling
├── ui/                        # Classic interactive interface
│   ├── interactive.go        # Guided user experience
│   └── display.go            # Terminal formatting
└── utils/                     # Utility functions
    ├── writer.go             # YAML output generation
    └── utils.go              # File operations and validation
```

## Advanced Features

### Redundant Address Cleanup
- **Smart Detection**: Identifies addresses with identical IP/netmask values
- **Scope Optimization**: Promotes addresses to shared scope when beneficial
- **Safe Commands**: Generates step-by-step cleanup commands with rule updates
- **Usage Analysis**: Deep re-parsing to ensure comprehensive relationship mapping

### Address Group Management
- **Intelligent Scope Selection**: Automatically determines optimal scope for new addresses
- **Custom IP Assignment**: User-specified IP addresses with CIDR notation support
- **Command Generation**: Creates both address objects and group membership commands
- **Multi-Group Support**: Handles addresses that belong to multiple groups

### Configuration Analysis
- **Device Group Relationships**: Tracks scope boundaries and inheritance
- **Nested Group Analysis**: Handles complex group hierarchies
- **Cross-Reference Detection**: Identifies shared usage patterns
- **Security Rule Context**: Determines how addresses are used (source, destination, etc.)

## Output Files

All results are saved to the `outputs/` directory:
- **`{address}_results.yml`**: Complete analysis with structured sections
- **`{address}_add_to_groups_commands.yml`**: Generated CLI commands for adding addresses to groups
- **`{address}_cleanup.yml`**: Commands for cleaning up redundant addresses
- **`multiple_addresses_results.yml`**: Combined analysis for multiple addresses

## Requirements

- **Go 1.23+**: Required for build and execution
- **Memory**: Recommended 2GB+ RAM for large configuration files
- **Storage**: Minimal disk space for output files
- **Terminal**: 80+ character width recommended for optimal TUI experience

## Configuration File Support

Supports standard Palo Alto Networks XML configuration exports:
- **Panorama**: Full device group hierarchies and shared objects
- **Firewall**: Local configuration with device-specific objects
- **Partial Exports**: Address objects, groups, security rules, and NAT rules

## Development

### Build Commands
```bash
make build          # Build binary only
make install        # Build and install globally
make clean          # Remove build artifacts
make help           # Show all available commands
```

### Testing
```bash
# Run with test configuration
./pan-parser -a linux1 -l panos-test.xml

# TUI mode testing
./pan-parser --tui

# Interactive mode testing
./pan-parser --verbose
```

## Offline/Air-gapped Deployment

The PAN parser is designed for offline and air-gapped environments with all dependencies fully vendored.

### Preparation
```bash
# Vendor all dependencies
make vendor

# Test offline capabilities
make test-offline

# Prepare for air-gapped deployment
make airgap-prep
```

### Offline Build
```bash
# Build using only vendored dependencies
go build -mod=vendor -o pan-parser main.go

# Or use Makefile (already configured for vendor mode)
make build
```

### Verification
```bash
# Verify all dependencies are vendored
go mod verify

# Test with network disabled (simulates air-gapped)
GOPROXY=off go build -mod=vendor -o pan-parser main.go
```

### Deployment
1. Copy the entire project directory to the target system
2. Ensure Go 1.23+ is installed on the target system
3. Run `make build` or `go build -mod=vendor`
4. No internet access required during build or runtime

The project includes 19 vendored modules covering all Bubble Tea TUI dependencies and Go standard library extensions.