# PAN Configuration Log Parser (Go Edition)

A high-performance, modular Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. Features a clean architecture with separated concerns and optimized for large Panorama configuration files with millions of lines.

## What It Does

This tool parses PAN configuration exports/logs to help network administrators understand how IP address objects are being used across their firewall configuration. It identifies:

- **Direct References**: Security rules and NAT rules that explicitly reference an address object
- **Indirect References**: Security rules that reference address groups containing the target address  
- **Address Group Memberships**: All address groups that contain the specified address object
- **Device Group Context**: Which device groups contain rules using the address
- **Redundant Address Detection**: Finds other address objects with the same IP/netmask
- **Nested Address Groups**: Analyzes complex address group hierarchies

## Architecture & Performance Features

### Modular Design
- **Clean Package Structure**: Separated concerns across focused packages (processor, models, ui, utils)
- **Type-Safe Models**: Well-defined data structures in dedicated models package
- **Separated UI Layer**: Independent UI package supporting both interactive and command-line modes
- **Utility Functions**: Reusable utilities for formatting, parsing, and file operations

### Performance Optimizations
- **Memory-Optimized Processing**: Loads entire configuration into memory for faster analysis
- **Pre-Compiled Regex**: All patterns compiled once at startup for maximum performance
- **Progress Reporting**: Real-time progress updates for large files (200K-500K line intervals)
- **Zero Dependencies**: Uses only Go standard library - no external dependencies required
- **Efficient Data Structures**: Native Go maps and slices for optimal performance

## Installation

### Prerequisites
- Go 1.20 or later (as specified in go.mod)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing

# Build the application (creates modular binary)
npm run setup
# or manually: go build -o pan-parser main.go

# Quick build without npm
npm run build

# Verify installation and show help
npm run test
# or: ./pan-parser -h
```

## Usage

### TUI Mode (Recommended - NEW!)
```bash
./pan-parser --tui
# or via npm: npm run tui
```
The new **Terminal User Interface (TUI)** provides a modern, intuitive experience with:
- **Clean visual interface** with professional blue/purple color scheme
- **Multi-select operations** - Select and execute multiple post-analysis operations
- **Guided workflow** - File selection → Address input → Analysis → Operations menu
- **Real-time feedback** - Progress indicators and status messages
- **Silent processing** - No output leakage outside the TUI window

### Interactive Mode (Classic)
```bash
./pan-parser -i
# or via npm: npm run parser

# Quick interactive run
npm run run
```
The classic interactive mode provides a guided command-line experience with colored terminal output, progress reporting, and prompts for all required inputs.

### Command Line Mode
```bash
# Search for a single address
./pan-parser -a web-server-01 -l firewall-config.log -o results.yml

# Search for multiple addresses (comma-separated)
./pan-parser -a "web-server-01,db-server-02,mail-server" -l config.log

# Use a configuration file
./pan-parser -c config.json

# Show help
./pan-parser -h
```

### Command Line Options
- `-a`: Address name(s) to search for (comma-separated for multiple)
- `-l`: Path to the PAN configuration log file (default: "default.log")
- `-o`: Output file name (optional)
- `-c`: Path to JSON configuration file
- `-i`: Run in interactive mode (classic)
- `--tui`: Run in TUI mode (modern interface)
- `-h`: Show help

## Input Format

The tool expects Palo Alto Networks configuration export files containing commands like:
```
set device-group DG-Production security rules "Allow-Web-Traffic" source "web-servers"
set shared address-group "web-servers" static [ web-server-01 web-server-02 ]
set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
```

## TUI Interface Features

The modern Terminal User Interface provides an intuitive workflow with multiple screens:

### 🎮 **Navigation Controls**
- **Arrow Keys / j,k** - Navigate menu options
- **Space** - Toggle selection (checkboxes)
- **Enter** - Confirm selection or execute action
- **Esc** - Go back to previous screen
- **Ctrl+C / q** - Quit application

### 📱 **Screen Flow**
1. **Main Menu** - Choose "Analyze Configuration File" or "Exit"
2. **File Selection** - Enter path to PAN configuration file (with auto-completion)
3. **Address Input** - Enter single or multiple address names (comma-separated)
4. **Processing** - Real-time progress with silent background processing
5. **Additional Options** - Multi-select operations menu:
   - ☑️ Generate Address Group Commands
   - ☑️ Generate Cleanup Commands
   - Execute Selected Operations
   - Return to Main Menu

### ✨ **Key Benefits**
- **Multi-Select Operations** - Run multiple post-analysis operations without restarting
- **Perfect Alignment** - Clean, professional interface with consistent spacing
- **Smart Navigation** - Automatically skips separator lines
- **Silent Processing** - No output interference with the TUI display
- **Real-time Feedback** - Status messages and operation completion notifications

## Output Format

Results are saved in a structured YAML-like format with sections for:

```yaml
# 🔥 PAN Log Parser Analysis Report v2.0 (Go Edition)
# 🎯 Target Address Object: web-server-01
# 📊 Configuration Lines Found: 15
# 🔗 Total Relationships: 8

# 📋 MATCHING CONFIGURATION LINES
  1. set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
  2. set shared address-group "web-servers" static [ web-server-01 web-server-02 ]

# 🏢 DEVICE GROUPS
  📌 1. DG-Production
  📌 2. DG-Staging

# 🛡️ DIRECT SECURITY RULES
  DG-Production:
    - Allow-Web-Traffic  # contains address in source
    - Outbound-HTTPS  # contains address in destination

# 📂 ADDRESS GROUPS
  📂 1. web-servers (shared scope):
     └─ Command: set shared address-group web-servers static [ web-server-01 web-server-02 ]
     └─ Members: [ web-server-01 web-server-02 ]

# 🔗 INDIRECT SECURITY RULES (VIA ADDRESS GROUPS)
  DG-Production:
    - Allow-Internal-Traffic  # references shared address-group 'web-servers' that contains web-server-01

# ⚠️ REDUNDANT ADDRESSES
  🔄 1. web-server-backup:
     └─ IP/Netmask: 192.168.1.10/32
     └─ Scope: DG-Production
     └─ Note: Same IP as target address - potential duplicate
```

## Configuration File Format

Create a JSON file with your search parameters:
```json
{
  "log_file": "/path/to/firewall-config.log",
  "address_name": ["web-server-01", "db-server-02"]
}
```

## Performance Benchmarks

Expected performance improvements over traditional line-by-line parsing:

- **Small files** (< 100K lines): 5-10x faster
- **Medium files** (100K-1M lines): 15-30x faster  
- **Large files** (1M+ lines): 20-50x faster
- **Memory usage**: Efficient - loads entire file into memory once
- **Startup time**: Near-instant (no dependency loading)

## Use Cases

- **Migration Planning**: Understand all dependencies before moving/changing an address object
- **Security Auditing**: Find all security rules that allow traffic to/from specific addresses
- **Configuration Cleanup**: Identify redundant address objects with the same IP
- **Group Management**: See which address groups contain specific addresses
- **Rule Analysis**: Understand both direct and indirect rule relationships
- **Large Panorama Analysis**: Process million-line configuration files efficiently

## Project Structure

### Package Architecture
```
├── main.go                 # CLI interface and orchestration
├── models/
│   └── models.go          # Data structures and type definitions
├── processor/
│   ├── processor.go       # Core processing engine
│   ├── analysis.go        # Advanced analysis algorithms
│   └── cleanup.go         # Redundant address cleanup logic
├── tui/                   # Modern Terminal User Interface (NEW!)
│   ├── tui.go            # TUI application entry point
│   ├── models.go         # TUI state management and logic
│   ├── styles.go         # Professional color scheme and styling
│   └── commands.go       # Background command execution
├── ui/
│   ├── display.go         # Classic terminal display and formatting
│   └── interactive.go     # Classic interactive mode implementation
├── utils/
│   ├── utils.go          # Utility functions
│   └── writer.go         # Output generation and file writing
├── setup.sh              # Build script
├── package.json          # NPM wrapper commands
├── go.mod               # Go module definition with Bubble Tea
└── outputs/             # Generated analysis results
```

### Component Responsibilities
- **Main**: Command-line interface, flag parsing, and orchestration
- **Models**: Type-safe data structures, regex patterns, result models
- **Processor**: Core parsing engine, pattern matching, relationship analysis, silent mode support
- **TUI**: Modern Terminal User Interface with Bubble Tea framework, multi-select operations, professional styling
- **UI**: Classic user interface layer with color formatting and interactive mode
- **Utils**: Reusable utilities for formatting, parsing, and file operations

## Build Requirements

- **Go 1.23+**: Required for building the application (as specified in go.mod)
- **Bubble Tea Framework**: Modern TUI framework for the new interface
- **Lipgloss**: Styling library for professional terminal UI appearance

### Dependencies
- **Runtime**: Minimal external dependencies - primarily Bubble Tea ecosystem
- **Core Logic**: Uses only Go standard library for processing
- **TUI**: Bubble Tea, Lipgloss for modern terminal interface

The tool is self-contained after building with all dependencies statically linked.

## License

MIT License - see the repository for details.