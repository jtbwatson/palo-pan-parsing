# PAN Configuration Log Parser (Go Edition)

A high-performance, modular Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. Features a clean architecture with separated concerns and optimized for large Panorama configuration files with millions of lines.

## Quick Start

```bash
# 1. Clone and install (one command does everything!)
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing
make install

# 2. Use from anywhere (runs TUI mode by default)
pan-parser
```

### Alternative Installation Methods

**Global installation:**
```bash
make install   # Install globally (includes all setup)
make uninstall # Remove from system
```

**Local development:**
```bash
make build     # Build only (no install)
make run       # Build and run locally (TUI mode)
make verbose   # Build and run locally (verbose mode)
```

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
- **Minimal Dependencies**: Core processing uses only Go standard library, TUI uses Bubble Tea ecosystem
- **Efficient Data Structures**: Native Go maps and slices for optimal performance

## Installation

### Prerequisites
- Go 1.23.0 or later (toolchain go1.24.4 as specified in go.mod)

### Setup
```bash
# Clone the repository
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing

# Install globally (one command does everything!)
make install

# Verify installation
pan-parser -h
```

## Usage

### Default Mode (TUI - Recommended)
```bash
# If installed globally:
pan-parser

# If local installation:
./pan-parser
# or: make run
```
By default, the tool runs in **Terminal User Interface (TUI)** mode, providing a modern, intuitive experience with:
- **Professional styling** - Clean blue/purple color scheme with consistent spacing
- **9-state navigation** - Comprehensive state machine with smart navigation
- **Multi-select operations** - Checkbox-based selection for post-analysis operations
- **Silent background processing** - No output interference with the TUI display
- **Real-time feedback** - Progress indicators, status messages, and operation completion notifications
- **Advanced workflows** - Support for multi-address operations and custom naming

### Verbose Mode (Classic Interactive)
```bash
# If installed globally:
pan-parser --verbose

# If local installation:
./pan-parser --verbose
# or: make verbose
```
The classic interactive mode provides a guided command-line experience with colored terminal output, progress reporting, and prompts for all required inputs.

### Command Line Mode
```bash
# If installed globally:
pan-parser -a web-server-01 -l firewall-config.log -o results.yml
pan-parser -a "web-server-01,db-server-02" -l config.log
pan-parser -c config.json
pan-parser -h

# If local installation:
./pan-parser -a web-server-01 -l firewall-config.log -o results.yml
./pan-parser -a "web-server-01,db-server-02" -l config.log
./pan-parser -c config.json
./pan-parser -h
```

### Quick Reference

**Makefile commands:**
```bash
make install     # One-step install: check deps, build, and install globally
make build       # Build the application only
make uninstall   # Remove from system PATH
make clean       # Remove build artifacts
make run         # Build and run (default TUI mode)
make verbose     # Build and run verbose interactive mode
make help        # Show available targets
```

**Command line usage:**
```bash
pan-parser                            # Default TUI interface (if installed)
pan-parser --verbose                  # Classic verbose mode
pan-parser -a <address> -l <file>     # Direct analysis
pan-parser -h                         # Show help
```

### Command Line Options
- `-a`: Address name(s) to search for (comma-separated for multiple)
- `-l`: Path to the PAN configuration log file (default: "default.log")
- `-o`: Output file name (optional)
- `-c`: Path to JSON configuration file
- `--verbose`: Run in verbose interactive mode (classic)
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

### 📱 **Screen Flow (9-State Machine)**
1. **Main Menu** - Choose "Analyze Configuration File" or "Exit"
2. **File Selection** - Enter path to PAN configuration file
3. **Address Input** - Enter single or multiple address names (comma-separated)
4. **Processing** - Real-time progress with silent background processing
5. **Results Summary** - Analysis completion confirmation with file generation status
6. **Additional Options** - Multi-select operations menu:
   - ☑️ Generate Address Group Commands
   - ☑️ Generate Cleanup Commands
   - Execute Selected Operations
   - Return to Main Menu
7. **Source Address Selection** - Choose source address for multi-address operations
8. **New Address Input** - Enter custom names for new address objects
9. **Operation Status** - Feedback screen for command execution results
10. **Error State** - Comprehensive error handling and user feedback

### ✨ **Key Benefits**
- **Comprehensive State Management** - 9-state machine with proper error handling
- **Multi-Select Operations** - Checkbox-based selection for multiple post-analysis operations
- **Professional Design** - Clean, consistent blue/purple interface styling
- **Smart Navigation** - Automatically skips separator lines and invalid selections
- **Silent Background Processing** - Maintains clean TUI display during operations
- **Advanced Workflows** - Support for multi-address operations and custom naming
- **Real-time Feedback** - Progress indicators and operation status notifications

## Output Format

Results are saved in a structured YAML-like format with sections for:

```yaml
# ═══════════════════════════════════════════════════════════════
# PAN Log Parser Analysis Report v2.0 (Go Edition)
# ═══════════════════════════════════════════════════════════════
# Target Address Object: web-server-01
# Configuration Lines Found: 12
# Total Relationships: 8
# ═══════════════════════════════════════════════════════════════

# MATCHING CONFIGURATION LINES
Found [12] lines containing 'web-server-01':
---
1. set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
2. set shared address-group "web-servers" static [ web-server-01 web-server-02 ]
3. set device-group DG-Production pre-rulebase security rules Allow-Web-Traffic source [ web-server-01 ]
---

# DEVICE GROUPS
Found [2] items:
---
1. DG-Production
2. DG-Staging
---

# DIRECT SECURITY RULES
Found [2] items:
---
1. Allow-Web-Traffic (device-group - DG-Production):
   └─ Command: set device-group DG-Production pre-rulebase security rules Allow-Web-Traffic source [ web-server-01 ]
   └─ Context: contains address in source
   └─ Device Group: DG-Production
2. Outbound-HTTPS (device-group - DG-Production):
   └─ Command: set device-group DG-Production pre-rulebase security rules Outbound-HTTPS destination [ web-server-01 ]
   └─ Context: contains address in destination
   └─ Device Group: DG-Production
---

# ADDRESS GROUPS
Found [1] items containing 'web-server-01':
---
1. web-servers (shared scope):
   └─ Command: set shared address-group web-servers static [ web-server-01 web-server-02 ]
   └─ Members: [ web-server-01 web-server-02 ]
---

# INDIRECT SECURITY RULES (VIA ADDRESS GROUPS)
Found [1] items:
---
1. Allow-Internal-Traffic (device-group - DG-Production):
   └─ Command: set device-group DG-Production pre-rulebase security rules Allow-Internal-Traffic source [ web-servers ]
   └─ Context: via address-group 'web-servers'
   └─ Device Group: DG-Production
---

# REDUNDANT ADDRESSES
Found [1] items with identical ip/netmask:
---
1. web-server-backup:
   └─ IP/Netmask: 192.168.1.10/32
   └─ Scope: DG-Production
   └─ Note: Same IP as target address - potential duplicate
---

# ═══════════════════════════════════════════════════════════════
# Analysis Complete
# Generated by: PAN Log Parser Tool v2.0 (Go Edition)
# Advanced Palo Alto Networks Configuration Analysis
# ═══════════════════════════════════════════════════════════════
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
├── main.go                 # CLI interface and orchestration (229 lines)
├── models/
│   └── models.go          # Data structures and type definitions (140 lines)
├── processor/
│   ├── processor.go       # Core processing engine (406 lines)
│   ├── analysis.go        # Advanced analysis algorithms (281 lines)
│   └── cleanup.go         # Redundant address cleanup logic (427 lines)
├── tui/                   # Modern Terminal User Interface
│   ├── tui.go            # TUI application entry point (32 lines)
│   ├── models.go         # TUI state management and logic (777 lines)
│   ├── styles.go         # Professional color scheme and styling (95 lines)
│   └── commands.go       # Background command execution (250 lines)
├── ui/
│   ├── display.go         # Classic terminal display and formatting (74 lines)
│   └── interactive.go     # Classic interactive mode implementation (305 lines)
├── utils/
│   ├── utils.go          # Utility functions (87 lines)
│   └── writer.go         # Output generation and file writing (467 lines)
├── Makefile              # Build system with installation and dependency management
├── go.mod               # Go module definition with Bubble Tea dependencies
└── outputs/             # Generated analysis results
```

### Component Responsibilities
- **Main**: Command-line interface, flag parsing, and orchestration (229 lines)
- **Models**: Type-safe data structures, regex patterns, result models (140 lines) 
- **Processor**: Core parsing engine, pattern matching, relationship analysis, silent mode support (1,114 lines total)
- **TUI**: Modern Terminal User Interface with 9-state machine, multi-select operations, professional styling (1,154 lines total)
- **UI**: Classic user interface layer with color formatting and interactive mode (379 lines total)
- **Utils**: Reusable utilities for formatting, parsing, and file operations (554 lines total)

**Total Codebase**: 3,570 lines across all packages

## Build Requirements

- **Go 1.23.0+**: Required for building the application (toolchain go1.24.4)
- **Bubble Tea Framework**: Modern TUI framework for the interface
- **Lipgloss**: Styling library for professional terminal UI appearance

### Dependencies
- **Core Processing**: Uses only Go standard library for analysis logic
- **TUI Framework**: Bubble Tea v1.3.5 and Lipgloss v1.1.0 for modern terminal interface
- **Transitive Dependencies**: 17 additional dependencies for TUI functionality (automatically managed)

The tool is self-contained after building with all dependencies statically linked.

## License

MIT License - see the repository for details.