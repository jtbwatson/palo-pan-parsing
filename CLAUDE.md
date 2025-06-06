# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PAN (Palo Alto Networks) Log Parser Tool - a high-performance Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. The tool searches for both direct and indirect references through address groups, security rules, NAT rules, and device groups, optimized for large Panorama configuration files.

## Common Commands

### Setup and Build
```bash
# Build the Go binary (recommended)
npm run setup
# or manually: go build -o pan-parser main.go

# Quick build without npm
npm run build

# Verify installation and show help
npm run test
# or: ./pan-parser -h
```

### Usage
```bash
# Run the parser in interactive mode (recommended for new users)
./pan-parser -i
# or via npm: npm run parser

# Quick interactive run
npm run run

# Command line mode with specific parameters
./pan-parser -a <address_name> -l <log_file> -o <output_file>

# Multiple address search
./pan-parser -a "address1,address2,address3" -l logfile.log

# Using configuration file
./pan-parser -c config.json

# Show help
./pan-parser -h
```

## Architecture Notes

### Core Functionality
- **Main Entry (`main.go`)**: Command-line interface, flag parsing, and high-level orchestration
- **Processor Package (`processor/`)**: Core parsing engine with optimized algorithms
  - `processor.go`: Main processing logic, file parsing, and pattern matching
  - `analysis.go`: Advanced analysis features (redundant addresses, indirect rules, nested groups)
  - `cleanup.go`: Redundant address cleanup analysis and command generation
- **Models Package (`models/`)**: Data structures and type definitions
  - `models.go`: All data models, regex patterns, and result structures
- **UI Package (`ui/`)**: User interface and terminal interaction
  - `display.go`: Color formatting and output display functions
  - `interactive.go`: Interactive mode implementation with guided user experience
- **Utils Package (`utils/`)**: Utility functions and file operations
  - `utils.go`: Formatting, parsing, and system utilities
  - `writer.go`: Structured YAML output generation and file writing
- **Setup Script (`setup.sh`)**: Bash script that builds the Go binary and verifies Go installation
- **NPM Integration**: Simple package.json provides convenient npm commands that wrap the Go tooling

### Key Processing Flow
1. **Memory-Optimized File Reading**: Loads entire configuration into memory for faster processing (processor/processor.go:63-203)
2. **Compiled Regex Patterns**: Pre-compiled regex patterns for maximum performance (models/models.go:6-18)
3. **Relationship Analysis**: Identifies direct and indirect relationships through address groups (processor/analysis.go)
4. **Context Extraction**: Determines how addresses are used (source, destination, etc.) (processor/processor.go:256-309)
5. **Redundant Address Cleanup**: Smart scope promotion and cleanup command generation (processor/cleanup.go)
6. **Structured Output Generation**: Creates YAML-like output files with detailed analysis results (utils/writer.go)

### Performance Optimizations
- **In-Memory Processing**: Entire configuration file loaded into memory for faster analysis
- **Pre-Compiled Regex**: All patterns compiled once at startup (models/models.go:23-37)
- **Efficient Data Structures**: Uses native Go maps and slices for optimal performance (models/models.go:35-96)
- **Progress Reporting**: Shows progress every 200K-500K lines for large files (processor/processor.go:120-137)
- **Minimal Dependencies**: Uses only Go standard library (no external dependencies)

### Data Structure Patterns
- **Modular Design**: Clean separation of concerns across packages
- **Structured Models**: Well-defined data structures for all components (models/models.go)
- **Address groups processed with context information** (shared vs device-group)
- **Security rules organized by device groups** with relationship context
- **Results include redundant address detection** based on IP netmask matching (processor/analysis.go:12-53)
- **Nested address group analysis** for complex hierarchies (processor/analysis.go:178-282)
- **Smart cleanup analysis** with scope promotion logic and usage pattern detection (processor/cleanup.go)

### Dependencies
- **Runtime**: Zero external dependencies - uses only Go standard library
- **Build Tools**: Go 1.20+ required (as specified in go.mod)

### File Structure
- **`main.go`**: CLI interface and orchestration (~202 lines)
- **`models/models.go`**: Data structures and type definitions (~102 lines)
- **`processor/processor.go`**: Core processing engine (~391 lines)
- **`processor/analysis.go`**: Advanced analysis algorithms (~282 lines)
- **`processor/cleanup.go`**: Redundant address cleanup logic (~400+ lines)
- **`ui/display.go`**: Terminal display and formatting (~75 lines)
- **`ui/interactive.go`**: Interactive mode implementation (~203 lines)
- **`utils/utils.go`**: Utility functions (~88 lines)
- **`utils/writer.go`**: Output generation and file writing (~288 lines)
- **`setup.sh`**: Bash script for building and optionally running the parser
- **`package.json`**: NPM wrapper scripts for convenient command execution
- **`go.mod`**: Go module definition (minimal, no external dependencies)
- **`outputs/`**: Auto-created directory for all result files (YAML format)

### Output Format
- **Main Results**: `{address}_results.yml` - Comprehensive analysis with structured sections
- **Group Commands**: `{address}_add_to_groups_commands.yml` - Generated CLI commands for adding new addresses to discovered groups
- **Cleanup Commands**: `{address}_redundant_cleanup_commands.yml` - Generated commands for cleaning up redundant addresses with smart scope promotion
- **Multi-Address**: `multiple_addresses_results.yml` - Combined analysis when processing multiple addresses

## Development Notes

- The tool supports both interactive and command-line modes
- Interactive mode provides guided user experience with colored terminal output and progress reporting
- All output files are automatically saved to `outputs/` directory with YAML-like structured format
- The parser handles quoted rule names and complex PAN configuration syntax
- Includes redundant address detection to identify objects with same IP netmask
- **Comprehensive redundant address cleanup** with smart scope promotion and command generation
- Optimized for large Panorama configuration files with millions of lines (in-memory processing)
- Memory-efficient processing suitable for resource-constrained environments
- Includes address group helper that can generate commands to add new addresses to existing groups
- **Smart scope optimization**: Automatically promotes addresses to shared scope when used in multiple device groups to reduce configuration file size

## Redundant Address Cleanup Feature

The tool includes comprehensive redundant address cleanup functionality that helps optimize PAN configurations by:

### Smart Scope Promotion
- **Automatic Detection**: Identifies when redundant addresses are used across multiple device groups
- **Shared Scope Promotion**: Promotes target addresses to shared scope when beneficial for configuration size reduction
- **Optimization Logic**: Only promotes to shared when used in more than one device group

### Deep Usage Analysis
- **Re-parsing for Accuracy**: Performs additional configuration parsing to ensure comprehensive usage detection
- **Context-Aware Analysis**: Understands how redundant addresses are used (source, destination, address groups, etc.)
- **Cross-Reference Detection**: Maps all relationships between redundant addresses and configuration elements

### Command Generation
- **Safe Cleanup Commands**: Generates step-by-step commands for safely removing redundant addresses
- **Rule Updates**: Creates commands to update security rules to use the target address instead of redundant ones
- **Address Group Updates**: Updates address group memberships to use optimized addresses
- **Scope Management**: Handles address object creation in appropriate scopes (shared vs device-group)

### Output Format
The cleanup commands are organized into logical steps:
1. **Security Rule Updates**: Commands to replace redundant addresses in rules
2. **Address Group Updates**: Commands to update group memberships
3. **Object Creation**: Commands to create target addresses in optimal scopes (if needed)
4. **Object Removal**: Commands to safely remove redundant address definitions

### Interactive Workflow
- **User Confirmation**: Prompts user before generating cleanup commands
- **Analysis Summary**: Shows impact analysis including number of device groups affected
- **Safety Warnings**: Reminds users to test in non-production environments first