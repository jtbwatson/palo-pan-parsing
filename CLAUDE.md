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
5. **Structured Output Generation**: Creates YAML-like output files with detailed analysis results (utils/writer.go)

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

### Dependencies
- **Runtime**: Zero external dependencies - uses only Go standard library
- **Build Tools**: Go 1.20+ required (as specified in go.mod)

### File Structure
- **`main.go`**: CLI interface and orchestration (~202 lines)
- **`models/models.go`**: Data structures and type definitions (~102 lines)
- **`processor/processor.go`**: Core processing engine (~391 lines)
- **`processor/analysis.go`**: Advanced analysis algorithms (~282 lines)
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
- **Multi-Address**: `multiple_addresses_results.yml` - Combined analysis when processing multiple addresses

## Development Notes

- The tool supports both interactive and command-line modes
- Interactive mode provides guided user experience with colored terminal output and progress reporting
- All output files are automatically saved to `outputs/` directory with YAML-like structured format
- The parser handles quoted rule names and complex PAN configuration syntax
- Includes redundant address detection to identify objects with same IP netmask
- Optimized for large Panorama configuration files with millions of lines (in-memory processing)
- Memory-efficient processing suitable for resource-constrained environments
- Includes address group helper that can generate commands to add new addresses to existing groups