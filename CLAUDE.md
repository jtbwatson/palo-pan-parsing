# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PAN (Palo Alto Networks) Log Parser Tool - a high-performance Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. The tool searches for both direct and indirect references through address groups, security rules, NAT rules, and device groups, optimized for large Panorama configuration files.

## Common Commands

### Setup and Build
```bash
# Build the Go binary
npm run setup
# or manually: go build -o pan-parser main.go

# Run tests
npm run test
```

### Usage
```bash
# Run the parser in interactive mode
./pan-parser -i
# or via npm: npm run parser

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
- **Main Parser (`main.go`)**: High-performance single-file Go application optimized for large configuration files
- **Setup Script (`setup.sh`)**: Bash script that builds the Go binary and verifies Go installation
- **NPM Integration**: Simple package.json provides convenient npm commands that wrap the Go tooling

### Key Processing Flow
1. **Memory-Optimized File Reading**: Loads entire configuration into memory for faster processing
2. **Compiled Regex Patterns**: Pre-compiled regex patterns for maximum performance
3. **Relationship Analysis**: Identifies direct and indirect relationships through address groups
4. **Context Extraction**: Determines how addresses are used (source, destination, etc.)
5. **Structured Output Generation**: Creates YAML-like output files with detailed analysis results

### Performance Optimizations
- **In-Memory Processing**: Entire configuration file loaded into memory for faster analysis
- **Pre-Compiled Regex**: All patterns compiled once at startup
- **Efficient Data Structures**: Uses native Go maps and slices for optimal performance
- **Progress Reporting**: Shows progress every 50K-150K lines for large files
- **Minimal Dependencies**: Uses only Go standard library (no external dependencies)

### Data Structure Patterns
- Address groups processed with context information (shared vs device-group)
- Security rules organized by device groups with relationship context
- Results include redundant address detection based on IP netmask matching
- Nested address group analysis for complex hierarchies

### Dependencies
- **Runtime**: Zero external dependencies - uses only Go standard library
- **Build Tools**: Go 1.19+ required

## Development Notes

- The tool supports both interactive and command-line modes
- Interactive mode provides guided user experience with colored terminal output
- Output files use YAML-like structured format for easy parsing
- The parser handles quoted rule names and complex PAN configuration syntax
- Includes redundant address detection to identify objects with same IP netmask
- Optimized for large Panorama configuration files with millions of lines
- Memory-efficient processing suitable for resource-constrained environments