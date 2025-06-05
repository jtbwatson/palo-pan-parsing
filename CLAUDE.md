# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PAN (Palo Alto Networks) Log Parser Tool - a Python-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. The tool searches for both direct and indirect references through address groups, security rules, NAT rules, and device groups.

## Common Commands

### Setup and Environment
```bash
# Initial setup with virtual environment and dependencies
npm run setup

# Run the parser in interactive mode
npm run parser
```

### Python Commands
```bash
# Run parser directly with Python (after setup)
python parse.py --interactive

# Command line mode with specific parameters
python parse.py -a <address_name> -l <log_file> -o <output_file>

# Multiple address search
python parse.py -a "address1,address2,address3" -l logfile.log

# Using configuration file
python parse.py -c config.json
```

## Architecture Notes

### Core Functionality
- **Main Parser (`parse.py`)**: Single-file Python application that handles log parsing, pattern matching, and result generation
- **Setup Script (`setup.sh`)**: Bash script that manages Python virtual environment using `uv` package manager
- **NPM Integration**: Simple package.json provides convenient npm commands that wrap the Python tooling

### Key Processing Flow
1. **Log File Reading**: Reads PAN configuration logs line by line
2. **Pattern Matching**: Uses regex patterns to find address object references
3. **Relationship Analysis**: Identifies direct and indirect relationships through address groups
4. **Context Extraction**: Determines how addresses are used (source, destination, etc.)
5. **Output Generation**: Creates structured YAML-like output files with detailed results

### Data Structure Patterns
- Address groups are processed with context information (shared vs device-group)
- Security rules are organized by device groups with relationship context
- Results include redundant address detection based on IP netmask matching
- Command generation feature creates PAN CLI commands for adding addresses to groups

### Dependencies
- Uses `uv` as Python package manager for fast dependency resolution
- Single Python dependency: `colorama` for terminal color output
- No complex framework dependencies - pure Python with standard library

## Development Notes

- The tool supports both interactive and command-line modes
- Interactive mode provides guided user experience with colored terminal output
- Output files use YAML-like structured format for easy parsing
- The parser handles quoted rule names and complex PAN configuration syntax
- Includes redundant address detection to identify objects with same IP netmask