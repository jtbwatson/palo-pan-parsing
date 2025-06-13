# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PAN (Palo Alto Networks) XML Configuration Parser - a high-performance Go-based command-line utility that analyzes Palo Alto Networks XML configuration files to find references to specific IP address objects. The tool searches for both direct and indirect references through address groups, security rules, NAT rules, and device groups, optimized for large Panorama XML configuration exports.

## Common Commands

### Setup and Build
```bash
# One-step installation (recommended)
make install
# or manually: go build -o pan-parser main.go

# Build only
make build

# Verify installation and show help
./pan-parser -h
```

### Usage
```bash
# Run in modern TUI mode (default - recommended)
./pan-parser
# or explicitly: ./pan-parser --tui
# or via make: make run

# Run the parser in classic interactive mode
./pan-parser --verbose
# or via make: make verbose

# Command line mode with specific parameters
./pan-parser -a <address_name> -l <xml_config_file> -o <output_file>

# Multiple address search
./pan-parser -a "address1,address2,address3" -l panos.xml

# Using configuration file
./pan-parser -c config.json

# Show help
./pan-parser -h
```

## Architecture Notes

### Core Functionality
- **Main Entry (`main.go`)**: Command-line interface, flag parsing, and high-level orchestration with TUI/interactive mode routing
- **Parser Package (`parser/`)**: XML parsing engine for PAN configuration files
  - `xml_reader.go`: Streaming XML parser for memory-efficient processing
  - `xml_types.go`: Type definitions for PAN XML configuration elements
  - `xml_utils.go`: XML parsing utilities and helper functions
- **Processor Package (`processor/`)**: Core analysis engine with optimized algorithms and silent mode support
  - `processor.go`: Main processing logic, XML parsing coordination, pattern matching, and analysis orchestration
  - `address_analyzer.go`: Address reference analysis, group membership detection, and cross-reference mapping
  - `redundancy_analyzer.go`: Redundant address detection with smart scope analysis and cleanup command generation
  - `scope_analyzer.go`: Scope optimization and device group analysis
- **Models Package (`models/`)**: Data structures and type definitions
  - `address.go`: Address object models, redundancy detection, and IP validation
  - `config.go`: Configuration management structures
  - `groups.go`: Address group models and membership structures
  - `results.go`: Analysis result models, statistics, and cross-reference structures
  - `rules.go`: Security rule and NAT rule models with address context detection
- **Cache Package (`cache/`)**: Memory optimization and performance caching
  - `memory_cache.go`: In-memory caching with TTL and automatic cleanup
  - `pattern_cache.go`: Regex pattern caching and result optimization
- **Utils Package (`utils/`)**: Utility functions and file operations
  - `utils.go`: Formatting, parsing, system utilities, and comprehensive IP address validation
  - `writer.go`: Structured YAML output generation and file writing
- **Build System**: Makefile-based build system with dependency checking and global installation support

### Key Processing Flow
1. **Streaming XML Processing**: Parses XML configuration files with memory-efficient streaming (parser/xml_reader.go)
2. **Element Recognition**: Identifies PAN configuration elements (addresses, groups, rules) using XML structure analysis
3. **Relationship Analysis**: Maps direct and indirect relationships through address groups and rule references (processor/address_analyzer.go)
4. **Context Extraction**: Determines how addresses are used (source, destination, group membership) with scope analysis
5. **Redundant Address Detection**: Smart detection of duplicate IP addresses with scope optimization (processor/redundancy_analyzer.go)
6. **Focused YAML Output**: Generates clean, nested YAML showing only target-relevant objects and references (utils/writer.go)

### Performance Optimizations
- **Streaming XML Processing**: Memory-efficient XML parsing for large configuration files
- **Pattern Caching**: Compiled regex patterns cached for reuse (cache/pattern_cache.go)
- **Memory Management**: TTL-based caching with automatic cleanup (cache/memory_cache.go)
- **Concurrent Processing**: Safe concurrent access with mutex protection
- **Focused Analysis**: Only processes and outputs target-relevant objects (no full config dumps)

### Data Structure Patterns
- **Modular Design**: Clean separation of concerns across packages
- **Structured Models**: Well-defined data structures across model files
- **Address groups processed with context information** (shared vs device-group)
- **Security rules organized by device groups** with relationship context
- **Results include redundant address detection** based on IP netmask matching
- **Nested address group analysis** for complex hierarchies
- **Smart cleanup analysis** with scope promotion logic and usage pattern detection

### Dependencies
- **Runtime**: Uses Bubble Tea framework for TUI (charmbracelet/bubbletea, bubbles, lipgloss)
- **Build Tools**: Go 1.23+ required (as specified in go.mod)
- **Vendor Management**: All dependencies vendored for security and reproducible builds
- **Key External Libraries**:
  - Bubble Tea: Modern TUI framework for terminal applications
  - Lipgloss: Styling and layout for terminal interfaces
  - Bubbles: Common TUI components (inputs, lists, etc.)

### File Structure
- **`main.go`**: CLI interface and orchestration
- **`parser/`**: XML configuration parsing engine
  - `xml_reader.go`: Streaming XML parser
  - `xml_types.go`: PAN XML element type definitions
  - `xml_utils.go`: XML processing utilities
- **`processor/`**: Analysis engine
  - `processor.go`: Main processing coordination
  - `address_analyzer.go`: Address reference analysis
  - `redundancy_analyzer.go`: Duplicate detection and cleanup
  - `scope_analyzer.go`: Scope optimization
- **`models/`**: Data structures (address.go, config.go, groups.go, results.go, rules.go)
- **`cache/`**: Performance optimization (memory_cache.go, pattern_cache.go)
- **`utils/`**: Utilities (utils.go, writer.go)
- **`tui/`**: Terminal User Interface implementation (empty - TUI code may be integrated in main.go)
- **`ui/`**: User Interface components (empty - UI code may be integrated elsewhere)
- **`Makefile`**: Comprehensive build system with multi-platform support
- **`go.mod`**: Go module definition with vendored dependencies
- **`outputs/`**: Auto-created directory for YAML analysis results

### Output Format
- **Main Results**: `{address}_results.yml` - Comprehensive analysis with structured sections
- **Group Commands**: `{address}_add_to_groups_commands.yml` - Generated CLI commands for adding new addresses to discovered groups
- **Cleanup Commands**: `{address}_cleanup.yml` - Generated commands for cleaning up redundant addresses with smart scope promotion
- **Multi-Address**: `multiple_addresses_results.yml` - Combined analysis when processing multiple addresses

## TUI (Terminal User Interface) Features

The modern TUI mode provides a comprehensive graphical interface within the terminal:

### Interface Architecture
- **Bubble Tea Framework**: Built on the modern, component-based Bubble Tea library for robust state management
- **Professional Styling**: Consistent blue/purple color scheme with Lipgloss for visual appeal
- **Multi-State Navigation**: Seamless transitions between file input, address selection, processing, and results
- **Silent Processing**: Background operations with no output interference to maintain clean interface

### User Experience Features
- **Multi-Select Operations**: Checkbox-based selection for post-analysis operations (Address Group Commands, Cleanup Commands)
- **Smart Navigation**: Arrow keys automatically skip separator lines and invalid selections
- **Perfect Alignment**: Consistent spacing and character alignment throughout all interface elements
- **Real-time Feedback**: Progress indicators, status messages, and operation completion notifications
- **Responsive Design**: Clean layout that adapts to terminal size with proper text wrapping
- **Enhanced Session Summary**: Color-coded session tracking with intelligent formatting for better visual hierarchy

### Workflow States
1. **Main Menu**: Choose analysis or exit with visual highlighting
2. **File Selection**: Enter configuration file path with input validation
3. **Address Input**: Single or multiple address entry with comma separation support
4. **Processing Screen**: Silent background analysis with progress indication
5. **Results Summary**: Analysis completion confirmation with file generation status
6. **Additional Options**: Multi-select menu for post-analysis operations
7. **Source Address Selection**: Choose source address for multi-address group operations
8. **New Address Input**: Enter custom names for new address objects
9. **IP Address Input**: Enter IP addresses for new address objects with CIDR notation
10. **Operation Status**: Feedback screen for command execution results
11. **Completion Screen**: Responsive thank you screen with analysis statistics
12. **Error State**: Comprehensive error handling and user feedback

Note: The exact TUI implementation may vary from this description as TUI source files are not currently present in the tui/ directory.

### Session Summary Formatting
The TUI features an intelligent session summary with enhanced visual formatting:

#### Color Scheme
- **Blue Italic**: Action descriptions ("Configuration Analysis Started", "Processing Started", "Analysis Complete")
- **Yellow (Warning)**: Input files, target lists, and redundant address indicators
- **Green (Success)**: Reference counts, address group detection, and successful operations
- **Red (Error)**: Error conditions and failed operations
- **White (Neutral)**: Default status information

#### Smart Color Logic
- **Contextual Coloring**: Status values are intelligently color-coded based on key-value relationships
- **Pattern Recognition**: Automatic detection of success/warning/error indicators in text
- **Priority-Based Styling**: Special cases override general patterns for accurate representation

#### Display Features
- **Count-Based Display**: Redundant addresses show counts (e.g., "Redundant Addresses: 3 found") instead of individual listings
- **Structured Hierarchy**: Indented sub-items for operation details and file generation summaries
- **Address Mappings**: Formatted arrows (→) for source-to-target address relationships
- **Enhanced Scrolling**: Mouse wheel support, keyboard shortcuts (PgUp/PgDn, Ctrl+U/D)
- **Scrollable Content**: Session history with pagination for long analysis sessions

### Completion Experience
The TUI provides a celebratory conclusion to analysis workflows:

#### Responsive Thank You Screen
- **Terminal Adaptive**: Three layout variants for different terminal sizes (60+, 45+, <45 characters)
- **Clean Design**: Professional completion message without garbled ASCII art
- **Analysis Statistics**: Summary of files generated, addresses analyzed, and configuration details
- **Workflow Integration**: All operation endings (selected operations, no additional options) lead to completion screen

#### Smart Session Management
- **Clean Reset**: Automatically clears session data when starting new analysis
- **Return to Menu**: Seamless transition back to main menu for additional analyses
- **Professional Closure**: Thanking users with network administration encouragement

### Technical Implementation
- **State Machine**: Clean state management with proper transitions and error handling
- **Background Commands**: Asynchronous operation execution using Bubble Tea command pattern
- **Silent Mode Integration**: Processor runs in silent mode to prevent output leakage
- **Memory Efficient**: Maintains TUI responsiveness even during large file processing

## Development Notes

- The tool supports three modes: modern TUI (default), classic interactive, and command-line
- **TUI mode (default)**: Modern interface with multi-state navigation, multi-select operations, and visual feedback
- **Interactive mode (`--verbose`)**: Classic guided command-line experience with colored terminal output
- **Command-line mode**: Direct execution for automation and scripting
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

## Enhanced Address Group Command Generation

The tool includes advanced address group command generation with intelligent scope optimization and comprehensive IP address management:

### Smart Scope Selection
- **Intelligent Scope Analysis**: Automatically determines the optimal scope for creating new address objects based on group memberships
- **Mixed Scope Optimization**: When groups exist in both shared and device-group scopes, creates address object in shared scope for maximum efficiency
- **Single Device-Group Isolation**: When all groups are in the same device-group, creates address object in that device-group for proper scope isolation
- **Multi Device-Group Efficiency**: When groups span multiple device-groups, creates address object in shared scope to avoid duplication

### Comprehensive IP Address Management
- **User-Specified IP Addresses**: Both TUI and interactive modes prompt for IP addresses instead of using placeholder values
- **Complete Command Generation**: Generates both address object creation commands AND group membership commands in proper execution order
- **Custom IP Validation**: Supports user-provided IP addresses with CIDR notation (e.g., 192.168.1.100/32)

### Enhanced TUI Workflow
- **Extended State Machine**: Added dedicated IP address input state (`StateIPAddressInput`) after new address name input
- **Progressive Input Flow**: 
  1. Address analysis and group discovery
  2. New address name input with validation
  3. IP address input with format guidance (e.g., 192.168.1.100/32)
  4. Smart scope analysis and command generation
- **Real-time Feedback**: Shows current address being processed and progress through multiple address mappings

### Optimized Output Format
The enhanced command generation produces two-step executable commands:
1. **STEP 1: Create Address Objects** - Generates commands to create address objects in optimal scopes with user-specified IP addresses
2. **STEP 2: Add to Address Groups** - Generates commands to add new addresses to discovered groups

### Smart Scope Examples
- **Shared + Device-Group Groups**: `set shared address newServer ip-netmask 10.0.1.100/32` (1 command vs 2+ previously)
- **Single Device-Group Only**: `set device-group production address newServer ip-netmask 10.0.1.100/32` (proper isolation)
- **Multiple Device-Groups**: `set shared address newServer ip-netmask 10.0.1.100/32` (efficiency over duplication)

### Interactive Mode Enhancements
- **IP Address Prompts**: Added comprehensive validation and user-friendly prompts for IP address input with support for IPv4/IPv6 and CIDR notation
- **Progress Feedback**: Shows address mapping with IP information (e.g., "newServer1 (10.0.1.100/32)")
- **Enhanced Error Handling**: Real-time IP address validation with automatic CIDR normalization and clear error messages
- **Per-Address IP Mapping**: Each source address gets its own unique IP address in multi-address workflows

### Technical Implementation
- **utils/writer.go**: Smart scope selection logic in address creation command generation
- **main.go**: May contain TUI implementation (tui/ directory is currently empty)
- Command generation functions with IP address parameter support
- Interactive prompts with IP address collection and validation

Note: Specific TUI implementation files (tui/models.go, tui/commands.go, ui/interactive.go) referenced in this documentation may not exist as separate files, as the TUI functionality may be integrated within main.go or other core files.