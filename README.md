# PAN Configuration Log Parser (Go Edition)

A high-performance Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. Optimized for large Panorama configuration files with millions of lines.

## What It Does

Parses PAN configuration exports to help network administrators understand how IP address objects are used across their firewall configuration:

- **Direct References**: Security rules and NAT rules that explicitly reference an address object
- **Indirect References**: Security rules that reference address groups containing the target address  
- **Address Group Memberships**: All address groups that contain the specified address object
- **Device Group Context**: Which device groups contain rules using the address
- **Redundant Address Detection**: Finds other address objects with the same IP/netmask
- **Nested Address Groups**: Analyzes complex address group hierarchies
- **Smart Command Generation**: Creates optimized PAN CLI commands for adding new addresses to existing groups with intelligent scope selection

## Installation

### Prerequisites
- Go 1.23.0 or later

### Setup
```bash
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing
make install
```

## Usage

### Default Mode (TUI - Recommended)
```bash
pan-parser
```
Modern Terminal User Interface with professional styling, 9-state navigation, multi-select operations, and real-time feedback.

### Verbose Mode (Classic Interactive)
```bash
pan-parser --verbose
```
Classic interactive mode with guided command-line experience and colored terminal output.

### Command Line Mode
```bash
pan-parser -a web-server-01 -l firewall-config.log -o results.yml
pan-parser -a "web-server-01,db-server-02" -l config.log
pan-parser -c config.json
```

### Command Line Options
- `-a`: Address name(s) to search for (comma-separated for multiple)
- `-l`: Path to the PAN configuration log file (default: "default.log")
- `-o`: Output file name (optional)
- `-c`: Path to JSON configuration file
- `--verbose`: Run in verbose interactive mode
- `-h`: Show help

## Input Format

Expects Palo Alto Networks configuration export files containing commands like:
```
set device-group DG-Production security rules "Allow-Web-Traffic" source "web-servers"
set shared address-group "web-servers" static [ web-server-01 web-server-02 ]
set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
```

## TUI Interface

### Navigation Controls
- **Arrow Keys / j,k** - Navigate menu options
- **Space** - Toggle selection (checkboxes)
- **Enter** - Confirm selection or execute action
- **Esc** - Go back to previous screen
- **PgUp/PgDn, Ctrl+U/D** - Scroll session summary pane
- **Mouse Wheel** - Scroll session summary when visible
- **Ctrl+C / q** - Quit application

### Key Features
- **10-state machine** with comprehensive navigation and completion screen
- **Multi-select operations** for post-analysis actions
- **Professional styling** with clean color scheme
- **Silent background processing** maintains clean display
- **Real-time feedback** with progress indicators
- **Enhanced session summary** with intelligent color-coding and visual hierarchy
- **Responsive completion screen** that adapts to any terminal size

### Session Summary Display
- **Color-coded status**: Yellow for input files/targets, green for success metrics, red for errors
- **Smart formatting**: Action descriptions in blue italic, status values intelligently colored
- **Count-based display**: Clean redundant address counts instead of long lists
- **Structured hierarchy**: Indented sub-items and formatted address mappings
- **Enhanced scrolling**: Mouse wheel support, PgUp/PgDn, Ctrl+U/D keyboard shortcuts
- **Scrollable history**: Full session tracking with pagination support

### Completion Experience
- **Celebratory finish**: Professional thank you screen with analysis statistics
- **Terminal adaptive**: Three responsive layouts for different window sizes (60+, 45+, <45 chars)
- **Clean workflow**: All operations end with polished completion screen
- **Easy restart**: Seamless transition to start new analysis or quit application

## Output Format

Results are saved in structured YAML-like format with sections for:
- Matching configuration lines
- Device groups
- Direct and indirect security rules
- Address groups
- Redundant addresses

Files are automatically saved to `outputs/` directory.

## Performance Features

- **Memory-optimized processing**: Loads entire configuration into memory for faster analysis
- **Pre-compiled regex**: All patterns compiled once at startup
- **Progress reporting**: Real-time updates for large files
- **Minimal dependencies**: Core processing uses only Go standard library

Performance improvements over traditional parsing:
- Small files (< 100K lines): 5-10x faster
- Medium files (100K-1M lines): 15-30x faster  
- Large files (1M+ lines): 20-50x faster

## Configuration File Format

Create a JSON file with your search parameters:
```json
{
  "log_file": "/path/to/firewall-config.log",
  "address_name": ["web-server-01", "db-server-02"]
}
```

## Use Cases

- **Migration Planning**: Understand dependencies before moving/changing address objects
- **Security Auditing**: Find all security rules for specific addresses
- **Configuration Cleanup**: Identify redundant address objects
- **Group Management**: See which address groups contain specific addresses
- **Large Panorama Analysis**: Process million-line configuration files efficiently

## Build Commands

```bash
make install     # Install globally with dependency check
make build       # Build the application only
make run         # Build and run (TUI mode)
make verbose     # Build and run (verbose mode)
make clean       # Remove build artifacts
```

## Enhanced Address Group Command Generation

The tool now includes advanced command generation for adding new address objects to existing address groups with intelligent scope optimization:

### Smart Scope Selection
- **Automatic Optimization**: Determines the most efficient scope for creating new address objects
- **Mixed Scope Logic**: When groups exist in both shared and device-group scopes, creates address object in shared scope for maximum efficiency
- **Device-Group Isolation**: When all groups are in a single device-group, creates address object there for proper scope isolation  
- **Multi-Group Efficiency**: When groups span multiple device-groups, uses shared scope to avoid duplication

### Complete Command Generation
- **Two-Step Process**: Generates both address object creation AND group membership commands
- **IP Address Input**: Prompts for actual IP addresses instead of using placeholders
- **Executable Commands**: Ready-to-use PAN CLI commands in proper execution order

### Example Output
```yaml
# STEP 1: Create Address Objects (1 commands)
# NOTE: Using provided IP address 192.168.45.2
set shared address newServer ip-netmask 192.168.45.2
---
# STEP 2: Add to Address Groups (3 commands)  
set shared address-group web-servers static newServer
set shared address-group all-servers static newServer
set device-group production address-group local-servers static newServer
```

### Benefits
- **Reduced Commands**: Smart scope selection eliminates redundant address object creation (often 50%+ fewer commands)
- **User-Specified IPs**: No manual editing required - uses actual IP addresses provided by user
- **Best Practices**: Follows PAN configuration best practices for scope management
- **Ready to Execute**: Generated commands can be directly pasted into PAN CLI or GUI

## Dependencies

- **Core Processing**: Go standard library only
- **TUI Framework**: Bubble Tea v1.3.5 and Lipgloss v1.1.0
- **Total Dependencies**: 17 automatically managed dependencies

## License

MIT License - see the repository for details.