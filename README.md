# PAN Configuration Log Parser

A high-performance Go tool that analyzes Palo Alto Networks configuration logs to find IP address object references. Optimized for large Panorama files.

## Features

- **Address Analysis**: Direct/indirect references, group memberships, device group context
- **Smart Detection**: Redundant addresses, nested groups, dependency mapping
- **Command Generation**: Optimized PAN CLI commands with intelligent scope selection
- **Performance**: 20-50x faster on large files with in-memory processing

## Quick Start

```bash
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing
make install
pan-parser  # Launch TUI mode
```

## Usage Modes

```bash
pan-parser                    # TUI mode (recommended)
pan-parser --verbose          # Interactive mode
pan-parser -a web-server-01 -l config.log  # Command line
```

### Options
- `-a`: Address name(s) (comma-separated)
- `-l`: Config file path
- `-o`: Output file name
- `-c`: JSON config file
- `--verbose`: Interactive mode

## Input Format

PAN configuration export files:
```
set device-group DG-Production security rules "Allow-Web-Traffic" source "web-servers"
set shared address-group "web-servers" static [ web-server-01 web-server-02 ]
set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
```

## TUI Interface

Modern terminal interface with 10-state navigation, multi-select operations, and real-time feedback.

### Controls
- **Arrow Keys/j,k**: Navigate options
- **Space**: Toggle selection
- **Enter**: Confirm/execute
- **Esc**: Go back
- **PgUp/PgDn**: Scroll session summary
- **Ctrl+C/q**: Quit

### Features
- Professional color scheme with intelligent status display
- Silent background processing maintains clean interface
- Responsive design adapts to terminal size
- Enhanced session summary with scrollable history

## Output

Structured YAML results saved to `outputs/` directory:
- Configuration matches
- Device groups and security rules  
- Address groups and redundant addresses
- Generated CLI commands

## Use Cases

- **Migration Planning**: Understand dependencies before moving/changing objects
- **Security Auditing**: Find all rules for specific addresses
- **Configuration Cleanup**: Identify redundant objects
- **Group Management**: Analyze address group memberships

## Build Commands

```bash
make install     # Install globally
make build       # Build only
make run         # Run TUI mode
make verbose     # Run interactive mode
```

## Smart Command Generation

Generates optimized PAN CLI commands with intelligent scope selection:

```yaml
# STEP 1: Create Address Objects
set shared address newServer ip-netmask 192.168.45.2
---
# STEP 2: Add to Address Groups  
set shared address-group web-servers static newServer
set device-group production address-group local-servers static newServer
```

### Benefits
- **Smart Scoping**: Automatically selects optimal scope (shared vs device-group)
- **User IPs**: Prompts for actual IP addresses instead of placeholders  
- **Reduced Commands**: Often 50%+ fewer commands through intelligent optimization
- **Ready to Execute**: Commands can be directly pasted into PAN CLI

## Dependencies

Go 1.23+ with Bubble Tea TUI framework (17 auto-managed dependencies)