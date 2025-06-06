# PAN Configuration Log Parser (Go Edition)

A high-performance Go-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. Optimized for large Panorama configuration files with millions of lines.

## What It Does

This tool parses PAN configuration exports/logs to help network administrators understand how IP address objects are being used across their firewall configuration. It identifies:

- **Direct References**: Security rules and NAT rules that explicitly reference an address object
- **Indirect References**: Security rules that reference address groups containing the target address  
- **Address Group Memberships**: All address groups that contain the specified address object
- **Device Group Context**: Which device groups contain rules using the address
- **Redundant Address Detection**: Finds other address objects with the same IP/netmask
- **Nested Address Groups**: Analyzes complex address group hierarchies

## Performance Features

- **Memory-Optimized Processing**: Loads entire configuration into memory for faster analysis
- **Pre-Compiled Regex**: All patterns compiled once at startup for maximum performance
- **Progress Reporting**: Real-time progress updates for large files (50K-150K line intervals)
- **Zero Dependencies**: Uses only Go standard library - no external dependencies required
- **Efficient Data Structures**: Native Go maps and slices for optimal performance

## Installation

### Prerequisites
- Go 1.19 or later

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing

# Build the application
npm run setup
# or manually: go build -o pan-parser main.go
```

## Usage

### Interactive Mode (Recommended)
```bash
./pan-parser -i
# or via npm: npm run parser
```
The interactive mode provides a guided experience with colored terminal output and prompts for all required inputs.

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
- `-i`: Run in interactive mode
- `-h`: Show help

## Input Format

The tool expects Palo Alto Networks configuration export files containing commands like:
```
set device-group DG-Production security rules "Allow-Web-Traffic" source "web-servers"
set shared address-group "web-servers" static [ web-server-01 web-server-02 ]
set device-group DG-Production address web-server-01 ip-netmask 192.168.1.10/32
```

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

## Build Requirements

- **Go 1.19+**: Required for building the application
- **No Runtime Dependencies**: Uses only Go standard library

The tool is completely self-contained after building - no external dependencies required.

## License

MIT License - see the repository for details.