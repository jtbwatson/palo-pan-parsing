# PAN Configuration Log Parser

A Python-based command-line utility that analyzes Palo Alto Networks configuration logs to find references to specific IP address objects. The tool searches for both direct and indirect references through address groups, security rules, NAT rules, and device groups.

## What It Does

This tool parses PAN configuration exports/logs to help network administrators understand how IP address objects are being used across their firewall configuration. It identifies:

- **Direct References**: Security rules and NAT rules that explicitly reference an address object
- **Indirect References**: Security rules that reference address groups containing the target address  
- **Address Group Memberships**: All address groups that contain the specified address object
- **Device Group Context**: Which device groups contain rules using the address
- **Redundant Address Detection**: Finds other address objects with the same IP/netmask
- **Command Generation**: Creates PAN CLI commands to add new addresses to existing groups

## Installation

### Prerequisites
- Python 3.x
- `uv` package manager (installed automatically by setup script)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/jtbwatson/palo-pan-parsing.git
cd palo-pan-parsing

# Run setup (creates virtual environment and installs dependencies)
npm run setup
```

## Usage

### Interactive Mode (Recommended)
```bash
npm run parser
```
The interactive mode provides a guided experience with colored terminal output and prompts for all required inputs.

### Command Line Mode
```bash
# Search for a single address
python parse.py -a web-server-01 -l firewall-config.log -o results.txt

# Search for multiple addresses (comma-separated)
python parse.py -a "web-server-01,db-server-02,mail-server" -l config.log

# Use a configuration file
python parse.py -c config.json
```

### Command Line Options
- `-a, --address`: Address name(s) to search for (comma-separated for multiple)
- `-l, --logfile`: Path to the PAN configuration log file
- `-o, --output`: Output file name (optional)
- `-c, --config`: Path to JSON configuration file
- `-i, --interactive`: Force interactive mode

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
Address: web-server-01
IP/Netmask: 192.168.1.10/32

Matching Log Lines:
  - [line numbers and content from the log file]

Device Groups:
  - DG-Production
  - DG-Staging

Direct Security Rules:
  DG-Production:
    - Allow-Web-Traffic (source context)
    - Outbound-HTTPS (destination context)

Address Groups (shared):
  - web-servers (contains: web-server-01, web-server-02)

Address Groups (device-group DG-Production):
  - production-servers (contains: web-server-01, db-server-01)

Indirect Security Rules:
  DG-Production:
    - Allow-Internal-Traffic (via address group: production-servers)

Commands to add 'new-web-server' to address groups:
  set shared address-group "web-servers" static new-web-server
  set device-group DG-Production address-group "production-servers" static new-web-server

Redundant Addresses (same IP/netmask):
  - web-server-backup (192.168.1.10/32)
```

## Configuration File Format

Create a JSON file with your search parameters:
```json
{
  "addresses": ["web-server-01", "db-server-02"],
  "logfile": "/path/to/firewall-config.log",
  "output": "results.txt"
}
```

## Use Cases

- **Migration Planning**: Understand all dependencies before moving/changing an address object
- **Security Auditing**: Find all security rules that allow traffic to/from specific addresses
- **Configuration Cleanup**: Identify redundant address objects with the same IP
- **Group Management**: See which address groups contain specific addresses
- **Rule Analysis**: Understand both direct and indirect rule relationships

## Dependencies

- **colorama**: For colored terminal output in interactive mode
- **uv**: Fast Python package manager (installed by setup script)

The tool uses only Python standard library features plus colorama, making it lightweight and portable.

## License

MIT License - see the repository for details.