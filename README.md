# PAN Log Parser Tool

A command-line utility for parsing Palo Alto Networks logs to analyze address object references.

## Overview

This tool searches PAN log files to find references to specific IP address objects, including:
- Security rules directly or indirectly referencing the address (via address groups)
- Address groups containing the address
- Device groups using the address
- NAT rules referencing the address
- Service groups containing the address

## Installation

### Prerequisites
- Python 3.x
- Node.js

### Setup
```bash
sudo apt install npm
```

## Usage
#### Interactive Mode
Run the parser in interactive mode for a guided experience:
```bash
npm run parser
```
#### Command Line Mode
```bash
python parse.py -a <address_name> -l <log_file> -o <output_file>
```

### Options:
-a, --address: Address name to search for (comma-separated for multiple)
-l, --logfile: Path to the log file (default: nsr-pan1.log)
-o, --output: Output file name
-c, --config: Path to configuration file
-i, --interactive: Run in interactive mode

## Features
- Multiple Address Search: Search for multiple addresses at once
- Address Group Detection: Find all address groups containing your target address
- Indirect Reference Analysis: Discover security rules that indirectly reference your address
- Rule Context: See how addresses are used (source, destination, etc.)
- Command Generation: Generate commands to add new addresses to identified groups
- Colored Output: Easy-to-read terminal output with color coding

## Output Format
Results are saved in a YAML-like format with sections for:

- Matching log lines
- Device groups
- Direct security rules
- Indirect security rules
- Address groups
- NAT rules
- Service groups

## Examples

Basic Search
```bash
python parse.py -a web-server-01 -l firewall.log
```
Multiple Address Search
```bash
python parse.py -a "web-server-01,db-server-02,proxy-01"
```
Using Configuration File
```bash
python parse.py -c config.json
```