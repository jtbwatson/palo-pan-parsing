import argparse
import json
import os
import re
from collections import defaultdict
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Define color constants
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.WHITE
COLOR_SECTION = Fore.BLUE + Style.BRIGHT
COLOR_HIGHLIGHT = Fore.CYAN
COLOR_SECONDARY = Fore.MAGENTA
COLOR_DIM = Style.DIM + Fore.WHITE
COLOR_LIST_ITEM = Fore.GREEN
COLOR_RESET = Style.RESET_ALL

# Pre-compiled regex patterns for better performance
PATTERNS = {
    'security_rule_quoted': re.compile(r'security-rule\s+"([^"]+)"'),
    'security_rule_unquoted': re.compile(r'security-rule\s+(\S+)'),
    'security_rules_quoted': re.compile(r'security\s+rules\s+"([^"]+)"'),
    'security_rules_unquoted': re.compile(r'security\s+rules\s+(\S+)'),
    'device_group': re.compile(r'device-group\s+(\S+)'),
    'address_group_shared': re.compile(r'set\s+shared\s+address-group\s+(\S+)\s+static\s+(.+)'),
    'address_group_device': re.compile(r'set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+static\s+(.+)'),
    'nat_rule': re.compile(r'nat-rule\s+(\S+)'),
    'service_group': re.compile(r'service-group\s+(\S+)'),
    'ip_netmask': re.compile(r'set\s+(?:shared|device-group\s+\S+)\s+address\s+(\S+)\s+ip-netmask\s+([\d\.]+/\d+)'),
    'address_by_ip': re.compile(r'set\s+(?:shared|device-group\s+(\S+))\s+address\s+(\S+)\s+ip-netmask\s+')
}

class PANLogProcessor:
    def __init__(self):
        self.results = defaultdict(lambda: {
            'matching_lines': [],
            'device_groups': set(),
            'direct_rules': {},
            'direct_rule_contexts': {},
            'indirect_rules': {},
            'indirect_rule_contexts': {},
            'address_groups': [],
            'nat_rules': set(),
            'service_groups': set(),
            'ip_netmask': None,
            'redundant_addresses': []
        })
        
    def process_file_single_pass(self, file_path, addresses):
        """Process file once, collecting all needed data for all addresses"""
        address_set = set(addresses)
        ip_to_addresses = {}  # Maps IP netmasks to addresses for redundancy detection
        
        try:
            with open(file_path, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Check for IP netmask definitions first
                    ip_match = PATTERNS['ip_netmask'].search(line)
                    if ip_match:
                        addr_name, ip_netmask = ip_match.groups()
                        if addr_name in address_set:
                            self.results[addr_name]['ip_netmask'] = ip_netmask
                        # Track all IP mappings for redundancy detection
                        if ip_netmask not in ip_to_addresses:
                            ip_to_addresses[ip_netmask] = []
                        ip_to_addresses[ip_netmask].append((addr_name, line))
                    
                    # Check if line contains any of our target addresses
                    matching_addresses = [addr for addr in address_set if addr in line]
                    
                    if not matching_addresses:
                        continue
                        
                    # Process line for each matching address
                    for address in matching_addresses:
                        self.results[address]['matching_lines'].append(line)
                        self._extract_items_from_line(line, address)
                        
        except FileNotFoundError:
            print(f"{COLOR_ERROR}Error: File '{file_path}' not found.")
            return False
        except Exception as e:
            print(f"{COLOR_ERROR}Error reading file: {e}")
            return False
            
        # Process redundant addresses
        self._find_redundant_addresses(ip_to_addresses, address_set)
        
        # Find indirect security rules (requires second pass only for address groups)
        self._find_indirect_rules(file_path, addresses)
        
        return True
    
    def _extract_items_from_line(self, line, address):
        """Extract all relevant items from a single line"""
        result = self.results[address]
        
        # Extract device groups
        dg_match = PATTERNS['device_group'].search(line)
        if dg_match:
            result['device_groups'].add(dg_match.group(1))
            
        # Extract security rules with context
        rule_name, context = self._extract_security_rule(line, address)
        if rule_name:
            # Determine device group for this rule
            device_group = dg_match.group(1) if dg_match else "Unknown"
            result['direct_rules'][rule_name] = device_group
            result['direct_rule_contexts'][rule_name] = context
            
        # Extract address groups
        ag_info = self._extract_address_group(line)
        if ag_info and ag_info not in result['address_groups']:
            result['address_groups'].append(ag_info)
            
        # Extract NAT rules
        nat_match = PATTERNS['nat_rule'].search(line)
        if nat_match:
            result['nat_rules'].add(nat_match.group(1))
            
        # Extract service groups
        sg_match = PATTERNS['service_group'].search(line)
        if sg_match:
            result['service_groups'].add(sg_match.group(1))
    
    def _extract_security_rule(self, line, address):
        """Extract security rule name and determine context"""
        rule_name = None
        
        # Try different patterns for security rules
        for pattern_name in ['security_rule_quoted', 'security_rule_unquoted', 
                           'security_rules_quoted', 'security_rules_unquoted']:
            match = PATTERNS[pattern_name].search(line)
            if match:
                rule_name = match.group(1)
                break
                
        if not rule_name:
            return None, None
            
        # Determine context
        context = "references directly"
        if "destination" in line and address in line.split("destination")[1].split("source")[0]:
            context = "contains address in destination"
        elif "source" in line and address in line.split("source")[1].split("destination")[0]:
            context = "contains address in source"
        elif "service" in line and address in line.split("service")[1]:
            context = "references address in service field"
            
        return rule_name, context
    
    def _extract_address_group(self, line):
        """Extract address group information with context"""
        # Check shared address groups
        match = PATTERNS['address_group_shared'].search(line)
        if match:
            group_name, definition = match.groups()
            return {
                "name": group_name,
                "context": "shared",
                "definition": definition
            }
            
        # Check device group address groups
        match = PATTERNS['address_group_device'].search(line)
        if match:
            device_group, group_name, definition = match.groups()
            return {
                "name": group_name,
                "context": "device-group",
                "device_group": device_group,
                "definition": definition
            }
            
        return None
    
    def _find_redundant_addresses(self, ip_to_addresses, target_addresses):
        """Find addresses with same IP netmask"""
        for ip_netmask, addr_list in ip_to_addresses.items():
            if len(addr_list) > 1:
                for target_addr in target_addresses:
                    if any(addr_name == target_addr for addr_name, _ in addr_list):
                        # Found redundant addresses for this target
                        redundant = []
                        for addr_name, line in addr_list:
                            if addr_name != target_addr:
                                # Determine device group
                                if line.startswith("set shared"):
                                    dg = "shared"
                                else:
                                    dg_match = re.search(r'set\s+device-group\s+(\S+)\s+address', line)
                                    dg = dg_match.group(1) if dg_match else "Unknown"
                                
                                redundant.append({
                                    "name": addr_name,
                                    "ip-netmask": ip_netmask,
                                    "device_group": dg
                                })
                        self.results[target_addr]['redundant_addresses'] = redundant
    
    def _find_indirect_rules(self, file_path, addresses):
        """Find security rules that reference address groups containing our addresses"""
        # Collect all address groups from results
        all_groups = {}
        for addr in addresses:
            for group in self.results[addr]['address_groups']:
                all_groups[group['name']] = (group, addr)
        
        if not all_groups:
            return
            
        # Single pass to find rules referencing these groups
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if not ("security rules" in line or "security-rule" in line):
                        continue
                        
                    # Check if line references any of our address groups
                    referenced_groups = [(name, info) for name, info in all_groups.items() if name in line]
                    if not referenced_groups:
                        continue
                        
                    # Extract rule name and device group
                    rule_name, _ = self._extract_security_rule(line, "")
                    if not rule_name:
                        continue
                        
                    dg_match = PATTERNS['device_group'].search(line)
                    device_group = dg_match.group(1) if dg_match else "Unknown"
                    
                    # Add to results for each relevant address
                    for group_name, (group_info, target_addr) in referenced_groups:
                        # Skip if already in direct rules
                        if rule_name in self.results[target_addr]['direct_rules']:
                            continue
                            
                        if 'indirect_rules' not in self.results[target_addr]:
                            self.results[target_addr]['indirect_rules'] = {}
                            self.results[target_addr]['indirect_rule_contexts'] = {}
                            
                        self.results[target_addr]['indirect_rules'][rule_name] = device_group
                        
                        # Create context
                        context = f"references address-group '{group_name}' that contains {target_addr}"
                        if group_info['context'] == "shared":
                            context = f"references shared address-group '{group_name}' that contains {target_addr}"
                        elif group_info['context'] == "device-group":
                            context = f"references address-group '{group_name}' from device-group '{group_info['device_group']}' that contains {target_addr}"
                            
                        # Add usage context
                        if "destination" in line and group_name in line:
                            # Check if group appears after "destination" keyword
                            dest_parts = line.split("destination")
                            if len(dest_parts) > 1 and group_name in dest_parts[1]:
                                context += " (in destination)"
                        elif "source" in line and group_name in line:
                            # Check if group appears after "source" keyword  
                            source_parts = line.split("source")
                            if len(source_parts) > 1 and group_name in source_parts[1]:
                                context += " (in source)"
                            
                        self.results[target_addr]['indirect_rule_contexts'][rule_name] = context
                        
        except Exception as e:
            print(f"{COLOR_ERROR}Error finding indirect rules: {e}")
    
    def format_results(self, address):
        """Format results for a specific address"""
        result = self.results[address]
        
        # Format direct rules
        direct_rules = []
        for rule, dg in result['direct_rules'].items():
            context = result['direct_rule_contexts'].get(rule, 'direct reference')
            direct_rules.append(f"{rule} (Device Group: {dg}, {context})")
            
        # Format indirect rules
        indirect_rules = []
        if 'indirect_rules' in result:
            for rule, dg in result.get('indirect_rules', {}).items():
                context = result.get('indirect_rule_contexts', {}).get(rule, 'indirect reference')
                indirect_rules.append(f"{rule} (Device Group: {dg}, {context})")
        
        return {
            "Device Groups": list(result['device_groups']),
            "Direct Security Rules": direct_rules,
            "Indirect Security Rules (via Address Groups)": indirect_rules,
            "Address Groups": result['address_groups'],
            "NAT Rules": list(result['nat_rules']),
            "Service Groups": list(result['service_groups']),
            "Redundant Addresses": result['redundant_addresses']
        }

def write_results(output_file, address_name, matching_lines, items_dict):
    """Write results to file in a structured YAML-like format"""
    try:
        with open(output_file, "w") as file:
            file.write(f"# Analysis for: {address_name}\n---\n\n")
            file.write(f"# Matching Lines: {len(matching_lines)}\n---\n\n")
            
            for line in matching_lines:
                file.write(f"  {line}\n")
            
            for category, items in items_dict.items():
                file.write(f"\n# {category}: {len(items) if items else 0}\n---\n")
                
                if "Security Rules" in category and items:
                    # Group rules by device group
                    rules_by_dg = {}
                    for item in items:
                        parts = item.split(" (Device Group: ")
                        if len(parts) == 2:
                            rule_name = parts[0]
                            dg_part = parts[1]
                            # Remove only the final closing parenthesis
                            if dg_part.endswith(")"):
                                dg_part = dg_part[:-1]
                            
                            if ", " in dg_part:
                                device_group, context = dg_part.split(", ", 1)
                            else:
                                device_group = dg_part
                                context = None
                            
                            if device_group not in rules_by_dg:
                                rules_by_dg[device_group] = []
                            rules_by_dg[device_group].append((rule_name, context))
                    
                    for dg, rules in sorted(rules_by_dg.items()):
                        file.write(f"  {dg}:\n")
                        for rule, context in rules:
                            if context:
                                file.write(f"    - {rule}  # {context}\n")
                            else:
                                file.write(f"    - {rule}\n")
                        file.write("\n")
                
                elif category == "Address Groups" and items:
                    for group in items:
                        if isinstance(group, dict):
                            if group["context"] == "shared":
                                file.write(f"  {group['name']} (shared):\n")
                                file.write(f"    set shared address-group {group['name']} static {group['definition']}\n\n")
                            else:
                                file.write(f"  {group['name']} (device-group: {group['device_group']}):\n")
                                file.write(f"    set device-group {group['device_group']} address-group {group['name']} static {group['definition']}\n\n")
                        else:
                            file.write(f"  - {group}\n")
                
                elif category == "Redundant Addresses" and items:
                    file.write("  Redundant address objects with same ip-netmask:\n")
                    for addr in items:
                        file.write(f"    - {addr['name']}:\n")
                        file.write(f"      - ip-netmask: {addr['ip-netmask']}\n")
                        file.write(f"      - device group: {addr['device_group']}\n")
                
                elif items:
                    for item in items:
                        file.write(f"  - {item}\n")
                else:
                    file.write("  # None found\n")
                
                file.write("\n")
        return True
    except Exception as e:
        print(f"{COLOR_ERROR}Error writing to output file: {e}")
        return False

def generate_add_commands(results_file, new_address):
    """Generate commands to add a new address to all address groups"""
    commands = []
    try:
        with open(results_file, 'r') as f:
            content = f.read()
        
        if "# Address Groups:" in content:
            address_groups_section = content.split("# Address Groups:")[1].split("#")[0]
            
            for line in address_groups_section.strip().split('\n'):
                if 'set ' in line:
                    if 'set device-group' in line:
                        parts = line.strip().split('address-group')
                        prefix = parts[0] + 'address-group'
                        remaining = parts[1].strip()
                        group_name = remaining.split('static', 1)[0].strip()
                        commands.append(f"{prefix} {group_name} member {new_address}")
                    elif 'set shared' in line:
                        parts = line.strip().split('address-group')
                        prefix = parts[0] + 'address-group'
                        remaining = parts[1].strip()
                        group_name = remaining.split('static', 1)[0].strip()
                        commands.append(f"{prefix} {group_name} member {new_address}")
    except Exception as e:
        print(f"{COLOR_ERROR}Error generating commands: {e}")
    
    return commands

def process_address(address_name, processor, interactive_mode, output_override=None):
    """Process a single address and generate results"""
    if interactive_mode:
        print(f"\n{COLOR_SECTION}Processing address: {COLOR_HIGHLIGHT}{address_name}")
    
    if address_name not in processor.results or not processor.results[address_name]['matching_lines']:
        print(f"{COLOR_WARNING}No matches found for '{address_name}'")
        return False
    
    result = processor.results[address_name]
    
    if interactive_mode:
        print(f"{COLOR_SUCCESS}✓ Found {COLOR_HIGHLIGHT}{len(result['matching_lines'])}{COLOR_SUCCESS} lines containing '{COLOR_HIGHLIGHT}{address_name}{COLOR_SUCCESS}'")
    
    # Format results
    items_dict = processor.format_results(address_name)
    
    # Get output file name
    output_file = output_override or f"{address_name}_results.yml"
    
    if interactive_mode:
        print(f"{COLOR_INFO}Writing results to {COLOR_HIGHLIGHT}{output_file}{COLOR_INFO}...")
    
    success = write_results(output_file, address_name, result['matching_lines'], items_dict)
    
    if success:
        if interactive_mode:
            print(f"{COLOR_SUCCESS}✓ Results successfully written to file!")
            print(f"\n{COLOR_SECTION}Summary of findings:")
            print(f"{COLOR_DIM}========================================")
        else:
            print(f"{COLOR_SUCCESS}Results written to {output_file}")
            
        for category, items in items_dict.items():
            count = len(items) if items else 0
            print(f"{COLOR_INFO}{category}: {COLOR_HIGHLIGHT}{count}{COLOR_INFO} found")
        
        if any(len(items) > 0 for items in items_dict.values()):
            print(f"\n{COLOR_INFO}All details have been written to {COLOR_HIGHLIGHT}{output_file}{COLOR_INFO}.")
            print(f"{COLOR_DIM}========================================")

        return True
    return False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
    {COLOR_TITLE}╔════════════════════════════════════════════╗
    {COLOR_TITLE}║           PAN Log Parser Tool              ║
    {COLOR_TITLE}╚════════════════════════════════════════════╝
    """
    print(banner)

def interactive_input(prompt, default=None):
    if default:
        user_input = input(f"{COLOR_SECTION}{prompt} {COLOR_RESET}[default: {COLOR_HIGHLIGHT}{default}{COLOR_RESET}]: ")
        return user_input if user_input else default
    else:
        return input(f"{COLOR_SECTION}{prompt}{COLOR_RESET}: ")

def parse_args():
    parser = argparse.ArgumentParser(description="Parse PAN logs for address references")
    parser.add_argument("-a", "--address", help="Address name to search for (comma-separated for multiple)")
    parser.add_argument("-l", "--logfile", help="Path to the log file", default="default.log")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    return parser.parse_args()

def read_config_file(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"{COLOR_ERROR}Error: Configuration file '{file_path}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"{COLOR_ERROR}Error: Configuration file '{file_path}' is not valid JSON.")
        return {}
    except Exception as e:
        print(f"{COLOR_ERROR}Error reading configuration file: {e}")
        return {}

def main():
    args = parse_args()
    interactive_mode = args.interactive
    
    if interactive_mode:
        clear_screen()
        print_banner()
        print(f"{COLOR_INFO}This tool will help you search for address objects in your PAN logs.\n")
    
    config = {}
    if args.config:
        config = read_config_file(args.config)
    
    # Get log file
    default_log = "default.log"
    if interactive_mode:
        config_file = interactive_input("Enter log file path", default_log)
    else:
        config_file = args.logfile or config.get("log_file") or input(f"Enter log file path [default: {default_log}]: ") or default_log
    
    # Get addresses
    addresses = []
    if interactive_mode:
        print(f"\n{COLOR_SECTION}You can enter multiple address objects to search for.")
        print(f"{COLOR_INFO}To enter multiple addresses, separate them with commas.")
        print(f"{COLOR_INFO}Example: {COLOR_HIGHLIGHT}address1,address2,address3\n")
        
        address_input = interactive_input("Enter address name(s)")
        while not address_input:
            print(f"{COLOR_ERROR}At least one address name is required!")
            address_input = interactive_input("Enter address name(s)")
        addresses = [addr.strip() for addr in address_input.split(",")]
    else:
        if args.address:
            addresses = [addr.strip() for addr in args.address.split(",")]
        elif config.get("address_name"):
            if isinstance(config["address_name"], list):
                addresses = config["address_name"]
            else:
                addresses = [addr.strip() for addr in config["address_name"].split(",")]
        else:
            address_input = input("Enter the address name (comma-separated for multiple): ")
            addresses = [addr.strip() for addr in address_input.split(",")]
    
    if interactive_mode:
        print(f"\n{COLOR_INFO}Reading log file: {COLOR_HIGHLIGHT}{config_file}{COLOR_INFO}...")
    
    # Process file once for all addresses
    processor = PANLogProcessor()
    if not processor.process_file_single_pass(config_file, addresses):
        return
    
    # Process results for each address
    if len(addresses) > 1 and interactive_mode:
        print(f"\n{COLOR_SECTION}Processing {COLOR_HIGHLIGHT}{len(addresses)}{COLOR_SECTION} address objects: {COLOR_HIGHLIGHT}{', '.join(addresses)}")
        
        use_single_file = interactive_input("Use a single output file for all addresses? (y/n)", "n").lower() == "y"
        
        if use_single_file:
            output_file = "multiple_addresses_results.yml"
            results_count = 0
            for address in addresses:
                result = process_address(address, processor, interactive_mode, output_file)
                if result:
                    results_count += 1
            
            if results_count > 0:
                print(f"\n{COLOR_SUCCESS}Processed {COLOR_HIGHLIGHT}{results_count}{COLOR_SUCCESS} out of {COLOR_HIGHLIGHT}{len(addresses)}{COLOR_SUCCESS} addresses.")
                print(f"{COLOR_SUCCESS}All results written to: {COLOR_HIGHLIGHT}{output_file}")
                
                if interactive_mode:
                    generate_commands = interactive_input("Would you like to generate commands to add a new address to all identified address groups? (y/n)", "n").lower() == "y"
                    if generate_commands:
                        new_address = interactive_input("Enter the new address object name")
                        if new_address:
                            commands = generate_add_commands(output_file, new_address)
                            if commands:
                                commands_file = f"add_{new_address}_commands.txt"
                                with open(commands_file, "w") as f:
                                    for cmd in commands:
                                        f.write(cmd + "\n")
                                
                                print(f"\n{COLOR_SUCCESS}Generated {COLOR_HIGHLIGHT}{len(commands)}{COLOR_SUCCESS} commands to add '{COLOR_HIGHLIGHT}{new_address}{COLOR_SUCCESS}' to address groups.")
                                print(f"{COLOR_SUCCESS}Commands written to: {COLOR_HIGHLIGHT}{commands_file}")
                                
                                if len(commands) > 0:
                                    print(f"\n{COLOR_SECTION}Sample commands:")
                                    for cmd in commands[:3]:
                                        print(f"  {COLOR_LIST_ITEM}{cmd}")
                                    if len(commands) > 3:
                                        print(f"  {COLOR_DIM}... {len(commands)-3} more commands in the file")
                            else:
                                print(f"{COLOR_WARNING}No address groups found to modify.")
        else:
            results_count = 0
            output_files = []
            
            for address in addresses:
                result = process_address(address, processor, interactive_mode)
                if result:
                    results_count += 1
                    output_files.append(f"{address}_results.yml")
            
            if results_count > 0:
                print(f"\n{COLOR_SUCCESS}Processed {COLOR_HIGHLIGHT}{results_count}{COLOR_SUCCESS} out of {COLOR_HIGHLIGHT}{len(addresses)}{COLOR_SUCCESS} addresses.")
                print(f"{COLOR_SUCCESS}Results written to individual files:")
                for output_file in output_files:
                    print(f"  {COLOR_LIST_ITEM}- {COLOR_HIGHLIGHT}{output_file}")
    else:
        # Single address
        process_address(addresses[0], processor, interactive_mode)
    
    if interactive_mode:
        print(f"\n{COLOR_TITLE}Thank you for using the PAN Log Parser Tool!")

if __name__ == "__main__":
    main()