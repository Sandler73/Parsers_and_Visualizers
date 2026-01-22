#!/usr/bin/env python3
"""
Synopsis:
    Utilities module for Cisco network configuration analysis

Description:
    This module provides utility functions used throughout the Cisco Network
    Configuration Analyzer project. It includes functions for file I/O,
    text parsing, IP address manipulation, and data validation using only
    Python standard library components.

Notes:
    - No external dependencies
    - All functions include comprehensive error handling
    - Supports multiple Cisco configuration formats
    - IP address functions handle both IPv4 and IPv6

Version: 1.0.0
"""

import re
import os
import csv
import io
from typing import List, Dict, Optional, Tuple, Any


def read_config_file(file_path: str) -> List[str]:
    """
    Read a configuration file and return its contents as a list of lines.

    This function reads a Cisco configuration file and returns each line
    as a separate element in a list, preserving the original structure.

    Args:
        file_path: Path to the configuration file

    Returns:
        List of strings, each representing a line from the configuration file

    Raises:
        FileNotFoundError: If the specified file does not exist
        IOError: If there is an error reading the file

    Examples:
        >>> lines = read_config_file('/path/to/config.txt')
        >>> print(len(lines))
        1500
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
        return [line.rstrip() for line in lines]
    except IOError as error:
        raise IOError(f"Error reading configuration file: {error}")


def write_config_file(file_path: str, lines: List[str]) -> None:
    """
    Write configuration lines to a file.

    Args:
        file_path: Path where the configuration file should be written
        lines: List of configuration lines to write

    Returns:
        None

    Raises:
        IOError: If there is an error writing the file
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            for line in lines:
                file.write(line + '\n')
    except IOError as error:
        raise IOError(f"Error writing configuration file: {error}")


def parse_hierarchical_config(lines: List[str]) -> Dict[int, List[str]]:
    """
    Parse configuration lines and organize them by indentation level.

    This function analyzes the indentation of each configuration line and
    creates a hierarchy map. This is useful for understanding parent-child
    relationships in configurations.

    Args:
        lines: List of configuration lines

    Returns:
        Dictionary mapping indentation level to list of lines at that level

    Examples:
        >>> config = ['interface GigabitEthernet0/0', ' ip address 10.0.0.1 255.255.255.0']
        >>> hierarchy = parse_hierarchical_config(config)
        >>> print(hierarchy)
        {0: ['interface GigabitEthernet0/0'], 1: [' ip address 10.0.0.1 255.255.255.0']}
    """
    hierarchy = {}

    for line in lines:
        if not line.strip():
            continue

        # Calculate indentation level (number of leading spaces)
        indent_level = len(line) - len(line.lstrip(' '))

        if indent_level not in hierarchy:
            hierarchy[indent_level] = []

        hierarchy[indent_level].append(line)

    return hierarchy


def find_parent_config(lines: List[str], child_index: int) -> Optional[int]:
    """
    Find the parent configuration line for a given child line.

    This function looks backward from a child line to find its parent
    by checking indentation levels.

    Args:
        lines: List of all configuration lines
        child_index: Index of the child line

    Returns:
        Index of the parent line, or None if no parent found

    Examples:
        >>> config = ['interface Gi0/0', ' description Test', ' ip address 10.0.0.1 255.255.255.0']
        >>> parent_idx = find_parent_config(config, 2)
        >>> print(config[parent_idx])
        interface Gi0/0
    """
    if child_index <= 0 or child_index >= len(lines):
        return None

    child_line = lines[child_index]
    child_indent = len(child_line) - len(child_line.lstrip(' '))

    # Look backward for a line with less indentation
    for index in range(child_index - 1, -1, -1):
        line = lines[index]
        if not line.strip():
            continue

        line_indent = len(line) - len(line.lstrip(' '))

        if line_indent < child_indent:
            return index

    return None


def extract_interface_name(line: str) -> Optional[str]:
    """
    Extract interface name from a configuration line.

    Args:
        line: Configuration line that may contain an interface name

    Returns:
        Interface name if found, None otherwise

    Examples:
        >>> extract_interface_name('interface GigabitEthernet0/0/1')
        'GigabitEthernet0/0/1'
        >>> extract_interface_name('interface FastEthernet0/1.100')
        'FastEthernet0/1.100'
    """
    # Pattern matches common Cisco interface naming conventions
    pattern = r'interface\s+(\S+)'
    match = re.search(pattern, line, re.IGNORECASE)

    if match:
        return match.group(1)

    return None


def extract_vlan_id(line: str) -> Optional[int]:
    """
    Extract VLAN ID from a configuration line.

    Args:
        line: Configuration line that may contain a VLAN ID

    Returns:
        VLAN ID as an integer if found, None otherwise

    Examples:
        >>> extract_vlan_id('vlan 100')
        100
        >>> extract_vlan_id('switchport access vlan 50')
        50
    """
    # Pattern for standalone VLAN declaration
    pattern1 = r'vlan\s+(\d+)'
    match = re.search(pattern1, line, re.IGNORECASE)
    if match:
        return int(match.group(1))

    # Pattern for switchport access vlan
    pattern2 = r'switchport\s+access\s+vlan\s+(\d+)'
    match = re.search(pattern2, line, re.IGNORECASE)
    if match:
        return int(match.group(1))

    return None


def extract_ip_address(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract IP address and subnet mask from a configuration line.

    Args:
        line: Configuration line that may contain an IP address

    Returns:
        Tuple of (ip_address, subnet_mask) or (None, None) if not found

    Examples:
        >>> extract_ip_address('ip address 192.168.1.1 255.255.255.0')
        ('192.168.1.1', '255.255.255.0')
        >>> extract_ip_address('no ip address')
        (None, None)
    """
    # Pattern for standard IPv4 address configuration
    pattern = r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, line, re.IGNORECASE)

    if match:
        return (match.group(1), match.group(2))

    return (None, None)


def extract_ipv6_address(line: str) -> Optional[str]:
    """
    Extract IPv6 address from a configuration line.

    Args:
        line: Configuration line that may contain an IPv6 address

    Returns:
        IPv6 address if found, None otherwise

    Examples:
        >>> extract_ipv6_address('ipv6 address 2001:db8::1/64')
        '2001:db8::1/64'
    """
    # Pattern for IPv6 address
    pattern = r'ipv6\s+address\s+([0-9a-fA-F:]+(?:/\d+)?)'
    match = re.search(pattern, line, re.IGNORECASE)

    if match:
        return match.group(1)

    return None


def parse_vlan_list(vlan_string: str) -> List[int]:
    """
    Parse a VLAN list string into individual VLAN IDs.

    This function handles VLAN ranges and comma-separated lists.

    Args:
        vlan_string: String containing VLANs (e.g., "10,20-25,30")

    Returns:
        List of individual VLAN IDs

    Examples:
        >>> parse_vlan_list("10,20-23,30")
        [10, 20, 21, 22, 23, 30]
    """
    vlans = []

    if not vlan_string or vlan_string.strip().lower() in ['none', 'all']:
        return vlans

    # Split by comma
    parts = vlan_string.split(',')

    for part in parts:
        part = part.strip()

        if '-' in part:
            # Handle range (e.g., "20-25")
            try:
                start, end = part.split('-')
                start_vlan = int(start)
                end_vlan = int(end)
                vlans.extend(range(start_vlan, end_vlan + 1))
            except ValueError:
                continue
        else:
            # Handle single VLAN
            try:
                vlans.append(int(part))
            except ValueError:
                continue

    return sorted(list(set(vlans)))


def is_valid_ipv4_address(ip_address: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.

    Args:
        ip_address: String to validate as IPv4 address

    Returns:
        True if valid IPv4 address, False otherwise

    Examples:
        >>> is_valid_ipv4_address("192.168.1.1")
        True
        >>> is_valid_ipv4_address("999.999.999.999")
        False
    """
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip_address)

    if not match:
        return False

    # Check each octet is in valid range (0-255)
    for octet in match.groups():
        if int(octet) > 255:
            return False

    return True


def is_valid_subnet_mask(mask: str) -> bool:
    """
    Validate if a string is a valid subnet mask.

    Args:
        mask: String to validate as subnet mask

    Returns:
        True if valid subnet mask, False otherwise

    Examples:
        >>> is_valid_subnet_mask("255.255.255.0")
        True
        >>> is_valid_subnet_mask("255.255.255.1")
        False
    """
    if not is_valid_ipv4_address(mask):
        return False

    # Convert to binary and check it's contiguous 1s followed by 0s
    octets = mask.split('.')
    binary = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])

    # Valid subnet mask has all 1s before all 0s with no gaps
    if '01' in binary:
        return False

    return True


def subnet_mask_to_cidr(mask: str) -> Optional[int]:
    """
    Convert subnet mask to CIDR notation.

    Args:
        mask: Subnet mask in dotted decimal notation

    Returns:
        CIDR prefix length as integer, or None if invalid

    Examples:
        >>> subnet_mask_to_cidr("255.255.255.0")
        24
        >>> subnet_mask_to_cidr("255.255.0.0")
        16
    """
    if not is_valid_subnet_mask(mask):
        return None

    octets = mask.split('.')
    binary = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])

    return binary.count('1')


def cidr_to_subnet_mask(cidr: int) -> Optional[str]:
    """
    Convert CIDR prefix length to subnet mask.

    Args:
        cidr: CIDR prefix length (0-32)

    Returns:
        Subnet mask in dotted decimal notation, or None if invalid

    Examples:
        >>> cidr_to_subnet_mask(24)
        '255.255.255.0'
        >>> cidr_to_subnet_mask(16)
        '255.255.0.0'
    """
    if cidr < 0 or cidr > 32:
        return None

    # Create binary string with 'cidr' number of 1s
    binary = '1' * cidr + '0' * (32 - cidr)

    # Convert to dotted decimal
    octets = [str(int(binary[i:i+8], 2)) for i in range(0, 32, 8)]

    return '.'.join(octets)


def calculate_network_address(ip_address: str, subnet_mask: str) -> Optional[str]:
    """
    Calculate network address from IP address and subnet mask.

    Args:
        ip_address: IP address in dotted decimal notation
        subnet_mask: Subnet mask in dotted decimal notation

    Returns:
        Network address, or None if invalid input

    Examples:
        >>> calculate_network_address("192.168.1.100", "255.255.255.0")
        '192.168.1.0'
    """
    if not is_valid_ipv4_address(ip_address) or not is_valid_subnet_mask(subnet_mask):
        return None

    ip_octets = [int(octet) for octet in ip_address.split('.')]
    mask_octets = [int(octet) for octet in subnet_mask.split('.')]

    network_octets = [str(ip_octets[i] & mask_octets[i]) for i in range(4)]

    return '.'.join(network_octets)


def normalize_interface_name(interface_name: str) -> str:
    """
    Normalize interface name to a standard format.

    This function expands abbreviated interface names to their full form.

    Args:
        interface_name: Interface name (may be abbreviated)

    Returns:
        Normalized interface name

    Examples:
        >>> normalize_interface_name("Gi0/0/1")
        'GigabitEthernet0/0/1'
        >>> normalize_interface_name("Fa0/1")
        'FastEthernet0/1'
    """
    # Dictionary of abbreviations to full names
    abbreviations = {
        'Gi': 'GigabitEthernet',
        'GE': 'GigabitEthernet',
        'Fa': 'FastEthernet',
        'FE': 'FastEthernet',
        'Te': 'TenGigabitEthernet',
        'TE': 'TenGigabitEthernet',
        'Eth': 'Ethernet',
        'Se': 'Serial',
        'Lo': 'Loopback',
        'Tu': 'Tunnel',
        'Po': 'Port-channel',
        'Vl': 'Vlan'
    }

    for abbrev, full_name in abbreviations.items():
        if interface_name.startswith(abbrev):
            return interface_name.replace(abbrev, full_name, 1)

    return interface_name


def parse_acl_entry(line: str) -> Dict[str, Any]:
    """
    Parse an ACL entry line into its components.

    Args:
        line: ACL entry configuration line

    Returns:
        Dictionary containing parsed ACL entry components

    Examples:
        >>> parse_acl_entry("permit tcp any host 10.0.0.1 eq 80")
        {'action': 'permit', 'protocol': 'tcp', 'source': 'any', 'destination': 'host 10.0.0.1', 'port': '80'}
    """
    entry = {
        'sequence': None,
        'action': '',
        'protocol': '',
        'source': '',
        'destination': '',
        'flags': [],
        'raw': line.strip()
    }

    # Remove leading whitespace
    line = line.strip()

    # Extract sequence number if present
    seq_match = re.match(r'(\d+)\s+', line)
    if seq_match:
        entry['sequence'] = int(seq_match.group(1))
        line = line[seq_match.end():]

    # Split line into tokens
    tokens = line.split()

    if len(tokens) < 2:
        return entry

    # Extract action (permit/deny)
    entry['action'] = tokens[0]

    # Extract protocol
    entry['protocol'] = tokens[1]

    # The rest depends on the protocol and ACL type
    # This is a simplified parser - could be expanded for more detail
    if len(tokens) > 2:
        entry['source'] = tokens[2]

    if len(tokens) > 3:
        entry['destination'] = tokens[3]

    return entry


def detect_device_type(config_lines: List[str]) -> str:
    """
    Detect the type of network device from its configuration.

    Args:
        config_lines: List of configuration lines

    Returns:
        Device type string (ios, iosxe, nxos, asa, junos, panos, eltex, fortigate, unknown)

    Examples:
        >>> lines = ["version 15.2", "hostname Router1"]
        >>> detect_device_type(lines)
        'ios'
        
        >>> lines = ["set system host-name router"]
        >>> detect_device_type(lines)
        'junos'
    """
    # Join first 100 lines for analysis
    header = '\n'.join(config_lines[:100]).lower()
    
    # Check for Juniper JunOS (set command format)
    if 'set system' in header or 'set interfaces' in header or 'set protocols' in header:
        return 'junos'
    
    # Check for Palo Alto (XML or set deviceconfig)
    if '<?xml' in header or '<config' in header or 'set deviceconfig' in header:
        return 'panos'
    
    # Check for Eltex (similar to Cisco but with eltex-specific commands)
    if 'eltex' in header or ('spanning-tree mode' in header and 'snmp-server community' in header):
        return 'eltex'
    
    # Check for Fortigate
    if 'config system' in header or 'fortigate' in header or 'fortios' in header:
        return 'fortigate'
    
    # Check for Cisco ASA
    if 'asa' in header or ('firewall' in header and 'cisco' in header):
        return 'asa'
    
    # Check for Cisco NX-OS
    if 'nx-os' in header or 'nexus' in header:
        return 'nxos'
    
    # Check for Cisco IOS-XE
    if 'ios-xe' in header:
        return 'iosxe'
    
    # Default to IOS for Cisco-like configs
    if 'version' in header and ('hostname' in header or 'interface' in header):
        return 'ios'
    
    return 'unknown'


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for file system use

    Examples:
        >>> sanitize_filename("my/file:name.txt")
        'my_file_name.txt'
    """
    # Replace invalid characters with underscore
    invalid_chars = r'[<>:"/\\|?*]'
    sanitized = re.sub(invalid_chars, '_', filename)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')

    return sanitized


def format_mac_address(mac: str) -> str:
    """
    Format MAC address to standard notation.

    Args:
        mac: MAC address in any common format

    Returns:
        MAC address in standard format (XX:XX:XX:XX:XX:XX)

    Examples:
        >>> format_mac_address("0011.2233.4455")
        '00:11:22:33:44:55'
        >>> format_mac_address("00-11-22-33-44-55")
        '00:11:22:33:44:55'
    """
    # Remove all separators
    mac_clean = re.sub(r'[.:\-]', '', mac)

    # Ensure it's 12 characters
    if len(mac_clean) != 12:
        return mac

    # Format as XX:XX:XX:XX:XX:XX
    formatted = ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])

    return formatted.upper()


# End of utilities.py