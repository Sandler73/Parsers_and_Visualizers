#!/usr/bin/env python3
"""
Synopsis:
    Comprehensive Cisco ASA Firewall Configuration Parser

Description:
    This module provides complete parsing capabilities for Cisco ASA firewall
    configurations. Handles security contexts, object groups, NAT rules,
    security levels, and ASA-specific ACL syntax.

Version: 2.0.0
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .ios_parser import IOSParser
from shared_components.data_structures import NetworkInterface, AccessControlList, Endpoint


class ASAParser(IOSParser):
    """
    Comprehensive parser for Cisco ASA firewall configurations.
    
    Handles ASA-specific features including security contexts, object groups,
    NAT configurations, and security level assignments.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize ASA parser."""
        super().__init__(verbose)
    
    def log(self, message: str) -> None:
        """Log with ASA prefix."""
        if self.verbose:
            print(f"[ASA Parser] {message}")
    
    def parse(self, config_lines):
        """Parse ASA configuration with firewall-specific features."""
        # Call parent parse
        device_config = super().parse(config_lines)
        
        # Add ASA-specific parsing
        self.parse_security_contexts()
        self.parse_asa_object_groups()  # Renamed to avoid conflict
        self.parse_nat_config()
        self.parse_failover_config()
        
        return device_config
    
    def parse_interface_details(self, interface, config_lines):
        """Parse ASA-specific interface details."""
        # First call parent method for common attributes
        super().parse_interface_details(interface, config_lines)
        
        # Add ASA-specific features
        for line in config_lines:
            # Nameif (ASA's interface name/description)
            nameif_match = re.search(r'^\s*nameif\s+(\S+)', line, re.IGNORECASE)
            if nameif_match:
                nameif = nameif_match.group(1)
                # Set as description if not already set
                if not interface.description or interface.description == '':
                    interface.description = nameif
                else:
                    interface.description = f"{nameif} - {interface.description}"
            
            # Security level
            sec_level_match = re.search(r'^\s*security-level\s+(\d+)', line, re.IGNORECASE)
            if sec_level_match:
                security_level = sec_level_match.group(1)
                interface.additional_config.append(f"Security Level: {security_level}")
            
            # ASA IP address format: "ip address 192.168.1.1 255.255.255.0"
            ip_match = re.search(
                r'^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
                line,
                re.IGNORECASE
            )
            if ip_match:
                interface.ip_address = ip_match.group(1)
                interface.ip_mask = ip_match.group(2)
            
            # ASA DHCP client
            if re.search(r'^\s*ip\s+address\s+dhcp', line, re.IGNORECASE):
                interface.ip_address = "DHCP"
                interface.ip_mask = ""
            
            # VLAN assignment (ASA uses "vlan" keyword)
            vlan_match = re.search(r'^\s*vlan\s+(\d+)', line, re.IGNORECASE)
            if vlan_match:
                interface.vlan = int(vlan_match.group(1))
    
    def parse_security_contexts(self) -> None:
        """Parse security context configuration."""
        self.log("Parsing security contexts")
        
        contexts = []
        
        for line in self.config_lines:
            context_match = re.match(r'context\s+(\S+)', line, re.IGNORECASE)
            if context_match:
                contexts.append(context_match.group(1))
        
        if contexts:
            self.device_config.aaa_config['security_contexts'] = contexts
            self.log(f"Found {len(contexts)} security contexts")
    
    def parse_asa_object_groups(self) -> None:
        """Parse ASA object-group definitions for ACL/NAT use."""
        self.log("Parsing ASA object groups")
        
        object_groups = {}
        current_group = None
        
        for line in self.config_lines:
            # Object-group declaration
            obj_match = re.match(
                r'object-group\s+(network|service|protocol)\s+(\S+)',
                line,
                re.IGNORECASE
            )
            
            if obj_match:
                group_type = obj_match.group(1)
                group_name = obj_match.group(2)
                current_group = group_name
                object_groups[group_name] = {
                    'type': group_type,
                    'members': []
                }
            
            elif current_group and line.startswith(' '):
                # Object-group member
                object_groups[current_group]['members'].append(line.strip())
            
            else:
                current_group = None
        
        if object_groups:
            self.device_config.aaa_config['object_groups'] = object_groups
            self.log(f"Parsed {len(object_groups)} object groups")
    
    def parse_nat_config(self) -> None:
        """Parse NAT configuration."""
        self.log("Parsing NAT configuration")
        
        nat_rules = []
        
        for line in self.config_lines:
            # NAT rules (various formats)
            if line.startswith('nat ') or line.startswith('static ') or line.startswith('object network'):
                nat_rules.append(line.strip())
        
        if nat_rules:
            self.device_config.aaa_config['nat_rules'] = nat_rules
            self.log(f"Found {len(nat_rules)} NAT-related configuration lines")
    
    def parse_failover_config(self) -> None:
        """Parse failover configuration."""
        self.log("Parsing failover configuration")
        
        failover_config = {}
        
        for line in self.config_lines:
            if 'failover' in line.lower():
                if 'failover lan interface' in line.lower():
                    failover_config['lan_interface'] = line.strip()
                elif 'failover interface ip' in line.lower():
                    failover_config['interface_ip'] = line.strip()
                elif line.strip() == 'failover':
                    failover_config['enabled'] = True
        
        if failover_config:
            self.device_config.aaa_config['failover'] = failover_config
            self.log("Failover configuration found")
    
    def parse_acls(self) -> None:
        """Parse ASA ACLs (which have extended syntax)."""
        self.log("Parsing ASA ACLs")
        
        # ASA uses extended ACL syntax by default
        # Call parent method but with ASA awareness
        super().parse_acls()
        
        # Parse additional ASA ACL features like object-groups in ACLs
        for acl in self.device_config.acls:
            for entry in acl.entries:
                # Check for object-group references in ACL entries
                if 'object-group' in entry.raw_config:
                    entry.flags.append('uses-object-group')


# End of asa_parser.py