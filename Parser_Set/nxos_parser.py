#!/usr/bin/env python3
"""
Synopsis:
    Comprehensive Cisco NX-OS Configuration Parser

Description:
    This module provides complete parsing capabilities for Cisco NX-OS (Nexus)
    device configurations. Extends IOS parser with NX-OS specific features including
    VDC support, FabricPath, vPC, and enhanced VLAN capabilities.

Version: 2.0.0
"""

import re
import sys
import os
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .ios_parser import IOSParser
from shared_components.data_structures import NetworkInterface, VLAN, Endpoint


class NXOSParser(IOSParser):
    """
    Comprehensive parser for Cisco NX-OS configurations.
    
    Inherits from IOSParser and adds NX-OS specific parsing for features
    like VDC, FabricPath, vPC, and enhanced VLAN handling.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize NX-OS parser."""
        super().__init__(verbose)
    
    def log(self, message: str) -> None:
        """Log with NX-OS prefix."""
        if self.verbose:
            print(f"[NX-OS Parser] {message}")
    
    def parse(self, config_lines):
        """Parse NX-OS configuration with additional NX-OS features."""
        # Call parent parse first
        device_config = super().parse(config_lines)
        
        # Add NX-OS specific parsing
        self.parse_vpc_config()
        self.parse_fabricpath_config()
        self.parse_vdc_config()
        
        return device_config
    
    def parse_interface_details(
        self,
        interface: NetworkInterface,
        config_lines: List[str]
    ) -> None:
        """
        Parse NX-OS interface configuration details.
        
        Handles NX-OS specific syntax including CIDR notation for IP addresses.
        Overrides base IOSParser to add NX-OS CIDR support.
        """
        # First, process NX-OS specific CIDR notation BEFORE calling parent
        for line in config_lines:
            line_stripped = line.strip()
            
            # IP Address - NX-OS uses CIDR notation: ip address 10.0.0.2/30
            if line_stripped.startswith('ip address '):
                ip_match = re.match(r'ip address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line_stripped)
                if ip_match:
                    ip = ip_match.group(1)
                    prefix_len = int(ip_match.group(2))
                    
                    # Convert CIDR to subnet mask
                    mask_bits = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
                    subnet_mask = f"{(mask_bits >> 24) & 0xff}.{(mask_bits >> 16) & 0xff}.{(mask_bits >> 8) & 0xff}.{mask_bits & 0xff}"
                    
                    interface.ip_address = ip
                    interface.ip_mask = subnet_mask
                    interface.cidr = f"{ip}/{prefix_len}"
        
        # Call parent method for standard parsing (but it won't overwrite CIDR IPs)
        super().parse_interface_details(interface, config_lines)
        
        # Add NX-OS specific features
        for line in config_lines:
            line_stripped = line.strip()
            
            # VPC configuration on interface
            vpc_match = re.search(r'vpc\s+(\d+)', line_stripped, re.IGNORECASE)
            if vpc_match:
                interface.additional_config.append(f"vPC {vpc_match.group(1)}")
            
            # FabricPath mode
            if 'switchport mode fabricpath' in line_stripped.lower():
                interface.additional_config.append("FabricPath mode")
            
            # Port-profile
            profile_match = re.search(r'inherit port-profile\s+(\S+)', line_stripped, re.IGNORECASE)
            if profile_match:
                interface.additional_config.append(f"Port-profile: {profile_match.group(1)}")
    
    def parse_administrative_access(self) -> None:
        """Parse administrative access configuration - NX-OS specific."""
        self.log("Parsing NX-OS administrative access")
        
        admin_config = {}
        
        # NX-OS doesn't use "enable secret" - authentication is role-based
        # Look for enable password if present
        for line in self.config_lines:
            enable_pw_match = re.match(r'enable\s+password\s+(?:(\d+)\s+)?(.+)$', line, re.IGNORECASE)
            if enable_pw_match:
                if enable_pw_match.group(1):
                    admin_config['enable_secret'] = f"{enable_pw_match.group(1)} {enable_pw_match.group(2)}"
                else:
                    admin_config['enable_secret'] = enable_pw_match.group(2)
        
        # If not found, NX-OS uses role-based authentication
        if 'enable_secret' not in admin_config:
            admin_config['enable_secret'] = 'Role-based (NX-OS)'
        
        self.device_config.aaa_config.update(admin_config)
    
    def parse_user_accounts(self) -> None:
        """Parse local user accounts - NX-OS specific syntax."""
        self.log("Parsing NX-OS user accounts")
        
        users = {}
        user_privileges = []
        credential_hashes = []
        
        for line in self.config_lines:
            # NX-OS username format: username NAME password TYPE HASH role ROLE
            user_match = re.match(
                r'username\s+(\S+)\s+password\s+(\d+)\s+(\S+)(?:\s+role\s+(\S+))?',
                line,
                re.IGNORECASE
            )
            
            if user_match:
                username = user_match.group(1)
                enc_type = user_match.group(2)
                password_hash = user_match.group(3)
                role = user_match.group(4) if user_match.group(4) else 'network-operator'
                
                # Map role to privilege level
                privilege_map = {
                    'network-admin': '15',
                    'network-operator': '5',
                    'vdc-admin': '15',
                    'vdc-operator': '5'
                }
                privilege = privilege_map.get(role, '1')
                
                users[username] = {
                    'privilege': privilege,
                    'role': role,
                    'hash': f"{enc_type} {password_hash}"
                }
                
                # Format for summary fields
                user_privileges.append(f"{username}: {role} (priv {privilege})")
                hash_display = password_hash[:20] + '...' if len(password_hash) > 20 else password_hash
                credential_hashes.append(f"{username}: {enc_type} {hash_display}")
        
        if users:
            self.device_config.aaa_config['users'] = users
            self.log(f"Found {len(users)} user accounts")
        
        # Store formatted summaries
        if user_privileges:
            self.device_config.aaa_config['user_privileges'] = '; '.join(user_privileges)
        else:
            self.device_config.aaa_config['user_privileges'] = 'Not configured'
        
        if credential_hashes:
            self.device_config.aaa_config['credential_hashes'] = '; '.join(credential_hashes)
        else:
            self.device_config.aaa_config['credential_hashes'] = 'Not configured'
    
    def parse_vpc_config(self) -> None:
        """Parse vPC (Virtual Port Channel) configuration."""
        self.log("Parsing vPC configuration")
        
        vpc_config = {}
        current_section = None
        
        for line in self.config_lines:
            # vPC domain
            vpc_domain_match = re.match(r'vpc\s+domain\s+(\d+)', line, re.IGNORECASE)
            if vpc_domain_match:
                vpc_config['domain'] = vpc_domain_match.group(1)
                current_section = 'domain'
                continue
            
            # vPC peer-keepalive
            if current_section == 'domain' and line.startswith(' '):
                keepalive_match = re.search(
                    r'peer-keepalive\s+destination\s+(\d+\.\d+\.\d+\.\d+)',
                    line,
                    re.IGNORECASE
                )
                if keepalive_match:
                    vpc_config['peer_keepalive'] = keepalive_match.group(1)
            
            # vPC peer-link
            peerlink_match = re.search(r'vpc\s+peer-link', line, re.IGNORECASE)
            if peerlink_match:
                # Find the interface this is applied to
                for interface in self.device_config.interfaces:
                    if line in str(interface.additional_config):
                        vpc_config['peer_link_interface'] = interface.name
        
        if vpc_config:
            self.device_config.aaa_config['vpc'] = vpc_config
            self.log(f"Parsed vPC configuration: domain {vpc_config.get('domain', 'N/A')}")
    
    def parse_fabricpath_config(self) -> None:
        """Parse FabricPath configuration."""
        self.log("Parsing FabricPath configuration")
        
        fabricpath_enabled = False
        
        for line in self.config_lines:
            if 'feature fabricpath' in line.lower():
                fabricpath_enabled = True
            
            # FabricPath on interfaces
            if fabricpath_enabled and 'switchport mode fabricpath' in line.lower():
                # This would be in an interface context
                pass
        
        if fabricpath_enabled:
            self.device_config.aaa_config['fabricpath_enabled'] = True
            self.log("FabricPath feature is enabled")
    
    def parse_vdc_config(self) -> None:
        """Parse VDC (Virtual Device Context) configuration."""
        self.log("Parsing VDC configuration")
        
        vdcs = []
        
        for line in self.config_lines:
            vdc_match = re.match(r'vdc\s+(\S+)', line, re.IGNORECASE)
            if vdc_match:
                vdcs.append(vdc_match.group(1))
        
        if vdcs:
            self.device_config.aaa_config['vdcs'] = vdcs
            self.log(f"Found {len(vdcs)} VDCs")
    
    
    
    def parse_dns_config(self) -> None:
        """Parse DNS name-server configuration for NX-OS."""
        dns_servers = []
        for line in self.config_lines:
            # NX-OS: ip name-server X.X.X.X
            dns_match = re.match(r'ip\s+name-server\s+(\S+)', line, re.IGNORECASE)
            if dns_match:
                server = dns_match.group(1)
                dns_servers.append(server)
                # Also create endpoint
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'DNS-{server}', ip_address=server)
                self.device_config.endpoints.append(endpoint)
        
        self.device_config.name_servers = dns_servers
        if dns_servers:
            self.log(f"Found {len(dns_servers)} DNS servers")
    def parse_vlans(self) -> None:
        """Parse NX-OS VLAN configuration."""
        self.log("Parsing NX-OS VLANs")
        
        # NX-OS can have VLAN ranges
        for line in self.config_lines:
            # VLAN range
            vlan_range_match = re.match(r'vlan\s+(\d+)-(\d+)', line, re.IGNORECASE)
            if vlan_range_match:
                start_vlan = int(vlan_range_match.group(1))
                end_vlan = int(vlan_range_match.group(2))
                
                for vlan_id in range(start_vlan, end_vlan + 1):
                    vlan = VLAN(vlan_id)
                    vlan.device_name = self.device_config.device_name
                    vlan.name = f"VLAN{vlan_id}"
                    self.device_config.add_vlan(vlan)
        
        # Also call parent VLAN parsing for individual VLANs
        super().parse_vlans()
        
        self.log(f"Total VLANs parsed: {len(self.device_config.vlans)}")


# End of nxos_parser.py