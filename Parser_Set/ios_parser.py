#!/usr/bin/env python3
"""
Synopsis:
    Comprehensive Cisco IOS/IOS-XE Configuration Parser

Description:
    This module provides complete parsing capabilities for Cisco IOS and IOS-XE
    device configurations. It extracts all network elements including interfaces,
    VLANs, ACLs, routes, administrative credentials, user accounts, and hardware
    information. Designed to support network flow mapping and comprehensive analysis.

Notes:
    - Supports IOS versions 12.x through 17.x
    - Supports IOS-XE versions
    - Handles routers, switches, and layer 3 switches
    - Extracts password hashes and administrative credentials
    - Pure Python implementation

Version: 2.0.0
"""

import re
import sys
import os
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared_components.data_structures import (
    DeviceConfiguration,
    NetworkInterface,
    VLAN,
    Endpoint,
    AccessControlList,
    AccessControlEntry,
    Route
)
from shared_components.constants import *


class IOSParser:
    """
    Comprehensive parser for Cisco IOS and IOS-XE configurations.
    
    This parser extracts all configuration elements needed for network analysis
    and visualization, including detailed credential and administrative access information.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize the IOS parser."""
        self.verbose = verbose
        self.config_lines = []
        self.device_config = DeviceConfiguration()
    
    def log(self, message: str) -> None:
        """Log message if verbose mode enabled."""
        if self.verbose:
            print(f"[IOS Parser] {message}")
    
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Parse IOS configuration lines.
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            DeviceConfiguration object with all parsed data
        """
        self.log(f"Parsing IOS configuration ({len(config_lines)} lines)")
        
        self.config_lines = config_lines
        self.device_config = DeviceConfiguration()
        
        # Parse all configuration sections
        self.parse_system_info()
        self.parse_version_info()
        self.parse_interfaces()
        self.parse_vlans()
        self.associate_interfaces_with_vlans()  # Must be after both interfaces and VLANs are parsed
        self.parse_acls()
        self.parse_routes()
        self.parse_endpoints()  # Parse network endpoints/servers
        self.parse_administrative_access()
        self.parse_user_accounts()
        self.parse_line_config()
        self.parse_aaa_config()
        self.parse_snmp_config()
        self.parse_ntp_config()
        self.parse_dns_config()
        self.parse_logging_config()
        self.parse_monitoring_config()  # Parse SPAN, NetFlow, monitors
        
        self.log(f"Parsing complete: {self.device_config.device_name}")
        
        return self.device_config
    
    def parse_system_info(self) -> None:
        """Extract system information."""
        for line in self.config_lines:
            # Hostname
            match = HOSTNAME_PATTERN.match(line)
            if match:
                self.device_config.device_name = match.group(1)
                self.log(f"Found hostname: {self.device_config.device_name}")
            
            # Domain name
            match = DOMAIN_NAME_PATTERN.match(line)
            if match:
                self.device_config.domain_name = match.group(1)
        
        if not self.device_config.device_name:
            self.device_config.device_name = "Unknown_Device"
    
    def parse_version_info(self) -> None:
        """Extract version and hardware information - ENHANCED."""
        version_found = False
        model_found = False
        
        for line in self.config_lines:
            # Enhanced OS version patterns
            if not version_found:
                version_patterns = [
                    r'(?:IOS|Version)\s+([\d\.]+\([^)]+\)[^\s,]*)',  # 15.2(4)E7
                    r'Version\s+([\d\.]+\w*)',  # 15.2.4
                    r'IOS\s+Software.*Version\s+([\d\.]+[^\s,]*)',
                    r'Cisco\s+IOS.*Version\s+([\d\.]+[^\s,]*)',
                ]
                for pattern in version_patterns:
                    version_match = re.search(pattern, line, re.IGNORECASE)
                    if version_match:
                        self.device_config.os_version = version_match.group(1)
                        version_found = True
                        break
            
            # Enhanced model/platform detection
            if not model_found:
                model_patterns = [
                    r'Cisco\s+(Catalyst\s+\S+)',  # Catalyst 3850-24P
                    r'Cisco\s+(\d{4}[\w-]*)',  # 2960X, 3850, etc
                    r'Cisco\s+(ISR\d+)',  # ISR4331
                    r'Cisco\s+(ASA\d+)',  # ASA5585
                    r'cisco\s+(\S+)\s+\(',  # Model before parenthesis
                    r'!\s*[Cc]isco\s+(\S+)',  # In comment lines
                ]
                for pattern in model_patterns:
                    model_match = re.search(pattern, line, re.IGNORECASE)
                    if model_match:
                        self.device_config.model = model_match.group(1).strip()
                        model_found = True
                        break
            
            if version_found and model_found:
                break
    
    def parse_interfaces(self) -> None:
        """Parse all interface configurations."""
        self.log("Parsing interfaces")
        
        current_interface = None
        interface_lines = []
        
        for index, line in enumerate(self.config_lines):
            # Interface declaration
            match = INTERFACE_PATTERN.match(line)
            
            if match:
                # Save previous interface
                if current_interface:
                    self.parse_interface_details(current_interface, interface_lines)
                
                # Start new interface
                interface_name = match.group(1)
                
                # Skip "range" pseudo-interfaces (e.g., "interface range Gi1/0/1 - 24")
                if interface_name.lower() == 'range' or interface_name.lower().startswith('range '):
                    self.log(f"Skipping pseudo-interface: {interface_name}")
                    current_interface = None
                    interface_lines = []
                    continue
                
                current_interface = NetworkInterface(interface_name)
                current_interface.device_name = self.device_config.device_name
                current_interface.parse_interface_name()
                interface_lines = []
            
            elif current_interface and line.startswith(' '):
                interface_lines.append(line)
            
            elif current_interface:
                # End of interface block
                self.parse_interface_details(current_interface, interface_lines)
                current_interface = None
                interface_lines = []
        
        # Handle last interface
        if current_interface:
            self.parse_interface_details(current_interface, interface_lines)
        
        self.log(f"Parsed {len(self.device_config.interfaces)} interfaces")
    
    def associate_interfaces_with_vlans(self) -> None:
        """Associate interfaces with VLANs and set VLAN state based on interfaces."""
        # Create VLAN lookup dict
        vlan_dict = {v.vlan_id: v for v in self.device_config.vlans}
        
        # Process each interface
        for intf in self.device_config.interfaces:
            # Check if interface has VLAN assignment
            vlan_id = None
            
            # Check for vlan attribute (ASA style)
            if hasattr(intf, 'vlan') and intf.vlan:
                vlan_id = int(intf.vlan)
            
            # Check for vlan_id attribute (switch port style)
            elif hasattr(intf, 'vlan_id') and intf.vlan_id:
                vlan_id = int(intf.vlan_id)
            
            # Check if interface name indicates VLAN (SVI style: Vlan10)
            elif intf.name.lower().startswith('vlan'):
                try:
                    vlan_id = int(re.search(r'vlan\s*(\d+)', intf.name, re.IGNORECASE).group(1))
                except:
                    pass
            
            # Associate interface with VLAN
            if vlan_id and vlan_id in vlan_dict:
                vlan = vlan_dict[vlan_id]
                
                # Add interface to VLAN's interface list
                if intf.name not in vlan.interfaces:
                    vlan.interfaces.append(intf.name)
                    self.log(f"Associated interface {intf.name} with VLAN {vlan_id}")
                
                # Update VLAN state based on interface state
                # Only set to active if currently unknown
                if vlan.state == "unknown":
                    if hasattr(intf, 'shutdown') and not intf.shutdown:
                        vlan.state = "active"
                        self.log(f"Set VLAN {vlan_id} state to active (from interface {intf.name})")
                    elif hasattr(intf, 'status') and intf.status == "up":
                        vlan.state = "active"
                        self.log(f"Set VLAN {vlan_id} state to active (from interface {intf.name})")
    
    def parse_interface_details(
        self,
        interface: NetworkInterface,
        config_lines: List[str]
    ) -> None:
        """Parse configuration details for a specific interface."""
        
        for line in config_lines:
            line_lower = line.lower().strip()
            
            # Description
            match = INTERFACE_DESC_PATTERN.match(line)
            if match:
                interface.description = match.group(1)
                continue
            
            # Shutdown status
            if INTERFACE_SHUTDOWN_PATTERN.match(line):
                interface.shutdown = True
                continue
            
            if INTERFACE_NO_SHUTDOWN_PATTERN.match(line):
                interface.shutdown = False
                continue
            
            # IP Address - Secondary
            match = IP_ADDRESS_SECONDARY_PATTERN.match(line)
            if match:
                ip = match.group(1)
                mask = match.group(2)
                interface.secondary_ips.append(f"{ip}/{self.mask_to_cidr(mask)}")
                continue
            
            # IP Address - Primary
            match = IP_ADDRESS_PATTERN.match(line)
            if match:
                interface.ip_address = match.group(1)
                interface.ip_mask = match.group(2)
                continue
            
            # IPv6 Address
            match = IPV6_ADDRESS_PATTERN.match(line)
            if match:
                interface.ipv6_addresses.append(match.group(1))
                continue
            
            # Switchport mode trunk
            if SWITCHPORT_TRUNK_PATTERN.match(line):
                interface.trunk_mode = True
                continue
            
            # Access VLAN
            match = SWITCHPORT_ACCESS_VLAN_PATTERN.match(line)
            if match:
                interface.access_vlan = int(match.group(1))
                continue
            
            # Allowed VLANs on trunk
            match = SWITCHPORT_TRUNK_ALLOWED_PATTERN.match(line)
            if match:
                vlan_string = match.group(1)
                interface.allowed_vlans = self.parse_vlan_list(vlan_string)
                continue
            
            # Speed
            match = SPEED_PATTERN.match(line)
            if match:
                interface.speed = match.group(1)
                continue
            
            # Duplex
            match = DUPLEX_PATTERN.match(line)
            if match:
                interface.duplex = match.group(1)
                continue
            
            # MTU
            match = MTU_PATTERN.match(line)
            if match:
                interface.mtu = int(match.group(1))
                continue
            
            # VRF
            match = VRF_FORWARD_PATTERN.match(line)
            if match:
                interface.vrf = match.group(1)
                continue
            
            # Channel Group
            match = CHANNEL_GROUP_PATTERN.match(line)
            if match:
                interface.channel_group = int(match.group(1))
                continue
            
            # Input ACL
            input_acl_match = re.search(r'ip\s+access-group\s+(\S+)\s+in', line, re.IGNORECASE)
            if input_acl_match:
                interface.input_acl = input_acl_match.group(1)
                continue
            
            # Output ACL
            output_acl_match = re.search(r'ip\s+access-group\s+(\S+)\s+out', line, re.IGNORECASE)
            if output_acl_match:
                interface.output_acl = output_acl_match.group(1)
                continue
            
            # MAC address
            mac_match = re.search(r'mac-address\s+([0-9a-fA-F.:]+)', line, re.IGNORECASE)
            if mac_match:
                interface.mac_address = mac_match.group(1)
                continue
            
            # Spanning tree
            if 'spanning-tree' in line_lower:
                if not interface.spanning_tree_mode:
                    interface.spanning_tree_mode = line.strip()
                continue
        
        # Add interface to device configuration
        self.device_config.add_interface(interface)
    
    def parse_vlan_list(self, vlan_string: str) -> List[int]:
        """Parse VLAN list string into individual VLAN IDs."""
        vlans = []
        
        if not vlan_string or vlan_string.strip().lower() in ['none', 'all']:
            return vlans
        
        parts = vlan_string.split(',')
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                try:
                    start, end = part.split('-')
                    start_vlan = int(start)
                    end_vlan = int(end)
                    vlans.extend(range(start_vlan, end_vlan + 1))
                except ValueError:
                    continue
            else:
                try:
                    vlans.append(int(part))
                except ValueError:
                    continue
        
        return sorted(list(set(vlans)))
    
    def mask_to_cidr(self, mask: str) -> int:
        """Convert subnet mask to CIDR notation."""
        octets = mask.split('.')
        binary = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])
        return binary.count('1')
    
    def parse_vlans(self) -> None:
        """Parse VLAN configurations."""
        self.log("Parsing VLANs")
        
        current_vlan = None
        vlan_lines = []
        vlan_ids_found = set()
        
        for line in self.config_lines:
            # VLAN declaration - handle single VLAN, ranges, and lists
            # Examples: vlan 10, vlan 10-20, vlan 10,20,30, vlan 10-15,20,25-30
            match = VLAN_PATTERN.match(line)
            
            if match:
                vlan_spec = match.group(1)
                
                # Parse VLAN specification (could be ranges and lists)
                vlan_ids = self.parse_vlan_specification(vlan_spec)
                
                # Save previous VLAN if exists
                if current_vlan:
                    self.parse_vlan_details(current_vlan, vlan_lines)
                    current_vlan = None
                    vlan_lines = []
                
                # Create VLANs for each ID
                for vlan_id in vlan_ids:
                    if vlan_id not in vlan_ids_found:
                        new_vlan = VLAN(vlan_id)
                        new_vlan.device_name = self.device_config.device_name
                        self.device_config.add_vlan(new_vlan)
                        vlan_ids_found.add(vlan_id)
                
                # If only one VLAN, prepare to parse details
                if len(vlan_ids) == 1:
                    current_vlan = self.device_config.vlans[-1]
                    vlan_lines = []
            
            elif current_vlan and line.startswith(' '):
                vlan_lines.append(line)
            
            elif current_vlan:
                # End of VLAN block
                self.parse_vlan_details(current_vlan, vlan_lines)
                current_vlan = None
                vlan_lines = []
        
        # Handle last VLAN
        if current_vlan:
            self.parse_vlan_details(current_vlan, vlan_lines)
        
        # Also capture VLANs assigned to interfaces but not explicitly defined
        self.capture_interface_vlans(vlan_ids_found)
        
        self.log(f"Parsed {len(self.device_config.vlans)} VLANs")
    
    def parse_vlan_specification(self, vlan_spec: str) -> List[int]:
        """
        Parse VLAN specification that may contain ranges and lists.
        
        Examples:
            "10" -> [10]
            "10-20" -> [10, 11, 12, ..., 20]
            "10,20,30" -> [10, 20, 30]
            "10-15,20,25-30" -> [10, 11, 12, 13, 14, 15, 20, 25, 26, 27, 28, 29, 30]
        """
        vlan_ids = []
        
        # Split by comma
        parts = vlan_spec.split(',')
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                # Range specification
                try:
                    start, end = part.split('-')
                    start_id = int(start.strip())
                    end_id = int(end.strip())
                    
                    # Add all VLANs in range
                    for vlan_id in range(start_id, end_id + 1):
                        if 1 <= vlan_id <= 4094:  # Valid VLAN range
                            vlan_ids.append(vlan_id)
                except (ValueError, AttributeError):
                    pass
            else:
                # Single VLAN
                try:
                    vlan_id = int(part)
                    if 1 <= vlan_id <= 4094:
                        vlan_ids.append(vlan_id)
                except ValueError:
                    pass
        
        return vlan_ids
    
    def capture_interface_vlans(self, explicitly_defined_vlans: set) -> None:
        """
        Capture VLANs that are assigned to interfaces but not explicitly defined.
        """
        interface_vlans = set()
        
        for interface in self.device_config.interfaces:
            # Check access VLAN
            if hasattr(interface, 'access_vlan') and interface.access_vlan:
                try:
                    vlan_id = int(interface.access_vlan)
                    if 1 <= vlan_id <= 4094:
                        interface_vlans.add(vlan_id)
                except (ValueError, TypeError):
                    pass
            
            # Check general VLAN attribute
            if hasattr(interface, 'vlan') and interface.vlan:
                try:
                    vlan_id = int(interface.vlan)
                    if 1 <= vlan_id <= 4094:
                        interface_vlans.add(vlan_id)
                except (ValueError, TypeError):
                    pass
            
            # Check allowed VLANs on trunk
            if hasattr(interface, 'allowed_vlans') and interface.allowed_vlans:
                # Parse allowed VLAN list
                try:
                    allowed = self.parse_vlan_specification(str(interface.allowed_vlans))
                    interface_vlans.update(allowed)
                except (ValueError, TypeError, AttributeError):
                    pass
        
        # Add any VLANs found on interfaces that weren't explicitly defined
        for vlan_id in interface_vlans:
            if vlan_id not in explicitly_defined_vlans:
                vlan = VLAN(vlan_id)
                vlan.device_name = self.device_config.device_name
                vlan.name = f"VLAN{vlan_id}"  # Default name
                vlan.state = "unknown"  # State unknown for undefined VLANs
                self.device_config.add_vlan(vlan)
    
    def parse_vlan_details(self, vlan: VLAN, config_lines: List[str]) -> None:
        """Parse VLAN configuration details."""
        for line in config_lines:
            # VLAN name
            match = VLAN_NAME_PATTERN.match(line)
            if match:
                vlan.name = match.group(1)
            
            # VLAN state
            if 'state' in line.lower():
                state_match = re.search(r'state\s+(\w+)', line, re.IGNORECASE)
                if state_match:
                    vlan.state = state_match.group(1)
        
        self.device_config.add_vlan(vlan)
    
    def parse_acls(self) -> None:
        """Parse Access Control Lists."""
        self.log("Parsing ACLs")
        
        acls = {}
        current_acl = None
        
        for line in self.config_lines:
            # Named ACL declaration
            match = ACL_NAMED_PATTERN.match(line)
            if match:
                acl_type = match.group(1)
                acl_name = match.group(2)
                
                if acl_name not in acls:
                    acl = AccessControlList(acl_name)
                    acl.acl_type = acl_type
                    acl.device_name = self.device_config.device_name
                    acls[acl_name] = acl
                    current_acl = acl
                else:
                    current_acl = acls[acl_name]
            
            elif current_acl and line.startswith(' '):
                # ACL entry
                ace = self.parse_acl_entry(line)
                if ace:
                    current_acl.add_entry(ace)
            
            else:
                current_acl = None
            
            # Inline ACL (numbered)
            if line.startswith('access-list'):
                acl_match = re.match(r'access-list\s+(\d+)\s+', line)
                if acl_match:
                    acl_number = acl_match.group(1)
                    
                    if acl_number not in acls:
                        acl = AccessControlList(acl_number)
                        acl.acl_type = "standard" if int(acl_number) < 100 else "extended"
                        acl.device_name = self.device_config.device_name
                        acls[acl_number] = acl
                    
                    ace = self.parse_acl_entry(line)
                    if ace:
                        acls[acl_number].add_entry(ace)
        
        # Add all ACLs to device configuration
        for acl in acls.values():
            self.device_config.add_acl(acl)
        
        self.log(f"Parsed {len(self.device_config.acls)} ACLs")
    
    def parse_acl_entry(self, line: str) -> Optional[AccessControlEntry]:
        """
        Parse a single ACL entry with proper handling of host keyword and wildcard masks.
        
        Handles formats like:
        - permit tcp any host 10.10.10.10 eq 80
        - deny ip 10.10.10.0 0.0.0.255 10.20.20.0 0.0.0.255
        - permit tcp host 10.10.10.10 host 10.20.20.10 eq 3306
        """
        ace = AccessControlEntry()
        ace.raw_config = line.strip()
        
        # Skip remark lines
        if 'remark' in line.lower():
            return None
        
        # Remove leading whitespace and access-list prefix
        line = line.strip()
        line = re.sub(r'^access-list\s+\d+\s+', '', line)
        
        # Extract sequence number if present
        seq_match = re.match(r'(\d+)\s+', line)
        if seq_match:
            ace.sequence = int(seq_match.group(1))
            line = line[seq_match.end():]
        
        # Split into tokens
        tokens = line.split()
        
        if len(tokens) < 2:
            return None
        
        # Extract action and protocol
        ace.action = tokens[0].lower()
        ace.protocol = tokens[1].lower()
        
        if ace.action not in ['permit', 'deny'] or len(tokens) < 4:
            return None
        
        # Parse source address (starts at token 2)
        idx = 2
        
        # Source address
        if tokens[idx] == 'host':
            idx += 1
            ace.source = tokens[idx]
            ace.source_wildcard = '0.0.0.0'
            idx += 1
        elif tokens[idx] == 'any':
            ace.source = 'any'
            ace.source_wildcard = '0.0.0.0'
            idx += 1
        else:
            # IP address potentially followed by wildcard
            ace.source = tokens[idx]
            idx += 1
            # Check if next token is a wildcard mask (x.x.x.x format)
            if idx < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[idx]):
                ace.source_wildcard = tokens[idx]
                idx += 1
            else:
                ace.source_wildcard = '0.0.0.0'
        
        # Source port (optional)
        if idx < len(tokens) and tokens[idx] in ['eq', 'gt', 'lt', 'neq', 'range']:
            port_op = tokens[idx]
            idx += 1
            if idx < len(tokens):
                ace.source_port = f"{port_op} {tokens[idx]}"
                idx += 1
                # Handle port range
                if port_op == 'range' and idx < len(tokens):
                    ace.source_port += f" {tokens[idx]}"
                    idx += 1
        
        # Destination address
        if idx >= len(tokens):
            return ace
        
        if tokens[idx] == 'host':
            idx += 1
            if idx < len(tokens):
                ace.destination = tokens[idx]
                ace.dest_wildcard = '0.0.0.0'
                idx += 1
        elif tokens[idx] == 'any':
            ace.destination = 'any'
            ace.dest_wildcard = '0.0.0.0'
            idx += 1
        else:
            # IP address potentially followed by wildcard
            ace.destination = tokens[idx]
            idx += 1
            # Check if next token is a wildcard mask
            if idx < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[idx]):
                ace.dest_wildcard = tokens[idx]
                idx += 1
            else:
                ace.dest_wildcard = '0.0.0.0'
        
        # Destination port (optional)
        if idx < len(tokens) and tokens[idx] in ['eq', 'gt', 'lt', 'neq', 'range']:
            port_op = tokens[idx]
            idx += 1
            if idx < len(tokens):
                ace.dest_port = f"{port_op} {tokens[idx]}"
                idx += 1
                # Handle port range
                if port_op == 'range' and idx < len(tokens):
                    ace.dest_port += f" {tokens[idx]}"
                    idx += 1
        
        # Extract additional flags
        if 'established' in line.lower():
            ace.flags.append('established')
        if 'log' in line.lower():
            ace.flags.append('log')
        
        return ace
    
    def parse_routes(self) -> None:
        """Parse routing configuration."""
        self.log("Parsing routes")
        
        for line in self.config_lines:
            # Static routes
            match = STATIC_ROUTE_PATTERN.match(line)
            if match:
                route = Route()
                route.route_type = "static"
                route.destination = match.group(1)
                route.mask = match.group(2)
                route.device_name = self.device_config.device_name
                
                # Parse next hop or interface
                remaining = match.group(3).strip()
                parts = remaining.split()
                
                if parts:
                    if re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        route.next_hop = parts[0]
                    else:
                        route.interface = parts[0]
                    
                    # Check for administrative distance
                    if len(parts) > 1 and parts[1].isdigit():
                        route.admin_distance = int(parts[1])
                
                self.device_config.add_route(route)
        
        self.log(f"Parsed {len(self.device_config.routes)} routes")
    
    def parse_endpoints(self) -> None:
        """
        Parse network endpoints and servers from configuration.
        
        Extracts endpoints/servers defined in configs while carefully excluding
        interface IP addresses and VLAN addresses to avoid misidentification.
        """
        self.log("Parsing endpoints and servers")
        
        # First, collect all interface and VLAN IPs to exclude them
        interface_ips = self.collect_interface_ips()
        
        # Track unique endpoints by IP to avoid duplicates
        endpoint_ips = {}
        
        # Parse object-group network definitions
        self.parse_object_groups(endpoint_ips, interface_ips)
        
        # Parse object network definitions
        self.parse_object_networks(endpoint_ips, interface_ips)
        
        # Parse NAT statements
        self.parse_nat_endpoints(endpoint_ips, interface_ips)
        
        # Parse ip host statements
        self.parse_ip_hosts(endpoint_ips, interface_ips)
        
        # Parse server farm definitions (load balancer)
        self.parse_server_farms(endpoint_ips, interface_ips)
        
        # Add all unique endpoints to device config
        for endpoint in endpoint_ips.values():
            self.device_config.add_endpoint(endpoint)
        
        self.log(f"Parsed {len(self.device_config.endpoints)} endpoints/servers")
    
    def collect_interface_ips(self) -> set:
        """
        Collect all IP addresses assigned to interfaces and VLANs.
        
        Returns:
            Set of IP addresses that are interface/VLAN IPs (to exclude from endpoints)
        """
        interface_ips = set()
        
        # Collect from parsed interfaces
        for interface in self.device_config.interfaces:
            if interface.ip_address:
                interface_ips.add(interface.ip_address)
            # Add secondary IPs
            if hasattr(interface, 'secondary_ips') and interface.secondary_ips:
                for ip in interface.secondary_ips:
                    if isinstance(ip, tuple):
                        interface_ips.add(ip[0])
                    else:
                        interface_ips.add(ip)
        
        # Collect from VLANs
        for vlan in self.device_config.vlans:
            if hasattr(vlan, 'gateway') and vlan.gateway:
                interface_ips.add(vlan.gateway)
        
        return interface_ips
    
    def parse_object_groups(self, endpoint_ips: dict, interface_ips: set) -> None:
        """Parse object-group network definitions."""
        current_group = None
        
        for line in self.config_lines:
            # Object-group network definition
            match = OBJECT_GROUP_NETWORK_PATTERN.match(line)
            if match:
                current_group = match.group(1)
                continue
            
            # Network object host within group
            if current_group:
                host_match = NETWORK_OBJECT_HOST_PATTERN.match(line)
                if host_match:
                    ip = host_match.group(1)
                    
                    # Skip if this is an interface IP
                    if ip in interface_ips:
                        continue
                    
                    # Add or update endpoint
                    if ip not in endpoint_ips:
                        endpoint = Endpoint(
                            device_name=self.device_config.device_name,
                            name=f"host_{ip.replace('.', '_')}",
                            ip_address=ip,
                            subnet_mask="255.255.255.255"
                        )
                        endpoint.endpoint_type = "host"
                        endpoint.source_context = f"object-group:{current_group}"
                        endpoint_ips[ip] = endpoint
                    
                    # Add group membership
                    endpoint_ips[ip].add_group_membership(current_group)
                    continue
                
                # Network object subnet within group
                subnet_match = NETWORK_OBJECT_SUBNET_PATTERN.match(line)
                if subnet_match:
                    network = subnet_match.group(1)
                    mask = subnet_match.group(2)
                    
                    # Skip if this is an interface network
                    if network in interface_ips:
                        continue
                    
                    # Add or update endpoint (using network as key)
                    key = f"{network}/{mask}"
                    if key not in endpoint_ips:
                        endpoint = Endpoint(
                            device_name=self.device_config.device_name,
                            name=f"net_{network.replace('.', '_')}",
                            ip_address=network,
                            subnet_mask=mask
                        )
                        endpoint.endpoint_type = "network"
                        endpoint.source_context = f"object-group:{current_group}"
                        endpoint_ips[key] = endpoint
                    
                    # Add group membership
                    endpoint_ips[key].add_group_membership(current_group)
                    continue
                
                # Exit object group if we hit a non-indented line
                if line and not line.startswith(' '):
                    current_group = None
    
    def parse_object_networks(self, endpoint_ips: dict, interface_ips: set) -> None:
        """Parse object network definitions."""
        current_object = None
        object_lines = []
        
        for line in self.config_lines:
            # Object network definition
            match = OBJECT_NETWORK_PATTERN.match(line)
            if match:
                # Process previous object if exists
                if current_object:
                    self.process_object_network(current_object, object_lines, endpoint_ips, interface_ips)
                
                current_object = match.group(1)
                object_lines = []
                continue
            
            # Collect lines within object
            if current_object and line.startswith(' '):
                object_lines.append(line)
            elif current_object:
                # Process object and reset
                self.process_object_network(current_object, object_lines, endpoint_ips, interface_ips)
                current_object = None
                object_lines = []
        
        # Process last object if exists
        if current_object:
            self.process_object_network(current_object, object_lines, endpoint_ips, interface_ips)
    
    def process_object_network(
        self,
        object_name: str,
        config_lines: List[str],
        endpoint_ips: dict,
        interface_ips: set
    ) -> None:
        """Process a single object network definition."""
        for line in config_lines:
            # Host definition
            host_match = NETWORK_OBJECT_HOST_PATTERN.match(line)
            if host_match:
                ip = host_match.group(1)
                
                if ip in interface_ips:
                    continue
                
                if ip not in endpoint_ips:
                    endpoint = Endpoint(
                        device_name=self.device_config.device_name,
                        name=object_name,
                        ip_address=ip,
                        subnet_mask="255.255.255.255"
                    )
                    endpoint.endpoint_type = "host"
                    endpoint.source_context = "object network"
                    endpoint_ips[ip] = endpoint
                continue
            
            # Subnet definition
            subnet_match = NETWORK_OBJECT_SUBNET_PATTERN.match(line)
            if subnet_match:
                network = subnet_match.group(1)
                mask = subnet_match.group(2)
                
                if network in interface_ips:
                    continue
                
                key = f"{network}/{mask}"
                if key not in endpoint_ips:
                    endpoint = Endpoint(
                        device_name=self.device_config.device_name,
                        name=object_name,
                        ip_address=network,
                        subnet_mask=mask
                    )
                    endpoint.endpoint_type = "network"
                    endpoint.source_context = "object network"
                    endpoint_ips[key] = endpoint
    
    def parse_nat_endpoints(self, endpoint_ips: dict, interface_ips: set) -> None:
        """Parse NAT statements to find endpoints."""
        for line in self.config_lines:
            # Static NAT
            match = NAT_STATIC_PATTERN.match(line)
            if match:
                local_ip = match.group(1)
                global_ip = match.group(2)
                
                # Add local IP (internal server)
                if local_ip not in interface_ips and local_ip not in endpoint_ips:
                    endpoint = Endpoint(
                        device_name=self.device_config.device_name,
                        name=f"nat_local_{local_ip.replace('.', '_')}",
                        ip_address=local_ip,
                        subnet_mask="255.255.255.255"
                    )
                    endpoint.endpoint_type = "server"
                    endpoint.source_context = "NAT static"
                    endpoint.description = f"NAT to {global_ip}"
                    endpoint_ips[local_ip] = endpoint
            
            # NAT pool (range of IPs)
            pool_match = NAT_POOL_PATTERN.match(line)
            if pool_match:
                pool_name = pool_match.group(1)
                start_ip = pool_match.group(2)
                end_ip = pool_match.group(3)
                
                # Just record the pool start (representative)
                if start_ip not in interface_ips and start_ip not in endpoint_ips:
                    endpoint = Endpoint(
                        device_name=self.device_config.device_name,
                        name=pool_name,
                        ip_address=start_ip,
                        subnet_mask="255.255.255.255"
                    )
                    endpoint.endpoint_type = "nat_pool"
                    endpoint.source_context = "NAT pool"
                    endpoint.description = f"Pool range: {start_ip} - {end_ip}"
                    endpoint_ips[start_ip] = endpoint
    
    def parse_ip_hosts(self, endpoint_ips: dict, interface_ips: set) -> None:
        """Parse ip host name resolution statements."""
        for line in self.config_lines:
            match = IP_HOST_PATTERN.match(line)
            if match:
                hostname = match.group(1)
                ip = match.group(2)
                
                if ip in interface_ips:
                    continue
                
                if ip not in endpoint_ips:
                    endpoint = Endpoint(
                        device_name=self.device_config.device_name,
                        name=hostname,
                        ip_address=ip,
                        subnet_mask="255.255.255.255"
                    )
                    endpoint.endpoint_type = "host"
                    endpoint.source_context = "ip host"
                    endpoint.description = f"DNS: {hostname}"
                    endpoint_ips[ip] = endpoint
    
    def parse_server_farms(self, endpoint_ips: dict, interface_ips: set) -> None:
        """Parse server farm definitions (load balancer)."""
        current_farm = None
        
        for line in self.config_lines:
            # Server farm definition
            farm_match = SERVER_FARM_PATTERN.match(line)
            if farm_match:
                current_farm = farm_match.group(1)
                continue
            
            # Real server within farm
            if current_farm:
                server_match = REAL_SERVER_PATTERN.match(line)
                if server_match:
                    ip = server_match.group(1)
                    
                    if ip in interface_ips:
                        continue
                    
                    if ip not in endpoint_ips:
                        endpoint = Endpoint(
                            device_name=self.device_config.device_name,
                            name=f"server_{ip.replace('.', '_')}",
                            ip_address=ip,
                            subnet_mask="255.255.255.255"
                        )
                        endpoint.endpoint_type = "server"
                        endpoint.source_context = f"server farm:{current_farm}"
                        endpoint_ips[ip] = endpoint
                    
                    # Add farm membership
                    endpoint_ips[ip].add_group_membership(current_farm)
                    continue
                
                # Exit farm if non-indented line
                if line and not line.startswith(' '):
                    current_farm = None
    
    def parse_administrative_access(self) -> None:
        """Parse administrative access configuration."""
        self.log("Parsing administrative access")
        
        # This data will be stored in device_config.aaa_config dictionary
        admin_config = {}
        
        # Parse enable secret/password
        for line in self.config_lines:
            # Enable secret with encryption type
            enable_match = re.match(r'enable\s+secret\s+(\d+)\s+(.+)$', line, re.IGNORECASE)
            if enable_match:
                enc_type = enable_match.group(1)
                hash_val = enable_match.group(2)
                admin_config['enable_secret'] = f"{enc_type} {hash_val}"
                continue
            
            # Enable password
            enable_pw_match = re.match(r'enable\s+password\s+(?:(\d+)\s+)?(.+)$', line, re.IGNORECASE)
            if enable_pw_match:
                if enable_pw_match.group(1):
                    admin_config['enable_password'] = f"{enable_pw_match.group(1)} {enable_pw_match.group(2)}"
                else:
                    admin_config['enable_password'] = enable_pw_match.group(2)
        
        # If neither found, mark as not configured
        if 'enable_secret' not in admin_config and 'enable_password' not in admin_config:
            admin_config['enable_secret'] = 'Not configured'
        # If only password is set, also populate secret field for consistency
        elif 'enable_password' in admin_config and 'enable_secret' not in admin_config:
            admin_config['enable_secret'] = admin_config['enable_password']
        
        # Parse domain name (supports both "ip domain-name" and "domain-name" formats)
        for line in self.config_lines:
            # Standard IOS: ip domain-name
            domain_match = re.match(r'ip\s+domain[- ]name\s+(\S+)', line, re.IGNORECASE)
            if domain_match:
                self.device_config.domain_name = domain_match.group(1)
                self.log(f"Found domain: {domain_match.group(1)}")
                break
            
            # ASA/Firewall: domain-name (without 'ip' prefix)
            domain_match2 = re.match(r'^domain[- ]name\s+(\S+)', line, re.IGNORECASE)
            if domain_match2:
                self.device_config.domain_name = domain_match2.group(1)
                self.log(f"Found domain: {domain_match2.group(1)}")
                break
        
        self.device_config.aaa_config.update(admin_config)
    
    def parse_user_accounts(self) -> None:
        """Parse local user accounts."""
        self.log("Parsing user accounts")
        
        users = {}
        user_privileges = []
        credential_hashes = []
        
        for line in self.config_lines:
            # Username with password/secret
            user_match = re.match(
                r'username\s+(\S+)(?:\s+privilege\s+(\d+))?(?:\s+(?:secret|password)\s+(\d+)\s+(.+))?',
                line,
                re.IGNORECASE
            )
            
            if user_match:
                username = user_match.group(1)
                privilege = user_match.group(2) if user_match.group(2) else '1'
                enc_type = user_match.group(3) if user_match.group(3) else ''
                password_hash = user_match.group(4) if user_match.group(4) else ''
                
                users[username] = {
                    'privilege': privilege,
                    'hash': f"{enc_type} {password_hash}" if enc_type else password_hash
                }
                
                # Format for summary fields
                user_privileges.append(f"{username}: {privilege}")
                if password_hash:
                    # Truncate hash for display
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
    
    def parse_line_config(self) -> None:
        """Parse line (VTY, console, aux) configurations - ENHANCED."""
        self.log("Parsing line configurations")
        
        current_line = None
        line_configs = []
        access_methods = set()
        management_acls = set()
        vty_details = []
        
        for i, line in enumerate(self.config_lines):
            # Start of line block
            line_match = re.match(r'^line\s+(\S+(?:\s+\S+)*)', line.strip(), re.IGNORECASE)
            if line_match:
                if current_line:
                    line_configs.append(current_line)
                
                line_type = line_match.group(1)
                current_line = {
                    'type': line_type,
                    'transport': '',
                    'acl': '',
                    'timeout': '',
                    'login': ''
                }
                continue
            
            # Parse line configuration (indented lines)
            if current_line and line.strip() and line.startswith(' '):
                config_line = line.strip()
                
                # Transport input
                if 'transport input' in config_line:
                    transport_match = re.search(r'transport\s+input\s+(.+)', config_line, re.IGNORECASE)
                    if transport_match:
                        transport = transport_match.group(1).strip()
                        current_line['transport'] = transport
                        for method in transport.split():
                            access_methods.add(method)
                
                # Access class
                elif 'access-class' in config_line:
                    acl_match = re.search(r'access-class\s+(\S+)', config_line, re.IGNORECASE)
                    if acl_match:
                        acl = acl_match.group(1)
                        current_line['acl'] = acl
                        management_acls.add(acl)
                
                # Exec timeout
                elif 'exec-timeout' in config_line:
                    timeout_match = re.search(r'exec-timeout\s+(\d+)\s+(\d+)', config_line, re.IGNORECASE)
                    if timeout_match:
                        current_line['timeout'] = f"{timeout_match.group(1)}:{timeout_match.group(2)}"
                
                # Login method
                elif re.match(r'^login\s+local', config_line, re.IGNORECASE):
                    current_line['login'] = 'local'
                elif re.match(r'^login\s+authentication', config_line, re.IGNORECASE):
                    auth_match = re.search(r'login\s+authentication\s+(\S+)', config_line, re.IGNORECASE)
                    if auth_match:
                        current_line['login'] = f"auth:{auth_match.group(1)}"
            
            # End of line block
            elif current_line and line.strip() and not line.startswith(' '):
                line_configs.append(current_line)
                current_line = None
        
        # Save last line config
        if current_line:
            line_configs.append(current_line)
        
        # Format VTY lines
        for line_cfg in line_configs:
            if 'vty' in line_cfg['type'].lower():
                vty_parts = [line_cfg['type']]
                if line_cfg['transport']:
                    vty_parts.append(f"transport:{line_cfg['transport']}")
                if line_cfg['acl']:
                    vty_parts.append(f"ACL:{line_cfg['acl']}")
                if line_cfg['login']:
                    vty_parts.append(f"login:{line_cfg['login']}")
                if line_cfg['timeout']:
                    vty_parts.append(f"timeout:{line_cfg['timeout']}")
                vty_details.append(' | '.join(vty_parts))
        
        # Store in device config
        if vty_details:
            self.device_config.aaa_config['vty_lines'] = '; '.join(vty_details)
            self.log(f"Parsed {len(vty_details)} line configurations")
        else:
            self.device_config.aaa_config['vty_lines'] = 'Not configured'
        
        if access_methods:
            self.device_config.aaa_config['access_methods'] = ', '.join(sorted(access_methods))
        if management_acls:
            self.device_config.aaa_config['management_acls'] = ', '.join(sorted(management_acls))
    
    def parse_aaa_config(self) -> None:
        """Parse AAA (Authentication, Authorization, Accounting) configuration."""
        self.log("Parsing AAA configuration")
        
        aaa_lines = []
        in_tacacs_block = False
        in_radius_block = False
        
        for line in self.config_lines:
            # Parse AAA configuration lines
            if line.strip().startswith('aaa'):
                aaa_lines.append(line.strip())
            
            # Modern TACACS format: tacacs server NAME
            if re.match(r'tacacs\s+server\s+\S+', line, re.IGNORECASE):
                in_tacacs_block = True
                continue
            
            # Extract IP from modern TACACS block
            if in_tacacs_block:
                addr_match = re.match(r'\s+address\s+(?:ipv4\s+)?(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
                if addr_match:
                    server = addr_match.group(1)
                    endpoint = Endpoint(device_name=self.device_config.device_name, name=f'TACACS-{server}', ip_address=server)
                    endpoint.endpoint_type = "TACACS+ Server"
                    self.device_config.endpoints.append(endpoint)
                    self.log(f"Found TACACS+ server (modern format): {server}")
                    in_tacacs_block = False
                    continue
                # Exit TACACS block if we hit a non-indented line
                if not line.startswith(' ') and not line.startswith('\t'):
                    in_tacacs_block = False
            
            # Legacy TACACS format: tacacs-server host <ip>
            tacacs_match = re.match(r'tacacs-server\s+host\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if tacacs_match:
                server = tacacs_match.group(1)
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'TACACS-{server}', ip_address=server)
                endpoint.endpoint_type = "TACACS+ Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found TACACS+ server: {server}")
                continue
            
            # Extract RADIUS servers (can be outside aaa block)
            radius_match = re.match(r'radius-server\s+host\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if radius_match:
                server = radius_match.group(1)
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'RADIUS-{server}', ip_address=server)
                endpoint.endpoint_type = "RADIUS Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found RADIUS server: {server}")
                continue
            
            # DHCP helper addresses (can appear anywhere, not just in aaa blocks)
            helper_match = re.match(r'\s*ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if helper_match:
                server = helper_match.group(1)
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'DHCP-{server}', ip_address=server)
                endpoint.endpoint_type = "DHCP Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found DHCP helper address: {server}")
        
        if aaa_lines:
            self.device_config.aaa_config['aaa_lines'] = '; '.join(aaa_lines[:5])  # First 5 lines
            self.log(f"Found {len(aaa_lines)} AAA configuration lines")
    
    def parse_snmp_config(self) -> None:
        """Parse SNMP configuration."""
        communities = []
        trap_hosts = []
        
        for line in self.config_lines:
            # SNMP community strings
            comm_match = re.match(r'snmp-server\s+community\s+(\S+)', line, re.IGNORECASE)
            if comm_match:
                communities.append(comm_match.group(1))
            
            # SNMP trap hosts - ASA format: snmp-server host <interface> <ip>
            asa_trap_match = re.match(r'snmp-server\s+host\s+\S+\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if asa_trap_match:
                server = asa_trap_match.group(1)
                trap_hosts.append(server)
                # Create endpoint for SNMP trap receiver
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'SNMP-Trap-{server}', ip_address=server)
                endpoint.endpoint_type = "SNMP Trap Receiver"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found SNMP trap host (ASA format): {server}")
                continue
            
            # SNMP trap hosts - Standard IOS format: snmp-server host <ip>
            trap_match = re.match(r'snmp-server\s+host\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if trap_match:
                server = trap_match.group(1)
                trap_hosts.append(server)
                # Create endpoint for SNMP trap receiver
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'SNMP-Trap-{server}', ip_address=server)
                endpoint.endpoint_type = "SNMP Trap Receiver"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found SNMP trap host: {server}")
                continue
        
        if communities:
            self.device_config.snmp_community = communities[0]  # Store first community
    
    def parse_ntp_config(self) -> None:
        """Parse NTP server configuration."""
        ntp_servers = []
        for line in self.config_lines:
            ntp_match = re.match(r'ntp\s+server\s+(\S+)', line, re.IGNORECASE)
            if ntp_match:
                server = ntp_match.group(1)
                ntp_servers.append(server)
                # Create endpoint for NTP server
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NTP-{server}', ip_address=server)
                endpoint.endpoint_type = "NTP Server"
                self.device_config.endpoints.append(endpoint)
        
        self.device_config.ntp_servers = ntp_servers
        if ntp_servers:
            self.log(f"Found {len(ntp_servers)} NTP servers")
    
    def parse_dns_config(self) -> None:
        """Parse DNS name-server configuration."""
        dns_servers = []
        for line in self.config_lines:
            dns_match = re.match(r'ip\s+name-server\s+(.+)', line, re.IGNORECASE)
            if dns_match:
                servers_str = dns_match.group(1)
                # Can be multiple IPs on one line
                for server in servers_str.split():
                    if re.match(r'\d+\.\d+\.\d+\.\d+', server):
                        dns_servers.append(server)
                        # Also create endpoint
                        endpoint = Endpoint(device_name=self.device_config.device_name, name=f'DNS-{server}', ip_address=server)
                        endpoint.endpoint_type = "DNS Server"
                        self.device_config.endpoints.append(endpoint)
        
        self.device_config.name_servers = dns_servers
        if dns_servers:
            self.log(f"Found {len(dns_servers)} DNS servers")
    
    def parse_logging_config(self) -> None:
        """Parse logging/syslog server configuration."""
        logging_servers = []
        for line in self.config_lines:
            # NX-OS format: logging server <ip>
            nxos_log_match = re.match(r'logging\s+server\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if nxos_log_match:
                server = nxos_log_match.group(1)
                logging_servers.append(server)
                # Create endpoint for syslog server
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'Syslog-{server}', ip_address=server)
                endpoint.endpoint_type = "Syslog Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found syslog server (NX-OS format): {server}")
                continue
            
            # ASA format: logging host <interface> <ip>
            asa_log_match = re.match(r'logging\s+host\s+\S+\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if asa_log_match:
                server = asa_log_match.group(1)
                logging_servers.append(server)
                # Create endpoint for syslog server
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'Syslog-{server}', ip_address=server)
                endpoint.endpoint_type = "Syslog Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found syslog server (ASA format): {server}")
                continue
            
            # Standard IOS format: logging host <ip> or logging <ip>
            log_match = re.match(r'logging\s+(?:host\s+)?(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if log_match:
                server = log_match.group(1)
                logging_servers.append(server)
                # Create endpoint for syslog server
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'Syslog-{server}', ip_address=server)
                endpoint.endpoint_type = "Syslog Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found syslog server: {server}")
                continue
        
        self.device_config.logging_servers = logging_servers
        if logging_servers:
            self.log(f"Found {len(logging_servers)} logging servers")
    
    def parse_monitoring_config(self) -> None:
        """Parse SPAN, RSPAN, and NetFlow monitoring configurations."""
        self.log("Parsing monitoring configurations")
        
        # Import monitoring structures
        from shared_components.monitoring_structures import SPANSession, NetFlowConfig
        
        span_sessions = {}  # Use dict to handle multiple lines for same session
        netflow_configs = []
        in_flow_exporter = False  # Track if we're inside a flow exporter block
        current_flow_exporter = None
        
        for line in self.config_lines:
            # SPAN session - single line format: monitor session 1 source interface Gi1/0/1 rx
            span_single_match = re.match(r'monitor\s+session\s+(\d+)\s+(source|destination)\s+(.*)', line, re.IGNORECASE)
            if span_single_match:
                session_id = span_single_match.group(1)
                direction = span_single_match.group(2).lower()
                details = span_single_match.group(3)
                
                # Create session if doesn't exist
                if session_id not in span_sessions:
                    span_sessions[session_id] = SPANSession(session_id)
                    span_sessions[session_id].device_name = self.device_config.device_name
                
                session = span_sessions[session_id]
                
                if direction == 'source':
                    # Parse source (interface or VLAN)
                    if 'vlan' in details.lower():
                        vlan_match = re.search(r'vlan\s+(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)', details, re.IGNORECASE)
                        if vlan_match:
                            session.source_vlans.append(vlan_match.group(1))
                    else:
                        # Interface source
                        intf_match = re.search(r'interface\s+((?:Gi|Fa|Eth|Te|Port-channel|Ethernet)\S*)', details, re.IGNORECASE)
                        if intf_match:
                            session.source_interfaces.append(intf_match.group(1))
                            self.log(f"SPAN session {session_id}: source interface {intf_match.group(1)}")
                elif direction == 'destination':
                    # Parse destination
                    intf_match = re.search(r'interface\s+((?:Gi|Fa|Eth|Te|Port-channel|Ethernet)\S*)', details, re.IGNORECASE)
                    if intf_match:
                        session.destination_interface = intf_match.group(1)
                        self.log(f"SPAN session {session_id}: destination interface {intf_match.group(1)}")
                continue
            
            # NetFlow configuration - ASA format: flow-export destination <interface> <ip> <port>
            asa_netflow_match = re.match(r'flow-export\s+destination\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)', line, re.IGNORECASE)
            if asa_netflow_match:
                collector_ip = asa_netflow_match.group(1)
                collector_port = asa_netflow_match.group(2)
                
                netflow = NetFlowConfig()
                netflow.device_name = self.device_config.device_name
                netflow.collector_ip = collector_ip
                netflow.collector_port = collector_port
                netflow.version = 'v5'  # ASA default
                netflow.description = f"NetFlow export to {collector_ip}:{collector_port}"
                netflow_configs.append(netflow)
                
                # Create endpoint for NetFlow collector
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{collector_ip}', ip_address=collector_ip)
                endpoint.endpoint_type = "NetFlow Collector"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found NetFlow collector (ASA format): {collector_ip}:{collector_port}")
                continue
            
            # NetFlow configuration - Old IOS format
            old_netflow_match = re.match(r'ip\s+flow-export\s+destination\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)', line, re.IGNORECASE)
            if old_netflow_match:
                collector_ip = old_netflow_match.group(1)
                collector_port = old_netflow_match.group(2)
                
                netflow = NetFlowConfig()
                netflow.device_name = self.device_config.device_name
                netflow.collector_ip = collector_ip
                netflow.collector_port = collector_port
                netflow.version = 'v5'  # Old format default
                netflow.description = f"NetFlow export to {collector_ip}:{collector_port}"
                netflow_configs.append(netflow)
                
                # Create endpoint for NetFlow collector
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{collector_ip}', ip_address=collector_ip)
                endpoint.endpoint_type = "NetFlow Collector"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found NetFlow collector (old format): {collector_ip}:{collector_port}")
                continue
            
            # NetFlow - Modern flow exporter format
            flow_exporter_match = re.match(r'flow\s+exporter\s+(\S+)', line, re.IGNORECASE)
            if flow_exporter_match:
                in_flow_exporter = True
                current_flow_exporter = flow_exporter_match.group(1)
                continue
            
            # Destination line (inside flow exporter block)
            if in_flow_exporter:
                dest_match = re.match(r'\s+destination\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?', line, re.IGNORECASE)
                if dest_match:
                    collector_ip = dest_match.group(1)
                    collector_port = dest_match.group(2) if dest_match.group(2) else '2055'
                    
                    netflow = NetFlowConfig()
                    netflow.device_name = self.device_config.device_name
                    netflow.collector_ip = collector_ip
                    netflow.collector_port = collector_port
                    netflow.version = 'v9'  # Modern format default
                    netflow.exporter_name = current_flow_exporter
                    netflow.description = f"NetFlow export to {collector_ip}:{collector_port} (exporter: {current_flow_exporter})"
                    netflow_configs.append(netflow)
                    
                    # Create endpoint
                    endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{collector_ip}', ip_address=collector_ip)
                    endpoint.endpoint_type = "NetFlow Collector"
                    self.device_config.endpoints.append(endpoint)
                    self.log(f"Found NetFlow collector (modern format): {collector_ip}:{collector_port}")
                    in_flow_exporter = False  # Exit flow exporter block
                    continue
                
                # Exit flow exporter block if we hit a non-indented line
                if not line.startswith(' ') and not line.startswith('\t'):
                    in_flow_exporter = False
        
        # Convert span_sessions dict to list
        self.device_config.span_sessions = list(span_sessions.values())
        self.device_config.netflow_configs = netflow_configs
        
        self.log(f"Parsed {len(span_sessions)} SPAN sessions, {len(netflow_configs)} NetFlow configs")
    
    def mask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR notation."""
        try:
            # Convert netmask to binary and count 1s
            octets = netmask.split('.')
            binary = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])
            return binary.count('1')
        except:
            return 24  # Default to /24 on error

# End of ios_parser.py