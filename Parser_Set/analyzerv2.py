#!/usr/bin/env python3
"""
Synopsis:
    Multi-Vendor Network Configuration Analyzer - Main Analysis Script

Description:
    This script provides comprehensive analysis of network device configurations
    from multiple vendors (Cisco, Juniper, Palo Alto, Fortigate, Eltex) with
    intelligent network flow mapping. It extracts interfaces, VLANs, ACLs, routes,
    and administrative settings, then correlates them into a coherent network flow
    map suitable for visualization and analysis.
    
    Vendor Support:
    - Cisco: IOS, IOS-XE, NX-OS, ASA, FTD/NGFW
    - Juniper: JunOS (MX, EX, SRX, QFX, PTX series)
    - Palo Alto: PAN-OS (with optional Global Protect VPN parsing)
    - Fortigate: FortiOS
    - Eltex: MES, ESR series
    
    Supports multiple output formats:
    - HTML Workbook (interactive, full-featured with filtering and themes)
    - XML (structured data export)
    - Segmented CSV (multiple sheets in single file)
    
    Can parse individual files or entire directories, with optional selective parsing
    of specific configuration sections.

Notes:
    - Pure Python implementation (standard library only)
    - Auto-detects vendor and device type
    - Network flow mapping correlates interfaces, ACLs, subnets, and devices
    - All output formats include organized sheets/sections:
      * Network Flow Mapping (for visualization)
      * Administration (management access and credentials)
      * Interfaces (state and type)
      * VLANs
      * Endpoints (deduplicated)
      * Data Monitoring (SPAN/NetFlow)
      * Global Protect VPN (Palo Alto only, when enabled)
      * Hardware
      * Summary

Usage:
    # Analyze single config (auto-detect vendor)
    python3 analyzer.py --config router.cfg --output analysis.html
    
    # Specify vendor
    python3 analyzer.py --config device.cfg --vendor juniper --output analysis.html
    
    # Palo Alto with Global Protect
    python3 analyzer.py --config palo_alto.cfg --vendor paloalto \
        --parse-globalprotect --output analysis.html
    
    # Analyze mixed-vendor directory
    python3 analyzer.py --config-dir ./configs --output analysis.html
    
    # Parse specific section only
    python3 analyzer.py --config switch.cfg --parse interfaces --output interfaces.csv
    
    # Specify output format
    python3 analyzer.py --config device.cfg --output result --format xml

Version: 2.2.0
"""

import sys
import os
import re
import csv
import json
import argparse
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
from collections import defaultdict

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import shared components
from shared_components.data_structures import (
    DeviceConfiguration,
    NetworkInterface,
    VLAN,
    AccessControlList,
    AccessControlEntry,
    Route
)
from shared_components.utilities import (
    read_config_file,
    detect_device_type,
    is_valid_ipv4_address,
    is_valid_subnet_mask,
    calculate_network_address,
    subnet_mask_to_cidr
)
from shared_components.constants import (
    VERSION,
    DEVICE_TYPE_IOS,
    DEVICE_TYPE_IOSXE,
    DEVICE_TYPE_NXOS,
    DEVICE_TYPE_ASA,
    DEVICE_TYPE_NGFW
)

# Multi-vendor device type constants
DEVICE_TYPE_JUNOS = 'junos'
DEVICE_TYPE_PANOS = 'panos'
DEVICE_TYPE_FORTIOS = 'fortios'
DEVICE_TYPE_ELTEX = 'eltex'

# Import BaseParser for vendor detection
from parser_modules.base_parser import BaseParser


class NetworkFlowMapping:
    """
    Represents network flow mapping data for an interface or VLAN.
    
    This class correlates all relevant network flow information including
    interfaces, ACLs, subnets, and connected devices to enable comprehensive
    traffic flow analysis and visualization.
    
    Attributes:
        device_name: Name of the device
        interface_name: Name of the interface or VLAN
        description: Interface/VLAN description
        ip_address: Primary IP address
        subnet_mask: Subnet mask
        network_address: Calculated network address
        cidr: CIDR notation
        vlan_id: Associated VLAN ID
        input_acls: List of inbound ACLs
        output_acls: List of outbound ACLs
        connected_networks: List of directly connected networks
        routed_networks: List of networks reachable via routing
        neighbor_devices: List of neighboring devices (from CDP/LLDP if available)
        connected_endpoints: List of endpoints connected to this interface/VLAN
        endpoint_count: Number of connected endpoints
        admin_status: Interface administrative status
        protocol_status: Interface protocol status
        interface_type: Type of interface (physical, logical, virtual)
        security_zone: Security zone if applicable (ASA/NGFW)
    """
    
    def __init__(self, device_name: str, interface_name: str):
        """Initialize network flow mapping for an interface."""
        self.device_name = device_name
        self.interface_name = interface_name
        self.description = ""
        self.ip_address = ""
        self.subnet_mask = ""
        self.network_address = ""
        self.cidr = ""
        self.vlan_id = None
        self.input_acls = []
        self.output_acls = []
        self.connected_networks = []
        self.routed_networks = []
        self.neighbor_devices = []
        self.connected_endpoints = []  # NEW: List of endpoint names/IPs
        self.endpoint_count = 0  # NEW: Count of connected endpoints
        self.admin_status = "unknown"
        self.protocol_status = "unknown"
        self.interface_type = "unknown"
        self.security_zone = ""
        
    def calculate_network_details(self) -> None:
        """Calculate network address and CIDR from IP and mask."""
        if self.ip_address and self.subnet_mask:
            self.network_address = calculate_network_address(
                self.ip_address, 
                self.subnet_mask
            ) or ""
            cidr_val = subnet_mask_to_cidr(self.subnet_mask)
            if cidr_val:
                self.cidr = f"{self.network_address}/{cidr_val}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for output."""
        return {
            'Device': self.device_name,
            'Interface/VLAN': self.interface_name,
            'Description': self.description,
            'IP Address': self.ip_address,
            'Subnet Mask': self.subnet_mask,
            'Network': self.network_address,
            'CIDR': self.cidr,
            'VLAN ID': self.vlan_id if self.vlan_id else '',
            'Input ACLs': ';'.join(self.input_acls),
            'Output ACLs': ';'.join(self.output_acls),
            'Connected Networks': ';'.join(self.connected_networks),
            'Routed Networks': ';'.join(self.routed_networks),
            'Connected Endpoints': ';'.join(self.connected_endpoints),
            'Endpoint Count': str(self.endpoint_count),
            'Neighbor Devices': ';'.join(self.neighbor_devices),
            'Admin Status': self.admin_status,
            'Protocol Status': self.protocol_status,
            'Interface Type': self.interface_type,
            'Security Zone': self.security_zone
        }


class AdministrationConfig:
    """
    Represents administrative configuration and access details.
    
    Attributes:
        device_name: Name of the device
        management_ips: List of management IP addresses/subnets
        admin_users: List of administrative usernames
        privilege_levels: Dictionary of user privilege levels
        credential_hashes: Dictionary of password hashes (if present)
        access_methods: List of enabled access methods (telnet, ssh, http, https)
        management_acls: List of ACLs controlling administrative access
        snmp_communities: List of SNMP community strings
        enable_secret: Enable secret hash (if present)
        vty_lines: VTY line configuration details
    """
    
    def __init__(self, device_name: str):
        """Initialize administration configuration."""
        self.device_name = device_name
        self.management_ips = []
        self.admin_users = []
        self.privilege_levels = {}
        self.credential_hashes = {}
        self.access_methods = []
        self.management_acls = []
        self.snmp_communities = []
        self.enable_secret = ""
        self.vty_lines = []
        # Formatted strings from parsers
        self.user_privileges_str = ""
        self.credential_hashes_str = ""
        # System administration fields
        self.domain_name = ""
        self.ntp_servers = []
        self.dns_servers = []
        self.logging_servers = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for output."""
        # Use formatted strings if available, otherwise format dicts
        user_privs = self.user_privileges_str if self.user_privileges_str else (
            '; '.join([f"{user}: {priv}" for user, priv in self.privilege_levels.items()])
            if self.privilege_levels else ''
        )
        
        cred_hashes = self.credential_hashes_str if self.credential_hashes_str else (
            '; '.join([f"{user}: {hash_val}" for user, hash_val in self.credential_hashes.items()])
            if self.credential_hashes else ''
        )
        
        return {
            'Device': self.device_name,
            'Domain Name': self.domain_name if self.domain_name else '',
            'NTP Servers': '; '.join(self.ntp_servers) if self.ntp_servers else '',
            'DNS Servers': '; '.join(self.dns_servers) if self.dns_servers else '',
            'Logging Servers': '; '.join(self.logging_servers) if self.logging_servers else '',
            'Management IPs': ';'.join(self.management_ips),
            'Admin Users': ';'.join(self.admin_users),
            'Access Methods': ';'.join(self.access_methods) if self.access_methods else 'Not configured',
            'Management ACLs': ';'.join(self.management_acls) if self.management_acls else 'Not configured',
            'SNMP Communities': ';'.join(self.snmp_communities),
            'Enable Secret': self.enable_secret if self.enable_secret else 'Not configured',
            'VTY Lines': ';'.join(self.vty_lines) if self.vty_lines else 'Not configured',
            'User Privileges': user_privs,
            'Credential Hashes': cred_hashes
        }


class ConfigurationAnalyzer:
    """
    Main analyzer class that orchestrates configuration parsing and analysis.
    
    This class coordinates all parsing operations, builds network flow mappings,
    and generates output in the requested format.
    """
    
    def __init__(self, verbose: bool = False, parse_globalprotect: bool = False):
        """
        Initialize the configuration analyzer.
        
        Args:
            verbose: Enable verbose logging
            parse_globalprotect: Enable Global Protect VPN parsing (Palo Alto only)
        """
        self.verbose = verbose
        self.parse_globalprotect = parse_globalprotect
        self.device_configs = []
        self.network_flows = []
        self.admin_configs = []
        
        # Global Protect data (populated when parse_globalprotect=True and vendor=paloalto)
        self.globalprotect_portals = []
        self.globalprotect_gateways = []
        self.globalprotect_client_configs = []
        self.globalprotect_data_list = []  # For dedicated GP report
        
    def log(self, message: str, level: str = 'INFO') -> None:
        """Log message if verbose mode enabled."""
        if self.verbose or level in ['WARNING', 'ERROR']:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] [{level}] {message}")
    
    def analyze_file(
        self, 
        config_path: str, 
        device_type: Optional[str] = None
    ) -> DeviceConfiguration:
        """
        Analyze a single configuration file.
        
        Args:
            config_path: Path to configuration file
            device_type: Optional device type override
            
        Returns:
            DeviceConfiguration object with parsed data
        """
        self.log(f"Analyzing configuration: {config_path}")
        
        # Read configuration
        try:
            config_lines = read_config_file(config_path)
            self.log(f"Read {len(config_lines)} lines")
        except Exception as error:
            self.log(f"Error reading file: {error}", 'ERROR')
            raise
        
        # Detect device type if not specified
        if not device_type:
            # Use BaseParser for multi-vendor detection
            vendor = BaseParser.detect_vendor_from_config(config_lines)
            self.log(f"Detected vendor: {vendor}")
            
            if vendor == 'cisco':
                # Use existing Cisco detection
                device_type = detect_device_type(config_lines)
            elif vendor == 'juniper':
                device_type = DEVICE_TYPE_JUNOS
            elif vendor == 'paloalto':
                device_type = DEVICE_TYPE_PANOS
            elif vendor == 'fortigate':
                device_type = DEVICE_TYPE_FORTIOS
            elif vendor == 'eltex':
                device_type = DEVICE_TYPE_ELTEX
            else:
                # Default to Cisco IOS if unknown
                device_type = DEVICE_TYPE_IOS
            
            self.log(f"Detected device type: {device_type}")
        
        # Import appropriate parser
        parser = self.get_parser(device_type)
        
        # Parse configuration
        try:
            device_config = parser.parse(config_lines)
            self.log(f"Parsed device: {device_config.device_name}")
            
            # Collect Global Protect data if applicable (wrapped to not fail whole parse)
            if device_type == DEVICE_TYPE_PANOS and self.parse_globalprotect:
                try:
                    if hasattr(parser, 'get_globalprotect_data'):
                        gp_data = parser.get_globalprotect_data()
                        if gp_data is not None:
                            self.globalprotect_data_list.append(gp_data)
                            
                            # Access as object (v2-style)
                            portals = getattr(gp_data, 'portals', [])  # Fallback to empty list if no attribute
                            gateways = getattr(gp_data, 'gateways', [])
                            client_configs = getattr(gp_data, 'client_configs', [])
                            hip_objects = getattr(gp_data, 'hip_objects', [])
                            
                            # For v1-style lists (if your output generators need them)
                            self.globalprotect_portals.extend(portals)
                            self.globalprotect_gateways.extend(gateways)
                            self.globalprotect_client_configs.extend(client_configs)
                            
                            # Log using lengths (safe for object or dict)
                            num_portals = getattr(gp_data, 'total_portals', len(portals))
                            num_gateways = getattr(gp_data, 'total_gateways', len(gateways))
                            num_hip_objects = getattr(gp_data, 'total_hip_objects', len(hip_objects))
                            
                            self.log(f"Collected GlobalProtect data: {num_portals} portals, "
                                     f"{num_gateways} gateways, "
                                     f"{num_hip_objects} HIP objects")
                except Exception as gp_error:
                    self.log(f"GlobalProtect collection error: {gp_error}", 'WARNING')
                    self.log("Continuing analysis without GlobalProtect data for this file", 'WARNING')
            
            return device_config
        except Exception as error:
            self.log(f"Parsing error: {error}", 'ERROR')
            raise

    def analyze_directory(
        self,
        config_dir: str,
        device_type: Optional[str] = None
    ) -> List[DeviceConfiguration]:
        """
        Analyze all configuration files in a directory.
        
        When parse_globalprotect is enabled, only Palo Alto configurations
        are processed (other vendors are skipped).
        
        Args:
            config_dir: Directory containing configuration files
            device_type: Optional device type override
            
        Returns:
            List of DeviceConfiguration objects
        """
        if not os.path.isdir(config_dir):
            raise NotADirectoryError(f"Not a directory: {config_dir}")
        
        self.log(f"Analyzing directory: {config_dir}")
        
        if self.parse_globalprotect:
            self.log("GlobalProtect mode: Only analyzing Palo Alto configurations")
        
        configs = []
        valid_extensions = ['.cfg', '.conf', '.config', '.txt', '.text', '.xml', '.log', '']
        
        for filename in sorted(os.listdir(config_dir)):
            file_path = os.path.join(config_dir, filename)
            
            if not os.path.isfile(file_path):
                continue
            
            # Check file extension
            _, ext = os.path.splitext(filename)
            if ext.lower() not in valid_extensions:
                self.log(f"Skipping {filename}: invalid extension", 'WARNING')
                continue
            
            # If GlobalProtect parsing is enabled, pre-filter for Palo Alto configs
            if self.parse_globalprotect:
                try:
                    config_lines = read_config_file(file_path)
                    vendor = BaseParser.detect_vendor_from_config(config_lines)
                    
                    if vendor != 'paloalto':
                        self.log(f"Skipping {filename}: Not a Palo Alto configuration (detected: {vendor})")
                        continue
                    
                except Exception as error:
                    self.log(f"Error detecting vendor for {filename}: {error}", 'WARNING')
                    continue
            
            try:
                device_config = self.analyze_file(file_path, device_type)
                configs.append(device_config)
            except Exception as error:
                self.log(f"Error analyzing {filename}: {error}", 'ERROR')
        
        self.log(f"Successfully analyzed {len(configs)} configuration files")
        
        if self.parse_globalprotect and len(configs) == 0:
            self.log("WARNING: No Palo Alto configurations found for GlobalProtect parsing", 'WARNING')
        
        return configs
    
    def get_parser(self, device_type: str):
        """
        Get appropriate parser for device type.
        
        Args:
            device_type: Device type string (ios, junos, panos, fortios, eltex, etc.)
            
        Returns:
            Parser instance for the specified device type
        """
        # Cisco parsers
        if device_type in [DEVICE_TYPE_IOS, DEVICE_TYPE_IOSXE]:
            from parser_modules.ios_parser import IOSParser
            return IOSParser(verbose=self.verbose)
        elif device_type == DEVICE_TYPE_NXOS:
            from parser_modules.nxos_parser import NXOSParser
            return NXOSParser(verbose=self.verbose)
        elif device_type == DEVICE_TYPE_ASA:
            from parser_modules.asa_parser import ASAParser
            return ASAParser(verbose=self.verbose)
        elif device_type == DEVICE_TYPE_NGFW:
            from parser_modules.ngfw_parser import NGFWParser
            return NGFWParser(verbose=self.verbose)
        
        # Multi-vendor parsers
        elif device_type == DEVICE_TYPE_JUNOS:
            from parser_modules.juniper_parser import JuniperParser
            return JuniperParser(verbose=self.verbose)
        elif device_type == DEVICE_TYPE_PANOS:
            from parser_modules.paloalto_parser import PaloAltoParser
            return PaloAltoParser(verbose=self.verbose, parse_globalprotect=self.parse_globalprotect)
        elif device_type == DEVICE_TYPE_FORTIOS:
            from parser_modules.fortigate_parser import FortigateParser
            return FortigateParser(verbose=self.verbose)
        elif device_type == DEVICE_TYPE_ELTEX:
            from parser_modules.eltex_parser import EltexParser
            return EltexParser(verbose=self.verbose)
        
        # Default fallback
        else:
            self.log(f"Unknown device type '{device_type}', defaulting to IOS parser", 'WARNING')
            from parser_modules.ios_parser import IOSParser
            return IOSParser(verbose=self.verbose)
    
    def build_network_flow_mappings(
        self, 
        device_config: DeviceConfiguration
    ) -> List[NetworkFlowMapping]:
        """
        Build network flow mappings from device configuration.
        
        This is the core correlation function that ties together interfaces,
        VLANs, ACLs, subnets, and routing information.
        
        Args:
            device_config: Parsed device configuration
            
        Returns:
            List of NetworkFlowMapping objects
        """
        self.log(f"Building network flow mappings for {device_config.device_name}")
        
        flow_mappings = []
        
        # Process interfaces
        for interface in device_config.interfaces:
            flow = NetworkFlowMapping(
                device_config.device_name,
                interface.name
            )
            
            # Basic interface info
            flow.description = interface.description
            flow.ip_address = interface.ip_address
            flow.subnet_mask = interface.ip_mask
            flow.vlan_id = interface.vlan or interface.access_vlan
            flow.admin_status = 'down' if interface.shutdown else 'up'
            flow.interface_type = interface.interface_type or 'physical'
            
            # Calculate network details
            flow.calculate_network_details()
            
            # ACLs
            if interface.input_acl:
                flow.input_acls.append(interface.input_acl)
            if interface.output_acl:
                flow.output_acls.append(interface.output_acl)
            
            # Connected networks (same subnet interfaces)
            if flow.network_address:
                flow.connected_networks.append(flow.cidr)
            
            # Add secondary IPs as connected networks
            for secondary in interface.secondary_ips:
                flow.connected_networks.append(secondary)
            
            flow_mappings.append(flow)
        
        # Process VLANs
        for vlan in device_config.vlans:
            flow = NetworkFlowMapping(
                device_config.device_name,
                f"VLAN{vlan.vlan_id}"
            )
            
            flow.description = vlan.name
            flow.vlan_id = vlan.vlan_id
            flow.ip_address = vlan.gateway
            flow.interface_type = 'vlan'
            
            if vlan.gateway:
                # Assume /24 for VLAN gateways if no explicit mask
                flow.subnet_mask = "255.255.255.0"
                flow.calculate_network_details()
            
            flow_mappings.append(flow)
        
        # Add routing information to flow mappings
        self.correlate_routing_info(device_config, flow_mappings)
        
        # Add endpoint information to flow mappings
        self.correlate_endpoints(device_config, flow_mappings)
        
        # Correlate ACLs with endpoints
        self.correlate_acl_endpoints(device_config)
        
        self.log(f"Created {len(flow_mappings)} network flow mappings")
        
        return flow_mappings
    
    def correlate_routing_info(
        self,
        device_config: DeviceConfiguration,
        flow_mappings: List[NetworkFlowMapping]
    ) -> None:
        """
        Correlate routing information with network flow mappings.
        
        Args:
            device_config: Device configuration
            flow_mappings: List of flow mappings to update
        """
        # Build interface map for quick lookup
        interface_map = {}
        for flow in flow_mappings:
            if flow.interface_name.startswith('VLAN'):
                continue
            interface_map[flow.interface_name] = flow
        
        # Process routes
        for route in device_config.routes:
            # Find egress interface
            if route.interface and route.interface in interface_map:
                flow = interface_map[route.interface]
                route_cidr = f"{route.destination}/{subnet_mask_to_cidr(route.mask) or '32'}"
                if route_cidr not in flow.routed_networks:
                    flow.routed_networks.append(route_cidr)
            
            # If route has next hop, try to find interface with that subnet
            elif route.next_hop:
                for flow in flow_mappings:
                    if flow.network_address and self.ip_in_subnet(
                        route.next_hop, 
                        flow.network_address, 
                        flow.subnet_mask
                    ):
                        route_cidr = f"{route.destination}/{subnet_mask_to_cidr(route.mask) or '32'}"
                        if route_cidr not in flow.routed_networks:
                            flow.routed_networks.append(route_cidr)
                        break
    
    def find_routing_interface_for_endpoint(
        self,
        endpoint_ip: str,
        device_config: DeviceConfiguration
    ) -> Optional[str]:
        """
        Find which interface would handle traffic to an endpoint IP.
        
        For endpoints not in local subnets (external services like NTP, syslog),
        this finds the interface that would route to them.
        
        Returns:
            Interface name that routes to this IP, or None
        """
        # Strategy 1: Check if there's a default route and find its interface
        # Look for interface that connects to the default gateway
        for route in device_config.routes:
            if route.destination == "0.0.0.0" or route.destination == "::/0":
                # This is a default route
                next_hop = route.next_hop
                
                # Find interface in same subnet as next-hop
                for interface in device_config.interfaces:
                    if interface.ip_address and interface.subnet_mask:
                        # Check if next-hop is in this interface's subnet
                        if self.ip_in_subnet(next_hop, interface.ip_address, interface.subnet_mask):
                            # This interface connects to the default gateway
                            return interface.name
        
        # Strategy 2: Return the first VLAN interface (SVI) as it's likely the gateway
        for interface in device_config.interfaces:
            if hasattr(interface, 'vlan_id') and interface.vlan_id and interface.ip_address:
                # This is a VLAN interface with an IP - likely a gateway
                return interface.name
        
        return None
    
    def ip_in_subnet(self, ip: str, network: str, mask: str) -> bool:
        """
        Check if IP address is in subnet.
        
        Args:
            ip: IP address to check (e.g., "10.10.20.243")
            network: Network address (e.g., "10.10.20.128")
            mask: Subnet mask (e.g., "255.255.255.128" for /25)
            
        Returns:
            True if IP is in the subnet, False otherwise
        """
        if not (is_valid_ipv4_address(ip) and is_valid_ipv4_address(network) 
                and is_valid_subnet_mask(mask)):
            return False
        
        # Calculate if IP is in subnet using bitwise AND
        ip_octets = [int(x) for x in ip.split('.')]
        net_octets = [int(x) for x in network.split('.')]
        mask_octets = [int(x) for x in mask.split('.')]
        
        # Apply mask to both IP and network and compare
        for i in range(4):
            if (ip_octets[i] & mask_octets[i]) != (net_octets[i] & mask_octets[i]):
                return False
        
        return True
    
    def find_most_specific_subnet_match(
        self,
        ip_address: str,
        subnet_candidates: List[tuple]
    ) -> Optional[tuple]:
        """
        Find the most specific (longest prefix) subnet match for an IP address.
        
        When multiple subnets contain an IP, returns the one with the longest
        prefix (most specific match). For example, if IP 10.10.20.243 matches
        both 10.10.20.0/24 and 10.10.20.128/25, returns the /25 subnet as it's
        more specific.
        
        Args:
            ip_address: IP address to match (e.g., "10.10.20.243")
            subnet_candidates: List of tuples (flow, network, mask) to check
            
        Returns:
            Tuple (flow, network, mask) with the most specific match, or None
            
        Example:
            IP: 10.10.20.243
            Candidates:
                - 10.10.20.0/25 (covers .0-.127) - NO MATCH
                - 10.10.20.128/25 (covers .128-.255) - MATCH (most specific)
                - 10.10.20.0/24 (covers .0-.255) - MATCH (less specific)
            Returns: 10.10.20.128/25
        """
        if not ip_address:
            return None
        
        matching_subnets = []
        
        # Find all matching subnets
        for flow, network, mask in subnet_candidates:
            if self.ip_in_subnet(ip_address, network, mask):
                # Calculate prefix length (CIDR notation)
                mask_bits = sum(bin(int(octet)).count('1') for octet in mask.split('.'))
                matching_subnets.append((flow, network, mask, mask_bits))
        
        if not matching_subnets:
            return None
        
        # Sort by prefix length (descending) - longest prefix is most specific
        matching_subnets.sort(key=lambda x: x[3], reverse=True)
        
        # Return the most specific match (without mask_bits)
        best_match = matching_subnets[0]
        return (best_match[0], best_match[1], best_match[2])
    
    
    def correlate_endpoints(
        self,
        device_config: DeviceConfiguration,
        flow_mappings: List[NetworkFlowMapping]
    ) -> None:
        """
        Correlate endpoints with their connected interfaces and VLANs.
        
        Uses intelligent matching to ensure ALL endpoints are linked:
        1. Most-specific subnet matching (handles overlapping subnets)
        2. VLAN ID matching
        3. Routing-based matching for external endpoints
        4. Fallback to first interface with IP as last resort
        
        Args:
            device_config: Device configuration with endpoints
            flow_mappings: List of flow mappings to update
        """
        if not device_config.endpoints:
            return
        
        self.log(f"Correlating {len(device_config.endpoints)} endpoints with interfaces/VLANs")
        
        # Build lookup maps for faster correlation
        interface_map = {}  # Maps interface name to flow
        vlan_map = {}  # Maps VLAN ID to flow
        subnet_map = []  # List of (flow, network, mask) for subnet matching
        
        for flow in flow_mappings:
            # Map by interface name
            interface_map[flow.interface_name] = flow
            
            # Map by VLAN ID
            if flow.vlan_id:
                vlan_map[flow.vlan_id] = flow
            
            # Map by subnet for IP matching
            if flow.network_address and flow.subnet_mask:
                subnet_map.append((flow, flow.network_address, flow.subnet_mask))
        
        # Track endpoints that couldn't be matched
        unmatched_endpoints = []
        
        # Process each endpoint
        for endpoint in device_config.endpoints:
            matched_flows = set()  # Use set to avoid duplicates
            
            # Method 1: MOST-SPECIFIC subnet match for IP address
            # This handles overlapping subnets correctly (e.g., /24 and /25)
            if endpoint.ip_address and ':' not in endpoint.ip_address:  # IPv4 only
                best_match = self.find_most_specific_subnet_match(
                    endpoint.ip_address,
                    subnet_map
                )
                if best_match:
                    flow, network, mask = best_match
                    matched_flows.add(flow)
                    
                    # Update endpoint with related interface/VLAN
                    if flow.interface_type == 'vlan':
                        endpoint.add_related_vlan(flow.vlan_id)
                        self.log(f"  Matched endpoint {endpoint.name} ({endpoint.ip_address}) to VLAN {flow.vlan_id} via most-specific subnet", level='DEBUG')
                    else:
                        endpoint.add_related_interface(flow.interface_name)
                        self.log(f"  Matched endpoint {endpoint.name} ({endpoint.ip_address}) to interface {flow.interface_name} via most-specific subnet", level='DEBUG')
                    
                    # Mark as directly connected
                    if not hasattr(endpoint, 'connection_type'):
                        endpoint.connection_type = "direct"
            
            # Method 2: Match by VLAN ID (if endpoint has VLAN context)
            if endpoint.source_context:
                vlan_match = re.search(r'vlan[:\s]+(\d+)', endpoint.source_context, re.IGNORECASE)
                if vlan_match:
                    vlan_id = int(vlan_match.group(1))
                    if vlan_id in vlan_map:
                        matched_flows.add(vlan_map[vlan_id])
                        endpoint.add_related_vlan(vlan_id)
                        self.log(f"  Matched endpoint {endpoint.name} to VLAN {vlan_id} via source context", level='DEBUG')
            
            # Method 3: Check related_vlans field if already populated
            for vlan_id in endpoint.related_vlans:
                if vlan_id in vlan_map:
                    matched_flows.add(vlan_map[vlan_id])
            
            # Method 4: Check related_interfaces field if already populated
            for interface_name in endpoint.related_interfaces:
                if interface_name in interface_map:
                    matched_flows.add(interface_map[interface_name])
            
            # Method 5: If endpoint not matched (external subnet), use routing
            if not matched_flows and endpoint.ip_address:
                # Skip IPv6 for now (routing logic is IPv4-only)
                if ':' not in endpoint.ip_address:
                    routing_interface = self.find_routing_interface_for_endpoint(
                        endpoint.ip_address,
                        device_config
                    )
                    if routing_interface and routing_interface in interface_map:
                        matched_flows.add(interface_map[routing_interface])
                        endpoint.add_related_interface(routing_interface)
                        # Mark this as a routed connection
                        if not hasattr(endpoint, 'connection_type'):
                            endpoint.connection_type = "routed"
                        self.log(f"  Matched endpoint {endpoint.name} ({endpoint.ip_address}) to interface {routing_interface} via routing", level='DEBUG')
            
            # Method 6: IPv6 endpoints - match to any interface with IPv6
            if not matched_flows and endpoint.ip_address and ':' in endpoint.ip_address:
                for flow in flow_mappings:
                    # Check if flow has IPv6 addresses
                    if hasattr(flow, 'ipv6_addresses') and flow.ipv6_addresses:
                        matched_flows.add(flow)
                        endpoint.add_related_interface(flow.interface_name)
                        if not hasattr(endpoint, 'connection_type'):
                            endpoint.connection_type = "ipv6"
                        self.log(f"  Matched IPv6 endpoint {endpoint.name} ({endpoint.ip_address}) to interface {flow.interface_name}", level='DEBUG')
                        break  # Match to first IPv6-capable interface
            
            # Method 7: LAST RESORT - If still not matched, link to first interface with IP
            # This ensures NO endpoints are left unlinked in visualization
            if not matched_flows:
                for flow in flow_mappings:
                    if flow.ip_address:
                        matched_flows.add(flow)
                        endpoint.add_related_interface(flow.interface_name)
                        if not hasattr(endpoint, 'connection_type'):
                            endpoint.connection_type = "fallback"
                        self.log(f"  FALLBACK: Matched endpoint {endpoint.name} ({endpoint.ip_address or 'no-ip'}) to interface {flow.interface_name}", level='DEBUG')
                        break  # Match to first available interface
            
            # Track if endpoint couldn't be matched even with fallback
            if not matched_flows:
                unmatched_endpoints.append(endpoint)
                self.log(f"  WARNING: Could not match endpoint {endpoint.name} ({endpoint.ip_address or 'no-ip'}) to any interface", level='WARNING')
            
            # Update matched flows with endpoint information
            for flow in matched_flows:
                endpoint_label = f"{endpoint.name} ({endpoint.ip_address})" if endpoint.ip_address else endpoint.name
                if endpoint_label not in flow.connected_endpoints:
                    flow.connected_endpoints.append(endpoint_label)
                    flow.endpoint_count += 1
        
        # Log results
        total_endpoints_mapped = sum(flow.endpoint_count for flow in flow_mappings)
        total_endpoints = len(device_config.endpoints)
        self.log(f"Mapped {total_endpoints_mapped} endpoint connections across {len(flow_mappings)} flows")
        
        if unmatched_endpoints:
            self.log(f"WARNING: {len(unmatched_endpoints)} endpoints could not be matched to any interface:", level='WARNING')
            for ep in unmatched_endpoints:
                self.log(f"  - {ep.name} ({ep.ip_address or 'no-ip'})", level='WARNING')
        else:
            self.log(f"SUCCESS: All {total_endpoints} endpoints successfully linked to interfaces")
    
    def correlate_neighbor_devices(
        self,
        all_device_configs: List[DeviceConfiguration],
        all_flow_mappings: List[List[NetworkFlowMapping]]
    ) -> None:
        """
        Detect and correlate neighbor devices across all device configurations.
        
        Uses multiple methods to identify neighbors:
        1. Subnet matching - interfaces on same subnet are neighbors
        2. Description parsing - extract device names from interface descriptions
        3. Point-to-point link detection - /30 and /31 subnets
        
        Args:
            all_device_configs: List of all device configurations
            all_flow_mappings: List of flow mappings for each device (parallel to device_configs)
        """
        self.log("Correlating neighbor devices across topology")
        
        # Build a comprehensive subnet map: subnet -> [(device, interface, flow)]
        subnet_to_interfaces = {}
        
        for device_config, flow_mappings in zip(all_device_configs, all_flow_mappings):
            for flow in flow_mappings:
                # Skip loopback interfaces
                if flow.interface_name.lower().startswith('loopback'):
                    continue
                
                if flow.network_address and flow.subnet_mask:
                    subnet_key = f"{flow.network_address}/{subnet_mask_to_cidr(flow.subnet_mask)}"
                    if subnet_key not in subnet_to_interfaces:
                        subnet_to_interfaces[subnet_key] = []
                    subnet_to_interfaces[subnet_key].append({
                        'device': device_config.device_name,
                        'interface': flow.interface_name,
                        'flow': flow,
                        'ip': flow.ip_address
                    })
        
        # Identify neighbor relationships
        neighbor_count = 0
        
        # Method 1: Subnet matching
        for subnet_key, interfaces in subnet_to_interfaces.items():
            # Skip subnets with only one interface (no neighbors)
            if len(interfaces) < 2:
                continue
            
            # For each interface in the subnet, all others are neighbors
            for i, intf_info in enumerate(interfaces):
                flow = intf_info['flow']
                device_name = intf_info['device']
                neighbors_found = {}  # device -> best label
                
                for j, neighbor_info in enumerate(interfaces):
                    if i == j:
                        continue  # Skip self
                    
                    neighbor_device = neighbor_info['device']
                    neighbor_interface = neighbor_info['interface']
                    neighbor_ip = neighbor_info['ip']
                    
                    # Format: "DEVICE-NAME (interface: IP)"
                    neighbor_label = f"{neighbor_device} ({neighbor_interface}: {neighbor_ip})"
                    
                    # Store best neighbor label per device
                    neighbors_found[neighbor_device] = neighbor_label
                
                # Add unique neighbors to flow
                for neighbor_label in neighbors_found.values():
                    if neighbor_label not in flow.neighbor_devices:
                        flow.neighbor_devices.append(neighbor_label)
                        neighbor_count += 1
        
        # Method 2: Parse interface descriptions for device names (if not already found)
        description_patterns = [
            r'(?:link|connect(?:ed)?|to)\s+(?:to\s+)?([A-Z0-9\-]+)',
            r'([A-Z0-9\-]+)\s+(?:link|connection)',
            r'\*{3}\s*(?:Link\s+to\s+)?([A-Z0-9\-]+)',  # *** Link to DEVICE-NAME ***
        ]
        
        for device_config, flow_mappings in zip(all_device_configs, all_flow_mappings):
            for flow in flow_mappings:
                if not flow.description:
                    continue
                
                # Try to extract device name from description
                for pattern in description_patterns:
                    match = re.search(pattern, flow.description, re.IGNORECASE)
                    if match:
                        potential_neighbor = match.group(1).upper()
                        
                        # Verify this is actually a device we know about
                        for other_device in all_device_configs:
                            if other_device.device_name.upper() == potential_neighbor:
                                # Check if we already have this neighbor from subnet matching
                                already_found = any(
                                    other_device.device_name in neighbor 
                                    for neighbor in flow.neighbor_devices
                                )
                                
                                if not already_found:
                                    # Found a new neighbor from description
                                    neighbor_interface = self._find_neighbor_interface(
                                        flow, other_device, all_flow_mappings
                                    )
                                    
                                    if neighbor_interface:
                                        neighbor_label = f"{other_device.device_name} ({neighbor_interface})"
                                    else:
                                        neighbor_label = other_device.device_name
                                    
                                    flow.neighbor_devices.append(neighbor_label)
                                    neighbor_count += 1
                                break
                        break  # Stop after first match
        
        self.log(f"Identified {neighbor_count} neighbor device connections")
    
    def correlate_endpoints_cross_device(
        self,
        all_device_configs: List[DeviceConfiguration],
        all_flow_mappings: List[List[NetworkFlowMapping]]
    ) -> None:
        """
        Correlate endpoints across all devices with interfaces across all devices.
        
        This method resolves the issue where endpoints discovered on one device
        (e.g., from ACLs) need to be associated with interfaces on a different device
        that actually connects to that subnet.
        
        Args:
            all_device_configs: List of all device configurations
            all_flow_mappings: List of flow mappings for each device (parallel to device_configs)
        """
        self.log("Correlating endpoints across all devices")
        
        # Build comprehensive maps
        all_endpoints = []
        all_flows = []
        subnet_to_flows = {}  # subnet_cidr -> list of flows
        
        # Collect all endpoints and flows from all devices
        for device_config in all_device_configs:
            all_endpoints.extend(device_config.endpoints)
        
        for flow_list in all_flow_mappings:
            all_flows.extend(flow_list)
        
        # Build subnet map for fast lookup
        for flow in all_flows:
            if flow.network_address and flow.subnet_mask:
                subnet_key = f"{flow.network_address}/{subnet_mask_to_cidr(flow.subnet_mask)}"
                if subnet_key not in subnet_to_flows:
                    subnet_to_flows[subnet_key] = []
                subnet_to_flows[subnet_key].append(flow)
        
        # Track statistics
        connections_added = 0
        endpoints_processed = 0
        
        # Correlate each endpoint with ALL matching interfaces across ALL devices
        for endpoint in all_endpoints:
            if not endpoint.ip_address:
                continue
            
            endpoints_processed += 1
            endpoint_matched = False
            
            # Method 1: For network-type endpoints, match by network address
            if endpoint.endpoint_type == 'network':
                # Try to extract network from endpoint
                endpoint_network = None
                endpoint_mask = None
                
                if '/' in endpoint.cidr:
                    # Has CIDR notation
                    endpoint_network, cidr_bits = endpoint.cidr.split('/')
                    prefix_len = int(cidr_bits)
                    mask_bits = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
                    endpoint_mask = f"{(mask_bits >> 24) & 0xff}.{(mask_bits >> 16) & 0xff}.{(mask_bits >> 8) & 0xff}.{mask_bits & 0xff}"
                elif endpoint.subnet_mask:
                    # Has mask but no CIDR
                    endpoint_network = endpoint.ip_address
                    endpoint_mask = endpoint.subnet_mask
                else:
                    # Assume /32 if no mask
                    endpoint_network = endpoint.ip_address
                    endpoint_mask = "255.255.255.255"
                
                # Match against flows with same network
                if endpoint_network:
                    for flow in all_flows:
                        # Check if flow's network matches endpoint's network
                        if flow.network_address == endpoint_network:
                            endpoint_label = f"{endpoint.name} ({endpoint.ip_address})"
                            if endpoint_label not in flow.connected_endpoints:
                                flow.connected_endpoints.append(endpoint_label)
                                flow.endpoint_count += 1
                                connections_added += 1
                                
                                # Update endpoint relations
                                if flow.interface_type == 'vlan':
                                    if flow.vlan_id and flow.vlan_id not in endpoint.related_vlans:
                                        endpoint.add_related_vlan(flow.vlan_id)
                                else:
                                    intf_str = f"{flow.device_name}:{flow.interface_name}"
                                    if intf_str not in endpoint.related_interfaces:
                                        endpoint.add_related_interface(intf_str)
                                
                                endpoint_matched = True
            
            # Method 2: For host-type endpoints, check subnet membership
            else:
                for subnet_key, flows in subnet_to_flows.items():
                    network, cidr = subnet_key.split('/')
                    prefix_len = int(cidr)
                    
                    # Calculate subnet mask from CIDR
                    mask_bits = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
                    subnet_mask = f"{(mask_bits >> 24) & 0xff}.{(mask_bits >> 16) & 0xff}.{(mask_bits >> 8) & 0xff}.{mask_bits & 0xff}"
                    
                    # Check if endpoint IP is in this subnet
                    if self.ip_in_subnet(endpoint.ip_address, network, subnet_mask):
                        for flow in flows:
                            # Create endpoint label
                            endpoint_label = f"{endpoint.name} ({endpoint.ip_address})"
                            
                            # Only add if not already present
                            if endpoint_label not in flow.connected_endpoints:
                                flow.connected_endpoints.append(endpoint_label)
                                flow.endpoint_count += 1
                                connections_added += 1
                                
                                # Update endpoint's related interfaces
                                if flow.interface_type == 'vlan':
                                    if flow.vlan_id and flow.vlan_id not in endpoint.related_vlans:
                                        endpoint.add_related_vlan(flow.vlan_id)
                                else:
                                    intf_str = f"{flow.device_name}:{flow.interface_name}"
                                    if intf_str not in endpoint.related_interfaces:
                                        endpoint.add_related_interface(intf_str)
                                
                                endpoint_matched = True
        
        self.log(f"Cross-device correlation: processed {endpoints_processed} endpoints, added {connections_added} new connections")
    
    def deduplicate_endpoints(
        self,
        all_device_configs: List[DeviceConfiguration]
    ) -> None:
        """
        Deduplicate endpoint entries while preserving legitimate multi-device networks.
        
        Rules:
        1. Host endpoints with same IP → Merge into one with combined sources
        2. Network endpoints representing actual interface subnets → Keep all (legitimate)
        3. Network endpoints from ACLs/object-groups with same IP → Merge
        
        Args:
            all_device_configs: List of all device configurations
        """
        self.log("Deduplicating endpoint entries")
        
        # Collect all endpoints with metadata
        all_endpoints_with_device = []
        for device_config in all_device_configs:
            for endpoint in device_config.endpoints:
                all_endpoints_with_device.append({
                    'endpoint': endpoint,
                    'device_config': device_config
                })
        
        # Group endpoints by IP address
        endpoints_by_ip = {}
        for item in all_endpoints_with_device:
            ep = item['endpoint']
            if ep.ip_address:
                if ep.ip_address not in endpoints_by_ip:
                    endpoints_by_ip[ep.ip_address] = []
                endpoints_by_ip[ep.ip_address].append(item)
        
        # Track removed endpoints
        endpoints_removed = 0
        
        # Process each IP group
        for ip_address, items in endpoints_by_ip.items():
            if len(items) <= 1:
                continue  # No duplicates
            
            # Categorize endpoints
            host_endpoints = [item for item in items if item['endpoint'].endpoint_type == 'host']
            network_endpoints = [item for item in items if item['endpoint'].endpoint_type == 'network']
            nat_endpoints = [item for item in items if item['endpoint'].endpoint_type in ['nat_pool', 'nat_local', 'nat_global']]
            
            # ==== Host Endpoint Deduplication ====
            if len(host_endpoints) > 1:
                # Keep the first one, merge sources from others
                primary = host_endpoints[0]['endpoint']
                primary_device = host_endpoints[0]['device_config']
                
                for item in host_endpoints[1:]:
                    duplicate = item['endpoint']
                    dup_device = item['device_config']
                    
                    # Merge source information
                    if duplicate.source_context and duplicate.source_context not in primary.source_context:
                        primary.source_context += f"; {duplicate.source_context}"
                    if duplicate.description and duplicate.description not in primary.description:
                        primary.description += f"; {duplicate.description}"
                    
                    # Merge device names if different
                    if dup_device.device_name != primary_device.device_name:
                        if dup_device.device_name not in primary.name:
                            primary.name += f"_{dup_device.device_name}"
                    
                    # Merge ACL references
                    for acl_ref in duplicate.acl_references:
                        if acl_ref not in primary.acl_references:
                            primary.acl_references.append(acl_ref)
                    
                    # Remove duplicate from its device config
                    dup_device.endpoints.remove(duplicate)
                    endpoints_removed += 1
            
            # ==== Network Endpoint Deduplication ====
            if len(network_endpoints) > 1:
                # Check if these are legitimate multi-device network subnets
                # (e.g., Management network 192.168.10.0/24 on multiple devices)
                
                # If ALL network endpoints have related interfaces, they're legitimate
                all_have_interfaces = all(
                    len(item['endpoint'].related_interfaces) > 0 
                    for item in network_endpoints
                )
                
                if all_have_interfaces:
                    # These are legitimate network subnets on multiple devices
                    # DO NOT DEDUPLICATE
                    self.log(f"  Preserving {len(network_endpoints)} network endpoints for {ip_address} (legitimate multi-device subnet)")
                else:
                    # These are likely ACL/object-group discovered networks
                    # Deduplicate by keeping one and merging sources
                    primary = network_endpoints[0]['endpoint']
                    primary_device = network_endpoints[0]['device_config']
                    
                    for item in network_endpoints[1:]:
                        duplicate = item['endpoint']
                        dup_device = item['device_config']
                        
                        # Only merge if no interfaces (not legitimate subnet)
                        if len(duplicate.related_interfaces) == 0:
                            # Merge sources
                            if duplicate.source_context and duplicate.source_context not in primary.source_context:
                                primary.source_context += f"; {duplicate.source_context}"
                            
                            # Remove duplicate
                            dup_device.endpoints.remove(duplicate)
                            endpoints_removed += 1
            
            # ==== NAT Endpoint Deduplication ====
            if len(nat_endpoints) > 1:
                # NAT entries should be kept separate per device
                # But if exact duplicates on same device, remove
                for i, item1 in enumerate(nat_endpoints):
                    for item2 in nat_endpoints[i+1:]:
                        if (item1['device_config'].device_name == item2['device_config'].device_name and
                            item1['endpoint'].name == item2['endpoint'].name):
                            # Exact duplicate on same device
                            item2['device_config'].endpoints.remove(item2['endpoint'])
                            endpoints_removed += 1
        
        self.log(f"Deduplication complete: removed {endpoints_removed} duplicate endpoints")
    
    def _find_neighbor_interface(
        self,
        source_flow: NetworkFlowMapping,
        neighbor_device: DeviceConfiguration,
        all_flow_mappings: List[List[NetworkFlowMapping]]
    ) -> Optional[str]:
        """
        Find the specific interface on neighbor device that connects to source.
        
        Args:
            source_flow: Flow from source device
            neighbor_device: Neighbor device config
            all_flow_mappings: All flow mappings
            
        Returns:
            Interface name on neighbor, or None
        """
        if not source_flow.network_address:
            return None
        
        # Find the neighbor device's flows
        neighbor_flows = None
        for i, flows in enumerate(all_flow_mappings):
            if flows and flows[0].device_name == neighbor_device.device_name:
                neighbor_flows = flows
                break
        
        if not neighbor_flows:
            return None
        
        # Find interface on neighbor in same subnet
        for flow in neighbor_flows:
            if flow.network_address == source_flow.network_address:
                return flow.interface_name
        
        return None
    
    def trace_network_path(
        self,
        source_ip: str,
        dest_ip: str,
        device_configs: List[DeviceConfiguration]
    ) -> List[Dict[str, Any]]:
        """
        Trace network path from source to destination IP.
        
        Analyzes routing tables, interface connections, and ACLs to determine
        the path traffic would take from source to destination.
        
        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            device_configs: List of device configurations
            
        Returns:
            List of path hops with interface and device information
        """
        path = []
        
        # Find source device/interface
        source_device = None
        source_interface = None
        
        for device_config in device_configs:
            # Check endpoints
            for endpoint in device_config.endpoints:
                if endpoint.ip_address == source_ip:
                    # Found source endpoint - determine its interface
                    for interface in device_config.interfaces:
                        if interface.ip_address and interface.ip_mask:
                            if self.ip_in_subnet(source_ip, 
                                calculate_network_address(interface.ip_address, interface.ip_mask),
                                interface.ip_mask):
                                source_device = device_config
                                source_interface = interface
                                break
                    break
            
            # Check interfaces directly
            if not source_device:
                for interface in device_config.interfaces:
                    if interface.ip_address == source_ip:
                        source_device = device_config
                        source_interface = interface
                        break
            
            if source_device:
                break
        
        if not source_device or not source_interface:
            return [{
                'hop': 0,
                'status': 'error',
                'message': f'Source IP {source_ip} not found in network'
            }]
        
        # Add source hop
        path.append({
            'hop': 1,
            'device': source_device.device_name,
            'interface': source_interface.name,
            'ip': source_ip,
            'action': 'source',
            'description': f'Traffic originates from {source_ip}'
        })
        
        # Find destination device/interface
        dest_device = None
        dest_interface = None
        
        for device_config in device_configs:
            # Check endpoints
            for endpoint in device_config.endpoints:
                if endpoint.ip_address == dest_ip:
                    # Found destination endpoint - determine its interface
                    for interface in device_config.interfaces:
                        if interface.ip_address and interface.ip_mask:
                            if self.ip_in_subnet(dest_ip,
                                calculate_network_address(interface.ip_address, interface.ip_mask),
                                interface.ip_mask):
                                dest_device = device_config
                                dest_interface = interface
                                break
                    break
            
            # Check interfaces directly
            if not dest_device:
                for interface in device_config.interfaces:
                    if interface.ip_address == dest_ip:
                        dest_device = device_config
                        dest_interface = interface
                        break
            
            if dest_device:
                break
        
        if not dest_device or not dest_interface:
            path.append({
                'hop': 2,
                'status': 'error',
                'message': f'Destination IP {dest_ip} not found in network'
            })
            return path
        
        # Check if source and dest are on same device
        if source_device.device_name == dest_device.device_name:
            # Same device - check if same subnet
            if source_interface.name == dest_interface.name:
                path.append({
                    'hop': 2,
                    'device': dest_device.device_name,
                    'interface': dest_interface.name,
                    'ip': dest_ip,
                    'action': 'destination',
                    'description': f'Same subnet - direct communication on {dest_interface.name}'
                })
            else:
                # Different interfaces on same device - routing/switching
                path.append({
                    'hop': 2,
                    'device': dest_device.device_name,
                    'interface': dest_interface.name,
                    'ip': dest_ip,
                    'action': 'inter-vlan-routing',
                    'description': f'Traffic routed from {source_interface.name} to {dest_interface.name}'
                })
                path.append({
                    'hop': 3,
                    'device': dest_device.device_name,
                    'interface': dest_interface.name,
                    'ip': dest_ip,
                    'action': 'destination',
                    'description': f'Traffic arrives at {dest_ip}'
                })
        else:
            # Different devices - find routing path
            # Simplified: Check if there's a route on source device to dest network
            dest_network = calculate_network_address(dest_ip, "255.255.255.0")  # Assume /24
            
            route_found = False
            for route in source_device.routes:
                route_network = calculate_network_address(route.destination, route.mask)
                if route_network == dest_network or route.destination == '0.0.0.0':
                    # Found matching route
                    path.append({
                        'hop': 2,
                        'device': source_device.device_name,
                        'interface': route.interface or 'via ' + route.next_hop,
                        'ip': route.next_hop or 'N/A',
                        'action': 'routing',
                        'description': f'Route to {route.destination}/{route.mask} via {route.next_hop or route.interface}'
                    })
                    route_found = True
                    break
            
            if not route_found:
                path.append({
                    'hop': 2,
                    'status': 'warning',
                    'message': f'No route found from {source_device.device_name} to {dest_network}'
                })
            
            # Add destination
            path.append({
                'hop': len(path) + 1,
                'device': dest_device.device_name,
                'interface': dest_interface.name,
                'ip': dest_ip,
                'action': 'destination',
                'description': f'Traffic arrives at {dest_ip} on {dest_device.device_name}'
            })
        
        return path
    
    def correlate_acl_endpoints(
        self,
        device_config: DeviceConfiguration
    ) -> None:
        """
        Correlate ACLs with endpoints by scanning ACL entries for endpoint IP references.
        
        Updates both ACL entries and endpoint objects with reference information.
        Handles:
        - Direct IP matches (host)
        - Network/wildcard matches
        - Object-group references (if endpoint is in group)
        
        Args:
            device_config: Device configuration with ACLs and endpoints
        """
        if not device_config.acls or not device_config.endpoints:
            return
        
        self.log(f"Correlating {len(device_config.acls)} ACLs with {len(device_config.endpoints)} endpoints")
        
        # Build endpoint lookup maps for efficient searching
        endpoint_by_ip = {}  # Maps IP address to endpoint
        endpoint_by_name = {}  # Maps endpoint name to endpoint
        
        for endpoint in device_config.endpoints:
            if endpoint.ip_address:
                endpoint_by_ip[endpoint.ip_address] = endpoint
            endpoint_by_name[endpoint.name] = endpoint
        
        # Process each ACL
        total_references = 0
        
        for acl in device_config.acls:
            acl_endpoints = set()  # Track unique endpoints per ACL
            
            # Process each ACE in the ACL
            for entry in acl.entries:
                entry_endpoints = set()
                
                # Check source IP field
                if entry.source:
                    matching_endpoints = self._find_matching_endpoints(
                        entry.source,
                        entry.source_wildcard,
                        endpoint_by_ip,
                        endpoint_by_name
                    )
                    entry_endpoints.update(matching_endpoints)
                
                # Check destination IP field
                if entry.destination:
                    matching_endpoints = self._find_matching_endpoints(
                        entry.destination,
                        entry.dest_wildcard,
                        endpoint_by_ip,
                        endpoint_by_name
                    )
                    entry_endpoints.update(matching_endpoints)
                
                # Update ACE with referenced endpoints
                for endpoint in entry_endpoints:
                    endpoint_label = f"{endpoint.name} ({endpoint.ip_address})"
                    if endpoint_label not in entry.referenced_endpoints:
                        entry.referenced_endpoints.append(endpoint_label)
                        total_references += 1
                
                # Update endpoints with ACL references
                for endpoint in entry_endpoints:
                    acl_ref = f"{acl.name} ({entry.action})"
                    endpoint.add_acl_reference(acl_ref)
                    acl_endpoints.add(endpoint)
            
            # Update ACL summary
            for endpoint in acl_endpoints:
                endpoint_label = f"{endpoint.name} ({endpoint.ip_address})"
                if endpoint_label not in acl.referenced_endpoints:
                    acl.referenced_endpoints.append(endpoint_label)
                    acl.endpoint_count += 1
        
        self.log(f"Found {total_references} ACL-endpoint references")
    
    def _find_matching_endpoints(
        self,
        ip_spec: str,
        wildcard: str,
        endpoint_by_ip: Dict[str, 'Endpoint'],
        endpoint_by_name: Dict[str, 'Endpoint']
    ) -> set:
        """
        Find endpoints matching an IP specification from an ACL entry.
        
        Args:
            ip_spec: IP address, network, hostname, or 'any'
            wildcard: Wildcard mask (if applicable)
            endpoint_by_ip: Dictionary mapping IPs to endpoints
            endpoint_by_name: Dictionary mapping names to endpoints
            
        Returns:
            Set of matching Endpoint objects
        """
        matches = set()
        
        # Skip common keywords that aren't IPs
        if ip_spec.lower() in ['any', 'host', '']:
            return matches
        
        # Check if it's a direct IP match (host x.x.x.x)
        if ip_spec in endpoint_by_ip:
            matches.add(endpoint_by_ip[ip_spec])
            return matches
        
        # Check if it's an endpoint name reference
        if ip_spec in endpoint_by_name:
            matches.add(endpoint_by_name[ip_spec])
            return matches
        
        # Check for network matches with wildcard mask
        if wildcard and wildcard != '0.0.0.0':
            # Convert wildcard to subnet mask for matching
            # Wildcard 0.0.0.255 = mask 255.255.255.0
            try:
                wildcard_octets = [int(x) for x in wildcard.split('.')]
                mask_octets = [255 - x for x in wildcard_octets]
                subnet_mask = '.'.join(str(x) for x in mask_octets)
                
                # Calculate network address
                network_addr = calculate_network_address(ip_spec, subnet_mask)
                
                if network_addr:
                    # Check each endpoint IP against this network
                    for endpoint_ip, endpoint in endpoint_by_ip.items():
                        if self.ip_in_subnet(endpoint_ip, network_addr, subnet_mask):
                            matches.add(endpoint)
            except (ValueError, AttributeError):
                # Invalid wildcard/IP, skip
                pass
        
        return matches
    
    def extract_administration_config(
        self,
        device_config: DeviceConfiguration
    ) -> AdministrationConfig:
        """
        Extract administrative configuration details.
        
        Args:
            device_config: Parsed device configuration
            
        Returns:
            AdministrationConfig object
        """
        self.log(f"Extracting administration config for {device_config.device_name}")
        
        admin = AdministrationConfig(device_config.device_name)
        
        # Management IPs from interfaces with management keywords
        for interface in device_config.interfaces:
            if interface.ip_address and interface.description:
                desc_lower = interface.description.lower()
                if any(keyword in desc_lower for keyword in ['manage', 'admin', 'mgmt', 'management']):
                    admin.management_ips.append(
                        f"{interface.ip_address}/{subnet_mask_to_cidr(interface.ip_mask) or '32'}"
                    )
        
        # SNMP communities
        if device_config.snmp_community:
            admin.snmp_communities.append(device_config.snmp_community)
        
        # System configuration
        if device_config.domain_name:
            admin.domain_name = device_config.domain_name
        
        if device_config.ntp_servers:
            admin.ntp_servers = device_config.ntp_servers.copy()
        
        if device_config.name_servers:
            admin.dns_servers = device_config.name_servers.copy()
        
        if device_config.logging_servers:
            admin.logging_servers = device_config.logging_servers.copy()
        
        # Extract data from aaa_config dictionary (populated by parsers)
        if device_config.aaa_config:
            # Enable secret/password
            if 'enable_secret' in device_config.aaa_config:
                admin.enable_secret = device_config.aaa_config['enable_secret']
            elif 'enable_password' in device_config.aaa_config:
                admin.enable_secret = device_config.aaa_config['enable_password']
            else:
                admin.enable_secret = 'Not configured'
            
            # Users - handle dict format from parsers
            if 'users' in device_config.aaa_config:
                users_data = device_config.aaa_config['users']
                if isinstance(users_data, dict):
                    # Format: {'username': {'privilege': '15', 'hash': '...'}}
                    for username, user_info in users_data.items():
                        admin.admin_users.append(username)
                        if isinstance(user_info, dict):
                            if 'privilege' in user_info:
                                admin.privilege_levels[username] = user_info['privilege']
                            if 'hash' in user_info:
                                admin.credential_hashes[username] = user_info['hash']
                elif isinstance(users_data, list):
                    # Old format compatibility
                    for user_entry in users_data:
                        if isinstance(user_entry, dict):
                            username = user_entry.get('username', '')
                            privilege = user_entry.get('privilege', '')
                            password_hash = user_entry.get('password_hash', '')
                            
                            if username:
                                admin.admin_users.append(username)
                            if username and privilege:
                                admin.privilege_levels[username] = privilege
                            if username and password_hash:
                                admin.credential_hashes[username] = password_hash
                        elif isinstance(user_entry, str):
                            admin.admin_users.append(user_entry)
            
            # User Privileges - from summary field
            if 'user_privileges' in device_config.aaa_config:
                # This is already a formatted string
                admin.user_privileges_str = device_config.aaa_config['user_privileges']
            
            # Credential Hashes - from summary field
            if 'credential_hashes' in device_config.aaa_config:
                # This is already a formatted string
                admin.credential_hashes_str = device_config.aaa_config['credential_hashes']
            
            # VTY lines - handle both old and new formats
            if 'vty_lines' in device_config.aaa_config:
                vty_data = device_config.aaa_config['vty_lines']
                if isinstance(vty_data, str):
                    # New format: pre-formatted string
                    admin.vty_lines.append(vty_data)
                elif isinstance(vty_data, list):
                    admin.vty_lines.extend(vty_data)
                elif isinstance(vty_data, dict):
                    for line_range, config in vty_data.items():
                        if isinstance(config, dict):
                            # New format with nested dict
                            cfg_list = config.get('config', [])
                            methods = config.get('access_methods', [])
                            acl = config.get('access_class')
                            parts = [line_range]
                            if methods:
                                parts.append(f"({', '.join(methods)})")
                            if acl:
                                parts.append(f"ACL: {acl}")
                            admin.vty_lines.append(' '.join(parts))
                        else:
                            admin.vty_lines.append(f"{line_range}: {config}")
            
            # Access methods - from summary field
            if 'access_methods' in device_config.aaa_config:
                methods_str = device_config.aaa_config['access_methods']
                if isinstance(methods_str, str) and methods_str != 'Not configured':
                    admin.access_methods = [m.strip() for m in methods_str.split(',')]
            
            # Also check lines dict for additional access methods
            if 'lines' in device_config.aaa_config:
                lines_data = device_config.aaa_config['lines']
                if isinstance(lines_data, dict):
                    for line_name, line_config in lines_data.items():
                        if isinstance(line_config, dict):
                            methods = line_config.get('access_methods', [])
                            admin.access_methods.extend(methods)
                        elif isinstance(line_config, list):
                            # Old format - search in config strings
                            for cfg_line in line_config:
                                if 'transport input ssh' in cfg_line.lower():
                                    admin.access_methods.append('SSH')
                                elif 'transport input telnet' in cfg_line.lower():
                                    admin.access_methods.append('Telnet')
            
            # Management ACLs - from summary field
            if 'management_acls' in device_config.aaa_config:
                acls_str = device_config.aaa_config['management_acls']
                if isinstance(acls_str, str) and acls_str != 'Not configured':
                    admin.management_acls = [acl.strip() for acl in acls_str.split(',')]
                elif isinstance(acls_str, list):
                    admin.management_acls.extend(acls_str)
        
        # Deduplicate access methods
        admin.access_methods = list(set(admin.access_methods))
        
        return admin
    
    def generate_output(
        self,
        device_configs: List[DeviceConfiguration],
        output_path: str,
        output_format: str = 'html',
        parse_section: Optional[str] = None
    ) -> None:
        """
        Generate output file in specified format.
        
        Args:
            device_configs: List of parsed device configurations
            output_path: Path for output file
            output_format: Output format (html, xml, csv)
            parse_section: Optional specific section to parse
        """
        self.log(f"Generating {output_format.upper()} output: {output_path}")
        
        # Build all analysis data
        all_network_flows = []
        all_flow_mappings = []  # Track flows per device for neighbor correlation
        all_admin_configs = []
        all_interfaces = []
        all_vlans = []
        all_endpoints = []
        all_hardware = []
        all_span_sessions = []  # Data monitoring
        all_netflow_configs = []  # Data monitoring
        
        for device_config in device_configs:
            # Network flow mappings
            flows = self.build_network_flow_mappings(device_config)
            all_network_flows.extend(flows)
            all_flow_mappings.append(flows)  # Keep per-device tracking
            
            # Administration config
            admin = self.extract_administration_config(device_config)
            all_admin_configs.append(admin)
            
            # Interfaces
            all_interfaces.extend(device_config.interfaces)
            
            # VLANs
            all_vlans.extend(device_config.vlans)
            
            # Endpoints
            all_endpoints.extend(device_config.endpoints)
            
            # Hardware info
            all_hardware.append(device_config)
            
            # Data monitoring
            all_span_sessions.extend(device_config.span_sessions)
            all_netflow_configs.extend(device_config.netflow_configs)
        
        # Correlate neighbor devices across all configs (after all flows are built)
        if len(device_configs) > 1:
            self.correlate_neighbor_devices(device_configs, all_flow_mappings)
        
        # Correlate endpoints across all devices (fixes cross-device endpoint discovery)
        self.correlate_endpoints_cross_device(device_configs, all_flow_mappings)
        
        # Deduplicate endpoints while preserving legitimate multi-device networks
        self.deduplicate_endpoints(device_configs)
        
        # Rebuild endpoint list after deduplication
        all_endpoints = []
        for device_config in device_configs:
            all_endpoints.extend(device_config.endpoints)
        
        # Generate output based on format
        if output_format == 'html':
            from output_generators.html_generator import HTMLWorkbookGenerator
            generator = HTMLWorkbookGenerator(verbose=self.verbose)
            generator.generate(
                network_flows=all_network_flows,
                admin_configs=all_admin_configs,
                interfaces=all_interfaces,
                vlans=all_vlans,
                endpoints=all_endpoints,
                hardware_configs=all_hardware,
                span_sessions=all_span_sessions,  # Data monitoring
                netflow_configs=all_netflow_configs,  # Data monitoring
                globalprotect_portals=self.globalprotect_portals,  # Global Protect
                globalprotect_gateways=self.globalprotect_gateways,  # Global Protect
                globalprotect_client_configs=self.globalprotect_client_configs,  # Global Protect
                output_path=output_path,
                parse_section=parse_section
            )
            
        # Generate companion flow mapping JSON for enhanced visualization
        if output_format == 'html' and all_network_flows:
            try:
                from output_generators.flow_mapping_generator import FlowMappingGenerator
                
                json_generator = FlowMappingGenerator(verbose=self.verbose)
                json_output = output_path.replace('.html', '_flow_mapping.json')
                
                # Call generate_json() - config_files is optional, pass empty list
                json_generator.generate_json(
                    output_path=json_output,
                    network_flows=all_network_flows,
                    endpoints=all_endpoints,
                    config_files=[]
                )
                
                self.log(f"Generated companion flow mapping JSON: {json_output}")
                
            except Exception as e:
                self.log(f"Warning: Failed to generate flow mapping file: {e}")
        
        #Generate XML output file
        elif output_format == 'xml':
            from output_generators.xml_generator import XMLGenerator
            generator = XMLGenerator(verbose=self.verbose)
            generator.generate(
                network_flows=all_network_flows,
                admin_configs=all_admin_configs,
                interfaces=all_interfaces,
                vlans=all_vlans,
                endpoints=all_endpoints,
                hardware_configs=all_hardware,
                span_sessions=all_span_sessions,  # Data monitoring
                netflow_configs=all_netflow_configs,  # Data monitoring
                globalprotect_portals=self.globalprotect_portals,  # Global Protect
                globalprotect_gateways=self.globalprotect_gateways,  # Global Protect
                globalprotect_client_configs=self.globalprotect_client_configs,  # Global Protect
                output_path=output_path,
                parse_section=parse_section
            )
        
        #Generate CSV output file
        elif output_format == 'csv':
            from output_generators.csv_workbook_generator import CSVWorkbookGenerator
            generator = CSVWorkbookGenerator(verbose=self.verbose)
            generator.generate(
                network_flows=all_network_flows,
                admin_configs=all_admin_configs,
                interfaces=all_interfaces,
                vlans=all_vlans,
                endpoints=all_endpoints,
                hardware_configs=all_hardware,
                span_sessions=all_span_sessions,  # Data monitoring
                netflow_configs=all_netflow_configs,  # Data monitoring
                globalprotect_portals=self.globalprotect_portals,  # Global Protect
                globalprotect_gateways=self.globalprotect_gateways,  # Global Protect
                globalprotect_client_configs=self.globalprotect_client_configs,  # Global Protect
                output_path=output_path,
                parse_section=parse_section
            )
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        self.log(f"Output generated successfully")
        
        # Generate separate flow mapping JSON for visualizer (if requested or always for HTML output)
        # This provides optimized, lightweight data for topology visualization
        flow_mapping_path = output_path.replace('.html', '_flow_mapping.json').replace('.xml', '_flow_mapping.json').replace('.csv', '_flow_mapping.json')
        
        if output_format == 'html' or hasattr(self, 'generate_flow_mapping'):
            try:
                from output_generators.flow_mapping_generator import FlowMappingGenerator
                flow_gen = FlowMappingGenerator(verbose=self.verbose)
                flow_gen.generate_json(
                    output_path=flow_mapping_path,
                    network_flows=all_network_flows,
                    endpoints=all_endpoints,
                    config_files=[]
                )
                self.log(f"Generated separate flow mapping file: {flow_mapping_path}")
            except Exception as e:
                self.log(f"Warning: Failed to generate flow mapping file: {e}")

    def generate_globalprotect_report(
        self,
        device_configs: List[DeviceConfiguration],
        output_path: str
    ) -> None:
        """
        Generate GlobalProtect VPN configuration report.
        
        This method generates a comprehensive HTML report containing only
        GlobalProtect VPN data (portals, gateways, HIP objects, etc.)
        when --parse-globalprotect flag is used.
        
        Args:
            device_configs: List of parsed device configurations (used for context)
            output_path: Path for output HTML file
        """
        self.log(f"Generating GlobalProtect VPN report: {output_path}")
        
        # Check if we have any GlobalProtect data
        if not self.globalprotect_data_list:
            self.log("WARNING: No GlobalProtect data found in parsed configurations", 'WARNING')
            print("\nWARNING: No GlobalProtect VPN configurations found!")
            print("Make sure you're analyzing Palo Alto XML configuration files.")
            print("GlobalProtect data can only be parsed from XML format (not set commands).\n")
            return
        
        # Import GlobalProtect report generator
        from output_generators.globalprotect_report_generator import GlobalProtectReportGenerator
        
        # Generate report
        generator = GlobalProtectReportGenerator(verbose=self.verbose)
        generator.generate(
            gp_data_list=self.globalprotect_data_list,
            output_path=output_path
        )
        
        self.log(f"GlobalProtect report generated successfully")
        
        # Print summary (works for both dict and object)
        total_portals = 0
        total_gateways = 0
        total_hip_objects = 0
        total_hip_profiles = 0
        for gp in self.globalprotect_data_list:
            if isinstance(gp, dict):
                total_portals += len(gp.get('portals', []))
                total_gateways += len(gp.get('gateways', []))
                total_hip_objects += len(gp.get('hip_objects', []))
                total_hip_profiles += len(gp.get('hip_profiles', []))
            else:
                total_portals += getattr(gp, 'total_portals', 0)
                total_gateways += getattr(gp, 'total_gateways', 0)
                total_hip_objects += getattr(gp, 'total_hip_objects', 0)
                total_hip_profiles += getattr(gp, 'total_hip_profiles', 0)
        
        print(f"\nGlobalProtect VPN Summary:")
        print(f"  Devices: {len(self.globalprotect_data_list)}")
        print(f"  Portals: {total_portals}")
        print(f"  Gateways: {total_gateways}")
        print(f"  HIP Objects: {total_hip_objects}")
        print(f"  HIP Profiles: {total_hip_profiles}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure command-line argument parser."""
    parser = argparse.ArgumentParser(
        description='Multi-Vendor Network Configuration Analyzer v2.2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze single configuration (auto-detect vendor):
    python3 analyzer.py --config router.cfg --output analysis.html
  
  Analyze with specific vendor:
    python3 analyzer.py --config juniper.cfg --vendor juniper --output analysis.html
  
  Palo Alto with Global Protect VPN:
    python3 analyzer.py --config paloalto.cfg --vendor paloalto --parse-globalprotect --output analysis.html
  
  Analyze mixed-vendor directory:
    python3 analyzer.py --config-dir ./configs --output network.html
  
  Parse only interfaces:
    python3 analyzer.py --config switch.cfg --parse interfaces --output interfaces.csv
  
  Specify device type (legacy):
    python3 analyzer.py --config device.cfg --device-type nxos --output result.html --verbose
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--config',
        type=str,
        help='Path to single configuration file'
    )
    input_group.add_argument(
        '--config-dir',
        type=str,
        help='Path to directory containing configuration files'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path (for single config mode)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        help='Output directory (for multi-config mode)'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['html', 'xml', 'csv'],
        default='html',
        help='Output format (default: html)'
    )
    
    # Parsing options
    parser.add_argument(
        '--parse',
        type=str,
        choices=['interfaces', 'vlans', 'acls', 'routes', 'admin', 'hardware', 'flows'],
        help='Parse only specific section'
    )
    parser.add_argument(
        '--vendor',
        type=str,
        choices=['cisco', 'juniper', 'paloalto', 'fortigate', 'eltex', 'auto'],
        default='auto',
        help='Specify vendor (default: auto-detect)'
    )
    parser.add_argument(
        '--device-type',
        type=str,
        choices=['ios', 'iosxe', 'nxos', 'asa', 'ngfw', 'junos', 'panos', 'fortios', 'eltex'],
        help='Force specific device type (overrides vendor auto-detection)'
    )
    parser.add_argument(
        '--parse-globalprotect',
        action='store_true',
        help='Enable Global Protect VPN parsing (Palo Alto only)'
    )
    
    # Other options
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Multi-Vendor Network Configuration Analyzer v2.2.0'
    )
    
    return parser


def main() -> int:
    """Main entry point for the analyzer."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # VALIDATION: --parse-globalprotect only works with --vendor paloalto
    if args.parse_globalprotect and args.vendor != 'paloalto':
        print("\n" + "="*70)
        print("ERROR: Invalid Command-Line Options")
        print("="*70)
        print("The --parse-globalprotect option requires --vendor paloalto")
        print("\nUsage:")
        print("  python3 analyzer.py --config paloalto.cfg --vendor paloalto --parse-globalprotect")
        print("\nOr with directory:")
        print("  python3 analyzer.py --config-dir ./configs --vendor paloalto --parse-globalprotect")
        return 1
    
    # Create analyzer with Global Protect flag
    analyzer = ConfigurationAnalyzer(
        verbose=args.verbose,
        parse_globalprotect=args.parse_globalprotect
    )
    
    # Convert vendor flag to device_type if specified
    device_type_override = args.device_type
    if not device_type_override and args.vendor != 'auto':
        # Map vendor to device type
        vendor_map = {
            'cisco': None,  # Cisco will auto-detect IOS/NX-OS/ASA/etc.
            'juniper': DEVICE_TYPE_JUNOS,
            'paloalto': DEVICE_TYPE_PANOS,
            'fortigate': DEVICE_TYPE_FORTIOS,
            'eltex': DEVICE_TYPE_ELTEX
        }
        device_type_override = vendor_map.get(args.vendor)
    
    try:
        # Parse configurations
        if args.config:
            # Single file mode
            device_config = analyzer.analyze_file(args.config, device_type_override)
            device_configs = [device_config]
            
            # Determine output path
            if not args.output:
                if args.parse_globalprotect:
                    # Special GlobalProtect report name
                    args.output = 'globalprotect_vpn_configuration_data.html'
                else:
                    base_name = os.path.splitext(os.path.basename(args.config))[0]
                    ext = '.html' if args.format == 'html' else f'.{args.format}'
                    args.output = f"{base_name}_analysis{ext}"
        
        else:
            # Directory mode
            device_configs = analyzer.analyze_directory(args.config_dir, device_type_override)
            
            if not device_configs:
                print("No valid configuration files found")
                return 1
            
            # Set output directory
            if not args.output_dir:
                args.output_dir = os.path.join(args.config_dir, 'analysis_results')
            
            os.makedirs(args.output_dir, exist_ok=True)
            
            # Generate combined output - use user-provided filename or default
            if args.output:
                # User provided output filename - use it in output_dir
                args.output = os.path.join(args.output_dir, os.path.basename(args.output))
            else:
                # No filename provided - use default
                if args.parse_globalprotect:
                    # Special GlobalProtect report name
                    args.output = os.path.join(args.output_dir, 'globalprotect_vpn_configuration_data.html')
                else:
                    ext = '.html' if args.format == 'html' else f'.{args.format}'
                    args.output = os.path.join(args.output_dir, f'combined_analysis{ext}')
        
        # SPECIAL HANDLING: GlobalProtect-only report generation
        if args.parse_globalprotect:
            analyzer.generate_globalprotect_report(device_configs, args.output)
        else:
            # Normal output generation
            analyzer.generate_output(
                device_configs,
                args.output,
                args.format,
                args.parse
            )
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETED SUCCESSFULLY")
        print("="*70)
        print(f"Output file: {args.output}")
        if args.parse_globalprotect:
            print("Report Type: GlobalProtect VPN Configuration")
        else:
            print(f"Format: {args.format.upper()}")
            if args.parse:
                print(f"Section: {args.parse}")
        print(f"Devices analyzed: {len(device_configs)}")
        
        return 0
    
    except Exception as error:
        print("\n" + "="*70)
        print("ERROR: Analysis failed")
        print("="*70)
        print(f"Error: {error}")
        
        if args.verbose:
            import traceback
            traceback.print_exc()
        
        return 1


if __name__ == '__main__':
    sys.exit(main())