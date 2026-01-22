#!/usr/bin/env python3
"""
Synopsis:
    Abstract Base Parser for Multi-Vendor Network Configuration Analysis

Description:
    Provides the abstract base class that all vendor-specific parsers inherit from.
    Defines common interface and shared parsing utilities that work across all
    network device vendors (Cisco, Juniper, Palo Alto, Fortigate, Eltex, etc.).
    
    This base parser enforces a consistent interface while allowing vendor-specific
    implementations to handle their unique configuration syntax and features.

Key Features:
    - Abstract methods that must be implemented by vendor parsers
    - Common utility methods for all parsers (logging, line processing, etc.)
    - Consistent data structure interface
    - Device type identification helpers
    - Common parsing patterns (IP addresses, interfaces, VLANs, etc.)

Architecture:
    BaseParser (this class)
    â”œâ”€â”€ CiscoBaseParser â†’ IOSParser, NXOSParser, ASAParser, etc.
    â”œâ”€â”€ JuniperParser â†’ JunOS-specific parsing
    â”œâ”€â”€ FortigateParser â†’ FortiOS-specific parsing
    â”œâ”€â”€ PaloAltoParser â†’ PAN-OS + Global Protect parsing
    â””â”€â”€ EltexParser â†’ Eltex-specific parsing

Notes:
    - All vendor parsers MUST inherit from this class
    - Subclasses MUST implement all abstract methods
    - Common data structures defined in shared_components/data_structures.py
    - Parser selection happens in analyzer.py based on device detection

Version: 2.2.0
Author: Network Configuration Analyzer Team
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import re
import ipaddress

# Import common data structures
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_components.data_structures import DeviceConfiguration


class BaseParser(ABC):
    """
    Abstract base class for all network device configuration parsers.
    
    This class defines the interface that all vendor-specific parsers must implement,
    and provides common utility methods used across all parsers.
    
    Attributes:
        config_lines (List[str]): Raw configuration file lines
        device_config (DeviceConfiguration): Parsed device configuration object
        verbose (bool): Enable verbose logging
        vendor (str): Vendor name (cisco, juniper, paloalto, fortigate, eltex)
        platform (str): Platform name (ios, nxos, junos, fortios, panos, eltex-mes)
    """
    
    def __init__(self, config_lines: List[str], verbose: bool = False):
        """
        Initialize base parser.
        
        Args:
            config_lines: List of configuration file lines
            verbose: Enable verbose logging
        """
        self.config_lines = config_lines
        self.verbose = verbose
        self.vendor = "unknown"
        self.platform = "unknown"
        
        # Initialize device configuration object
        self.device_config = DeviceConfiguration()
        self.device_config.vendor = self.vendor
        self.device_config.platform = self.platform
    
    # ========================================================================
    # ABSTRACT METHODS - Must be implemented by all vendor parsers
    # ========================================================================
    
    @abstractmethod
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Main parsing method - MUST be implemented by subclass.
        
        This method orchestrates the entire parsing process for the specific
        vendor's configuration format.
        
        Args:
            config_lines: List of configuration lines to parse
            
        Returns:
            DeviceConfiguration object with all parsed data
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclass must implement parse() method")
    
    @abstractmethod
    def detect_device_type(self) -> str:
        """
        Detect the device type from configuration content.
        
        Returns:
            Device type string (e.g., 'ios', 'junos', 'panos', 'fortios')
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclass must implement detect_device_type() method")
    
    @abstractmethod
    def parse_hostname(self) -> Optional[str]:
        """
        Parse device hostname - MUST be implemented by subclass.
        
        Returns:
            Hostname string or None if not found
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclass must implement parse_hostname() method")
    
    @abstractmethod
    def parse_interfaces(self) -> None:
        """
        Parse interface configurations - MUST be implemented by subclass.
        
        Populates device_config.interfaces list with NetworkInterface objects.
        
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclass must implement parse_interfaces() method")
    
    @abstractmethod
    def parse_routing(self) -> None:
        """
        Parse routing configurations - MUST be implemented by subclass.
        
        Populates device_config with routing information (static routes, 
        routing protocols, default gateway, etc.).
        
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclass must implement parse_routing() method")
    
    # ========================================================================
    # OPTIONAL METHODS - Can be overridden by vendor parsers if needed
    # ========================================================================
    
    def parse_vlans(self) -> None:
        """
        Parse VLAN configurations (optional - override if vendor supports VLANs).
        
        Default implementation does nothing. Override in subclass if the vendor
        platform supports VLANs.
        """
        self.log("VLAN parsing not implemented for this vendor")
    
    def parse_acls(self) -> None:
        """
        Parse ACL configurations (optional - override if vendor supports ACLs).
        
        Default implementation does nothing. Override in subclass if the vendor
        platform supports ACLs.
        """
        self.log("ACL parsing not implemented for this vendor")
    
    def parse_nat(self) -> None:
        """
        Parse NAT configurations (optional - override if vendor supports NAT).
        
        Default implementation does nothing. Override in subclass if the vendor
        platform supports NAT.
        """
        self.log("NAT parsing not implemented for this vendor")
    
    def parse_vpn(self) -> None:
        """
        Parse VPN configurations (optional - override if vendor supports VPN).
        
        Default implementation does nothing. Override in subclass if the vendor
        platform supports VPN (IPsec, SSL VPN, Global Protect, etc.).
        """
        self.log("VPN parsing not implemented for this vendor")
    
    def parse_monitoring_config(self) -> None:
        """
        Parse monitoring configurations (optional - SPAN, NetFlow, sFlow, etc.).
        
        Default implementation does nothing. Override in subclass if the vendor
        platform supports traffic monitoring features.
        """
        self.log("Monitoring parsing not implemented for this vendor")
    
    # ========================================================================
    # COMMON UTILITY METHODS - Available to all parsers
    # ========================================================================
    
    def log(self, message: str) -> None:
        """
        Log message if verbose mode enabled.
        
        Args:
            message: Message to log
        """
        if self.verbose:
            vendor_platform = f"{self.vendor.title()} {self.platform.upper()}" if self.vendor != "unknown" else "Parser"
            print(f"[{vendor_platform}] {message}")
    
    def normalize_interface_name(self, interface_name: str) -> str:
        """
        Normalize interface name to consistent format.
        
        Examples:
            "Gi0/0" â†’ "GigabitEthernet0/0"
            "Fa0/1" â†’ "FastEthernet0/1"
            "eth0" â†’ "Ethernet0"
            "ge-0/0/0" â†’ "GigabitEthernet0/0/0" (Juniper)
            
        Args:
            interface_name: Raw interface name from config
            
        Returns:
            Normalized interface name
        """
        # Common abbreviation mappings (add more as needed)
        abbreviations = {
            'Gi': 'GigabitEthernet',
            'Fa': 'FastEthernet',
            'Te': 'TenGigabitEthernet',
            'Eth': 'Ethernet',
            'Lo': 'Loopback',
            'Po': 'Port-channel',
            'Vl': 'Vlan',
            'Tu': 'Tunnel',
            'Se': 'Serial',
            'Ma': 'Management'
        }
        
        # Try to expand abbreviations
        for abbr, full in abbreviations.items():
            if interface_name.startswith(abbr):
                return interface_name.replace(abbr, full, 1)
        
        return interface_name
    
    def is_valid_ipv4(self, ip_string: str) -> bool:
        """
        Check if string is a valid IPv4 address.
        
        Args:
            ip_string: String to validate
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_string)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def is_valid_ipv6(self, ip_string: str) -> bool:
        """
        Check if string is a valid IPv6 address.
        
        Args:
            ip_string: String to validate
            
        Returns:
            True if valid IPv6 address, False otherwise
        """
        try:
            ipaddress.IPv6Address(ip_string)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def subnet_mask_to_cidr(self, subnet_mask: str) -> int:
        """
        Convert subnet mask to CIDR prefix length.
        
        Args:
            subnet_mask: Subnet mask (e.g., "255.255.255.0")
            
        Returns:
            CIDR prefix length (e.g., 24)
            
        Example:
            "255.255.255.0" â†’ 24
            "255.255.0.0" â†’ 16
        """
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False).prefixlen
        except (ipaddress.AddressValueError, ValueError):
            return 0
    
    def wildcard_to_netmask(self, wildcard: str) -> str:
        """
        Convert wildcard mask to subnet mask.
        
        Args:
            wildcard: Wildcard mask (e.g., "0.0.0.255")
            
        Returns:
            Subnet mask (e.g., "255.255.255.0")
            
        Example:
            "0.0.0.255" â†’ "255.255.255.0"
            "0.0.255.255" â†’ "255.255.0.0"
        """
        try:
            parts = wildcard.split('.')
            mask_parts = [str(255 - int(part)) for part in parts]
            return '.'.join(mask_parts)
        except (ValueError, AttributeError):
            return "255.255.255.255"
    
    def calculate_network_address(self, ip: str, netmask: str) -> str:
        """
        Calculate network address from IP and netmask.
        
        Args:
            ip: IP address (e.g., "192.168.1.100")
            netmask: Subnet mask (e.g., "255.255.255.0")
            
        Returns:
            Network address (e.g., "192.168.1.0")
        """
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network.network_address)
        except (ipaddress.AddressValueError, ValueError):
            return ip
    
    def extract_ip_addresses(self, text: str) -> List[str]:
        """
        Extract all IPv4 addresses from text using regex.
        
        Args:
            text: Text to search for IP addresses
            
        Returns:
            List of IPv4 addresses found
        """
        # IPv4 pattern
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        matches = re.findall(ipv4_pattern, text)
        
        # Validate each match
        valid_ips = []
        for match in matches:
            if self.is_valid_ipv4(match):
                valid_ips.append(match)
        
        return valid_ips
    
    def clean_config_line(self, line: str) -> str:
        """
        Clean configuration line (remove extra whitespace, comments, etc.).
        
        Args:
            line: Raw configuration line
            
        Returns:
            Cleaned configuration line
        """
        # Remove trailing whitespace
        line = line.rstrip()
        
        # Remove inline comments (vendor-specific, override if needed)
        # Default: remove anything after '#' or '!'
        if '#' in line:
            line = line.split('#')[0].rstrip()
        if '!' in line and not line.strip().startswith('!'):
            # Don't remove '!' if it's at the start (Cisco section marker)
            pass
        
        return line
    
    def get_indentation_level(self, line: str) -> int:
        """
        Get indentation level of configuration line.
        
        Args:
            line: Configuration line
            
        Returns:
            Number of leading spaces
        """
        return len(line) - len(line.lstrip())
    
    def strip_quotes(self, text: str) -> str:
        """
        Remove surrounding quotes from text.
        
        Args:
            text: Text that may be quoted
            
        Returns:
            Text with quotes removed
        """
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1]
        if text.startswith("'") and text.endswith("'"):
            return text[1:-1]
        return text
    
    # ========================================================================
    # VENDOR DETECTION HELPERS
    # ========================================================================
    
    @staticmethod
    def detect_vendor_from_config(config_lines: List[str]) -> str:
        """
        Detect vendor from configuration content.
        
        Analyzes config syntax patterns to identify vendor:
        - Cisco: "interface GigabitEthernet", "router bgp", version line
        - Juniper: "set" commands or curly brace hierarchy
        - Palo Alto: XML format or "set deviceconfig"
        - Fortigate: "config" blocks, "set" commands
        - Eltex: Similar to Cisco but with Eltex-specific keywords
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            Vendor string: 'cisco', 'juniper', 'paloalto', 'fortigate', 'eltex', 'unknown'
        """
        config_text = '\n'.join(config_lines[:100])  # Check first 100 lines
        
        # Juniper detection (highest priority - very distinct syntax)
        # Check for Juniper-specific "set" command patterns
        # Works for both curly-brace format and display-set format
        juniper_set_patterns = [
            r'^set\s+system\s+host-name',
            r'^set\s+system\s+root-authentication',
            r'^set\s+interfaces\s+\S+\s+unit',
            r'^set\s+protocols\s+(bgp|ospf|isis)',
            r'^set\s+routing-options',
            r'^set\s+security\s+(policies|zones)',
            r'^set\s+firewall\s+family',
            r'junos',
            r'juniper'
        ]
        for pattern in juniper_set_patterns:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return 'juniper'
        
        # Juniper curly-brace format detection
        # Look for distinctive Juniper hierarchical keywords
        juniper_curly_patterns = [
            r'^\s*system\s*\{',
            r'^\s*routing-options\s*\{',
            r'^\s*protocols\s*\{',
            r'^\s*security\s*\{',
            r'^\s*chassis\s*\{',
            r'^\s*firewall\s*\{',
            r'host-name\s+\S+;',
            r'vlan-id\s+\d+;'
        ]
        # Count matches to avoid false positives
        juniper_curly_matches = 0
        for pattern in juniper_curly_patterns:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                juniper_curly_matches += 1
                if juniper_curly_matches >= 2:  # Need at least 2 matches
                    return 'juniper'
        
        # Palo Alto detection
        if re.search(r'set\s+deviceconfig|set\s+network|set\s+vsys', config_text, re.IGNORECASE):
            return 'paloalto'
        if '<config' in config_text or '<entry name=' in config_text:
            return 'paloalto'
        
        # Fortigate detection
        # FortiOS configs start with "config system" and use "edit/next/end" structure
        if re.search(r'^config\s+system\s+(global|interface|admin)', config_text, re.MULTILINE | re.IGNORECASE):
            # Fortigate-specific: uses "edit" and "next" keywords in config blocks
            if re.search(r'^\s*(edit|next)\s', config_text, re.MULTILINE | re.IGNORECASE):
                return 'fortigate'
        # Legacy check for explicit FortiGate/FortiOS mentions
        if 'FortiGate' in config_text or 'FortiOS' in config_text:
            return 'fortigate'
        
        # Eltex detection
        if 'Eltex' in config_text or 'MES' in config_text:
            return 'eltex'
        
        # Cisco detection (most common, check last)
        cisco_patterns = [
            r'version\s+\d+\.\d+',
            r'interface\s+(GigabitEthernet|FastEthernet|Ethernet|Vlan)',
            r'router\s+(bgp|ospf|eigrp|rip)',
            r'ip\s+(route|address|nat)',
            r'Cisco\s+(IOS|NX-OS|ASA)',
            r'hostname\s+\S+',
            r'!\s*$'  # Cisco section markers
        ]
        
        for pattern in cisco_patterns:
            if re.search(pattern, config_text, re.IGNORECASE):
                return 'cisco'
        
        return 'unknown'
    
    @staticmethod
    def detect_platform_from_config(config_lines: List[str], vendor: str) -> str:
        """
        Detect specific platform within a vendor.
        
        Args:
            config_lines: List of configuration lines
            vendor: Vendor name (cisco, juniper, etc.)
            
        Returns:
            Platform string (ios, nxos, junos, panos, fortios, etc.)
        """
        config_text = '\n'.join(config_lines[:100])
        
        if vendor == 'cisco':
            if 'NX-OS' in config_text or 'Nexus' in config_text:
                return 'nxos'
            elif 'IOS-XE' in config_text:
                return 'iosxe'
            elif 'ASA' in config_text or 'Adaptive Security Appliance' in config_text:
                return 'asa'
            elif 'Firepower' in config_text or 'FTD' in config_text:
                return 'ftd'
            else:
                return 'ios'  # Default Cisco platform
        
        elif vendor == 'juniper':
            return 'junos'
        
        elif vendor == 'paloalto':
            return 'panos'
        
        elif vendor == 'fortigate':
            return 'fortios'
        
        elif vendor == 'eltex':
            if 'ESR' in config_text:
                return 'eltex-esr'
            else:
                return 'eltex-mes'
        
        return 'unknown'


# End of base_parser.py
    # ========================================================================
    # ENHANCED v3.0 HELPER METHODS
    # ========================================================================
    
    def create_port_channel_membership(self, port_channel_name: str, mode: str = '', protocol: str = '', status: str = 'bundled'):
        """Create a PortChannelMembership object."""
        from shared_components.data_structures import PortChannelMembership
        return PortChannelMembership(port_channel_name, mode, protocol, status)
    
    def register_port_channel_member(self, port_channel_name: str, member_interface_name: str) -> None:
        """Register an interface as a member of a port-channel."""
        if not hasattr(self, 'port_channel_map'):
            self.port_channel_map = {}
        if port_channel_name not in self.port_channel_map:
            self.port_channel_map[port_channel_name] = []
        if member_interface_name not in self.port_channel_map[port_channel_name]:
            self.port_channel_map[port_channel_name].append(member_interface_name)
    
    def apply_port_channel_associations(self) -> None:
        """Apply port-channel associations to interfaces."""
        if not hasattr(self, 'port_channel_map'):
            return
        for interface in self.device_config.interfaces:
            if interface.is_port_channel:
                pc_name = interface.name
                members = self.port_channel_map.get(pc_name, [])
                interface.member_interfaces = members.copy()
    
    def create_admin_account(self, account_type: str, username: str, privilege_level: str = '', credential: str = '', credential_type: str = '', hash_algorithm: str = '', access_methods: List[str] = None, vty_lines: str = '', acl_name: str = '', source_ips: List[str] = None, enabled: bool = True, description: str = ''):
        """Create an AdministrativeAccount object."""
        from shared_components.data_structures import AdministrativeAccount
        account = AdministrativeAccount()
        account.device_name = self.device_config.device_name
        account.account_type = account_type
        account.username = username
        account.privilege_level = privilege_level
        account.credential = credential
        account.credential_type = credential_type
        account.hash_algorithm = hash_algorithm
        account.access_methods = access_methods or []
        account.vty_lines = vty_lines
        account.acl_name = acl_name
        account.source_ips = source_ips or []
        account.enabled = enabled
        account.description = description
        return account
    
    def parse_hash_algorithm(self, password_hash: str) -> tuple:
        """Detect hash algorithm from password hash."""
        if not password_hash:
            return ('none', 'none')
        hash_str = password_hash.strip()
        if hash_str.startswith('$1$'): return ('md5', 'hash')
        elif hash_str.startswith('$8$'): return ('pbkdf2', 'hash')
        elif hash_str.startswith('$9$'): return ('scrypt', 'hash')
        elif hash_str.startswith('$5$'): return ('sha256', 'hash')
        elif hash_str.startswith('$6$'): return ('sha512', 'hash')
        elif re.match(r'^[0-9A-F]{4,}$', hash_str, re.IGNORECASE): return ('type7', 'hash')
        elif hash_str.startswith('$') and len(hash_str) > 20: return ('encrypted', 'hash')
        else: return ('plaintext', 'plaintext')
    
    def create_monitoring_config(self, monitoring_type: str, session_name: str = '', source_interfaces: List[str] = None, source_vlans: List[str] = None, destination_interface: str = '', destination_ip: str = '', destination_port: int = None, direction: str = '', flow_version: int = None, sampling_rate: str = '', source_address: str = '', filter_acl: str = '', description: str = ''):
        """Create a DataMonitoringConfig object."""
        from shared_components.data_structures import DataMonitoringConfig
        config = DataMonitoringConfig()
        config.device_name = self.device_config.device_name
        config.monitoring_type = monitoring_type
        config.session_name = session_name
        config.source_interfaces = source_interfaces or []
        config.source_vlans = source_vlans or []
        config.destination_interface = destination_interface
        config.destination_ip = destination_ip
        config.destination_port = destination_port
        config.direction = direction
        config.flow_version = flow_version
        config.sampling_rate = sampling_rate
        config.source_address = source_address
        config.filter_acl = filter_acl
        config.description = description
        return config
    
    def generate_network_flow_mappings(self) -> None:
        """Generate NetworkFlowMapping objects from parsed interfaces."""
        from shared_components.data_structures import NetworkFlowMapping
        for interface in self.device_config.interfaces:
            if not interface.ip_address:
                continue
            flow = NetworkFlowMapping(self.device_config.device_name, interface.name)
            flow.interface_type = interface.interface_type or 'unknown'
            flow.description = interface.description
            flow.ip_address = interface.ip_address
            flow.subnet_mask = interface.ip_mask
            if interface.ip_address and interface.ip_mask:
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(f"{interface.ip_address}/{interface.ip_mask}", strict=False)
                    flow.network = str(network.network_address)
                    flow.cidr = str(network)
                except:
                    pass
            flow.vlan_id = interface.vlan or interface.access_vlan
            flow.input_acls = [interface.input_acl] if interface.input_acl else []
            flow.output_acls = [interface.output_acl] if interface.output_acl else []
            flow.admin_status = 'down' if interface.shutdown else 'up'
            flow.protocol_status = 'up'
            if interface.port_channel:
                flow.port_channel = interface.port_channel.port_channel_name
            flow.is_port_channel = interface.is_port_channel
            flow.member_interfaces = interface.member_interfaces.copy() if interface.member_interfaces else []
            flow.vrf = interface.vrf
            self.device_config.flow_mappings.append(flow)
