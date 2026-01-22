#!/usr/bin/env python3
"""
Synopsis:
    Palo Alto PAN-OS Configuration Parser - Comprehensive Implementation

Description:
    Complete parser for Palo Alto Networks firewall configurations (PAN-OS).
    Supports both XML format (default GUI export) and set-command format.
    Implements all lessons learned from multi-vendor parser development.

Configuration Formats Supported:
    1. XML Format (default from GUI export):
       <config>
         <devices><entry name="localhost.localdomain">
           <deviceconfig><system><hostname>PA-FW-01</hostname></system></deviceconfig>
         </entry></devices>
       </config>
    
    2. Set Command Format:
       set deviceconfig system hostname PA-FW-01
       set network interface ethernet ethernet1/1 layer3 ip 192.168.1.1/24

Key Features:
    - Automatic format detection (XML vs set commands)
    - Complete system configuration parsing (domain, NTP, DNS, logging, SNMP)
    - IPv4 and IPv6 interface support
    - MTU parsing
    - Zone parsing (represented as VLANs)
    - Administrative endpoint creation
    - Static route parsing

Notes:
    - XML is the PRIMARY format (GUI export default)
    - Set format is CLI-only and less common
    - Zones act as VLAN equivalents in PAN-OS

Version: 3.0.0
"""

from typing import List, Optional, Dict, Any
import re
import xml.etree.ElementTree as ET
from .base_parser import BaseParser
from shared_components.data_structures import (
    DeviceConfiguration, NetworkInterface, VLAN, Route, Endpoint
)
from parser_modules.globalprotect_xml_parser import GlobalProtectXMLParser
from shared_components.globalprotect_structures import GlobalProtectData


class PaloAltoParser(BaseParser):
    """
    Comprehensive parser for Palo Alto PAN-OS configurations.
    
    Supports both XML and set command formats.
    Parses system config, interfaces, zones, routing, and monitoring.
    """
    
    def __init__(self, verbose: bool = False, parse_globalprotect: bool = False):
        """Initialize Palo Alto parser."""
        super().__init__([], verbose)
        self.vendor = "paloalto"
        self.platform = "panos"
        self.parse_globalprotect = parse_globalprotect
        self.config_format = None  # 'xml' or 'set'
        self.xml_root = None
    
    def detect_device_type(self) -> str:
        """Detect Palo Alto device type."""
        return 'panos'
    
    def detect_config_format(self) -> str:
        """
        Detect whether config is XML or set-command format.
        
        Returns:
            'xml' or 'set'
        """
        # Check first 10 non-empty lines
        for line in self.config_lines[:10]:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            # XML format check
            if line_stripped.startswith('<?xml') or line_stripped.startswith('<config'):
                return 'xml'
            
            # Set format check
            if line_stripped.startswith('set '):
                return 'set'
        
        # Default to set if unclear
        return 'set'
    
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Parse Palo Alto PAN-OS configuration.
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            DeviceConfiguration object with parsed data
        """
        self.config_lines = config_lines
        self.device_config = DeviceConfiguration()
        self.device_config.vendor = "paloalto"
        self.device_config.platform = "panos"
        
        # Detect format
        self.config_format = self.detect_config_format()
        self.log(f"[Palo Alto PAN-OS] Detected config format: {self.config_format.upper()}")
        
        if self.config_format == 'xml':
            self._parse_xml_format()
        else:
            self._parse_set_format()
        
        # Create administrative endpoints (common to both formats)
        self.create_administrative_endpoints()
        
        self.log(f"[Palo Alto PAN-OS] Parsed {len(self.device_config.interfaces)} interfaces")
        self.log(f"[Palo Alto PAN-OS] Parsed {len(self.device_config.vlans)} zones")
        self.log(f"[Palo Alto PAN-OS] Parsed {len(self.device_config.routes)} routes")
        self.log(f"[Palo Alto PAN-OS] Parsed {len(self.device_config.endpoints)} endpoints")
        
        return self.device_config
    
    def _parse_xml_format(self) -> None:
        """Parse XML format configuration."""
        try:
            # Join all lines and parse as XML
            xml_content = ''.join(self.config_lines)
            self.xml_root = ET.fromstring(xml_content)
            
            # Extract software version from config tag
            if self.xml_root.tag == 'config' and 'version' in self.xml_root.attrib:
                version = self.xml_root.attrib['version']
                self.device_config.os_version = f"PAN-OS {version}"
                self.log(f"[Palo Alto PAN-OS] Found software version: {version}")
            
            self.log("[Palo Alto PAN-OS] Parsing XML format configuration")
            
            # Parse each section
            self._parse_xml_hostname()
            self._parse_xml_system_config()
            self._parse_xml_users()  # Parse management users
            self._parse_xml_tacacs()  # Parse TACACS servers
            self._parse_xml_interfaces()
            self._parse_xml_zones()
            self._parse_xml_routing()
            
        except ET.ParseError as e:
            self.log(f"[Palo Alto PAN-OS] ERROR: Failed to parse XML: {e}")
            # Fall back to set format parsing
            self._parse_set_format()
    
    def _parse_xml_hostname(self) -> None:
        """Parse hostname from XML."""
        # Path: config/devices/entry/deviceconfig/system/hostname
        hostname_elem = self.xml_root.find('.//deviceconfig/system/hostname')
        if hostname_elem is not None and hostname_elem.text:
            hostname = hostname_elem.text.strip()
            self.device_config.hostname = hostname
            self.device_config.device_name = hostname
            self.log(f"[Palo Alto PAN-OS] Found hostname: {hostname}")
    
    def _parse_xml_system_config(self) -> None:
        """Parse system configuration from XML."""
        system_elem = self.xml_root.find('.//deviceconfig/system')
        if system_elem is None:
            return
        
        # Domain name
        domain_elem = system_elem.find('domain')
        if domain_elem is not None and domain_elem.text:
            self.device_config.domain_name = domain_elem.text.strip()
            self.log(f"[Palo Alto PAN-OS] Found domain: {self.device_config.domain_name}")
        
        # NTP servers
        ntp_servers_elem = system_elem.find('ntp-servers')
        if ntp_servers_elem is not None:
            for primary in ntp_servers_elem.findall('.//primary-ntp-server'):
                for server in primary.findall('ntp-server-address'):
                    if server.text:
                        ntp_addr = server.text.strip()
                        if ntp_addr not in self.device_config.ntp_servers:
                            self.device_config.ntp_servers.append(ntp_addr)
                            self.log(f"[Palo Alto PAN-OS] Found NTP server: {ntp_addr}")
            
            for secondary in ntp_servers_elem.findall('.//secondary-ntp-server'):
                for server in secondary.findall('ntp-server-address'):
                    if server.text:
                        ntp_addr = server.text.strip()
                        if ntp_addr not in self.device_config.ntp_servers:
                            self.device_config.ntp_servers.append(ntp_addr)
                            self.log(f"[Palo Alto PAN-OS] Found NTP server: {ntp_addr}")
        
        # DNS servers
        dns_setting_elem = system_elem.find('dns-setting')
        if dns_setting_elem is not None:
            for server_elem in dns_setting_elem.findall('.//servers/entry'):
                if server_elem.text:
                    dns_addr = server_elem.text.strip()
                    if dns_addr not in self.device_config.name_servers:
                        self.device_config.name_servers.append(dns_addr)
                        self.log(f"[Palo Alto PAN-OS] Found DNS server: {dns_addr}")
        
        # Syslog servers
        syslog_elem = self.xml_root.find('.//shared/log-settings/syslog')
        if syslog_elem is not None:
            for entry in syslog_elem.findall('entry'):
                name = entry.get('name', '')
                servers_elem = entry.find('servers')  # Changed from 'server' to 'servers'
                if servers_elem is not None:
                    for srv in servers_elem.findall('entry'):
                        srv_name = srv.get('name', '')
                        # Get actual IP address from <address> element
                        address_elem = srv.find('address')
                        if address_elem is not None and address_elem.text:
                            syslog_addr = address_elem.text.strip()
                            if syslog_addr not in self.device_config.logging_servers:
                                self.device_config.logging_servers.append(syslog_addr)
                                self.log(f"[Palo Alto PAN-OS] Found syslog server: {syslog_addr}")
        
        # SNMP
        snmp_elem = self.xml_root.find('.//deviceconfig/system/snmp-setting')
        if snmp_elem is not None:
            # Community strings - accumulate all
            for entry in snmp_elem.findall('.//snmp-community-string/entry'):
                community_name = entry.get('name', '')
                auth_elem = entry.find('authorization')
                if auth_elem is not None and auth_elem.text:
                    auth = "RO" if auth_elem.text.lower() == "read-only" else "RW"
                    community_str = f"{community_name} ({auth})"
                    if self.device_config.snmp_community:
                        self.device_config.snmp_community += f"; {community_str}"
                    else:
                        self.device_config.snmp_community = community_str
                    self.log(f"[Palo Alto PAN-OS] Found SNMP community: {community_name} ({auth})")
    
    def _parse_xml_users(self) -> None:
        """Parse management user accounts from XML."""
        self.log("[Palo Alto PAN-OS] Parsing user accounts")
        
        users_elem = self.xml_root.find('.//mgt-config/users')
        if users_elem is None:
            return
        
        users = {}
        user_privileges = []
        credential_hashes = []
        
        for entry in users_elem.findall('entry'):
            username = entry.get('name', '')
            if not username:
                continue
            
            # Get password hash
            phash_elem = entry.find('phash')
            password_hash = phash_elem.text if phash_elem is not None and phash_elem.text else ''
            
            # Determine role/privilege
            role = 'unknown'
            permissions_elem = entry.find('permissions')
            if permissions_elem is not None:
                role_based_elem = permissions_elem.find('role-based')
                if role_based_elem is not None:
                    # Check for superuser
                    superuser_elem = role_based_elem.find('superuser')
                    if superuser_elem is not None and superuser_elem.text == 'yes':
                        role = 'superuser'
                    else:
                        # Check for custom profile
                        custom_elem = role_based_elem.find('custom/profile')
                        if custom_elem is not None and custom_elem.text:
                            role = custom_elem.text
            
            # Store user info
            users[username] = {
                'role': role,
                'hash': password_hash if password_hash else 'Not configured'
            }
            
            # Format for summary fields
            user_privileges.append(f"{username}: {role}")
            if password_hash:
                credential_hashes.append(f"{username}: phash")
            
            self.log(f"[Palo Alto PAN-OS] Found user: {username} (role: {role})")
        
        # Store in AAA config
        if users:
            self.device_config.aaa_config['users'] = users
            self.device_config.aaa_config['user_privileges'] = '; '.join(user_privileges)
            if credential_hashes:
                self.device_config.aaa_config['credential_hashes'] = '; '.join(credential_hashes)
            else:
                self.device_config.aaa_config['credential_hashes'] = 'Not configured'
            self.log(f"[Palo Alto PAN-OS] Parsed {len(users)} user accounts")
        else:
            self.device_config.aaa_config['credential_hashes'] = 'Not configured'
    
    def _parse_xml_tacacs(self) -> None:
        """Parse TACACS+ server configuration from XML."""
        self.log("[Palo Alto PAN-OS] Parsing TACACS+ configuration")
        
        # Path: shared/authentication-profile/entry/servers
        auth_profiles = self.xml_root.findall('.//shared/authentication-profile/entry')
        if not auth_profiles:
            return
        
        tacacs_servers = []
        aaa_lines = []
        
        for profile in auth_profiles:
            profile_name = profile.get('name', '')
            
            # Check if it's a TACACS profile
            servers_elem = profile.find('servers')
            if servers_elem is not None:
                for server_entry in servers_elem.findall('entry'):
                    server_name = server_entry.get('name', '')
                    ip_elem = server_entry.find('ip-address')
                    
                    if ip_elem is not None and ip_elem.text:
                        tacacs_ip = ip_elem.text.strip()
                        tacacs_servers.append(tacacs_ip)
                        aaa_lines.append(f"TACACS+ server: {tacacs_ip} (profile: {profile_name})")
                        
                        # Create TACACS+ endpoint
                        from shared_components.data_structures import Endpoint
                        endpoint = Endpoint(
                            device_name=self.device_config.device_name,
                            name=f"TACACS+-{tacacs_ip}",
                            ip_address=tacacs_ip
                        )
                        endpoint.endpoint_type = "TACACS+ Server"
                        endpoint.description = f"TACACS+ Authentication Server (profile: {profile_name})"
                        endpoint.source_context = "Authentication Profile"
                        self.device_config.endpoints.append(endpoint)
                        
                        self.log(f"[Palo Alto PAN-OS] Found TACACS+ server: {tacacs_ip} in profile {profile_name}")
        
        # Store in AAA config
        if tacacs_servers:
            self.device_config.aaa_config['tacacs_servers'] = tacacs_servers
            self.device_config.aaa_config['aaa_lines'] = '; '.join(aaa_lines)
    
    def _parse_xml_interfaces(self) -> None:
        """Parse interfaces from XML."""
        # Path: config/devices/entry/network/interface/ethernet
        ethernet_elem = self.xml_root.find('.//network/interface/ethernet')
        if ethernet_elem is None:
            return
        
        for entry in ethernet_elem.findall('entry'):
            intf_name = entry.get('name', '')
            if not intf_name:
                continue
            
            interface = NetworkInterface(intf_name)
            interface.device_name = self.device_config.device_name
            
            # Layer 3 configuration
            layer3_elem = entry.find('layer3')
            if layer3_elem is not None:
                # MTU
                mtu_elem = layer3_elem.find('mtu')
                if mtu_elem is not None and mtu_elem.text:
                    try:
                        interface.mtu = int(mtu_elem.text)
                    except ValueError:
                        pass
                
                # IPv4 addresses
                for ip_entry in layer3_elem.findall('.//ip/entry'):
                    ip_name = ip_entry.get('name', '')
                    if ip_name and '/' in ip_name:
                        # Parse IP/CIDR
                        ip_addr, cidr = ip_name.split('/')
                        interface.ip_address = ip_addr
                        # Convert CIDR to subnet mask
                        mask_bits = int(cidr)
                        mask = (0xffffffff << (32 - mask_bits)) & 0xffffffff
                        interface.subnet_mask = f"{(mask>>24)&0xff}.{(mask>>16)&0xff}.{(mask>>8)&0xff}.{mask&0xff}"
                        break  # Use first IP as primary
                
                # IPv6 addresses
                for ipv6_entry in layer3_elem.findall('.//ipv6/entry'):
                    ipv6_name = ipv6_entry.get('name', '')
                    if ipv6_name:
                        if not hasattr(interface, 'ipv6_addresses'):
                            interface.ipv6_addresses = []
                        interface.ipv6_addresses.append(ipv6_name)
            
            # Comment/description
            comment_elem = entry.find('comment')
            if comment_elem is not None and comment_elem.text:
                interface.description = comment_elem.text.strip()
            
            self.device_config.interfaces.append(interface)
    
    def _parse_xml_zones(self) -> None:
        """
        Parse security zones from XML.
        
        In PAN-OS, zones are somewhat analogous to VLANs - they group interfaces.
        We'll represent them as VLAN objects for consistency.
        """
        # Path: config/devices/entry/vsys/entry/zone
        vsys_elem = self.xml_root.find('.//vsys/entry')
        if vsys_elem is None:
            return
        
        zone_elem = vsys_elem.find('zone')
        if zone_elem is None:
            return
        
        zone_id = 1  # Auto-increment since PAN-OS zones don't have numeric IDs
        for entry in zone_elem.findall('entry'):
            zone_name = entry.get('name', '')
            if not zone_name:
                continue
            
            # Create VLAN object to represent zone
            vlan = VLAN(zone_id)
            vlan.name = zone_name
            vlan.device_name = self.device_config.device_name
            vlan.description = f"Security Zone: {zone_name}"
            
            # Find interfaces in this zone
            network_elem = entry.find('network')
            if network_elem is not None:
                for layer3_elem in network_elem.findall('.//layer3/member'):
                    if layer3_elem.text:
                        intf_name = layer3_elem.text.strip()
                        if intf_name not in vlan.interfaces:
                            vlan.interfaces.append(intf_name)
            
            self.device_config.vlans.append(vlan)
            self.log(f"[Palo Alto PAN-OS] Found zone: {zone_name} with {len(vlan.interfaces)} interfaces")
            zone_id += 1
    
    def _parse_xml_routing(self) -> None:
        """Parse static routes from XML."""
        # Path: config/devices/entry/network/virtual-router
        vr_elem = self.xml_root.find('.//network/virtual-router')
        if vr_elem is None:
            return
        
        for entry in vr_elem.findall('entry'):
            routing_table = entry.find('routing-table')
            if routing_table is None:
                continue
            
            static_route = routing_table.find('ip/static-route')
            if static_route is None:
                continue
            
            for route_entry in static_route.findall('entry'):
                route_name = route_entry.get('name', '')
                
                # Destination
                dest_elem = route_entry.find('destination')
                if dest_elem is None or not dest_elem.text:
                    continue
                
                dest = dest_elem.text.strip()
                
                # Next hop
                nexthop_elem = route_entry.find('nexthop/ip-address')
                if nexthop_elem is None or not nexthop_elem.text:
                    continue
                
                next_hop = nexthop_elem.text.strip()
                
                # Parse destination
                if '/' in dest:
                    network, cidr = dest.split('/')
                    mask_bits = int(cidr)
                    mask = (0xffffffff << (32 - mask_bits)) & 0xffffffff
                    subnet_mask = f"{(mask>>24)&0xff}.{(mask>>16)&0xff}.{(mask>>8)&0xff}.{mask&0xff}"
                else:
                    network = dest
                    subnet_mask = "255.255.255.255"
                
                route = Route()
                route.destination = network
                route.mask = subnet_mask
                route.next_hop = next_hop
                route.device_name = self.device_config.device_name
                route.description = route_name
                route.route_type = "static"
                
                self.device_config.routes.append(route)
                self.log(f"[Palo Alto PAN-OS] Found static route: {network}/{subnet_mask} via {next_hop}")
    
    def _parse_set_format(self) -> None:
        """Parse set-command format configuration."""
        self.log("[Palo Alto PAN-OS] Parsing set-command format configuration")
        
        self._parse_set_hostname()
        self._parse_set_system_config()
        self._parse_set_interfaces()
        self._parse_set_zones()
        self._parse_set_routing()
    
    def _parse_set_hostname(self) -> None:
        """Parse hostname from set commands."""
        for line in self.config_lines:
            match = re.search(r'set\s+deviceconfig\s+system\s+hostname\s+(\S+)', line, re.IGNORECASE)
            if match:
                hostname = match.group(1)
                self.device_config.hostname = hostname
                self.device_config.device_name = hostname
                self.log(f"[Palo Alto PAN-OS] Found hostname: {hostname}")
                return
    
    def _parse_set_system_config(self) -> None:
        """Parse system configuration from set commands."""
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Domain name
            domain_match = re.match(r'set\s+deviceconfig\s+system\s+domain\s+(\S+)', 
                                   line_stripped, re.IGNORECASE)
            if domain_match:
                self.device_config.domain_name = domain_match.group(1)
                self.log(f"[Palo Alto PAN-OS] Found domain: {self.device_config.domain_name}")
            
            # NTP servers
            ntp_match = re.search(r'set\s+deviceconfig\s+system\s+ntp-servers?\s+.*?ntp-server-address\s+(\S+)', 
                                 line_stripped, re.IGNORECASE)
            if ntp_match:
                ntp_server = ntp_match.group(1)
                if ntp_server not in self.device_config.ntp_servers:
                    self.device_config.ntp_servers.append(ntp_server)
                    self.log(f"[Palo Alto PAN-OS] Found NTP server: {ntp_server}")
            
            # DNS servers
            dns_match = re.search(r'set\s+deviceconfig\s+system\s+dns-setting\s+servers\s+(\S+)', 
                                 line_stripped, re.IGNORECASE)
            if dns_match:
                dns_server = dns_match.group(1)
                if dns_server not in self.device_config.name_servers:
                    self.device_config.name_servers.append(dns_server)
                    self.log(f"[Palo Alto PAN-OS] Found DNS server: {dns_server}")
            
            # SNMP communities - accumulate all
            snmp_match = re.search(r'set\s+deviceconfig\s+system\s+snmp-setting.*?community\s+(\S+)', 
                                  line_stripped, re.IGNORECASE)
            if snmp_match:
                community = snmp_match.group(1)
                # Determine access level
                access = "RO" if "read-only" in line_stripped.lower() else "RW"
                community_str = f"{community} ({access})"
                if self.device_config.snmp_community:
                    if community_str not in self.device_config.snmp_community:
                        self.device_config.snmp_community += f"; {community_str}"
                else:
                    self.device_config.snmp_community = community_str
                self.log(f"[Palo Alto PAN-OS] Found SNMP community: {community} ({access})")
    
    def _parse_set_interfaces(self) -> None:
        """Parse interfaces from set commands."""
        interface_configs = {}
        
        for line in self.config_lines:
            # Match interface configuration
            intf_match = re.match(r'set\s+network\s+interface\s+ethernet\s+(\S+)\s+(.+)', 
                                 line.strip(), re.IGNORECASE)
            if not intf_match:
                continue
            
            intf_name = intf_match.group(1)
            config_part = intf_match.group(2)
            
            if intf_name not in interface_configs:
                interface_configs[intf_name] = {
                    'name': intf_name,
                    'ip_address': '',
                    'subnet_mask': '',
                    'ipv6_addresses': [],
                    'mtu': 1500,
                    'description': ''
                }
            
            intf_config = interface_configs[intf_name]
            
            # IP address: layer3 ip 192.168.1.1/24
            ip_match = re.search(r'layer3\s+ip\s+(\S+)', config_part)
            if ip_match:
                addr_cidr = ip_match.group(1)
                if '/' in addr_cidr:
                    ip_addr, cidr = addr_cidr.split('/')
                    intf_config['ip_address'] = ip_addr
                    mask_bits = int(cidr)
                    mask = (0xffffffff << (32 - mask_bits)) & 0xffffffff
                    intf_config['subnet_mask'] = f"{(mask>>24)&0xff}.{(mask>>16)&0xff}.{(mask>>8)&0xff}.{mask&0xff}"
            
            # IPv6
            ipv6_match = re.search(r'layer3\s+ipv6\s+(\S+)', config_part)
            if ipv6_match:
                ipv6_addr = ipv6_match.group(1)
                if ipv6_addr not in intf_config['ipv6_addresses']:
                    intf_config['ipv6_addresses'].append(ipv6_addr)
            
            # MTU
            mtu_match = re.search(r'mtu\s+(\d+)', config_part)
            if mtu_match:
                intf_config['mtu'] = int(mtu_match.group(1))
            
            # Comment
            comment_match = re.search(r'comment\s+["\']?([^"\']+)["\']?', config_part)
            if comment_match:
                intf_config['description'] = comment_match.group(1).strip('"\'')
        
        # Create NetworkInterface objects
        for intf_name, config in interface_configs.items():
            interface = NetworkInterface(intf_name)
            interface.device_name = self.device_config.device_name
            interface.ip_address = config['ip_address']
            interface.subnet_mask = config['subnet_mask']
            if config['ipv6_addresses']:
                interface.ipv6_addresses = config['ipv6_addresses']
            interface.mtu = config['mtu']
            interface.description = config['description']
            
            self.device_config.interfaces.append(interface)
    
    def _parse_set_zones(self) -> None:
        """Parse security zones from set commands."""
        zone_configs = {}
        
        for line in self.config_lines:
            # Match zone configuration
            zone_match = re.match(r'set\s+zone\s+(\S+)\s+(.+)', line.strip(), re.IGNORECASE)
            if not zone_match:
                continue
            
            zone_name = zone_match.group(1)
            config_part = zone_match.group(2)
            
            if zone_name not in zone_configs:
                zone_configs[zone_name] = {
                    'name': zone_name,
                    'interfaces': []
                }
            
            # Interface membership
            intf_match = re.search(r'network\s+layer3\s+(\S+)', config_part)
            if intf_match:
                intf_name = intf_match.group(1)
                if intf_name not in zone_configs[zone_name]['interfaces']:
                    zone_configs[zone_name]['interfaces'].append(intf_name)
        
        # Create VLAN objects for zones
        zone_id = 1
        for zone_name, config in zone_configs.items():
            vlan = VLAN(zone_id)
            vlan.name = zone_name
            vlan.device_name = self.device_config.device_name
            vlan.description = f"Security Zone: {zone_name}"
            vlan.interfaces = config['interfaces'].copy()
            
            self.device_config.vlans.append(vlan)
            self.log(f"[Palo Alto PAN-OS] Found zone: {zone_name}")
            zone_id += 1
    
    def _parse_set_routing(self) -> None:
        """Parse static routes from set commands."""
        for line in self.config_lines:
            route_match = re.search(
                r'set\s+network\s+virtual-router\s+\S+\s+routing-table\s+ip\s+static-route\s+\S+\s+destination\s+(\S+)\s+nexthop\s+ip-address\s+(\S+)',
                line, re.IGNORECASE
            )
            if route_match:
                dest = route_match.group(1)
                next_hop = route_match.group(2)
                
                # Parse destination
                if '/' in dest:
                    network, cidr = dest.split('/')
                    mask_bits = int(cidr)
                    mask = (0xffffffff << (32 - mask_bits)) & 0xffffffff
                    subnet_mask = f"{(mask>>24)&0xff}.{(mask>>16)&0xff}.{(mask>>8)&0xff}.{mask&0xff}"
                else:
                    network = dest
                    subnet_mask = "255.255.255.255"
                
                route = Route()
                route.destination = network
                route.mask = subnet_mask
                route.next_hop = next_hop
                route.device_name = self.device_config.device_name
                route.route_type = "static"
                
                self.device_config.routes.append(route)
                self.log(f"[Palo Alto PAN-OS] Found static route: {network}/{subnet_mask} via {next_hop}")
    
    def create_administrative_endpoints(self) -> None:
        """
        Create Endpoint objects for all administrative servers.
        Populates the Endpoints tab with NTP, DNS, syslog, SNMP hosts.
        """
        # NTP servers
        for ntp_server in self.device_config.ntp_servers:
            endpoint = Endpoint(
                device_name=self.device_config.device_name,
                name=f"NTP-{ntp_server}",
                ip_address=ntp_server
            )
            endpoint.endpoint_type = "NTP Server"
            endpoint.description = "Network Time Protocol Server"
            endpoint.source_context = "System Configuration"
            self.device_config.endpoints.append(endpoint)
            self.log(f"[Palo Alto PAN-OS] Created NTP endpoint: {ntp_server}")
        
        # DNS servers
        for dns_server in self.device_config.name_servers:
            endpoint = Endpoint(
                device_name=self.device_config.device_name,
                name=f"DNS-{dns_server}",
                ip_address=dns_server
            )
            endpoint.endpoint_type = "DNS Server"
            endpoint.description = "Domain Name System Server"
            endpoint.source_context = "System Configuration"
            self.device_config.endpoints.append(endpoint)
            self.log(f"[Palo Alto PAN-OS] Created DNS endpoint: {dns_server}")
        
        # Syslog servers
        for syslog_server in self.device_config.logging_servers:
            endpoint = Endpoint(
                device_name=self.device_config.device_name,
                name=f"Syslog-{syslog_server}",
                ip_address=syslog_server
            )
            endpoint.endpoint_type = "Syslog Server"
            endpoint.description = "System Logging Server"
            endpoint.source_context = "System Configuration"
            self.device_config.endpoints.append(endpoint)
            self.log(f"[Palo Alto PAN-OS] Created Syslog endpoint: {syslog_server}")
    
    # Abstract method implementations (delegates to format-specific methods)
    def parse_hostname(self) -> Optional[str]:
        """Stub - actual parsing done in format-specific methods."""
        return None
    
    def parse_interfaces(self) -> None:
        """Stub - actual parsing done in format-specific methods."""
        pass
    
    def parse_routing(self) -> None:
        """Stub - actual parsing done in format-specific methods."""
        pass
    
    # ========================================================================
    # GlobalProtect VPN Parsing (Enhanced v3.0)
    # ========================================================================
    
    def _parse_globalprotect_data(self) -> Optional[GlobalProtectData]:
        """
        Parse GlobalProtect VPN configuration data.
        
        This method is called internally when --parse-globalprotect flag is used.
        Only works with XML format configurations.
        
        Returns:
            GlobalProtectData object with all parsed VPN data, or None if not XML format
        """
        if self.config_format != 'xml' or self.xml_root is None:
            self.log("[GlobalProtect] Cannot parse GlobalProtect - requires XML format configuration")
            return None
        
        if not self.parse_globalprotect:
            return None
        
        self.log("[GlobalProtect] Starting GlobalProtect VPN parsing")
        
        try:
            # Create GlobalProtect XML parser
            gp_parser = GlobalProtectXMLParser(verbose=self.verbose)
            
            # Parse from the XML root element
            gp_data = gp_parser.parse_from_element(self.xml_root)
            
            self.log(f"[GlobalProtect] Parsed {gp_data.total_portals} portals, "
                    f"{gp_data.total_gateways} gateways, "
                    f"{gp_data.total_hip_objects} HIP objects, "
                    f"{gp_data.total_hip_profiles} HIP profiles")
            
            return gp_data
            
        except Exception as e:
            self.log(f"[GlobalProtect] ERROR: Failed to parse GlobalProtect data: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def get_globalprotect_data(self) -> Optional[GlobalProtectData]:
        """
        Get parsed GlobalProtect data.
        
        This method is called by analyzer.py to retrieve GlobalProtect data
        after parsing is complete.
        
        Returns:
            GlobalProtectData object if parse_globalprotect was enabled, None otherwise
        """
        if not self.parse_globalprotect:
            return None
        
        # Parse GlobalProtect data if not already done
        return self._parse_globalprotect_data()