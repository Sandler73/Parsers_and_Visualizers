#!/usr/bin/env python3
"""
Synopsis:
    Juniper JunOS Configuration Parser - Comprehensive Implementation

Description:
    Complete parser for Juniper Networks JunOS device configurations.
    Implements all lessons learned from multi-vendor parser development.
    
    Supports JunOS devices including:
    - MX Series (routers)
    - EX Series (switches)
    - SRX Series (firewalls)
    - QFX Series (data center switches)

Key Features:
    - Complete system configuration parsing (domain, NTP, DNS, logging, SNMP)
    - IPv4 and IPv6 interface support
    - MTU parsing
    - VLAN parsing with interface assignments
    - jFlow (NetFlow) monitoring
    - Port mirroring/analyzer
    - Administrative endpoint creation
    - Routing configuration

Configuration Format:
    Set command format:
        set system host-name ROUTER-01
        set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
        set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64

Notes:
    - Interface names: ge-0/0/0 (GigE), xe-0/0/0 (10GigE), et-0/0/0 (25/40/100G)
    - Units are logical interfaces (similar to subinterfaces)
    - VLANs use irb (integrated routing and bridging) interfaces

Version: 2.2.4
"""

from typing import List, Optional, Dict, Any
import re
from .base_parser import BaseParser
from shared_components.data_structures import (
    DeviceConfiguration, NetworkInterface, VLAN, Route, Endpoint
)
from shared_components.monitoring_structures import SPANSession, NetFlowConfig


class JuniperParser(BaseParser):
    """
    Comprehensive parser for Juniper JunOS configurations.
    
    Parses system config, interfaces, VLANs, routing, and monitoring.
    Creates administrative endpoints for NTP, DNS, syslog, SNMP, flow collectors.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize Juniper parser."""
        super().__init__([], verbose)
        self.vendor = "juniper"
        self.platform = "junos"
    
    def detect_device_type(self) -> str:
        """Detect JunOS device type from configuration."""
        for line in self.config_lines[:50]:
            if re.search(r'set\s+(system|interfaces|protocols)', line, re.IGNORECASE):
                return 'junos'
            if 'junos' in line.lower() or 'juniper' in line.lower():
                return 'junos'
        return 'junos'
    
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Parse Juniper JunOS configuration.
        
        Supports both formats:
        - Set format: set system host-name HOSTNAME
        - Curly-brace format: host-name HOSTNAME;
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            DeviceConfiguration object with parsed data
        """
        # Detect config format
        is_set_format = any('set ' in line for line in config_lines[:20])
        is_curly_format = any('{' in line for line in config_lines[:20])
        
        self.log(f"[Juniper JunOS] Format detection: is_set={is_set_format}, is_curly={is_curly_format}")
        self.log(f"[Juniper JunOS] Config has {len(config_lines)} lines")
        
        # Show first few lines for debugging
        if self.verbose:
            self.log("[Juniper JunOS] First 5 non-empty lines:")
            count = 0
            for line in config_lines:
                if line.strip():
                    self.log(f"  {line.rstrip()}")
                    count += 1
                    if count >= 5:
                        break
        
        # Convert curly-brace to set format if needed
        if is_curly_format and not is_set_format:
            self.log("[Juniper JunOS] Detected curly-brace format, converting to set format")
            config_lines = self._convert_curly_to_set(config_lines)
        
        self.config_lines = config_lines
        self.device_config = DeviceConfiguration()
        self.device_config.vendor = "juniper"
        self.device_config.platform = "junos"
        
        self.log("[Juniper JunOS] Starting JunOS configuration parse")
        
        # Parse sections in logical order
        self.parse_hostname()
        self.parse_system_config()      # Domain, NTP, DNS, SNMP, logging
        self.parse_interfaces()
        self.parse_vlans()
        self.parse_routing()
        self.parse_monitoring_config()  # jFlow, port mirroring
        self.create_administrative_endpoints()
        
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.interfaces)} interfaces")
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.vlans)} VLANs")
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.routes)} routes")
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.netflow_configs)} jFlow configs")
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.span_sessions)} port-mirror sessions")
        self.log(f"[Juniper JunOS] Parsed {len(self.device_config.endpoints)} endpoints")
        
        return self.device_config
    
    def _convert_curly_to_set(self, config_lines: List[str]) -> List[str]:
        """
        Convert curly-brace hierarchical format to set command format.
        
        Handles both:
        - Multi-line blocks: system {\n    host-name test;\n}
        - Inline braces: vlan10 { vlan-id 10; }
        """
        set_lines = []
        path_stack = []
        
        for line in config_lines:
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Check for inline braces (all on one line)
            if '{' in line_stripped and '}' in line_stripped and line_stripped.count('{') == line_stripped.count('}'):
                # Extract path and content
                # Example: vlan10 { vlan-id 10; } or vlan10 { vlan-id 10; }
                parts = line_stripped.split('{')
                element = parts[0].strip()
                content = parts[1].split('}')[0].strip()
                
                # Split content by semicolons
                for statement in content.split(';'):
                    statement = statement.strip()
                    if statement:
                        if path_stack:
                            full_path = ' '.join(path_stack) + ' ' + element + ' ' + statement
                        else:
                            full_path = element + ' ' + statement
                        set_line = f"set {full_path}"
                        set_lines.append(set_line)
                continue
            
            # Opening brace - add to path stack
            if line_stripped.endswith('{'):
                element = line_stripped.replace('{', '').strip()
                path_stack.append(element)
            
            # Closing brace - pop from path stack
            elif line_stripped == '}':
                if path_stack:
                    path_stack.pop()
            
            # Configuration statement
            elif line_stripped.endswith(';'):
                statement = line_stripped.replace(';', '').strip()
                
                # Build full path
                if path_stack:
                    full_path = ' '.join(path_stack) + ' ' + statement
                    set_line = f"set {full_path}"
                    set_lines.append(set_line)
        
        return set_lines
    
    def parse_hostname(self) -> Optional[str]:
        """
        Parse device hostname.
        
        Formats: 
            set system host-name HOSTNAME
            host-name HOSTNAME;
        """
        for line in self.config_lines:
            # Set format
            match = re.search(r'set\s+system\s+host-name\s+(\S+)', line, re.IGNORECASE)
            if match:
                hostname = match.group(1)
                self.device_config.hostname = hostname
                self.device_config.device_name = hostname
                self.log(f"[Juniper JunOS] Found hostname: {hostname}")
                return hostname
            
            # Curly-brace format
            match = re.search(r'^\s*host-name\s+([^;]+);', line, re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                self.device_config.hostname = hostname
                self.device_config.device_name = hostname
                self.log(f"[Juniper JunOS] Found hostname: {hostname}")
                return hostname
        return None
    
    def parse_system_config(self) -> None:
        """
        Parse system configuration: domain name, NTP, DNS, SNMP, logging, users, TACACS.
        
        Formats:
            set system domain-name example.com
            set system ntp server 10.1.1.10
            set system name-server 10.1.1.20
            set system syslog host 10.1.1.60
            set snmp community public authorization read-only
            set snmp trap-group TRAPS targets 10.1.1.50
            set system login user admin1 class super-user
            set system login user admin1 authentication encrypted-password "$6$hash"
            set security authentication tacplus-server 192.168.99.51 secret "key"
        """
        users = {}
        user_privileges = []
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Domain name
            domain_match = re.match(r'set\s+system\s+domain-name\s+(\S+)', line_stripped, re.IGNORECASE)
            if domain_match:
                self.device_config.domain_name = domain_match.group(1)
                self.log(f"[Juniper JunOS] Found domain: {domain_match.group(1)}")
            
            # NTP servers
            ntp_match = re.match(r'set\s+system\s+ntp\s+server\s+(\S+)', line_stripped, re.IGNORECASE)
            if ntp_match:
                ntp_server = ntp_match.group(1)
                if ntp_server not in self.device_config.ntp_servers:
                    self.device_config.ntp_servers.append(ntp_server)
                    self.log(f"[Juniper JunOS] Found NTP server: {ntp_server}")
            
            # DNS/Name servers
            dns_match = re.match(r'set\s+system\s+name-server\s+(\S+)', line_stripped, re.IGNORECASE)
            if dns_match:
                dns_server = dns_match.group(1)
                if dns_server not in self.device_config.name_servers:
                    self.device_config.name_servers.append(dns_server)
                    self.log(f"[Juniper JunOS] Found DNS server: {dns_server}")
            
            # Syslog hosts
            syslog_match = re.match(r'set\s+system\s+syslog\s+host\s+(\S+)', line_stripped, re.IGNORECASE)
            if syslog_match:
                syslog_host = syslog_match.group(1)
                if syslog_host not in self.device_config.logging_servers:
                    self.device_config.logging_servers.append(syslog_host)
                    self.log(f"[Juniper JunOS] Found syslog host: {syslog_host}")
            
            # SNMP community
            snmp_match = re.match(r'set\s+(?:system\s+)?snmp\s+community\s+(\S+)\s+authorization\s+(read-only|read-write)', 
                                 line_stripped, re.IGNORECASE)
            if snmp_match:
                community = snmp_match.group(1)
                access = "RO" if "read-only" in line_stripped.lower() else "RW"
                community_str = f"{community} ({access})"
                if self.device_config.snmp_community:
                    self.device_config.snmp_community += f"; {community_str}"
                else:
                    self.device_config.snmp_community = community_str
                self.log(f"[Juniper JunOS] Found SNMP community: {community} ({access})")
            
            # Users - class/privilege
            user_class_match = re.match(r'set\s+system\s+login\s+user\s+(\S+)\s+class\s+(\S+)', line_stripped, re.IGNORECASE)
            if user_class_match:
                username = user_class_match.group(1)
                user_class = user_class_match.group(2)
                if username not in users:
                    users[username] = {'class': user_class, 'hash': ''}
                else:
                    users[username]['class'] = user_class
                self.log(f"[Juniper JunOS] Found user {username} with class {user_class}")
            
            # Users - encrypted password
            user_pass_match = re.match(r'set\s+system\s+login\s+user\s+(\S+)\s+authentication\s+encrypted-password\s+"?([^"]+)"?', line_stripped, re.IGNORECASE)
            if user_pass_match:
                username = user_pass_match.group(1)
                password_hash = user_pass_match.group(2).strip('"')
                if username not in users:
                    users[username] = {'class': 'unknown', 'hash': password_hash}
                else:
                    users[username]['hash'] = password_hash
                self.log(f"[Juniper JunOS] Found password hash for user {username}")
            
            # TACACS+ server
            tacacs_match = re.match(r'set\s+security\s+authentication\s+tacplus-server\s+(\S+)', line_stripped, re.IGNORECASE)
            if tacacs_match:
                tacacs_server = tacacs_match.group(1)
                # Create endpoint
                endpoint = Endpoint(
                    device_name=self.device_config.device_name,
                    name=f'TACACS-{tacacs_server}',
                    ip_address=tacacs_server
                )
                endpoint.endpoint_type = "TACACS+ Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"[Juniper JunOS] Found TACACS+ server: {tacacs_server}")
        
        # Store users in aaa_config
        if users:
            for username, info in users.items():
                user_privileges.append(f"{username}: {info['class']}")
            
            self.device_config.aaa_config['users'] = users
            self.device_config.aaa_config['user_privileges'] = '; '.join(user_privileges)
            self.log(f"[Juniper JunOS] Parsed {len(users)} user accounts")
    
    def parse_interfaces(self) -> None:
        """
        Parse interfaces with IPv4, IPv6, MTU, VLANs, and descriptions.
        
        Formats:
            set interfaces ge-0/0/0 description "Uplink"
            set interfaces ge-0/0/0 mtu 9000
            set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
            set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64
            set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members VLAN10
            set interfaces irb unit 10 family inet address 10.10.1.1/24
        """
        # Group interface configurations
        interface_configs = {}
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Match interface configuration
            intf_match = re.match(r'set\s+interfaces\s+(\S+)\s+(.+)', line_stripped, re.IGNORECASE)
            if not intf_match:
                continue
            
            intf_name = intf_match.group(1)
            config_part = intf_match.group(2)
            
            # Initialize interface config if needed
            if intf_name not in interface_configs:
                interface_configs[intf_name] = {
                    'name': intf_name,
                    'description': '',
                    'mtu': 1500,
                    'units': {}  # Logical interfaces (unit numbers)
                }
            
            intf_config = interface_configs[intf_name]
            
            # Description
            desc_match = re.match(r'description\s+["\']?([^"\']+)["\']?', config_part)
            if desc_match:
                intf_config['description'] = desc_match.group(1).strip('"\'')
            
            # MTU
            mtu_match = re.match(r'mtu\s+(\d+)', config_part)
            if mtu_match:
                intf_config['mtu'] = int(mtu_match.group(1))
            
            # Unit (logical interface) configuration
            unit_match = re.match(r'unit\s+(\d+)\s+(.+)', config_part)
            if unit_match:
                unit_num = unit_match.group(1)
                unit_config = unit_match.group(2)
                
                if unit_num not in intf_config['units']:
                    intf_config['units'][unit_num] = {
                        'ipv4_addresses': [],
                        'ipv6_addresses': [],
                        'vlans': [],
                        'description': ''
                    }
                
                unit = intf_config['units'][unit_num]
                
                # IPv4 address
                ipv4_match = re.search(r'family\s+inet\s+address\s+(\S+)', unit_config)
                if ipv4_match:
                    addr = ipv4_match.group(1)
                    if addr not in unit['ipv4_addresses']:
                        unit['ipv4_addresses'].append(addr)
                
                # IPv6 address
                ipv6_match = re.search(r'family\s+inet6\s+address\s+(\S+)', unit_config)
                if ipv6_match:
                    addr = ipv6_match.group(1)
                    if addr not in unit['ipv6_addresses']:
                        unit['ipv6_addresses'].append(addr)
                
                # VLAN membership
                vlan_match = re.search(r'vlan\s+members\s+(\S+)', unit_config)
                if vlan_match:
                    vlan = vlan_match.group(1)
                    if vlan not in unit['vlans']:
                        unit['vlans'].append(vlan)
                
                # Unit description
                unit_desc_match = re.search(r'description\s+["\']?([^"\']+)["\']?', unit_config)
                if unit_desc_match:
                    unit['description'] = unit_desc_match.group(1).strip('"\'')
        
        # Create NetworkInterface objects
        for intf_name, config in interface_configs.items():
            # For interfaces with units, create separate interface for each unit
            if config['units']:
                for unit_num, unit_config in config['units'].items():
                    full_name = f"{intf_name}.{unit_num}"
                    interface = NetworkInterface(full_name)
                    interface.device_name = self.device_config.device_name
                    interface.description = unit_config.get('description') or config.get('description', '')
                    interface.mtu = config.get('mtu', 1500)
                    
                    # Set IPv4 address (primary)
                    if unit_config['ipv4_addresses']:
                        addr_cidr = unit_config['ipv4_addresses'][0]
                        if '/' in addr_cidr:
                            interface.ip_address, cidr = addr_cidr.split('/')
                            # Convert CIDR to subnet mask
                            mask_bits = int(cidr)
                            mask = (0xffffffff << (32 - mask_bits)) & 0xffffffff
                            interface.subnet_mask = f"{(mask>>24)&0xff}.{(mask>>16)&0xff}.{(mask>>8)&0xff}.{mask&0xff}"
                    
                    # Set IPv6 addresses
                    if unit_config['ipv6_addresses']:
                        interface.ipv6_addresses = unit_config['ipv6_addresses'].copy()
                    
                    # VLAN tagging (for unit > 0)
                    if unit_num != '0' and unit_num.isdigit():
                        interface.vlan = int(unit_num)
                    
                    # VLAN membership (for switches)
                    if unit_config['vlans']:
                        # Store VLAN names for later linking
                        if not hasattr(interface, 'vlan_names'):
                            interface.vlan_names = []
                        interface.vlan_names.extend(unit_config['vlans'])
                    
                    self.device_config.interfaces.append(interface)
            else:
                # Interface without units
                interface = NetworkInterface(intf_name)
                interface.device_name = self.device_config.device_name
                interface.description = config.get('description', '')
                interface.mtu = config.get('mtu', 1500)
                self.device_config.interfaces.append(interface)
    
    
    def parse_dns_servers(self) -> None:
        """Parse DNS name-server configuration."""
        dns_servers = []
        for line in self.config_lines:
            # set system name-server X.X.X.X
            dns_match = re.match(r'set\s+system\s+name-server\s+(\S+)', line, re.IGNORECASE)
            if dns_match:
                server = dns_match.group(1)
                dns_servers.append(server)
                # Also create endpoint
                endpoint = Endpoint(server, 'DNS', device=self.device_config.device_name)
                self.device_config.endpoints.append(endpoint)
        
        self.device_config.name_servers = dns_servers
        if dns_servers:
            self.log(f"Found {len(dns_servers)} DNS servers")
    def parse_vlans(self) -> None:
        """
        Parse VLANs and link to interfaces.
        
        Formats:
            set vlans VLAN10 vlan-id 10
            set vlans VLAN10 description "Management"
            set vlans VLAN10 l3-interface irb.10
        """
        vlan_configs = {}
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Match VLAN configuration
            vlan_match = re.match(r'set\s+vlans\s+(\S+)\s+(.+)', line_stripped, re.IGNORECASE)
            if not vlan_match:
                continue
            
            vlan_name = vlan_match.group(1)
            config_part = vlan_match.group(2)
            
            if vlan_name not in vlan_configs:
                vlan_configs[vlan_name] = {
                    'name': vlan_name,
                    'vlan_id': None,
                    'description': '',
                    'l3_interface': ''
                }
            
            vlan_cfg = vlan_configs[vlan_name]
            
            # VLAN ID
            id_match = re.match(r'vlan-id\s+(\d+)', config_part)
            if id_match:
                vlan_cfg['vlan_id'] = int(id_match.group(1))
            
            # Description
            desc_match = re.match(r'description\s+["\']?([^"\']+)["\']?', config_part)
            if desc_match:
                vlan_cfg['description'] = desc_match.group(1).strip('"\'')
            
            # L3 interface (gateway)
            l3_match = re.match(r'l3-interface\s+(\S+)', config_part)
            if l3_match:
                vlan_cfg['l3_interface'] = l3_match.group(1)
        
        # Create VLAN objects
        for vlan_name, config in vlan_configs.items():
            if config['vlan_id'] is not None:
                vlan = VLAN(config['vlan_id'])
                vlan.name = vlan_name
                vlan.description = config.get('description', '')
                vlan.device_name = self.device_config.device_name
                
                # Find gateway from L3 interface
                if config['l3_interface']:
                    for interface in self.device_config.interfaces:
                        if interface.name == config['l3_interface']:
                            if interface.ip_address:
                                vlan.gateway = interface.ip_address
                            # Link this L3 interface to the VLAN
                            if interface.name not in vlan.interfaces:
                                vlan.interfaces.append(f"{interface.name} (gateway)")
                            break
                
                self.device_config.vlans.append(vlan)
                self.log(f"[Juniper JunOS] Parsed VLAN {config['vlan_id']}: {vlan_name}")
        
        # Link interfaces to VLANs based on vlan_names
        for interface in self.device_config.interfaces:
            if hasattr(interface, 'vlan_names'):
                for vlan_name in interface.vlan_names:
                    for vlan in self.device_config.vlans:
                        if vlan.name == vlan_name:
                            if interface.name not in vlan.interfaces:
                                vlan.interfaces.append(interface.name)
                            break
    
    def parse_routing(self) -> None:
        """
        Parse static routes.
        
        Format: set routing-options static route 0.0.0.0/0 next-hop 10.1.1.1
        """
        for line in self.config_lines:
            route_match = re.search(
                r'set\s+routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)',
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
                self.log(f"[Juniper JunOS] Found static route: {network}/{subnet_mask} via {next_hop}")
    
    def parse_monitoring_config(self) -> None:
        """
        Parse jFlow (NetFlow) and port mirroring configuration.
        
        jFlow formats:
            set services flow-monitoring version9 template ipv4
            set forwarding-options sampling instance FLOW input rate 1000
            set forwarding-options sampling instance FLOW family inet output flow-server 10.1.100.10 port 9996
            
        Port mirroring:
            set forwarding-options analyzer MIRROR input ingress interface ge-0/0/1
            set forwarding-options analyzer MIRROR output interface ge-0/0/24
        """
        # Parse jFlow/NetFlow
        flow_configs = {}
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Flow server (collector)
            flow_match = re.search(
                r'flow-server\s+(\S+)\s+port\s+(\d+)',
                line_stripped, re.IGNORECASE
            )
            if flow_match:
                collector_ip = flow_match.group(1)
                collector_port = flow_match.group(2)
                
                collector_key = f"{collector_ip}:{collector_port}"
                if collector_key not in flow_configs:
                    netflow = NetFlowConfig("", self.device_config.device_name)
                    netflow.version = "jFlow"
                    netflow.exporter_destination = collector_ip
                    netflow.exporter_port = int(collector_port)
                    netflow.collector_ip = collector_ip  # For endpoint correlation
                    netflow.collector_port = collector_port  # For endpoint correlation
                    netflow.description = f"jFlow export to {collector_ip}:{collector_port}"
                    flow_configs[collector_key] = netflow
                    
                    self.device_config.netflow_configs.append(netflow)
                    self.log(f"[Juniper JunOS] Found jFlow collector: {collector_ip}:{collector_port}")
        
        # Parse port mirroring (analyzer)
        analyzer_sessions = {}
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Analyzer configuration
            analyzer_match = re.match(r'set\s+forwarding-options\s+analyzer\s+(\S+)\s+(.+)', 
                                     line_stripped, re.IGNORECASE)
            if not analyzer_match:
                continue
            
            session_name = analyzer_match.group(1)
            config_part = analyzer_match.group(2)
            
            if session_name not in analyzer_sessions:
                analyzer_sessions[session_name] = {
                    'name': session_name,
                    'source_interfaces': [],
                    'destination': ''
                }
            
            session = analyzer_sessions[session_name]
            
            # Source interface
            source_match = re.search(r'input\s+ingress\s+interface\s+(\S+)', config_part)
            if source_match:
                source_intf = source_match.group(1)
                if source_intf not in session['source_interfaces']:
                    session['source_interfaces'].append(source_intf)
            
            # Destination interface
            dest_match = re.search(r'output\s+interface\s+(\S+)', config_part)
            if dest_match:
                session['destination'] = dest_match.group(1)
        
        # Create SPAN sessions for analyzers
        for session_name, config in analyzer_sessions.items():
            if config['destination']:
                span = SPANSession(session_name, self.device_config.device_name)
                span.session_type = "local"
                span.source_interfaces = config['source_interfaces'].copy()
                span.destination_interface = config['destination']
                span.description = f"Port mirror session {session_name}"
                
                self.device_config.span_sessions.append(span)
                self.log(f"[Juniper JunOS] Found analyzer session: {session_name}")
    
    def create_administrative_endpoints(self) -> None:
        """
        Create Endpoint objects for all administrative servers.
        Populates the Endpoints tab with NTP, DNS, syslog, SNMP hosts, flow collectors.
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
            self.log(f"[Juniper JunOS] Created NTP endpoint: {ntp_server}")
        
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
            self.log(f"[Juniper JunOS] Created DNS endpoint: {dns_server}")
        
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
            self.log(f"[Juniper JunOS] Created Syslog endpoint: {syslog_server}")
        
        # jFlow collectors
        for netflow_config in self.device_config.netflow_configs:
            if netflow_config.exporter_destination:
                endpoint = Endpoint(
                    device_name=self.device_config.device_name,
                    name=f"jFlow-{netflow_config.exporter_destination}",
                    ip_address=netflow_config.exporter_destination
                )
                endpoint.endpoint_type = "jFlow Collector"
                endpoint.description = f"jFlow Collector (port {netflow_config.exporter_port})"
                endpoint.source_context = "Flow Monitoring Configuration"
                self.device_config.endpoints.append(endpoint)
                self.log(f"[Juniper JunOS] Created jFlow endpoint: {netflow_config.exporter_destination}")
