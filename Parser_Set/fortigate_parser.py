#!/usr/bin/env python3
"""
Synopsis:
    Fortigate FortiOS Configuration Parser - Comprehensive Implementation

Description:
    Complete parser for Fortinet FortiGate firewall configurations (FortiOS).
    Implements all lessons learned from multi-vendor parser development.
    
    Handles FortiOS config-block based syntax including:
    - System configuration (hostname, DNS, NTP, SNMP, logging)
    - Interfaces (physical and VLAN)
    - IPv4 and IPv6 addresses
    - VLANs and zones
    - Static routing
    - sFlow and NetFlow monitoring
    - Administrative endpoint creation

Configuration Format:
    config system global
        set hostname "FORTIGATE-FW-01"
        set timezone 04
    end
    
    config system interface
        edit "port1"
            set vdom "root"
            set ip 192.168.1.1 255.255.255.0
            set allowaccess ping https ssh
        next
    end

Key Features:
    - Complete system configuration parsing
    - IPv4 + IPv6 support
    - MTU parsing
    - VLAN parsing with interface assignments
    - sFlow and NetFlow monitoring
    - Administrative endpoint creation
    - Multiple SNMP community accumulation

Notes:
    - FortiOS uses config blocks with "edit"/"next"/"end" structure
    - Interface names are quoted strings (e.g., "port1", "internal")
    - VLANs can be standalone or assigned to interfaces

Version: 2.2.4
"""

from typing import List, Optional, Dict, Any
import re
from .base_parser import BaseParser
from shared_components.data_structures import (
    DeviceConfiguration, NetworkInterface, VLAN, Route, Endpoint
)
from shared_components.monitoring_structures import NetFlowConfig


class FortigateParser(BaseParser):
    """
    Comprehensive parser for Fortigate FortiOS configurations.
    
    Parses system config, interfaces, VLANs, routing, and monitoring.
    Creates administrative endpoints for NTP, DNS, syslog, SNMP hosts, flow collectors.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize Fortigate parser."""
        super().__init__([], verbose)
        self.vendor = "fortigate"
        self.platform = "fortios"
    
    def detect_device_type(self) -> str:
        """Detect Fortigate device type."""
        return 'fortios'
    
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Parse Fortigate FortiOS configuration.
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            DeviceConfiguration object with parsed data
        """
        self.config_lines = config_lines
        self.device_config = DeviceConfiguration()
        self.device_config.vendor = "fortigate"
        self.device_config.platform = "fortios"
        
        self.log("[Fortigate FortiOS] Starting FortiOS configuration parse")
        
        # Parse sections in logical order
        self.parse_hostname()
        self.parse_system_config()      # Domain, NTP, DNS, SNMP, logging
        self.parse_interfaces()
        self.parse_vlans()
        self.parse_routing()
        self.parse_monitoring_config()  # sFlow, NetFlow
        self.create_administrative_endpoints()
        
        self.log(f"[Fortigate FortiOS] Parsed {len(self.device_config.interfaces)} interfaces")
        self.log(f"[Fortigate FortiOS] Parsed {len(self.device_config.vlans)} VLANs")
        self.log(f"[Fortigate FortiOS] Parsed {len(self.device_config.routes)} routes")
        self.log(f"[Fortigate FortiOS] Parsed {len(self.device_config.netflow_configs)} flow configs")
        self.log(f"[Fortigate FortiOS] Parsed {len(self.device_config.endpoints)} endpoints")
        
        return self.device_config
    
    def parse_hostname(self) -> Optional[str]:
        """
        Parse hostname from config system global block.
        
        Format:
            config system global
                set hostname "FORTIGATE-FW-01"
            end
        """
        in_global = False
        for line in self.config_lines:
            if 'config system global' in line:
                in_global = True
            elif in_global and 'set hostname' in line:
                match = re.search(r'set hostname\s+"?([^"\n]+)"?', line, re.IGNORECASE)
                if match:
                    hostname = self.strip_quotes(match.group(1))
                    self.device_config.hostname = hostname
                    self.device_config.device_name = hostname
                    self.log(f"[Fortigate FortiOS] Found hostname: {hostname}")
                    return hostname
            elif in_global and line.strip() == 'end':
                in_global = False
        return None
    
    def parse_system_config(self) -> None:
        # Initialize server lists
        self.device_config.name_servers = []
        self.device_config.ntp_servers = []
        self.device_config.logging_servers = []

        """
        Parse system configuration: domain, NTP, DNS, SNMP, logging.
        
        Formats:
            config system dns
                set primary 10.1.1.20
                set secondary 10.1.1.21
            end
            
            config system ntp
                set ntpsync enable
                set server-mode enable
                config ntpserver
                    edit 1
                        set server "10.1.1.10"
                    next
                end
            end
            
            config log syslogd setting
                set status enable
                set server "10.1.1.60"
            end
            
            config system snmp community
                edit 1
                    set name "public"
                    set query-v1-status enable
                next
            end
        """
        # Parse DNS
        in_dns_block = False
        for line in self.config_lines:
            if 'config system dns' in line:
                in_dns_block = True
            elif in_dns_block:
                if 'set primary' in line:
                    match = re.search(r'set primary\s+(\S+)', line)
                    if match:
                        dns_server = self.strip_quotes(match.group(1))
                        if dns_server not in self.device_config.name_servers:
                            self.device_config.name_servers.append(dns_server)
                            self.log(f"[Fortigate FortiOS] Found DNS server (primary): {dns_server}")
                elif 'set secondary' in line:
                    match = re.search(r'set secondary\s+(\S+)', line)
                    if match:
                        dns_server = self.strip_quotes(match.group(1))
                        if dns_server not in self.device_config.name_servers:
                            self.device_config.name_servers.append(dns_server)
                            self.log(f"[Fortigate FortiOS] Found DNS server (secondary): {dns_server}")
                elif 'end' in line:
                    in_dns_block = False
        
        # Parse NTP
        in_ntp_block = False
        in_ntpserver_block = False
        for line in self.config_lines:
            if 'config system ntp' in line:
                in_ntp_block = True
            elif in_ntp_block:
                if 'config ntpserver' in line:
                    in_ntpserver_block = True
                elif in_ntpserver_block:
                    if 'set server' in line:
                        match = re.search(r'set server\s+"?([^"\n]+)"?', line)
                        if match:
                            ntp_server = self.strip_quotes(match.group(1))
                            if ntp_server not in self.device_config.ntp_servers:
                                self.device_config.ntp_servers.append(ntp_server)
                                self.log(f"[Fortigate FortiOS] Found NTP server: {ntp_server}")
                    elif 'end' in line:
                        in_ntpserver_block = False
                elif 'end' in line and not in_ntpserver_block:
                    in_ntp_block = False
        
        # Parse Syslog
        in_syslog_block = False
        for line in self.config_lines:
            if 'config log syslogd' in line or 'config log syslogd2' in line or 'config log syslogd3' in line:
                in_syslog_block = True
            elif in_syslog_block:
                if 'set server' in line:
                    match = re.search(r'set server\s+"?([^"\n]+)"?', line)
                    if match:
                        syslog_server = self.strip_quotes(match.group(1))
                        if syslog_server not in self.device_config.logging_servers:
                            self.device_config.logging_servers.append(syslog_server)
                            self.log(f"[Fortigate FortiOS] Found syslog server: {syslog_server}")
                elif 'end' in line:
                    in_syslog_block = False
        
        # Parse SNMP communities - accumulate all
        in_snmp_community = False
        in_nested_block = False  # Track nested config blocks like "config hosts"
        nested_depth = 0
        current_community_name = ""
        current_community_access = "RO"
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if 'config system snmp community' in line_stripped:
                in_snmp_community = True
                nested_depth = 0
            elif in_snmp_community:
                # Track nested config blocks (like "config hosts")
                if line_stripped.startswith('config ') and 'config system snmp community' not in line_stripped:
                    nested_depth += 1
                elif line_stripped == 'end':
                    if nested_depth > 0:
                        # This is closing a nested block, not the community block
                        nested_depth -= 1
                    else:
                        # This is closing the entire SNMP community block
                        in_snmp_community = False
                elif line_stripped.startswith('set name'):
                    match = re.search(r'set name\s+"?([^"\n]+)"?', line_stripped)
                    if match:
                        current_community_name = self.strip_quotes(match.group(1))
                elif 'set query-v1-status enable' in line_stripped or 'set query-v2c-status enable' in line_stripped:
                    current_community_access = "RO"
                elif 'set trap-v1-status enable' in line_stripped or 'set trap-v2c-status enable' in line_stripped:
                    # Traps usually indicate RW or at least more than RO
                    current_community_access = "RW"
                elif line_stripped == 'next' and nested_depth == 0:
                    # Only process 'next' at the top level (not in nested blocks)
                    if current_community_name:
                        community_str = f"{current_community_name} ({current_community_access})"
                        if self.device_config.snmp_community:
                            if community_str not in self.device_config.snmp_community:
                                self.device_config.snmp_community += f"; {community_str}"
                        else:
                            self.device_config.snmp_community = community_str
                        self.log(f"[Fortigate FortiOS] Found SNMP community: {current_community_name} ({current_community_access})")
                        current_community_name = ""
                        current_community_access = "RO"
        
        # Parse domain name (from system global)
        in_global = False
        for line in self.config_lines:
            if 'config system global' in line:
                in_global = True
            elif in_global:
                if 'set hostname' in line:
                    # Extract domain from FQDN if present
                    match = re.search(r'set hostname\s+"?([^"\n]+)"?', line)
                    if match:
                        hostname = self.strip_quotes(match.group(1))
                        if '.' in hostname:
                            parts = hostname.split('.', 1)
                            if len(parts) > 1:
                                self.device_config.domain_name = parts[1]
                                self.log(f"[Fortigate FortiOS] Found domain from FQDN: {parts[1]}")
                elif 'end' in line:
                    in_global = False
    
    def parse_interfaces(self) -> None:
        """
        Parse interfaces from config system interface blocks.
        
        Formats:
            config system interface
                edit "port1"
                    set vdom "root"
                    set ip 192.168.1.1 255.255.255.0
                    set allowaccess ping https ssh
                    set description "WAN Interface"
                    set mtu 1500
                next
                edit "port2"
                    set vdom "root"
                    set mode dhcp
                    set description "Internal Network"
                    set mtu 9000
                next
                edit "vlan10"
                    set vdom "root"
                    set ip 10.10.1.1 255.255.255.0
                    set interface "internal"
                    set vlanid 10
                next
            end
        """
        in_interface_block = False
        current_interface = None
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if line_stripped.startswith('config system interface'):
                in_interface_block = True
                continue
            
            if not in_interface_block:
                continue
            
            if line_stripped == 'end':
                in_interface_block = False
                current_interface = None
                continue
            
            # Edit interface
            edit_match = re.match(r'edit\s+"?([^"\n]+)"?', line_stripped, re.IGNORECASE)
            if edit_match:
                intf_name = self.strip_quotes(edit_match.group(1))
                current_interface = NetworkInterface(intf_name)
                current_interface.device_name = self.device_config.device_name
                self.device_config.interfaces.append(current_interface)
                continue
            
            if not current_interface:
                continue
            
            # Parse interface settings
            if line_stripped.startswith('set ip'):
                ip_match = re.search(r'set ip\s+(\S+)\s+(\S+)', line_stripped, re.IGNORECASE)
                if ip_match:
                    current_interface.ip_address = ip_match.group(1)
                    current_interface.subnet_mask = ip_match.group(2)
            
            elif line_stripped.startswith('set description'):
                desc_match = re.search(r'set description\s+"?([^"\n]+)"?', line_stripped, re.IGNORECASE)
                if desc_match:
                    current_interface.description = self.strip_quotes(desc_match.group(1))
            
            elif line_stripped.startswith('set vlanid'):
                vlan_match = re.search(r'set vlanid\s+(\d+)', line_stripped, re.IGNORECASE)
                if vlan_match:
                    current_interface.vlan = int(vlan_match.group(1))
            
            elif line_stripped.startswith('set mtu'):
                mtu_match = re.search(r'set mtu\s+(\d+)', line_stripped, re.IGNORECASE)
                if mtu_match:
                    current_interface.mtu = int(mtu_match.group(1))
            
            elif line_stripped.startswith('set interface'):
                # Physical interface this VLAN is on
                parent_match = re.search(r'set interface\s+"?([^"\n]+)"?', line_stripped, re.IGNORECASE)
                if parent_match:
                    current_interface.parent_interface = self.strip_quotes(parent_match.group(1))
            
            elif 'set status' in line_stripped:
                current_interface.status = 'up' if 'up' in line_stripped else 'down'
            
            # IPv6 address
            elif line_stripped.startswith('set ipv6'):
                # FortiOS IPv6 can be in different formats
                ipv6_match = re.search(r'set ipv6\s+(\S+)', line_stripped, re.IGNORECASE)
                if ipv6_match:
                    ipv6_addr = ipv6_match.group(1)
                    if ipv6_addr and ipv6_addr != '::':
                        if not hasattr(current_interface, 'ipv6_addresses'):
                            current_interface.ipv6_addresses = []
                        current_interface.ipv6_addresses.append(ipv6_addr)
    
    def parse_vlans(self) -> None:
        """
        Parse VLANs and link to interfaces.
        
        In FortiOS, VLANs are configured as interfaces with vlanid set.
        We create VLAN objects from these VLAN interfaces.
        """
        for interface in self.device_config.interfaces:
            if hasattr(interface, 'vlan') and interface.vlan:
                vlan_id = interface.vlan
                
                # Check if VLAN already exists
                existing_vlan = None
                for vlan in self.device_config.vlans:
                    if vlan.vlan_id == vlan_id:
                        existing_vlan = vlan
                        break
                
                if not existing_vlan:
                    # Create new VLAN
                    vlan = VLAN(vlan_id)
                    vlan.name = interface.name
                    vlan.device_name = self.device_config.device_name
                    vlan.description = interface.description or f"VLAN {vlan_id}"
                    
                    # Set gateway if interface has IP
                    if interface.ip_address:
                        vlan.gateway = interface.ip_address
                    
                    # Link this interface to the VLAN
                    if interface.name not in vlan.interfaces:
                        vlan.interfaces.append(f"{interface.name} (gateway)")
                    
                    # If there's a parent interface, link it too
                    if hasattr(interface, 'parent_interface') and interface.parent_interface:
                        if interface.parent_interface not in vlan.interfaces:
                            vlan.interfaces.append(interface.parent_interface)
                    
                    self.device_config.vlans.append(vlan)
                    self.log(f"[Fortigate FortiOS] Parsed VLAN {vlan_id}: {vlan.name}")
    
    def parse_routing(self) -> None:
        """
        Parse static routes from config router static blocks.
        
        Format:
            config router static
                edit 1
                    set dst 0.0.0.0 0.0.0.0
                    set gateway 192.168.1.254
                    set device "port1"
                next
                edit 2
                    set dst 10.0.0.0 255.0.0.0
                    set gateway 10.1.1.254
                next
            end
        """
        in_static_block = False
        current_route = {}
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            if line_stripped.startswith('config router static'):
                in_static_block = True
                continue
            
            if not in_static_block:
                continue
            
            if line_stripped == 'end':
                in_static_block = False
                continue
            
            if line_stripped.startswith('edit'):
                # Start new route
                current_route = {}
            
            elif line_stripped.startswith('set dst'):
                match = re.search(r'set dst\s+(\S+)\s+(\S+)', line_stripped)
                if match:
                    current_route['network'] = match.group(1)
                    current_route['mask'] = match.group(2)
            
            elif line_stripped.startswith('set gateway'):
                match = re.search(r'set gateway\s+(\S+)', line_stripped)
                if match:
                    current_route['gateway'] = match.group(1)
            
            elif line_stripped.startswith('set device'):
                match = re.search(r'set device\s+"?([^"\n]+)"?', line_stripped)
                if match:
                    current_route['interface'] = self.strip_quotes(match.group(1))
            
            elif line_stripped == 'next':
                # End of route entry - create Route object
                if 'network' in current_route and 'mask' in current_route:
                    route = Route()
                    route.destination = current_route['network']
                    route.mask = current_route['mask']
                    route.next_hop = current_route.get('gateway', '')
                    route.interface = current_route.get('interface', '')
                    route.device_name = self.device_config.device_name
                    route.route_type = "static"
                    
                    self.device_config.routes.append(route)
                    self.log(f"[Fortigate FortiOS] Found static route: {route.destination}/{route.mask} via {route.next_hop}")
                
                current_route = {}
    
    def parse_monitoring_config(self) -> None:
        """
        Parse sFlow and NetFlow configurations.
        
        Formats:
            config system sflow
                set collector-ip 10.1.100.10
                set collector-port 6343
            end
            
            config system netflow
                set collector-ip 10.1.100.20
                set collector-port 2055
            end
        """
        # Parse sFlow
        in_sflow_block = False
        sflow_config = {}
        
        for line in self.config_lines:
            if 'config system sflow' in line:
                in_sflow_block = True
                sflow_config = {}
            elif in_sflow_block:
                if 'set collector-ip' in line:
                    match = re.search(r'set collector-ip\s+(\S+)', line)
                    if match:
                        sflow_config['ip'] = match.group(1)
                elif 'set collector-port' in line:
                    match = re.search(r'set collector-port\s+(\d+)', line)
                    if match:
                        sflow_config['port'] = int(match.group(1))
                elif 'end' in line:
                    if 'ip' in sflow_config:
                        netflow = NetFlowConfig("", self.device_config.device_name)
                        netflow.version = 'sFlow'
                        netflow.exporter_destination = sflow_config['ip']
                        netflow.exporter_port = sflow_config.get('port', 6343)
                        netflow.description = f"sFlow export to {sflow_config['ip']}:{netflow.exporter_port}"
                        
                        self.device_config.netflow_configs.append(netflow)
                        self.log(f"[Fortigate FortiOS] Found sFlow collector: {sflow_config['ip']}:{netflow.exporter_port}")
                    
                    in_sflow_block = False
        
        # Parse NetFlow
        in_netflow_block = False
        netflow_config = {}
        
        for line in self.config_lines:
            if 'config system netflow' in line:
                in_netflow_block = True
                netflow_config = {}
            elif in_netflow_block:
                if 'set collector-ip' in line:
                    match = re.search(r'set collector-ip\s+(\S+)', line)
                    if match:
                        netflow_config['ip'] = match.group(1)
                elif 'set collector-port' in line:
                    match = re.search(r'set collector-port\s+(\d+)', line)
                    if match:
                        netflow_config['port'] = int(match.group(1))
                elif 'end' in line:
                    if 'ip' in netflow_config:
                        netflow = NetFlowConfig("", self.device_config.device_name)
                        netflow.version = 'NetFlow v5'
                        netflow.exporter_destination = netflow_config['ip']
                        netflow.exporter_port = netflow_config.get('port', 2055)
                        netflow.collector_ip = netflow_config['ip']  # For endpoint correlation
                        netflow.collector_port = str(netflow_config.get('port', 2055))  # For endpoint correlation
                        netflow.description = f"NetFlow export to {netflow_config['ip']}:{netflow.exporter_port}"
                        
                        self.device_config.netflow_configs.append(netflow)
                        self.log(f"[Fortigate FortiOS] Found NetFlow collector: {netflow_config['ip']}:{netflow.exporter_port}")
                    
                    in_netflow_block = False
    
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
            self.log(f"[Fortigate FortiOS] Created NTP endpoint: {ntp_server}")
        
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
            self.log(f"[Fortigate FortiOS] Created DNS endpoint: {dns_server}")
        
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
            self.log(f"[Fortigate FortiOS] Created Syslog endpoint: {syslog_server}")
        
        # Flow collectors (sFlow and NetFlow)
        for netflow_config in self.device_config.netflow_configs:
            if netflow_config.exporter_destination:
                flow_type = "sFlow" if "sflow" in netflow_config.version.lower() else "NetFlow"
                endpoint = Endpoint(
                    device_name=self.device_config.device_name,
                    name=f"{flow_type}-{netflow_config.exporter_destination}",
                    ip_address=netflow_config.exporter_destination
                )
                endpoint.endpoint_type = f"{flow_type} Collector"
                endpoint.description = f"{flow_type} Collector (port {netflow_config.exporter_port})"
                endpoint.source_context = "Flow Monitoring Configuration"
                self.device_config.endpoints.append(endpoint)
                self.log(f"[Fortigate FortiOS] Created {flow_type} endpoint: {netflow_config.exporter_destination}")
    
    def strip_quotes(self, text: str) -> str:
        """Remove surrounding quotes from text."""
        return text.strip('"\'')