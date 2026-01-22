#!/usr/bin/env python3
"""
Synopsis:
    Eltex Network Equipment Configuration Parser - Complete Version

Description:
    Comprehensive parser for Eltex network equipment configurations.
    Eltex devices (MES, ESR series) use IOS-like syntax similar to Cisco.
    
    This parser extracts:
    - System configuration (hostname, domain, NTP, DNS, logging, SNMP)
    - Interfaces with full configuration
    - VLANs with interface assignments and descriptions
    - Routing (static routes, default gateway)
    - Monitoring (SPAN sessions, NetFlow)
    - Administrative endpoints (NTP servers, DNS servers, log hosts, SNMP hosts)

Supported Platforms:
    - MES Series (Managed Ethernet Switches)
    - ESR Series (Enterprise Service Routers)

Version: 2.2.1
"""

from typing import List, Optional
import re
from .base_parser import BaseParser
from shared_components.data_structures import (
    DeviceConfiguration, NetworkInterface, VLAN, Endpoint, Route
)
from shared_components.monitoring_structures import SPANSession, NetFlowConfig


class EltexParser(BaseParser):
    """Comprehensive parser for Eltex configurations (IOS-like syntax)."""
    
    def __init__(self, verbose: bool = False):
        super().__init__([], verbose)
        self.vendor = "eltex"
        self.platform = "eltex-mes"
    
    def detect_device_type(self) -> str:
        """Detect if device is ESR or MES series."""
        for line in self.config_lines[:20]:
            if 'ESR' in line.upper():
                return 'eltex-esr'
        return 'eltex-mes'
    
    def parse(self, config_lines: List[str]) -> DeviceConfiguration:
        """
        Main parsing method - orchestrates all parsing functions.
        
        Args:
            config_lines: List of configuration lines
            
        Returns:
            DeviceConfiguration object with all parsed data
        """
        self.config_lines = config_lines
        self.device_config = DeviceConfiguration()
        self.device_config.vendor = "eltex"
        self.device_config.platform = self.detect_device_type()
        
        self.log("Starting Eltex configuration parse")
        
        # Parse all sections
        self.parse_hostname()
        self.parse_system_config()  # Domain, NTP, DNS, SNMP, logging
        self.parse_administrative_access()  # Enable password, domain
        self.parse_user_accounts()  # Local users
        self.parse_line_config()  # VTY/Console lines
        self.parse_interfaces()
        self.parse_vlans()
        self.parse_routing()
        self.parse_monitoring_config()  # SPAN, NetFlow
        self.create_administrative_endpoints()  # Create endpoint objects
        
        self.log(f"Parsed {len(self.device_config.interfaces)} interfaces")
        self.log(f"Parsed {len(self.device_config.vlans)} VLANs")
        self.log(f"Parsed {len(self.device_config.routes)} routes")
        self.log(f"Parsed {len(self.device_config.span_sessions)} SPAN sessions")
        self.log(f"Parsed {len(self.device_config.netflow_configs)} NetFlow configs")
        self.log(f"Parsed {len(self.device_config.endpoints)} endpoints")
        
        return self.device_config
    
    def parse_hostname(self) -> Optional[str]:
        """Parse hostname from configuration."""
        for line in self.config_lines:
            match = re.match(r'^hostname\s+(\S+)', line.strip(), re.IGNORECASE)
            if match:
                hostname = match.group(1)
                self.device_config.hostname = hostname
                self.device_config.device_name = hostname
                self.log(f"Found hostname: {hostname}")
                return hostname
        
        # Fallback if hostname not found
        self.device_config.hostname = "Eltex-Device"
        self.device_config.device_name = "Eltex-Device"
        self.log("Hostname not found, using default: Eltex-Device")
        return "Eltex-Device"
    
    def parse_system_config(self) -> None:
        """
        Parse system configuration: domain name, NTP, DNS, SNMP, logging, hardware.
        Populates administration-related fields in DeviceConfiguration.
        """
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Hardware version from comments
            hw_match = re.match(r'!\s*Hardware Version:\s*(\S+)', line_stripped, re.IGNORECASE)
            if hw_match:
                self.device_config.model = hw_match.group(1)
                self.log(f"Found hardware: {hw_match.group(1)}")
            
            # Firmware/Software version from comments
            fw_match = re.match(r'!\s*Firmware Version:\s*(\S+)', line_stripped, re.IGNORECASE)
            if fw_match:
                self.device_config.os_version = fw_match.group(1)
                self.log(f"Found firmware: {fw_match.group(1)}")
            
            # Domain name
            domain_match = re.match(r'ip domain[- ]name\s+(\S+)', line_stripped, re.IGNORECASE)
            if domain_match:
                self.device_config.domain_name = domain_match.group(1)
                self.log(f"Found domain: {domain_match.group(1)}")
            
            # NTP servers
            ntp_match = re.match(r'ntp server\s+(\S+)', line_stripped, re.IGNORECASE)
            if ntp_match:
                ntp_server = ntp_match.group(1)
                if ntp_server not in self.device_config.ntp_servers:
                    self.device_config.ntp_servers.append(ntp_server)
                    self.log(f"Found NTP server: {ntp_server}")
            
            # DNS/Name servers
            dns_match = re.match(r'ip name-server\s+(\S+)', line_stripped, re.IGNORECASE)
            if dns_match:
                dns_server = dns_match.group(1)
                if dns_server not in self.device_config.name_servers:
                    self.device_config.name_servers.append(dns_server)
                    self.log(f"Found DNS server: {dns_server}")
            
            # Logging/Syslog hosts - multiple formats
            # Format 1: logging host <ip>
            log_match = re.match(r'logging host\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if log_match:
                log_host = log_match.group(1)
                if log_host not in self.device_config.logging_servers:
                    self.device_config.logging_servers.append(log_host)
                    self.log(f"Found logging host: {log_host}")
            
            # Format 2: syslog server <ip> [level xxx]
            syslog_match = re.match(r'syslog server\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if syslog_match:
                log_host = syslog_match.group(1)
                if log_host not in self.device_config.logging_servers:
                    self.device_config.logging_servers.append(log_host)
                    self.log(f"Found syslog server: {log_host}")
            
            # Format 3: syslog enable server <ip>
            syslog_match2 = re.match(r'syslog enable server\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if syslog_match2:
                log_host = syslog_match2.group(1)
                if log_host not in self.device_config.logging_servers:
                    self.device_config.logging_servers.append(log_host)
                    self.log(f"Found syslog server: {log_host}")
            
            # TACACS servers
            tacacs_match = re.match(r'tacacs server\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if tacacs_match:
                tacacs_server = tacacs_match.group(1)
                # Create TACACS endpoint
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'TACACS-{tacacs_server}', ip_address=tacacs_server)
                endpoint.endpoint_type = "TACACS+ Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found TACACS server: {tacacs_server}")
            
            # TACACS enable format
            tacacs_match2 = re.match(r'tacacs enable server\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if tacacs_match2:
                tacacs_server = tacacs_match2.group(1)
                # Create TACACS endpoint
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'TACACS-{tacacs_server}', ip_address=tacacs_server)
                endpoint.endpoint_type = "TACACS+ Server"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Found TACACS server: {tacacs_server}")
            
            # SNMP community - accumulate all communities
            snmp_match = re.match(r'snmp.*community\s+(\S+)\s+(ro|rw)', line_stripped, re.IGNORECASE)
            if snmp_match:
                community = snmp_match.group(1)
                access = snmp_match.group(2).upper()
                community_str = f"{community} ({access})"
                if self.device_config.snmp_community:
                    # Append to existing
                    self.device_config.snmp_community += f"; {community_str}"
                else:
                    # First community
                    self.device_config.snmp_community = community_str
                self.log(f"Found SNMP community: {community} ({access})")
            
            # SNMP host (trap destination)
            snmp_host_match = re.match(r'snmp.*host\s+(\d+\.\d+\.\d+\.\d+)', line_stripped, re.IGNORECASE)
            if snmp_host_match:
                snmp_host = snmp_host_match.group(1)
                # Store in AAA config for now
                if 'snmp_hosts' not in self.device_config.aaa_config:
                    self.device_config.aaa_config['snmp_hosts'] = []
                self.device_config.aaa_config['snmp_hosts'].append(snmp_host)
                self.log(f"Found SNMP trap host: {snmp_host}")
    
    def parse_administrative_access(self) -> None:
        """Parse administrative access configuration (enable password)."""
        self.log("Parsing administrative access")
        
        # Parse enable secret/password
        for line in self.config_lines:
            # Enable secret with encryption type
            enable_match = re.match(r'enable\s+secret\s+(\d+)\s+(.+)$', line, re.IGNORECASE)
            if enable_match:
                enc_type = enable_match.group(1)
                hash_val = enable_match.group(2)
                self.device_config.aaa_config['enable_secret'] = f"{enc_type} {hash_val}"
                self.log(f"Found enable secret (type {enc_type})")
                continue
            
            # Enable password
            enable_pw_match = re.match(r'enable\s+password\s+(?:(\d+)\s+)?(.+)$', line, re.IGNORECASE)
            if enable_pw_match:
                if enable_pw_match.group(1):
                    self.device_config.aaa_config['enable_password'] = f"{enable_pw_match.group(1)} {enable_pw_match.group(2)}"
                else:
                    self.device_config.aaa_config['enable_password'] = enable_pw_match.group(2)
                self.log(f"Found enable password")
                # Also set enable_secret if not already set
                if 'enable_secret' not in self.device_config.aaa_config:
                    self.device_config.aaa_config['enable_secret'] = self.device_config.aaa_config['enable_password']
                continue
        
        # If neither found, mark as not configured
        if 'enable_secret' not in self.device_config.aaa_config:
            self.device_config.aaa_config['enable_secret'] = 'Not configured'
    
    def parse_user_accounts(self) -> None:
        """Parse local user accounts."""
        self.log("Parsing user accounts")
        
        users = {}
        user_privileges = []
        credential_hashes = []
        
        for line in self.config_lines:
            # Username with password/secret (Eltex uses similar format to Cisco)
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
                    credential_hashes.append(f"{username}: {enc_type}")
                
                self.log(f"Found user: {username} (privilege {privilege})")
        
        # Store in AAA config
        if users:
            self.device_config.aaa_config['users'] = users
            self.device_config.aaa_config['user_privileges'] = '; '.join(user_privileges)
            if credential_hashes:
                self.device_config.aaa_config['credential_hashes'] = '; '.join(credential_hashes)
            else:
                self.device_config.aaa_config['credential_hashes'] = 'Not configured'
            self.log(f"Found {len(users)} user accounts")
        else:
            self.device_config.aaa_config['credential_hashes'] = 'Not configured'
    
    def parse_line_config(self) -> None:
        """Parse console and VTY line configuration."""
        self.log("Parsing line configurations")
        
        vty_details = []
        access_methods = set()
        management_acls = set()
        
        line_configs = []
        current_line = None
        
        for line in self.config_lines:
            # Line declaration (console, vty, aux)
            line_match = re.match(r'line\s+(console|vty|aux)\s+(.+)', line, re.IGNORECASE)
            if line_match:
                # Save previous line config
                if current_line:
                    line_configs.append(current_line)
                
                line_type = line_match.group(1)
                line_range = line_match.group(2)
                current_line = {
                    'type': f"{line_type} {line_range}",
                    'transport': '',
                    'acl': '',
                    'login': '',
                    'timeout': ''
                }
                continue
            
            # Parse line configuration commands
            if current_line and line.startswith(' '):
                config_line = line.strip()
                
                # Transport input/output
                transport_match = re.search(r'transport\s+(?:input|output)\s+(.+)', config_line, re.IGNORECASE)
                if transport_match:
                    protocols = transport_match.group(1)
                    current_line['transport'] = protocols
                    for proto in protocols.split():
                        access_methods.add(proto.upper())
                
                # Access class (ACL)
                acl_match = re.search(r'access-class\s+(\S+)', config_line, re.IGNORECASE)
                if acl_match:
                    current_line['acl'] = acl_match.group(1)
                    management_acls.add(acl_match.group(1))
                
                # Exec timeout
                timeout_match = re.search(r'exec-timeout\s+(\d+\s+\d+)', config_line, re.IGNORECASE)
                if timeout_match:
                    current_line['timeout'] = timeout_match.group(1)
                
                # Login authentication
                if 'login' in config_line.lower():
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
    
    def parse_interfaces(self) -> None:
        """
        Parse interface configurations with full details.
        Handles interface blocks with indented configuration.
        """
        current_interface = None
        in_interface_block = False
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Interface definition
            intf_match = re.match(r'interface\s+(.+)', line_stripped, re.IGNORECASE)
            if intf_match:
                intf_full_name = intf_match.group(1).strip()
                
                # Check if this is a VLAN interface (SVI)
                vlan_intf_match = re.match(r'vlan\s*(\d+)', intf_full_name, re.IGNORECASE)
                if vlan_intf_match:
                    # This is a VLAN interface (SVI) - Layer 3 interface for a VLAN
                    vlan_id = int(vlan_intf_match.group(1))
                    intf_name = f"vlan{vlan_id}"
                    
                    current_interface = NetworkInterface(intf_name)
                    current_interface.device_name = self.device_config.device_name
                    current_interface.interface_type = "SVI"
                    current_interface.vlan_id = vlan_id  # Store associated VLAN
                    self.device_config.interfaces.append(current_interface)
                    in_interface_block = True
                    self.log(f"Found VLAN interface (SVI): vlan{vlan_id}")
                    continue
                else:
                    # Regular interface
                    intf_name = intf_full_name
                    current_interface = NetworkInterface(intf_name)
                    current_interface.device_name = self.device_config.device_name
                    self.device_config.interfaces.append(current_interface)
                    in_interface_block = True
                    continue
            
            # Exit interface block (new section or explicit exit)
            if in_interface_block and (line_stripped.startswith('!') or 
                                      (not line.startswith(' ') and line_stripped and 
                                       not line_stripped.startswith('interface'))):
                in_interface_block = False
                current_interface = None
            
            if not in_interface_block or not current_interface:
                continue
            
            # Parse interface configuration
            # IP address
            ip_match = re.match(r'ip address\s+(\S+)\s+(\S+)', line_stripped, re.IGNORECASE)
            if ip_match:
                current_interface.ip_address = ip_match.group(1)
                current_interface.subnet_mask = ip_match.group(2)
            
            # IPv6 address
            ipv6_match = re.match(r'ipv6 address\s+([0-9a-fA-F:]+)/(\d+)', line_stripped, re.IGNORECASE)
            if ipv6_match:
                ipv6_addr = f"{ipv6_match.group(1)}/{ipv6_match.group(2)}"
                if not hasattr(current_interface, 'ipv6_addresses'):
                    current_interface.ipv6_addresses = []
                if ipv6_addr not in current_interface.ipv6_addresses:
                    current_interface.ipv6_addresses.append(ipv6_addr)
            
            # Description
            desc_match = re.match(r'description\s+(.+)', line_stripped, re.IGNORECASE)
            if desc_match:
                desc_text = desc_match.group(1).strip()
                # Remove surrounding quotes if present
                current_interface.description = desc_text.strip('"\'')
            
            # MTU
            mtu_match = re.match(r'mtu\s+(\d+)', line_stripped, re.IGNORECASE)
            if mtu_match:
                current_interface.mtu = int(mtu_match.group(1))
            
            # Switchport mode
            if re.match(r'switchport mode trunk', line_stripped, re.IGNORECASE):
                current_interface.trunk_mode = True
            elif re.match(r'switchport mode access', line_stripped, re.IGNORECASE):
                current_interface.trunk_mode = False
            
            # Switchport access VLAN
            access_vlan_match = re.match(r'switchport access vlan\s+(\d+)', line_stripped, re.IGNORECASE)
            if access_vlan_match:
                current_interface.access_vlan = int(access_vlan_match.group(1))
            
            # Switchport trunk allowed VLANs
            trunk_vlan_match = re.match(r'switchport trunk allowed vlan\s+(.+)', line_stripped, re.IGNORECASE)
            if trunk_vlan_match:
                vlan_list = trunk_vlan_match.group(1)
                # Parse VLAN ranges (e.g., "10,20,30" or "10-20,30")
                for vlan_part in vlan_list.split(','):
                    if '-' in vlan_part:
                        start, end = vlan_part.split('-')
                        current_interface.allowed_vlans.extend([str(v) for v in range(int(start), int(end)+1)])
                    else:
                        current_interface.allowed_vlans.append(vlan_part.strip())
            
            # Shutdown status
            if re.match(r'shutdown', line_stripped, re.IGNORECASE):
                current_interface.shutdown = True
            elif re.match(r'no shutdown', line_stripped, re.IGNORECASE):
                current_interface.shutdown = False
            
            # Speed
            speed_match = re.match(r'speed\s+(\S+)', line_stripped, re.IGNORECASE)
            if speed_match:
                current_interface.speed = speed_match.group(1)
            
            # Duplex
            duplex_match = re.match(r'duplex\s+(\S+)', line_stripped, re.IGNORECASE)
            if duplex_match:
                current_interface.duplex = duplex_match.group(1)
    
    def parse_vlans(self) -> None:
        """
        Parse VLAN database with interface assignments and descriptions.
        Handles both vlan database format and individual vlan commands.
        """
        in_vlan_database = False
        current_vlan_id = None
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # Enter VLAN database
            if re.match(r'vlan database', line_stripped, re.IGNORECASE):
                in_vlan_database = True
                continue
            
            # Exit VLAN database
            if in_vlan_database and re.match(r'exit', line_stripped, re.IGNORECASE):
                in_vlan_database = False
                continue
            
            # VLAN definition in database
            if in_vlan_database:
                vlan_match = re.match(r'vlan\s+(\d+)(?:\s+name\s+"?([^"\n]+)"?)?', line_stripped, re.IGNORECASE)
                if vlan_match:
                    vlan_id = int(vlan_match.group(1))
                    vlan_name = vlan_match.group(2) if vlan_match.group(2) else f"VLAN{vlan_id:04d}"
                    
                    vlan = VLAN(vlan_id)
                    vlan.name = vlan_name.strip()
                    vlan.device_name = self.device_config.device_name
                    vlan.state = "active"
                    self.device_config.vlans.append(vlan)
                    current_vlan_id = vlan_id
        
        # Link VLANs to interfaces
        for interface in self.device_config.interfaces:
            # Check if this is a VLAN interface (SVI)
            if hasattr(interface, 'vlan_id') and interface.vlan_id:
                # This is an SVI - link it to the VLAN and set gateway
                for vlan in self.device_config.vlans:
                    if vlan.vlan_id == interface.vlan_id:
                        # Set the VLAN's gateway IP from the SVI
                        if interface.ip_address:
                            vlan.gateway = interface.ip_address
                        # Add the SVI to the VLAN's interfaces
                        if interface.name not in vlan.interfaces:
                            vlan.interfaces.append(f"{interface.name} (SVI/gateway)")
                        self.log(f"Linked SVI {interface.name} to VLAN {vlan.vlan_id}, gateway: {interface.ip_address}")
                        break
            
            # Access mode interface
            if interface.access_vlan:
                for vlan in self.device_config.vlans:
                    if vlan.vlan_id == interface.access_vlan:
                        if interface.name not in vlan.interfaces:
                            vlan.interfaces.append(interface.name)
            
            # Trunk mode interface
            if interface.trunk_mode and interface.allowed_vlans:
                for allowed_vlan in interface.allowed_vlans:
                    try:
                        vlan_id = int(allowed_vlan)
                        for vlan in self.device_config.vlans:
                            if vlan.vlan_id == vlan_id:
                                if interface.name not in vlan.interfaces:
                                    vlan.interfaces.append(f"{interface.name} (trunk)")
                    except ValueError:
                        continue
    
    def parse_routing(self) -> None:
        """Parse routing configuration (static routes, default gateway)."""
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # IP default gateway
            gw_match = re.match(r'ip default-gateway\s+(\S+)', line_stripped, re.IGNORECASE)
            if gw_match:
                route = Route()
                route.destination_network = "0.0.0.0"
                route.destination_mask = "0.0.0.0"
                route.next_hop = gw_match.group(1)
                route.protocol = "static"
                route.device_name = self.device_config.device_name
                self.device_config.routes.append(route)
                self.log(f"Found default gateway: {gw_match.group(1)}")
            
            # IP route
            route_match = re.match(r'ip route\s+(\S+)\s+(\S+)\s+(\S+)', line_stripped, re.IGNORECASE)
            if route_match:
                route = Route()
                route.destination_network = route_match.group(1)
                route.destination_mask = route_match.group(2)
                route.next_hop = route_match.group(3)
                route.protocol = "static"
                route.device_name = self.device_config.device_name
                self.device_config.routes.append(route)
                self.log(f"Found static route: {route.destination_network}/{route.destination_mask} via {route.next_hop}")
    
    def parse_monitoring_config(self) -> None:
        """
        Parse monitoring configurations: SPAN sessions and NetFlow.
        Includes source interfaces, source VLANs, and destinations.
        """
        self._parse_span_sessions()
        self._parse_netflow()
    
    def _parse_span_sessions(self) -> None:
        """Parse SPAN (monitor session) configurations with full details."""
        from shared_components.monitoring_structures import SPANSession
        
        span_sessions = {}
        
        for line in self.config_lines:
            line_lower = line.lower()
            
            # Eltex format: monitor port source <int> destination <int>
            eltex_match = re.match(r'monitor\s+port\s+source\s+(\S+)\s+destination\s+(\S+)', line.strip(), re.IGNORECASE)
            if eltex_match:
                source_intf = eltex_match.group(1)
                dest_intf = eltex_match.group(2)
                
                # Create a SPAN session
                session_id = "1"  # Eltex doesn't use session IDs like Cisco
                span = SPANSession(session_id, self.device_config.device_name)
                span.session_type = 'local'
                span.description = f"Monitor port: {source_intf} to {dest_intf}"
                span.source_interfaces = [source_intf]
                span.destination_interface = dest_intf
                
                self.device_config.span_sessions.append(span)
                self.log(f"Found monitor port: {source_intf} -> {dest_intf}")
                continue
            
            # Standard Cisco format: monitor session <id>
            if 'monitor session' in line_lower:
                # Extract session ID
                session_match = re.search(r'monitor\s+session\s+(\d+)', line, re.IGNORECASE)
                if session_match:
                    session_id = session_match.group(1)
                    
                    if session_id not in span_sessions:
                        span = SPANSession(session_id, self.device_config.device_name)
                        span.session_type = 'local'
                        span.description = f"SPAN session {session_id}"
                        span.source_interfaces = []
                        span.source_vlans = []
                        
                        span_sessions[session_id] = span
                    
                    span = span_sessions[session_id]
                    
                    # Source interface
                    if 'source interface' in line_lower:
                        intf_match = re.search(r'interface\s+([\w/]+)', line, re.IGNORECASE)
                        if intf_match:
                            intf = intf_match.group(1)
                            if intf not in span.source_interfaces:
                                span.source_interfaces.append(intf)
                                self.log(f"SPAN session {session_id}: added source interface {intf}")
                    
                    # Source VLAN
                    if 'source vlan' in line_lower:
                        vlan_match = re.search(r'vlan\s+(\d+)', line, re.IGNORECASE)
                        if vlan_match:
                            vlan = vlan_match.group(1)
                            if vlan not in span.source_vlans:
                                span.source_vlans.append(vlan)
                                self.log(f"SPAN session {session_id}: added source VLAN {vlan}")
                    
                    # Destination interface
                    if 'destination interface' in line_lower:
                        intf_match = re.search(r'interface\s+([\w/]+)', line, re.IGNORECASE)
                        if intf_match:
                            span.destination_interface = intf_match.group(1)
                            self.log(f"SPAN session {session_id}: destination {span.destination_interface}")
        
        # Add all SPAN sessions to device config
        for span in span_sessions.values():
            self.device_config.span_sessions.append(span)
            self.log(f"Added SPAN session {span.session_id} with {len(span.source_interfaces)} interfaces, {len(span.source_vlans)} VLANs")
    
    def _parse_netflow(self) -> None:
        """Parse NetFlow export configuration with version and destinations."""
        from shared_components.monitoring_structures import NetFlowConfig
        
        netflow_version = None
        netflow_dests = []
        netflow_source = None
        flow_interfaces = []
        
        for line in self.config_lines:
            line_stripped = line.strip()
            
            # NetFlow version
            if 'ip flow-export version' in line.lower() or 'flow export version' in line.lower():
                ver_match = re.search(r'version\s+(\d+)', line, re.IGNORECASE)
                if ver_match:
                    netflow_version = ver_match.group(1)
                    self.log(f"Found NetFlow version: {netflow_version}")
            
            # NetFlow destination - Eltex format: flow export destination <ip> [port]
            eltex_dest_match = re.match(r'flow\s+export\s+destination\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?', line_stripped, re.IGNORECASE)
            if eltex_dest_match:
                dest_ip = eltex_dest_match.group(1)
                dest_port = eltex_dest_match.group(2) if eltex_dest_match.group(2) else '2055'
                netflow_dests.append((dest_ip, dest_port))
                self.log(f"Found NetFlow destination (Eltex format): {dest_ip}:{dest_port}")
                
                # Create endpoint for NetFlow collector
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{dest_ip}', ip_address=dest_ip)
                endpoint.endpoint_type = "NetFlow Collector"
                self.device_config.endpoints.append(endpoint)
                continue
            
            # NetFlow destination - Eltex format without "destination": flow export <ip> [port]
            eltex_dest_match2 = re.match(r'flow\s+export\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?', line_stripped, re.IGNORECASE)
            if eltex_dest_match2:
                dest_ip = eltex_dest_match2.group(1)
                dest_port = eltex_dest_match2.group(2) if eltex_dest_match2.group(2) else '2055'
                netflow_dests.append((dest_ip, dest_port))
                self.log(f"Found NetFlow destination (Eltex short format): {dest_ip}:{dest_port}")
                
                # Create endpoint for NetFlow collector
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{dest_ip}', ip_address=dest_ip)
                endpoint.endpoint_type = "NetFlow Collector"
                self.device_config.endpoints.append(endpoint)
                continue
            
            # NetFlow destination - Eltex MES format: flow control enable destination <ip> [port]
            eltex_dest_match3 = re.match(r'flow\s+control\s+enable\s+destination\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?', line_stripped, re.IGNORECASE)
            if eltex_dest_match3:
                dest_ip = eltex_dest_match3.group(1)
                dest_port = eltex_dest_match3.group(2) if eltex_dest_match3.group(2) else '2055'
                netflow_dests.append((dest_ip, dest_port))
                self.log(f"Found NetFlow destination (Eltex MES format): {dest_ip}:{dest_port}")
                
                # Create endpoint for NetFlow collector
                endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{dest_ip}', ip_address=dest_ip)
                endpoint.endpoint_type = "NetFlow Collector"
                self.device_config.endpoints.append(endpoint)
                continue
            
            # NetFlow destination - Standard IOS format
            if 'ip flow-export destination' in line.lower():
                dest_match = re.search(r'destination\s+([\d\.]+)\s+(\d+)', line, re.IGNORECASE)
                if dest_match:
                    dest_ip = dest_match.group(1)
                    dest_port = dest_match.group(2)
                    netflow_dests.append((dest_ip, dest_port))
                    self.log(f"Found NetFlow destination: {dest_ip}:{dest_port}")
                    
                    # Create endpoint
                    endpoint = Endpoint(device_name=self.device_config.device_name, name=f'NetFlow-{dest_ip}', ip_address=dest_ip)
                    endpoint.endpoint_type = "NetFlow Collector"
                    self.device_config.endpoints.append(endpoint)
            
            # NetFlow source interface
            if 'ip flow-export source' in line.lower() or 'flow export source' in line.lower():
                source_match = re.search(r'source\s+(\S+)', line, re.IGNORECASE)
                if source_match:
                    netflow_source = source_match.group(1)
                    self.log(f"Found NetFlow source: {netflow_source}")
            
            # Interface with flow enabled
            if re.match(r'ip flow (ingress|egress)', line_stripped, re.IGNORECASE):
                # Find the interface this belongs to
                for i, config_line in enumerate(self.config_lines):
                    if config_line.strip().lower() == line_stripped.lower():
                        # Look backwards for the interface statement
                        for j in range(i-1, max(0, i-20), -1):
                            intf_match = re.match(r'interface\s+(.+)', self.config_lines[j].strip(), re.IGNORECASE)
                            if intf_match:
                                intf_name = intf_match.group(1).strip()
                                direction = 'ingress' if 'ingress' in line.lower() else 'egress'
                                flow_interfaces.append((intf_name, direction))
                                self.log(f"Found NetFlow on interface {intf_name} ({direction})")
                                break
                        break
        
        # Create NetFlow config objects for each destination
        for dest_ip, dest_port in netflow_dests:
            netflow = NetFlowConfig("", self.device_config.device_name)
            netflow.version = f"v{netflow_version}" if netflow_version else "v5"
            netflow.collector_ip = dest_ip
            netflow.collector_port = dest_port
            netflow.source_interface = netflow_source if netflow_source else ""
            netflow.description = f"NetFlow export to {dest_ip}:{dest_port}"
            
            # Add interfaces where flow is enabled
            netflow.applied_interfaces = [f"{intf} ({direction})" for intf, direction in flow_interfaces]
            
            self.device_config.netflow_configs.append(netflow)
            self.log(f"Added NetFlow config: {dest_ip}:{dest_port} with {len(flow_interfaces)} interfaces")
    
    def create_administrative_endpoints(self) -> None:
        """
        Create Endpoint objects for all administrative servers.
        This populates the Endpoints tab with NTP, DNS, syslog, SNMP hosts.
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
            self.log(f"Created NTP endpoint: {ntp_server}")
        
        # Logging/Syslog hosts
        for log_host in self.device_config.logging_servers:
            endpoint = Endpoint(
                device_name=self.device_config.device_name,
                name=f"Syslog-{log_host}",
                ip_address=log_host
            )
            endpoint.endpoint_type = "Syslog Server"
            endpoint.description = "System Logging Server"
            endpoint.source_context = "System Configuration"
            self.device_config.endpoints.append(endpoint)
            self.log(f"Created Syslog endpoint: {log_host}")
        
        # SNMP trap hosts
        if 'snmp_hosts' in self.device_config.aaa_config:
            for snmp_host in self.device_config.aaa_config['snmp_hosts']:
                endpoint = Endpoint(
                    device_name=self.device_config.device_name,
                    name=f"SNMP-{snmp_host}",
                    ip_address=snmp_host
                )
                endpoint.endpoint_type = "SNMP Trap Host"
                endpoint.description = "SNMP Trap Destination"
                endpoint.source_context = "SNMP Configuration"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Created SNMP endpoint: {snmp_host}")
        
        # NetFlow collectors
        for netflow_config in self.device_config.netflow_configs:
            if netflow_config.exporter_destination:
                endpoint = Endpoint(
                    device_name=self.device_config.device_name,
                    name=f"NetFlow-{netflow_config.exporter_destination}",
                    ip_address=netflow_config.exporter_destination
                )
                endpoint.endpoint_type = "NetFlow Collector"
                endpoint.description = f"NetFlow {netflow_config.version} Collector (Port {netflow_config.exporter_port})"
                endpoint.source_context = "NetFlow Configuration"
                self.device_config.endpoints.append(endpoint)
                self.log(f"Created NetFlow collector endpoint: {netflow_config.exporter_destination}")


# End of eltex_parser.py