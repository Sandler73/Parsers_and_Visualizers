#!/usr/bin/env python3
"""
Synopsis:
    GlobalProtect VPN XML Configuration Parser for Palo Alto PAN-OS

Description:
    This module provides comprehensive parsing of GlobalProtect VPN configurations
    from Palo Alto PAN-OS XML configuration files. It extracts portals, gateways,
    HIP objects/profiles, authentication settings, tunnel configurations, and
    correlates network access rules (ACLs, zones, VLANs, accessible networks).
    
    The parser handles the complete XML hierarchy of Palo Alto configurations,
    including:
    - GlobalProtect portals with agent configurations
    - GlobalProtect gateways with tunnel and client settings
    - Host Information Profile (HIP) objects and profiles
    - Authentication infrastructure (profiles, certificates)
    - Network objects referenced by GlobalProtect
    - Security policies affecting GlobalProtect traffic
    - Cross-references between zones, addresses, and services

Notes:
    - Supports PAN-OS XML format (running-config.xml / candidate-config.xml)
    - Handles both firewall and Panorama configurations
    - Parses multi-vsys setups
    - Correlates network access across security policies and zones
    - No external dependencies (uses Python xml.etree.ElementTree)

Version: 3.0.0
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any, Set
from shared_components.globalprotect_structures import (
    GlobalProtectData,
    GlobalProtectPortal,
    GlobalProtectGateway,
    AgentConfiguration,
    HIPObject,
    HIPProfile,
    AuthenticationProfile,
    CertificateProfile,
    SSLTLSProfile,
    TunnelInterface,
    SecurityPolicy
)


class GlobalProtectXMLParser:
    """
    Parser for extracting GlobalProtect VPN configurations from Palo Alto XML.
    
    This parser navigates the complex XML structure of PAN-OS configurations
    and extracts all GlobalProtect-related data including network access rules.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the GlobalProtect XML parser.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.root = None
        self.device_name = "Unknown"
        
        # Cached network objects for cross-referencing
        self.zones = {}
        self.address_objects = {}
        self.service_objects = {}
        self.security_policies = []
    
    def log(self, message: str) -> None:
        """Log message if verbose mode enabled."""
        if self.verbose:
            print(f"[GP Parser] {message}")
    
    def parse_from_file(self, xml_path: str) -> GlobalProtectData:
        """
        Parse GlobalProtect data from XML file.
        
        Args:
            xml_path: Path to PAN-OS XML configuration file
            
        Returns:
            GlobalProtectData object with all parsed information
        """
        self.log(f"Parsing XML file: {xml_path}")
        
        try:
            tree = ET.parse(xml_path)
            self.root = tree.getroot()
        except Exception as e:
            self.log(f"Error parsing XML file: {e}")
            raise
        
        return self.parse_from_element(self.root)
    
    def parse_from_string(self, xml_content: str) -> GlobalProtectData:
        """
        Parse GlobalProtect data from XML string.
        
        Args:
            xml_content: XML configuration as string
            
        Returns:
            GlobalProtectData object with all parsed information
        """
        self.log("Parsing XML content")
        
        try:
            self.root = ET.fromstring(xml_content)
        except Exception as e:
            self.log(f"Error parsing XML content: {e}")
            raise
        
        return self.parse_from_element(self.root)
    
    def parse_from_lines(self, config_lines: List[str]) -> GlobalProtectData:
        """
        Parse GlobalProtect data from configuration lines.
        
        Args:
            config_lines: List of configuration file lines
            
        Returns:
            GlobalProtectData object with all parsed information
        """
        xml_content = '\n'.join(config_lines)
        return self.parse_from_string(xml_content)
    
    def parse_from_element(self, root_element: ET.Element) -> GlobalProtectData:
        """
        Parse GlobalProtect data from XML Element.
        
        Args:
            root_element: Root XML element
            
        Returns:
            GlobalProtectData object with all parsed information
        """
        self.root = root_element
        
        # Find device entry (localhost.localdomain or specific device)
        device_entry = self._find_device_entry()
        if device_entry is None:
            self.log("No device entry found in XML")
            return GlobalProtectData(device_name=self.device_name)
        
        # Extract device name and hostname
        self.device_name = device_entry.get('name', 'Unknown')
        hostname = self._get_text(device_entry, './/hostname', 'Unknown')
        management_ip = self._get_text(device_entry, './/ip-address', '')
        
        self.log(f"Device: {self.device_name}, Hostname: {hostname}")
        
        # Create data container
        gp_data = GlobalProtectData(
            device_name=self.device_name,
            hostname=hostname,
            management_ip=management_ip
        )
        
        # Parse network objects first (needed for cross-referencing)
        self._parse_network_objects(device_entry, gp_data)
        
        # Parse security policies (for network access correlation)
        self._parse_security_policies(device_entry, gp_data)
        
        # Parse GlobalProtect configurations
        self._parse_portals(device_entry, gp_data)
        self._parse_gateways(device_entry, gp_data)
        
        # Parse HIP objects and profiles
        self._parse_hip_objects(device_entry, gp_data)
        self._parse_hip_profiles(device_entry, gp_data)
        
        # Parse supporting infrastructure
        self._parse_authentication_profiles(device_entry, gp_data)
        self._parse_certificate_profiles(device_entry, gp_data)
        self._parse_ssl_tls_profiles(device_entry, gp_data)
        self._parse_tunnel_interfaces(device_entry, gp_data)
        
        # Correlate network access for portals and gateways
        self._correlate_network_access(gp_data)
        
        self.log(f"Parsed {gp_data.total_portals} portals, {gp_data.total_gateways} gateways, "
                f"{gp_data.total_hip_objects} HIP objects")
        
        return gp_data
    
    def _find_device_entry(self) -> Optional[ET.Element]:
        """Find the device entry element in XML."""
        # Try common paths
        paths = [
            ".//devices/entry[@name='localhost.localdomain']",
            ".//devices/entry",
            ".//entry[@name='localhost.localdomain']"
        ]
        
        for path in paths:
            element = self.root.find(path)
            if element is not None:
                return element
        
        return None
    
    def _get_text(self, element: ET.Element, path: str, default: str = '') -> str:
        """
        Safely get text from XML element.
        
        Args:
            element: Parent element
            path: XPath to child element
            default: Default value if not found
            
        Returns:
            Element text or default
        """
        child = element.find(path)
        if child is not None and child.text:
            return child.text.strip()
        return default
    
    def _get_members(self, element: ET.Element, path: str) -> List[str]:
        """
        Get list of member elements.
        
        Args:
            element: Parent element
            path: XPath to member container
            
        Returns:
            List of member values
        """
        members = []
        container = element.find(path)
        if container is not None:
            for member in container.findall('member'):
                if member.text:
                    members.append(member.text.strip())
        return members
    
    def _parse_network_objects(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse zones, address objects, and service objects for cross-referencing."""
        self.log("Parsing network objects")
        
        # Find vsys entry (usually vsys1)
        vsys_entries = device_entry.findall('.//vsys/entry')
        for vsys_entry in vsys_entries:
            vsys_name = vsys_entry.get('name', 'vsys1')
            
            # Parse zones
            for zone_entry in vsys_entry.findall('.//zone/entry'):
                zone_name = zone_entry.get('name', '')
                if zone_name:
                    zone_info = {
                        'name': zone_name,
                        'network_type': self._get_text(zone_entry, 'network/layer3', 'layer3'),
                        'interfaces': self._get_members(zone_entry, 'network/layer3/member')
                    }
                    gp_data.zones[zone_name] = zone_info
                    self.zones[zone_name] = zone_info
            
            # Parse address objects
            for addr_entry in vsys_entry.findall('.//address/entry'):
                addr_name = addr_entry.get('name', '')
                if addr_name:
                    # Try different address types
                    ip_netmask = self._get_text(addr_entry, 'ip-netmask', '')
                    ip_range = self._get_text(addr_entry, 'ip-range', '')
                    fqdn = self._get_text(addr_entry, 'fqdn', '')
                    
                    value = ip_netmask or ip_range or fqdn or 'any'
                    gp_data.address_objects[addr_name] = value
                    self.address_objects[addr_name] = value
            
            # Parse service objects
            for svc_entry in vsys_entry.findall('.//service/entry'):
                svc_name = svc_entry.get('name', '')
                if svc_name:
                    protocol = self._get_text(svc_entry, 'protocol/tcp/port', '')
                    if not protocol:
                        protocol = self._get_text(svc_entry, 'protocol/udp/port', '')
                    if not protocol:
                        protocol = 'any'
                    gp_data.service_objects[svc_name] = protocol
                    self.service_objects[svc_name] = protocol
        
        self.log(f"Parsed {len(self.zones)} zones, {len(self.address_objects)} addresses, "
                f"{len(self.service_objects)} services")
    
    def _parse_security_policies(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse security policies that may apply to GlobalProtect traffic."""
        self.log("Parsing security policies")
        
        vsys_entries = device_entry.findall('.//vsys/entry')
        for vsys_entry in vsys_entries:
            # Parse all rulebases (pre, main, post)
            for rulebase_path in ['.//rulebase/security/rules', './/pre-rulebase/security/rules', './/post-rulebase/security/rules']:
                rules_container = vsys_entry.find(rulebase_path)
                if rules_container is not None:
                    for rule_entry in rules_container.findall('entry'):
                        policy = self._parse_security_policy(rule_entry)
                        if policy:
                            gp_data.security_policies.append(policy)
                            self.security_policies.append(policy)
        
        self.log(f"Parsed {len(gp_data.security_policies)} security policies")
    
    def _parse_security_policy(self, rule_entry: ET.Element) -> Optional[SecurityPolicy]:
        """Parse a single security policy rule."""
        name = rule_entry.get('name', '')
        if not name:
            return None
        
        policy = SecurityPolicy(name=name)
        
        # Source zones
        policy.source_zones = self._get_members(rule_entry, 'from')
        
        # Destination zones
        policy.destination_zones = self._get_members(rule_entry, 'to')
        
        # Source addresses
        policy.source_addresses = self._get_members(rule_entry, 'source')
        
        # Destination addresses
        policy.destination_addresses = self._get_members(rule_entry, 'destination')
        
        # Source users
        policy.source_users = self._get_members(rule_entry, 'source-user')
        
        # Applications
        policy.applications = self._get_members(rule_entry, 'application')
        
        # Services
        policy.services = self._get_members(rule_entry, 'service')
        
        # Action
        policy.action = self._get_text(rule_entry, 'action', 'allow')
        
        # HIP profiles
        policy.hip_profiles = self._get_members(rule_entry, 'hip-profiles')
        
        # Log setting
        policy.log_setting = self._get_text(rule_entry, 'log-setting', '')
        
        # Profile group
        policy.profile_group = self._get_text(rule_entry, 'profile-setting/group', '')
        
        return policy
    
    def _parse_portals(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse GlobalProtect portal configurations."""
        self.log("Parsing GlobalProtect portals")
        
        # Correct path for actual Palo Alto configs: /network/global-protect/portals/entry
        portal_path = './/network/global-protect/portals/entry'
        
        # Try alternative paths if not found
        if device_entry.find(portal_path) is None:
            portal_path = './/global-protect/portals/entry'
        if device_entry.find(portal_path) is None:
            portal_path = './/globalprotect/portals/entry'
        
        for portal_entry in device_entry.findall(portal_path):
            portal = self._parse_portal(portal_entry)
            if portal:
                gp_data.portals.append(portal)
    
    def _parse_portal(self, portal_entry: ET.Element) -> Optional[GlobalProtectPortal]:
        """Parse a single GlobalProtect portal."""
        name = portal_entry.get('name', '')
        if not name:
            return None
        
        self.log(f"  Parsing portal: {name}")
        
        portal = GlobalProtectPortal(name=name)
        
        # Network settings
        portal.interface = self._get_text(portal_entry, 'network/interface', '')
        portal.ipv4_address = self._get_text(portal_entry, 'network/ip/ipv4', '')
        portal.ipv6_address = self._get_text(portal_entry, 'network/ip/ipv6', '')
        portal.fqdn = self._get_text(portal_entry, 'network/fqdn', '')
        
        port_text = self._get_text(portal_entry, 'network/port', '443')
        try:
            portal.port = int(port_text)
        except:
            portal.port = 443
        
        # Enabled status
        enabled_text = self._get_text(portal_entry, 'enable', 'yes')
        portal.enabled = (enabled_text.lower() == 'yes')
        
        # SSL/TLS and authentication
        portal.ssl_tls_profile = self._get_text(portal_entry, 'authentication/server-auth/ssl-tls-service-profile', '')
        portal.authentication_profile = self._get_text(portal_entry, 'authentication/authentication-profile', '')
        
        # Try actual PAN-OS structure if not found
        if not portal.authentication_profile:
            portal.authentication_profile = self._get_text(portal_entry, 'authentication/client-auth/entry/server-profile', '')
        
        portal.certificate_profile = self._get_text(portal_entry, 'authentication/client-auth/entry/certificate-profile', '')
        
        portal.description = self._get_text(portal_entry, 'description', '')
        
        # Authentication override (cookie settings)
        auth_override = portal_entry.find('authentication-override')
        if auth_override is not None:
            generate_cookie = self._get_text(auth_override, 'generate-cookie', 'no')
            portal.auth_override_enabled = (generate_cookie.lower() == 'yes')
            
            lifetime_days = self._get_text(auth_override, 'cookie-lifetime/days', '1')
            try:
                portal.auth_cookie_lifetime_days = int(lifetime_days)
            except:
                portal.auth_cookie_lifetime_days = 1
            
            portal.auth_cookie_encrypt_cert = self._get_text(auth_override, 'certificate', '')
        
        # Data collection settings
        data_collection = portal_entry.find('portal-data-collection')
        if data_collection is not None:
            enable_dc = self._get_text(data_collection, 'enable', 'no')
            portal.data_collection_enabled = (enable_dc.lower() == 'yes')
            
            interval = self._get_text(data_collection, 'interval', '24')
            try:
                portal.data_collection_interval = int(interval)
            except:
                portal.data_collection_interval = 24
            
            max_age = self._get_text(data_collection, 'max-data-age', '30')
            try:
                portal.data_collection_max_age = int(max_age)
            except:
                portal.data_collection_max_age = 30
        
        # Agent configurations
        # Try actual PAN-OS structure first: agent/config/client-config/entry
        agent_entries = portal_entry.findall('agent/config/client-config/entry')
        if not agent_entries:
            # Fall back to documented path
            agent_entries = portal_entry.findall('agent/entry')
        
        for agent_entry in agent_entries:
            agent_config = self._parse_agent_configuration(agent_entry)
            if agent_config:
                portal.agent_configs.append(agent_config)
        
        # Internal host detection
        internal_hosts = portal_entry.findall('internal-host-detection/host')
        for host in internal_hosts:
            if host.text:
                portal.internal_hosts.append(host.text.strip())
        
        internal_domains = self._get_members(portal_entry, 'internal-host-detection/domain')
        portal.internal_domains = internal_domains
        
        return portal
    
    def _parse_agent_configuration(self, agent_entry: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse agent configuration within a portal (handles both formats)."""
        name = agent_entry.get('name', '')
        if not name:
            return None
        
        agent_config = {
            'name': name,
            'os_filter': self._get_members(agent_entry, 'config-selection-criteria/user-user-group/os'),
            'user_groups': self._get_members(agent_entry, 'config-selection-criteria/user-user-group/user-user-group'),
            'source_regions': self._get_members(agent_entry, 'config-selection-criteria/regions/country/include'),
            
            # Connection settings
            'connect_method': self._get_text(agent_entry, 'app/connect-method', 'user-logon'),
            'allow_user_disable': self._get_text(agent_entry, 'app/allow-disable', 'yes') == 'yes',
            'allow_change_portal': self._get_text(agent_entry, 'app/allow-change-portal-address', 'no') == 'yes',
            'allow_uninstall': self._get_text(agent_entry, 'app/allow-uninstall', 'no') == 'yes',
            
            # Gateways
            'external_gateways': self._parse_gateway_list(agent_entry, 'external-gateway'),
            'internal_gateways': self._parse_gateway_list(agent_entry, 'internal-gateway'),
            
            # Network settings
            'dns_suffixes': self._get_members(agent_entry, 'network/dns-suffix'),
            'dns_servers': [self._get_text(agent_entry, 'network/dns-server/primary', ''),
                           self._get_text(agent_entry, 'network/dns-server/secondary', '')],
            'wins_servers': [self._get_text(agent_entry, 'network/wins-server/primary', ''),
                            self._get_text(agent_entry, 'network/wins-server/secondary', '')],
            'split_dns_domains': self._get_members(agent_entry, 'network/split-dns/entry'),
            
            # HIP settings
            'hip_notification_enabled': self._get_text(agent_entry, 'hip-notification/enabled', 'no') == 'yes',
            'hip_notification_message': self._get_text(agent_entry, 'hip-notification/message', ''),
            'hip_profiles': self._get_members(agent_entry, 'hip-profiles'),
            
            # App UI
            'app_display_mode': self._get_text(agent_entry, 'app/app-display-mode', 'normal'),
            'show_notifications': self._get_text(agent_entry, 'app/show-notifications', 'yes') == 'yes',
            'enable_logging': self._get_text(agent_entry, 'app/enable-logging', 'yes') == 'yes',
        }
        
        # Handle actual PAN-OS client-config structure (simpler format)
        match_elem = agent_entry.find('match')
        if match_elem is not None:
            # This is actual PAN-OS client-config format
            match_user = self._get_text(match_elem, 'user', '')
            if match_user:
                agent_config['user_groups'] = [match_user]
        
        # Split tunnel in actual PAN-OS format
        split_tunnel = agent_entry.find('split-tunnel')
        if split_tunnel is not None:
            agent_config['split_tunnel_include'] = self._get_members(split_tunnel, 'access-route')
            agent_config['split_tunnel_exclude'] = self._get_members(split_tunnel, 'no-access-route')
        
        # DNS in actual PAN-OS format
        dns_elem = agent_entry.find('dns')
        if dns_elem is not None:
            dns_primary = self._get_text(dns_elem, 'primary', '')
            dns_secondary = self._get_text(dns_elem, 'secondary', '')
            if dns_primary or dns_secondary:
                agent_config['dns_servers'] = [s for s in [dns_primary, dns_secondary] if s]
        
        # Remove empty DNS/WINS servers if not already set
        if 'dns_servers' in agent_config:
            agent_config['dns_servers'] = [s for s in agent_config['dns_servers'] if s]
        if 'wins_servers' in agent_config:
            agent_config['wins_servers'] = [s for s in agent_config['wins_servers'] if s]
        
        return agent_config
    
    def _parse_gateway_list(self, parent: ET.Element, path: str) -> List[Dict[str, Any]]:
        """Parse gateway list (external or internal)."""
        gateways = []
        for gw_entry in parent.findall(f'{path}/entry'):
            gw_name = gw_entry.get('name', '')
            if gw_name:
                gateway = {
                    'name': gw_name,
                    'fqdn': self._get_text(gw_entry, 'fqdn', ''),
                    'ip': self._get_text(gw_entry, 'ip', ''),
                    'priority': self._get_text(gw_entry, 'priority', '1'),
                    'accept_cookie': self._get_text(gw_entry, 'accept-cookie', 'no') == 'yes',
                }
                gateways.append(gateway)
        return gateways
    
    def _parse_gateways(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse GlobalProtect gateway configurations."""
        self.log("Parsing GlobalProtect gateways")
        
        # Correct path for actual Palo Alto configs: /network/global-protect/gateways/entry
        gateway_path = './/network/global-protect/gateways/entry'
        
        # Try alternative paths if not found
        if device_entry.find(gateway_path) is None:
            gateway_path = './/global-protect/gateways/entry'
        if device_entry.find(gateway_path) is None:
            gateway_path = './/globalprotect/gateways/entry'
        
        for gateway_entry in device_entry.findall(gateway_path):
            gateway = self._parse_gateway(gateway_entry)
            if gateway:
                gp_data.gateways.append(gateway)
    
    def _parse_gateway(self, gateway_entry: ET.Element) -> Optional[GlobalProtectGateway]:
        """Parse a single GlobalProtect gateway."""
        name = gateway_entry.get('name', '')
        if not name:
            return None
        
        self.log(f"  Parsing gateway: {name}")
        
        gateway = GlobalProtectGateway(name=name)
        
        # Network settings
        gateway.interface = self._get_text(gateway_entry, 'network/interface', '')
        gateway.ipv4_address = self._get_text(gateway_entry, 'network/ip/ipv4', '')
        gateway.ipv6_address = self._get_text(gateway_entry, 'network/ip/ipv6', '')
        
        port_text = self._get_text(gateway_entry, 'network/port', '443')
        try:
            gateway.port = int(port_text)
        except:
            gateway.port = 443
        
        # Enabled status
        enabled_text = self._get_text(gateway_entry, 'enable', 'yes')
        gateway.enabled = (enabled_text.lower() == 'yes')
        
        # SSL/TLS and authentication
        gateway.ssl_tls_profile = self._get_text(gateway_entry, 'authentication/server-auth/ssl-tls-service-profile', '')
        gateway.authentication_profile = self._get_text(gateway_entry, 'authentication/authentication-profile', '')
        
        # Try actual PAN-OS structure if not found
        if not gateway.authentication_profile:
            gateway.authentication_profile = self._get_text(gateway_entry, 'authentication/client-auth/entry/server-profile', '')
        
        gateway.certificate_profile = self._get_text(gateway_entry, 'authentication/client-auth/entry/certificate-profile', '')
        
        gateway.description = self._get_text(gateway_entry, 'description', '')
        
        # Tunnel settings
        tunnel_settings = gateway_entry.find('tunnel-settings')
        if tunnel_settings is not None:
            gateway.tunnel_mode_enabled = self._get_text(tunnel_settings, 'tunnel-mode', 'yes') == 'yes'
            gateway.ipsec_enabled = self._get_text(tunnel_settings, 'enable-ipsec', 'no') == 'yes'
            gateway.tunnel_interface = self._get_text(tunnel_settings, 'tunnel-interface', '')
            
            mtu_text = self._get_text(tunnel_settings, 'tunnel-mtu', '1400')
            try:
                gateway.tunnel_mtu = int(mtu_text)
            except:
                gateway.tunnel_mtu = 1400
            
            timeout_text = self._get_text(tunnel_settings, 'tunnel-timeout', '3600')
            try:
                gateway.tunnel_timeout = int(timeout_text)
            except:
                gateway.tunnel_timeout = 3600
            
            gateway.ipsec_crypto_profile = self._get_text(tunnel_settings, 'ipsec-crypto-profile', '')
        
        # IP pools (can be at gateway level or client-settings level)
        # Try new path first: ip-pool/member (actual PAN-OS config format)
        ip_pool_members = self._get_members(gateway_entry, 'ip-pool')
        if ip_pool_members:
            gateway.ipv4_pools = ip_pool_members
        else:
            # Fall back to documented path
            gateway.ipv4_pools = self._get_members(gateway_entry, 'client-ip-pool/ipv4')
        
        gateway.ipv6_pools = self._get_members(gateway_entry, 'client-ip-pool/ipv6')
        
        # Split tunnel settings (try actual PAN-OS structure first)
        tunnel_mode = gateway_entry.find('tunnel-mode')
        if tunnel_mode is not None:
            split_tunnel = tunnel_mode.find('split-tunnel')
            if split_tunnel is not None:
                # Actual PAN-OS structure
                gateway.split_tunnel_include_routes = self._get_members(split_tunnel, 'access-route')
                gateway.split_tunnel_exclude_routes = self._get_members(split_tunnel, 'no-access-route')
        
        # Client settings (default for all clients)
        client_settings = gateway_entry.find('client-settings')
        if client_settings is not None:
            self._parse_gateway_client_settings(client_settings, gateway)
        
        # Client-specific configurations
        client_entries = gateway_entry.findall('agent/entry')
        for client_entry in client_entries:
            client_config = self._parse_gateway_client_config(client_entry)
            if client_config:
                gateway.client_configs.append(client_config)
        
        # Session settings
        login_lifetime = self._get_text(gateway_entry, 'timeout-settings/login-lifetime/days', '30')
        try:
            gateway.login_lifetime_days = int(login_lifetime)
        except:
            gateway.login_lifetime_days = 30
        
        inactivity_timeout = self._get_text(gateway_entry, 'timeout-settings/inactivity-timeout', '60')
        try:
            gateway.inactivity_timeout_minutes = int(inactivity_timeout)
        except:
            gateway.inactivity_timeout_minutes = 60
        
        # HIP settings
        hip = gateway_entry.find('hip')
        if hip is not None:
            gateway.hip_collection_enabled = self._get_text(hip, 'collect', 'no') == 'yes'
            
            report_interval = self._get_text(hip, 'report-interval', '60')
            try:
                gateway.hip_report_interval = int(report_interval)
            except:
                gateway.hip_report_interval = 60
            
            gateway.hip_profiles = self._get_members(hip, 'hip-profiles')
        
        return gateway
    
    def _parse_gateway_client_settings(self, client_settings: ET.Element, gateway: GlobalProtectGateway) -> None:
        """Parse default client settings for gateway."""
        # DNS
        gateway.dns_primary = self._get_text(client_settings, 'dns/primary', '')
        gateway.dns_secondary = self._get_text(client_settings, 'dns/secondary', '')
        
        # WINS
        gateway.wins_primary = self._get_text(client_settings, 'wins/primary', '')
        gateway.wins_secondary = self._get_text(client_settings, 'wins/secondary', '')
        
        # NTP
        gateway.ntp_primary = self._get_text(client_settings, 'ntp/primary', '')
        
        # Split tunnel
        split_tunnel = client_settings.find('split-tunnel')
        if split_tunnel is not None:
            gateway.split_tunnel_include_routes = self._get_members(split_tunnel, 'access-route/include')
            gateway.split_tunnel_exclude_routes = self._get_members(split_tunnel, 'access-route/exclude')
            gateway.split_tunnel_include_domains = self._get_members(split_tunnel, 'domain/include')
            gateway.split_tunnel_exclude_domains = self._get_members(split_tunnel, 'domain/exclude')
            gateway.split_tunnel_include_apps = self._get_members(split_tunnel, 'application/include')
    
    def _parse_gateway_client_config(self, client_entry: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse client-specific configuration for gateway."""
        name = client_entry.get('name', '')
        if not name:
            return None
        
        client_config = {
            'name': name,
            'os_filter': self._get_members(client_entry, 'config-selection-criteria/os'),
            'user_groups': self._get_members(client_entry, 'config-selection-criteria/user-user-group'),
            'source_regions': self._get_members(client_entry, 'config-selection-criteria/regions/country/include'),
            
            # IP pools (client-specific)
            'ipv4_pools': self._get_members(client_entry, 'client-settings/ip-pool/ipv4'),
            'ipv6_pools': self._get_members(client_entry, 'client-settings/ip-pool/ipv6'),
            
            # DNS/WINS/NTP
            'dns_primary': self._get_text(client_entry, 'client-settings/dns/primary', ''),
            'dns_secondary': self._get_text(client_entry, 'client-settings/dns/secondary', ''),
            'wins_primary': self._get_text(client_entry, 'client-settings/wins/primary', ''),
            'wins_secondary': self._get_text(client_entry, 'client-settings/wins/secondary', ''),
            
            # Split tunnel
            'split_tunnel_include_routes': self._get_members(client_entry, 'client-settings/split-tunnel/access-route/include'),
            'split_tunnel_exclude_routes': self._get_members(client_entry, 'client-settings/split-tunnel/access-route/exclude'),
            'split_tunnel_include_domains': self._get_members(client_entry, 'client-settings/split-tunnel/domain/include'),
            'split_tunnel_exclude_domains': self._get_members(client_entry, 'client-settings/split-tunnel/domain/exclude'),
            'split_tunnel_include_apps': self._get_members(client_entry, 'client-settings/split-tunnel/application/include'),
        }
        
        return client_config
    
    def _parse_hip_objects(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse HIP (Host Information Profile) objects."""
        self.log("Parsing HIP objects")
        
        vsys_entries = device_entry.findall('.//vsys/entry')
        for vsys_entry in vsys_entries:
            for hip_entry in vsys_entry.findall('.//hip-objects/entry'):
                hip_obj = self._parse_hip_object(hip_entry)
                if hip_obj:
                    gp_data.hip_objects.append(hip_obj)
    
    def _parse_hip_object(self, hip_entry: ET.Element) -> Optional[HIPObject]:
        """Parse a single HIP object."""
        name = hip_entry.get('name', '')
        if not name:
            return None
        
        hip_obj = HIPObject(name=name)
        hip_obj.description = self._get_text(hip_entry, 'description', '')
        
        # OS requirements
        host_info = hip_entry.find('host-info')
        if host_info is not None:
            os_elem = host_info.find('os')
            if os_elem is not None:
                hip_obj.os_vendor = self._get_text(os_elem, 'vendor', '')
                hip_obj.os_version = self._get_text(os_elem, 'version', '')
            
            # Antivirus
            av_elem = host_info.find('anti-malware')
            if av_elem is not None:
                hip_obj.antivirus_vendor = self._get_text(av_elem, 'vendor', '')
                hip_obj.antivirus_version = self._get_text(av_elem, 'version', '')
                hip_obj.antivirus_def_date = self._get_text(av_elem, 'definition-date', '')
            
            # Anti-malware
            am_elem = host_info.find('anti-malware')
            if am_elem is not None:
                hip_obj.antimalware_vendor = self._get_text(am_elem, 'vendor', '')
                hip_obj.antimalware_version = self._get_text(am_elem, 'version', '')
            
            # Anti-spyware
            as_elem = host_info.find('anti-spyware')
            if as_elem is not None:
                hip_obj.antispyware_vendor = self._get_text(as_elem, 'vendor', '')
                hip_obj.antispyware_version = self._get_text(as_elem, 'version', '')
            
            # System settings
            hip_obj.firewall_enabled = self._get_text(host_info, 'firewall/is-enabled', 'no') == 'yes'
            hip_obj.disk_encryption_enabled = self._get_text(host_info, 'disk-encryption/is-enabled', 'no') == 'yes'
            hip_obj.disk_backup_enabled = self._get_text(host_info, 'disk-backup/is-enabled', 'no') == 'yes'
            hip_obj.patch_management_enabled = self._get_text(host_info, 'patch-management/is-enabled', 'no') == 'yes'
        
        # Custom checks
        for proc_entry in hip_entry.findall('process-list/entry'):
            proc_name = self._get_text(proc_entry, 'name', '')
            if proc_name:
                hip_obj.process_list.append(proc_name)
        
        # Registry keys (Windows)
        for reg_entry in hip_entry.findall('custom-check/registry/entry'):
            reg_key = self._get_text(reg_entry, 'key', '')
            if reg_key:
                hip_obj.registry_keys.append(reg_key)
        
        # Plist entries (Mac)
        for plist_entry in hip_entry.findall('custom-check/plist/entry'):
            plist_path = self._get_text(plist_entry, 'path', '')
            if plist_path:
                hip_obj.plist_entries.append(plist_path)
        
        # File checks
        for file_entry in hip_entry.findall('custom-check/file/entry'):
            file_path = self._get_text(file_entry, 'path', '')
            if file_path:
                hip_obj.file_checks.append(file_path)
        
        # Certificate requirements
        cert_elem = hip_entry.find('certificate')
        if cert_elem is not None:
            hip_obj.certificate_issuer = self._get_text(cert_elem, 'issuer', '')
            hip_obj.certificate_subject = self._get_text(cert_elem, 'subject', '')
        
        return hip_obj
    
    def _parse_hip_profiles(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse HIP profiles."""
        self.log("Parsing HIP profiles")
        
        vsys_entries = device_entry.findall('.//vsys/entry')
        for vsys_entry in vsys_entries:
            for profile_entry in vsys_entry.findall('.//hip-profiles/entry'):
                profile = self._parse_hip_profile(profile_entry)
                if profile:
                    gp_data.hip_profiles.append(profile)
    
    def _parse_hip_profile(self, profile_entry: ET.Element) -> Optional[HIPProfile]:
        """Parse a single HIP profile."""
        name = profile_entry.get('name', '')
        if not name:
            return None
        
        profile = HIPProfile(name=name)
        profile.description = self._get_text(profile_entry, 'description', '')
        
        # Match logic (AND/OR)
        if profile_entry.find('match/and') is not None:
            profile.match_logic = 'and'
            profile.hip_objects = self._get_members(profile_entry, 'match/and')
        elif profile_entry.find('match/or') is not None:
            profile.match_logic = 'or'
            profile.hip_objects = self._get_members(profile_entry, 'match/or')
        else:
            # Default to AND if no match element
            profile.hip_objects = self._get_members(profile_entry, 'hip-objects')
        
        return profile
    
    def _parse_authentication_profiles(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse authentication profiles."""
        self.log("Parsing authentication profiles")
        
        # Authentication profiles can be in /shared or /vsys
        for path in ['.//shared/authentication-profile/entry', './/vsys/entry/authentication-profile/entry']:
            for auth_entry in device_entry.findall(path):
                auth_prof = self._parse_authentication_profile(auth_entry)
                if auth_prof:
                    gp_data.authentication_profiles.append(auth_prof)
    
    def _parse_authentication_profile(self, auth_entry: ET.Element) -> Optional[AuthenticationProfile]:
        """Parse a single authentication profile."""
        name = auth_entry.get('name', '')
        if not name:
            return None
        
        prof = AuthenticationProfile(name=name)
        
        # Method (ldap, radius, saml, kerberos, local)
        prof.method = self._get_text(auth_entry, 'method', '')
        if not prof.method:
            # Try alternative paths
            if auth_entry.find('ldap') is not None:
                prof.method = 'ldap'
            elif auth_entry.find('radius') is not None:
                prof.method = 'radius'
            elif auth_entry.find('saml') is not None:
                prof.method = 'saml'
            elif auth_entry.find('kerberos') is not None:
                prof.method = 'kerberos'
            elif auth_entry.find('local-database') is not None:
                prof.method = 'local'
        
        # Server profile
        prof.server_profile = self._get_text(auth_entry, 'server-profile', '')
        
        # Allow/deny groups
        prof.allow_groups = self._get_members(auth_entry, 'allow-list')
        prof.deny_groups = self._get_members(auth_entry, 'block-list')
        
        # Multi-factor
        prof.factor_profile = self._get_text(auth_entry, 'factor-profile', '')
        
        # Certificate profile
        prof.certificate_profile = self._get_text(auth_entry, 'certificate-profile', '')
        
        return prof
    
    def _parse_certificate_profiles(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse certificate profiles."""
        self.log("Parsing certificate profiles")
        
        for path in ['.//shared/certificate-profile/entry', './/vsys/entry/certificate-profile/entry']:
            for cert_entry in device_entry.findall(path):
                cert_prof = self._parse_certificate_profile(cert_entry)
                if cert_prof:
                    gp_data.certificate_profiles.append(cert_prof)
    
    def _parse_certificate_profile(self, cert_entry: ET.Element) -> Optional[CertificateProfile]:
        """Parse a single certificate profile."""
        name = cert_entry.get('name', '')
        if not name:
            return None
        
        prof = CertificateProfile(name=name)
        
        # CA certificates
        prof.ca_certificates = self._get_members(cert_entry, 'ca')
        
        # OCSP/CRL
        prof.use_ocsp = self._get_text(cert_entry, 'use-ocsp', 'no') == 'yes'
        prof.use_crl = self._get_text(cert_entry, 'use-crl', 'no') == 'yes'
        
        # Username field
        prof.username_field = self._get_text(cert_entry, 'username-field', 'subject-common-name')
        
        # Domain
        prof.domain = self._get_text(cert_entry, 'domain', '')
        
        return prof
    
    def _parse_ssl_tls_profiles(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse SSL/TLS service profiles."""
        self.log("Parsing SSL/TLS profiles")
        
        for path in ['.//shared/ssl-tls-service-profile/entry']:
            for ssl_entry in device_entry.findall(path):
                ssl_prof = self._parse_ssl_tls_profile(ssl_entry)
                if ssl_prof:
                    gp_data.ssl_tls_profiles.append(ssl_prof)
    
    def _parse_ssl_tls_profile(self, ssl_entry: ET.Element) -> Optional[SSLTLSProfile]:
        """Parse a single SSL/TLS profile."""
        name = ssl_entry.get('name', '')
        if not name:
            return None
        
        prof = SSLTLSProfile(name=name)
        
        # Protocol versions
        prof.min_version = self._get_text(ssl_entry, 'protocol-settings/min-version', 'tls1-2')
        prof.max_version = self._get_text(ssl_entry, 'protocol-settings/max-version', 'tls1-3')
        
        # Certificate
        prof.certificate = self._get_text(ssl_entry, 'certificate', '')
        
        # Cipher suites
        prof.cipher_suites = self._get_members(ssl_entry, 'cipher-suite')
        
        return prof
    
    def _parse_tunnel_interfaces(self, device_entry: ET.Element, gp_data: GlobalProtectData) -> None:
        """Parse tunnel interfaces."""
        self.log("Parsing tunnel interfaces")
        
        for tunnel_entry in device_entry.findall('.//network/interface/tunnel/units/entry'):
            tunnel = self._parse_tunnel_interface(tunnel_entry)
            if tunnel:
                gp_data.tunnel_interfaces.append(tunnel)
    
    def _parse_tunnel_interface(self, tunnel_entry: ET.Element) -> Optional[TunnelInterface]:
        """Parse a single tunnel interface."""
        name = tunnel_entry.get('name', '')
        if not name:
            return None
        
        tunnel = TunnelInterface(name=name)
        
        # IP addresses
        tunnel.ip_address = self._get_text(tunnel_entry, 'ip/ipv4', '')
        tunnel.ipv6_address = self._get_text(tunnel_entry, 'ip/ipv6', '')
        
        # MTU
        mtu_text = self._get_text(tunnel_entry, 'mtu', '1400')
        try:
            tunnel.mtu = int(mtu_text)
        except:
            tunnel.mtu = 1400
        
        # Zone assignment
        tunnel.zone = self._get_text(tunnel_entry, 'zone', '')
        
        # Virtual router
        tunnel.virtual_router = self._get_text(tunnel_entry, 'virtual-router', '')
        
        # Comment
        tunnel.comment = self._get_text(tunnel_entry, 'comment', '')
        
        return tunnel
    
    def _correlate_network_access(self, gp_data: GlobalProtectData) -> None:
        """
        Correlate network access for portals and gateways.
        
        This determines what networks/subnets are accessible via each portal/gateway
        by analyzing security policies, zones, and address objects.
        """
        self.log("Correlating network access")
        
        # For each portal
        for portal in gp_data.portals:
            self._determine_portal_network_access(portal, gp_data)
        
        # For each gateway
        for gateway in gp_data.gateways:
            self._determine_gateway_network_access(gateway, gp_data)
    
    def _determine_portal_network_access(self, portal: GlobalProtectPortal, gp_data: GlobalProtectData) -> None:
        """Determine network access for a portal."""
        # Find the zone associated with portal interface
        portal_zone = self._find_zone_for_interface(portal.interface, gp_data.zones)
        
        if portal_zone:
            portal.applied_zones.append(portal_zone)
            
            # Find policies where this zone is the source
            for policy in gp_data.security_policies:
                if portal_zone in policy.source_zones or 'any' in policy.source_zones:
                    # Add destination addresses as accessible networks
                    for dest_addr in policy.destination_addresses:
                        if dest_addr in gp_data.address_objects:
                            network = gp_data.address_objects[dest_addr]
                            if network not in portal.accessible_networks:
                                portal.accessible_networks.append(network)
                        elif dest_addr != 'any':
                            if dest_addr not in portal.accessible_networks:
                                portal.accessible_networks.append(dest_addr)
                    
                    # Track ACL (policy name acts as ACL)
                    if policy.name not in portal.applied_acls:
                        portal.applied_acls.append(policy.name)
    
    def _determine_gateway_network_access(self, gateway: GlobalProtectGateway, gp_data: GlobalProtectData) -> None:
        """Determine network access for a gateway."""
        # Find the zone associated with gateway's tunnel interface
        tunnel_zone = self._find_zone_for_interface(gateway.tunnel_interface, gp_data.zones)
        
        if tunnel_zone:
            gateway.applied_zones.append(tunnel_zone)
            
            # Add split tunnel routes as accessible networks
            gateway.accessible_networks.extend(gateway.split_tunnel_include_routes)
            
            # Find policies where tunnel zone is source
            for policy in gp_data.security_policies:
                if tunnel_zone in policy.source_zones or 'any' in policy.source_zones:
                    # Add destination addresses
                    for dest_addr in policy.destination_addresses:
                        if dest_addr in gp_data.address_objects:
                            network = gp_data.address_objects[dest_addr]
                            if network not in gateway.accessible_networks:
                                gateway.accessible_networks.append(network)
                        elif dest_addr != 'any':
                            if dest_addr not in gateway.accessible_networks:
                                gateway.accessible_networks.append(dest_addr)
                    
                    # Track ACL
                    if policy.name not in gateway.applied_acls:
                        gateway.applied_acls.append(policy.name)
        
        # Check for VLAN assignments (if tunnel interface has VLAN config)
        # Note: Palo Alto doesn't use VLANs the same way as Cisco, 
        # but we track zone-based segments which serve similar purpose
        for zone_name, zone_info in gp_data.zones.items():
            if gateway.tunnel_interface in zone_info.get('interfaces', []):
                if zone_name not in gateway.applied_zones:
                    gateway.applied_zones.append(zone_name)
    
    def _find_zone_for_interface(self, interface: str, zones: Dict[str, Dict[str, Any]]) -> Optional[str]:
        """Find the security zone assigned to an interface."""
        for zone_name, zone_info in zones.items():
            if interface in zone_info.get('interfaces', []):
                return zone_name
        return None


# Convenience function for direct use
def parse_globalprotect_config(config_path: str, verbose: bool = False) -> GlobalProtectData:
    """
    Parse GlobalProtect configuration from a Palo Alto XML file.
    
    Args:
        config_path: Path to XML configuration file
        verbose: Enable verbose logging
        
    Returns:
        GlobalProtectData object with all parsed information
    """
    parser = GlobalProtectXMLParser(verbose=verbose)
    return parser.parse_from_file(config_path)