#!/usr/bin/env python3
"""
Synopsis:
    GlobalProtect VPN Data Structures for Palo Alto configuration analysis

Description:
    Data structures for Palo Alto GlobalProtect VPN configurations.
    These structures capture portal, gateway, and client configuration
    details specific to GlobalProtect SSL VPN.

Global Protect Components:
    - Portal: User-facing login page
    - Gateway: VPN connection endpoint
    - Client Config: Client settings distributed to endpoints
    - Hip Profiles: Host Information Profile for endpoint checking

Usage:
    Used only when --parse-globalprotect flag is enabled during analysis.

Version: 3.0.0
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class GlobalProtectPortal:
    """
    Represents a GlobalProtect Portal configuration.
    
    The portal handles client authentication, agent configuration distribution,
    and data collection. Multiple portals can exist in a single configuration.
    
    Attributes:
        name: Portal name (key identifier)
        interface: Network interface (e.g., 'ethernet1/1')
        ipv4_address: IPv4 address for portal access
        ipv6_address: IPv6 address for portal access (optional)
        fqdn: Fully qualified domain name for portal
        port: TCP port (default 443)
        enabled: Whether portal is enabled
        ssl_tls_profile: SSL/TLS service profile name
        authentication_profile: Authentication profile name
        certificate_profile: Certificate profile name for client auth
        description: Portal description
        
        # Authentication override settings
        auth_override_enabled: Cookie-based auth enabled
        auth_cookie_lifetime_days: Cookie lifetime in days
        auth_cookie_encrypt_cert: Certificate used for cookie encryption
        
        # Data collection settings
        data_collection_enabled: Endpoint data collection enabled
        data_collection_interval: Collection interval in hours
        data_collection_max_age: Max age of collected data in days
        
        # Agent configurations (list of dicts with agent settings)
        agent_configs: List of agent configuration objects
        
        # Network access (derived from security policies)
        accessible_networks: List of networks/subnets accessible via portal
        applied_acls: List of ACL names applied to portal traffic
        applied_zones: List of security zones for portal
        
        # Internal host detection
        internal_hosts: List of internal hosts for detection
        internal_domains: List of internal domains
    """
    name: str
    interface: str = ""
    ipv4_address: str = ""
    ipv6_address: str = ""
    fqdn: str = ""
    port: int = 443
    enabled: bool = True
    ssl_tls_profile: str = ""
    authentication_profile: str = ""
    certificate_profile: str = ""
    description: str = ""
    
    # Authentication override
    auth_override_enabled: bool = False
    auth_cookie_lifetime_days: int = 1
    auth_cookie_encrypt_cert: str = ""
    
    # Data collection
    data_collection_enabled: bool = False
    data_collection_interval: int = 24
    data_collection_max_age: int = 30
    
    # Agent configurations
    agent_configs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Network access (cross-referenced from policies)
    accessible_networks: List[str] = field(default_factory=list)
    applied_acls: List[str] = field(default_factory=list)
    applied_zones: List[str] = field(default_factory=list)
    
    # Internal host detection
    internal_hosts: List[str] = field(default_factory=list)
    internal_domains: List[str] = field(default_factory=list)


@dataclass
class AgentConfiguration:
    """
    Represents a client agent configuration within a portal.
    
    Agent configurations define how the GlobalProtect client behaves,
    including connection methods, gateway selections, and app settings.
    
    Attributes:
        name: Configuration name
        os_filter: Operating system filter (Windows, Mac, Linux, etc.)
        user_groups: User/group membership filters
        source_regions: Geographic region filters
        
        # Connection settings
        connect_method: on-demand | user-logon | pre-logon | always-on
        allow_user_disable: Allow user to disable VPN
        allow_change_portal: Allow user to change portal address
        allow_uninstall: Allow app uninstall
        
        # Gateway settings
        external_gateways: List of external gateway entries
        internal_gateways: List of internal gateway entries
        
        # Network settings
        dns_suffixes: DNS search suffixes
        dns_servers: DNS servers
        wins_servers: WINS servers
        split_dns_domains: Split DNS domain list
        
        # HIP settings
        hip_notification_enabled: HIP notification enabled
        hip_notification_message: HIP notification message text
        hip_profiles: List of HIP profile names
        
        # App UI settings
        app_display_mode: normal | minimal | hidden
        show_notifications: Show system tray notifications
        enable_logging: Enable client-side logging
    """
    name: str
    os_filter: List[str] = field(default_factory=list)
    user_groups: List[str] = field(default_factory=list)
    source_regions: List[str] = field(default_factory=list)
    
    # Connection
    connect_method: str = "user-logon"
    allow_user_disable: bool = True
    allow_change_portal: bool = False
    allow_uninstall: bool = False
    
    # Gateways
    external_gateways: List[Dict[str, Any]] = field(default_factory=list)
    internal_gateways: List[Dict[str, Any]] = field(default_factory=list)
    
    # Network
    dns_suffixes: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    wins_servers: List[str] = field(default_factory=list)
    split_dns_domains: List[str] = field(default_factory=list)
    
    # HIP
    hip_notification_enabled: bool = False
    hip_notification_message: str = ""
    hip_profiles: List[str] = field(default_factory=list)
    
    # App UI
    app_display_mode: str = "normal"
    show_notifications: bool = True
    enable_logging: bool = True


@dataclass
class GlobalProtectGateway:
    """
    Represents a GlobalProtect Gateway configuration.
    
    The gateway manages VPN tunnels, IP address assignment, routing,
    and client network settings.
    
    Attributes:
        name: Gateway name (key identifier)
        interface: Network interface (e.g., 'ethernet1/2')
        ipv4_address: IPv4 address for gateway access
        ipv6_address: IPv6 address for gateway access (optional)
        port: TCP port (default 443)
        enabled: Whether gateway is enabled
        ssl_tls_profile: SSL/TLS service profile name
        authentication_profile: Authentication profile name
        certificate_profile: Certificate profile name
        description: Gateway description
        
        # Tunnel settings
        tunnel_mode_enabled: SSL tunnel mode enabled
        ipsec_enabled: IPSec tunnel enabled
        tunnel_interface: Tunnel interface name (e.g., 'tunnel.1')
        tunnel_mtu: Tunnel MTU size
        tunnel_timeout: Tunnel timeout in seconds
        ipsec_crypto_profile: IPSec crypto profile name
        
        # IP pool settings
        ipv4_pools: List of IPv4 address pools
        ipv6_pools: List of IPv6 address pools
        
        # Client network settings
        dns_primary: Primary DNS server
        dns_secondary: Secondary DNS server
        wins_primary: Primary WINS server
        wins_secondary: Secondary WINS server
        ntp_primary: Primary NTP server
        
        # Split tunnel settings
        split_tunnel_include_routes: Routes to tunnel
        split_tunnel_exclude_routes: Routes to bypass tunnel
        split_tunnel_include_domains: Domains to tunnel
        split_tunnel_exclude_domains: Domains to bypass
        split_tunnel_include_apps: Applications to tunnel
        
        # Session settings
        login_lifetime_days: Maximum session lifetime in days
        inactivity_timeout_minutes: Inactivity timeout in minutes
        
        # HIP settings
        hip_collection_enabled: HIP data collection enabled
        hip_report_interval: HIP report interval in minutes
        hip_profiles: List of HIP profile names required
        
        # Client-specific settings
        client_configs: List of client configuration objects
        
        # Network access (cross-referenced from policies)
        accessible_networks: List of networks/subnets accessible
        applied_acls: List of ACL names applied
        applied_zones: List of security zones
        applied_vlans: List of VLAN IDs
    """
    name: str
    interface: str = ""
    ipv4_address: str = ""
    ipv6_address: str = ""
    port: int = 443
    enabled: bool = True
    ssl_tls_profile: str = ""
    authentication_profile: str = ""
    certificate_profile: str = ""
    description: str = ""
    
    # Tunnel
    tunnel_mode_enabled: bool = True
    ipsec_enabled: bool = False
    tunnel_interface: str = ""
    tunnel_mtu: int = 1400
    tunnel_timeout: int = 3600
    ipsec_crypto_profile: str = ""
    
    # IP pools
    ipv4_pools: List[str] = field(default_factory=list)
    ipv6_pools: List[str] = field(default_factory=list)
    
    # DNS/WINS/NTP
    dns_primary: str = ""
    dns_secondary: str = ""
    wins_primary: str = ""
    wins_secondary: str = ""
    ntp_primary: str = ""
    
    # Split tunnel
    split_tunnel_include_routes: List[str] = field(default_factory=list)
    split_tunnel_exclude_routes: List[str] = field(default_factory=list)
    split_tunnel_include_domains: List[str] = field(default_factory=list)
    split_tunnel_exclude_domains: List[str] = field(default_factory=list)
    split_tunnel_include_apps: List[str] = field(default_factory=list)
    
    # Sessions
    login_lifetime_days: int = 30
    inactivity_timeout_minutes: int = 60
    
    # HIP
    hip_collection_enabled: bool = False
    hip_report_interval: int = 60
    hip_profiles: List[str] = field(default_factory=list)
    
    # Client configs
    client_configs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Network access
    accessible_networks: List[str] = field(default_factory=list)
    applied_acls: List[str] = field(default_factory=list)
    applied_zones: List[str] = field(default_factory=list)
    applied_vlans: List[str] = field(default_factory=list)


@dataclass
class HIPObject:
    """
    Represents a Host Information Profile (HIP) object.
    
    HIP objects define specific security checks performed on client endpoints
    before allowing VPN access.
    
    Attributes:
        name: HIP object name
        description: Object description
        
        # OS requirements
        os_vendor: Required OS vendor (e.g., 'Microsoft', 'Apple')
        os_version: Required OS version
        
        # Security software
        antivirus_vendor: Required antivirus vendor
        antivirus_version: Required antivirus version
        antivirus_def_date: Required definition date
        
        antimalware_vendor: Required anti-malware vendor
        antimalware_version: Required version
        
        antispyware_vendor: Required anti-spyware vendor
        antispyware_version: Required version
        
        # System settings
        firewall_enabled: Host firewall must be enabled
        disk_encryption_enabled: Disk encryption required
        disk_backup_enabled: Disk backup required
        patch_management_enabled: Patch management required
        
        # Custom checks
        process_list: List of required running processes
        registry_keys: List of required registry keys (Windows)
        plist_entries: List of required plist entries (Mac)
        file_checks: List of required file paths
        
        # Certificate requirements
        certificate_issuer: Required cert issuer
        certificate_subject: Required cert subject
    """
    name: str
    description: str = ""
    
    # OS
    os_vendor: str = ""
    os_version: str = ""
    
    # Security software
    antivirus_vendor: str = ""
    antivirus_version: str = ""
    antivirus_def_date: str = ""
    
    antimalware_vendor: str = ""
    antimalware_version: str = ""
    
    antispyware_vendor: str = ""
    antispyware_version: str = ""
    
    # System
    firewall_enabled: bool = False
    disk_encryption_enabled: bool = False
    disk_backup_enabled: bool = False
    patch_management_enabled: bool = False
    
    # Custom
    process_list: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    plist_entries: List[str] = field(default_factory=list)
    file_checks: List[str] = field(default_factory=list)
    
    # Certificates
    certificate_issuer: str = ""
    certificate_subject: str = ""


@dataclass
class HIPProfile:
    """
    Represents a Host Information Profile (HIP) profile.
    
    HIP profiles combine multiple HIP objects with boolean logic (AND/OR)
    to create complex endpoint compliance requirements.
    
    Attributes:
        name: HIP profile name
        description: Profile description
        match_logic: 'and' or 'or' for combining HIP objects
        hip_objects: List of HIP object names in this profile
    """
    name: str
    description: str = ""
    match_logic: str = "and"  # 'and' or 'or'
    hip_objects: List[str] = field(default_factory=list)


@dataclass
class AuthenticationProfile:
    """
    Represents an authentication profile referenced by GlobalProtect.
    
    Attributes:
        name: Profile name
        method: Authentication method (ldap, radius, saml, kerberos, local)
        server_profile: Server profile name
        allow_groups: List of allowed user groups
        deny_groups: List of denied user groups
        factor_profile: Multi-factor auth profile name
        certificate_profile: Certificate profile name
    """
    name: str
    method: str = ""
    server_profile: str = ""
    allow_groups: List[str] = field(default_factory=list)
    deny_groups: List[str] = field(default_factory=list)
    factor_profile: str = ""
    certificate_profile: str = ""


@dataclass
class CertificateProfile:
    """
    Represents a certificate profile used by GlobalProtect.
    
    Attributes:
        name: Profile name
        ca_certificates: List of CA certificate names
        use_ocsp: Use OCSP for certificate validation
        use_crl: Use CRL for certificate validation
        username_field: Certificate field to extract username from
        domain: Domain to append to username
    """
    name: str
    ca_certificates: List[str] = field(default_factory=list)
    use_ocsp: bool = False
    use_crl: bool = False
    username_field: str = "subject-common-name"
    domain: str = ""


@dataclass
class SSLTLSProfile:
    """
    Represents an SSL/TLS service profile.
    
    Attributes:
        name: Profile name
        min_version: Minimum TLS version (e.g., 'tls1-2')
        max_version: Maximum TLS version (e.g., 'tls1-3')
        certificate: Server certificate name
        cipher_suites: List of allowed cipher suites
    """
    name: str
    min_version: str = "tls1-2"
    max_version: str = "tls1-3"
    certificate: str = ""
    cipher_suites: List[str] = field(default_factory=list)


@dataclass
class TunnelInterface:
    """
    Represents a tunnel interface used by GlobalProtect gateway.
    
    Attributes:
        name: Interface name (e.g., 'tunnel.1')
        ip_address: IPv4 address with mask
        ipv6_address: IPv6 address with prefix
        mtu: MTU size
        zone: Security zone assignment
        virtual_router: Virtual router assignment
        comment: Interface comment/description
    """
    name: str
    ip_address: str = ""
    ipv6_address: str = ""
    mtu: int = 1400
    zone: str = ""
    virtual_router: str = ""
    comment: str = ""


@dataclass
class SecurityPolicy:
    """
    Represents a security policy that may apply to GlobalProtect traffic.
    
    Attributes:
        name: Policy name
        rule_type: pre-rulebase, rulebase, post-rulebase
        source_zones: List of source zones
        destination_zones: List of destination zones
        source_addresses: List of source addresses/objects
        destination_addresses: List of destination addresses/objects
        source_users: List of source users/groups
        applications: List of applications
        services: List of services
        action: allow, deny, drop, reset
        hip_profiles: List of required HIP profiles
        log_setting: Log forwarding profile
        profile_group: Security profile group
    """
    name: str
    rule_type: str = "rulebase"
    source_zones: List[str] = field(default_factory=list)
    destination_zones: List[str] = field(default_factory=list)
    source_addresses: List[str] = field(default_factory=list)
    destination_addresses: List[str] = field(default_factory=list)
    source_users: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    action: str = "allow"
    hip_profiles: List[str] = field(default_factory=list)
    log_setting: str = ""
    profile_group: str = ""


@dataclass
class GlobalProtectData:
    """
    Container for all GlobalProtect VPN configuration data.
    
    This is the top-level data structure that holds all parsed GlobalProtect
    information from a Palo Alto configuration.
    
    Attributes:
        device_name: Name of the Palo Alto device
        hostname: Hostname from configuration
        management_ip: Management IP address
        
        portals: List of GlobalProtect portals
        gateways: List of GlobalProtect gateways
        hip_objects: List of HIP objects
        hip_profiles: List of HIP profiles
        authentication_profiles: List of authentication profiles
        certificate_profiles: List of certificate profiles
        ssl_tls_profiles: List of SSL/TLS profiles
        tunnel_interfaces: List of tunnel interfaces
        security_policies: List of security policies affecting GP
        
        # Global settings
        global_settings: Dict of global GP settings
        
        # Network objects referenced
        zones: Dict of zone names to zone info
        address_objects: Dict of address object names to values
        service_objects: Dict of service object names to values
        
        # Statistics
        total_portals: Count of portals
        total_gateways: Count of gateways
        total_hip_objects: Count of HIP objects
        total_hip_profiles: Count of HIP profiles
    """
    device_name: str
    hostname: str = ""
    management_ip: str = ""
    
    portals: List[GlobalProtectPortal] = field(default_factory=list)
    gateways: List[GlobalProtectGateway] = field(default_factory=list)
    hip_objects: List[HIPObject] = field(default_factory=list)
    hip_profiles: List[HIPProfile] = field(default_factory=list)
    authentication_profiles: List[AuthenticationProfile] = field(default_factory=list)
    certificate_profiles: List[CertificateProfile] = field(default_factory=list)
    ssl_tls_profiles: List[SSLTLSProfile] = field(default_factory=list)
    tunnel_interfaces: List[TunnelInterface] = field(default_factory=list)
    security_policies: List[SecurityPolicy] = field(default_factory=list)
    
    global_settings: Dict[str, Any] = field(default_factory=dict)
    
    zones: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    address_objects: Dict[str, str] = field(default_factory=dict)
    service_objects: Dict[str, str] = field(default_factory=dict)
    
    @property
    def total_portals(self) -> int:
        return len(self.portals)
    
    @property
    def total_gateways(self) -> int:
        return len(self.gateways)
    
    @property
    def total_hip_objects(self) -> int:
        return len(self.hip_objects)
    
    @property
    def total_hip_profiles(self) -> int:
        return len(self.hip_profiles)
