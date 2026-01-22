#!/usr/bin/env python3
"""
Synopsis:
    Data structures module for Multi-Vendor network configuration analysis

Description:
    This module defines comprehensive data structures used throughout the
    Network Configuration Analyzer project. It provides classes for
    representing network interfaces, VLANs, ACLs, routes, and other network
    configuration elements in a standardized format.
    
    ENHANCED v3.0 ADDITIONS:
    - PortChannelMembership: Represents port-channel/aggregate membership
    - AdministrativeAccount: Individual admin account objects (no concatenation)
    - DataMonitoringConfig: Individual monitoring configuration objects
    - NetworkFlowMapping: Network flow data for visualization

Notes:
    - All classes use Python built-in types only (no external dependencies)
    - Data structures are designed for easy CSV serialization
    - Supports multiple vendors (Cisco, Juniper, Palo Alto, Fortigate, Eltex)
    - Includes validation methods for data integrity
    - v3.0: Enhanced for individual admin accounts and port-channel tracking

Version: 3.0.0
"""

import re
from typing import List, Dict, Optional, Any, Tuple


class NetworkInterface:
    """
    Represents a network interface configuration.

    This class encapsulates all configuration details for a network interface
    including physical properties, logical configuration, and associated policies.

    Attributes:
        name: Full interface name (e.g., 'GigabitEthernet0/0/1')
        interface_type: Type of interface (e.g., 'GigabitEthernet', 'FastEthernet')
        slot: Slot number if applicable
        port: Port number
        subinterface: Subinterface number if applicable
        description: Interface description string
        ip_address: Primary IPv4 address
        ip_mask: IPv4 subnet mask
        ipv6_addresses: List of IPv6 addresses
        secondary_ips: List of secondary IPv4 addresses
        vlan: VLAN ID if configured
        trunk_mode: Boolean indicating if interface is in trunk mode
        allowed_vlans: List of allowed VLANs for trunk interfaces
        access_vlan: Access VLAN ID for access mode
        shutdown: Boolean indicating if interface is administratively down
        speed: Configured speed (e.g., '1000', 'auto')
        duplex: Configured duplex (e.g., 'full', 'half', 'auto')
        mtu: Maximum transmission unit size
        mac_address: MAC address if configured
        input_acl: Name of input ACL
        output_acl: Name of output ACL
        vrf: VRF name if configured
        channel_group: Port-channel group number if member
        spanning_tree_mode: Spanning tree portfast/mode settings
        device_name: Name of the device this interface belongs to
    """

    def __init__(self, name: str):
        """
        Initialize a NetworkInterface object.

        Args:
            name: Full interface name

        Returns:
            None
        """
        self.name = name
        self.interface_type = ""
        self.slot = None
        self.port = None
        self.subinterface = None
        self.description = ""
        self.ip_address = ""
        self.ip_mask = ""
        self.ipv6_addresses = []
        self.secondary_ips = []
        self.vlan = None
        self.trunk_mode = False
        self.allowed_vlans = []
        self.access_vlan = None
        self.shutdown = False
        self.speed = ""
        self.duplex = ""
        self.mtu = 1500
        self.mac_address = ""
        self.input_acl = ""
        self.output_acl = ""
        self.vrf = ""
        self.channel_group = None
        self.spanning_tree_mode = ""
        self.device_name = ""
        self.additional_config = []
        
        # ENHANCED v3.0: Port-channel tracking
        self.port_channel = None  # PortChannelMembership object if member
        self.is_port_channel = False  # True if this IS a port-channel
        self.member_interfaces = []  # List of member interface names if port-channel

    def parse_interface_name(self) -> Tuple[str, Optional[int], Optional[int], Optional[int]]:
        """
        Parse interface name into component parts.

        Returns:
            Tuple containing (interface_type, slot, port, subinterface)

        Examples:
            'GigabitEthernet0/0/1' -> ('GigabitEthernet', 0, 0, 1)
            'FastEthernet0/1.100' -> ('FastEthernet', 0, 1, 100)
        """
        # Pattern for interfaces like GigabitEthernet0/0/1
        pattern1 = r'([A-Za-z-]+)(\d+)/(\d+)/(\d+)(?:\.(\d+))?'
        # Pattern for interfaces like FastEthernet0/1
        pattern2 = r'([A-Za-z-]+)(\d+)/(\d+)(?:\.(\d+))?'
        # Pattern for interfaces like Vlan100
        pattern3 = r'([A-Za-z-]+)(\d+)'

        match = re.match(pattern1, self.name)
        if match:
            self.interface_type = match.group(1)
            self.slot = int(match.group(2))
            self.port = int(match.group(3))
            sub = match.group(5)
            self.subinterface = int(sub) if sub else None
            return (self.interface_type, self.slot, self.port, self.subinterface)

        match = re.match(pattern2, self.name)
        if match:
            self.interface_type = match.group(1)
            self.slot = int(match.group(2))
            self.port = int(match.group(3))
            sub = match.group(4)
            self.subinterface = int(sub) if sub else None
            return (self.interface_type, self.slot, self.port, self.subinterface)

        match = re.match(pattern3, self.name)
        if match:
            self.interface_type = match.group(1)
            self.slot = int(match.group(2))
            return (self.interface_type, self.slot, None, None)

        return (self.name, None, None, None)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert interface object to dictionary for CSV export.

        Returns:
            Dictionary containing all interface attributes

        Notes:
            Lists are converted to semicolon-separated strings for CSV compatibility
        """
        return {
            'Device': self.device_name,
            'Interface': self.name,
            'Type': self.interface_type,
            'Slot': self.slot if self.slot is not None else '',
            'Port': self.port if self.port is not None else '',
            'Subinterface': self.subinterface if self.subinterface is not None else '',
            'Description': self.description,
            'IP Address': self.ip_address,
            'Subnet Mask': self.ip_mask,
            'IPv6 Addresses': ';'.join(self.ipv6_addresses) if self.ipv6_addresses else '',
            'Secondary IPs': ';'.join(self.secondary_ips) if self.secondary_ips else '',
            'VLAN': self.vlan if self.vlan is not None else '',
            'Trunk Mode': 'Yes' if self.trunk_mode else 'No',
            'Allowed VLANs': ';'.join(map(str, self.allowed_vlans)) if self.allowed_vlans else '',
            'Access VLAN': self.access_vlan if self.access_vlan is not None else '',
            'Admin Status': 'Down' if self.shutdown else 'Up',
            'Speed': self.speed,
            'Duplex': self.duplex,
            'MTU': self.mtu,
            'MAC Address': self.mac_address,
            'Input ACL': self.input_acl,
            'Output ACL': self.output_acl,
            'VRF': self.vrf,
            'Port-Channel': self.channel_group if self.channel_group is not None else '',
            'Spanning Tree': self.spanning_tree_mode,
            'Additional Config': ';'.join(self.additional_config) if self.additional_config else ''
        }


class VLAN:
    """
    Represents a VLAN configuration.

    Attributes:
        vlan_id: VLAN identifier (1-4094)
        name: VLAN name
        state: VLAN state (active, suspend, etc.)
        interfaces: List of interfaces assigned to this VLAN
        device_name: Name of the device this VLAN is configured on
        gateway: Gateway IP address for the VLAN
        dhcp_helper: List of DHCP helper/relay addresses
    """

    def __init__(self, vlan_id: int):
        """
        Initialize a VLAN object.

        Args:
            vlan_id: VLAN identifier

        Returns:
            None
        """
        self.vlan_id = vlan_id
        self.name = ""
        self.state = "active"
        self.interfaces = []
        self.device_name = ""
        self.gateway = ""
        self.dhcp_helper = []

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert VLAN object to dictionary for CSV export.

        Returns:
            Dictionary containing all VLAN attributes
        """
        return {
            'Device': self.device_name,
            'VLAN ID': self.vlan_id,
            'Name': self.name,
            'State': self.state,
            'Gateway': self.gateway,
            'DHCP Helpers': ';'.join(self.dhcp_helper) if self.dhcp_helper else '',
            'Interfaces': ';'.join(self.interfaces) if self.interfaces else ''
        }


class Endpoint:
    """
    Represents a network endpoint or server defined in configuration.
    
    This class captures endpoints/servers configured in the network that are
    NOT interface IP addresses. These are hosts, servers, or network objects
    defined in configurations like object-group network, NAT statements,
    access-lists, route statements, etc.
    
    Attributes:
        device_name: Device where endpoint is defined
        name: Endpoint name or identifier
        ip_address: IP address of the endpoint
        subnet_mask: Subnet mask (if network object)
        cidr: CIDR notation (e.g., '192.168.1.10/32' or '10.0.0.0/24')
        endpoint_type: Type of endpoint (host, network, server, etc.)
        description: Description of the endpoint
        source_context: Where this endpoint was defined (object-group, NAT, ACL, etc.)
        group_memberships: List of object groups this endpoint belongs to
        acl_references: List of ACLs that reference this endpoint
        related_interfaces: List of interfaces this endpoint is associated with
        related_vlans: List of VLANs this endpoint is associated with
    """
    
    def __init__(
        self,
        device_name: str = "",
        name: str = "",
        ip_address: str = "",
        subnet_mask: str = ""
    ):
        """
        Initialize an Endpoint object.
        
        Args:
            device_name: Device where endpoint is defined
            name: Endpoint name or identifier
            ip_address: IP address of the endpoint
            subnet_mask: Subnet mask (if network object)
        """
        self.device_name = device_name
        self.name = name
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
        self.cidr = ""
        self.endpoint_type = ""  # host, network, server, etc.
        self.description = ""
        self.source_context = ""  # object-group, NAT, ACL, route, etc.
        self.group_memberships = []
        self.acl_references = []
        self.related_interfaces = []
        self.related_vlans = []
        
        # Calculate CIDR if IP and mask provided
        if self.ip_address and self.subnet_mask:
            self.calculate_cidr()
    
    def calculate_cidr(self) -> None:
        """Calculate CIDR notation from IP and subnet mask."""
        if not self.ip_address:
            return
        
        if self.subnet_mask:
            # Convert subnet mask to prefix length
            try:
                octets = [int(x) for x in self.subnet_mask.split('.')]
                binary = ''.join([bin(octet)[2:].zfill(8) for octet in octets])
                prefix_len = binary.count('1')
                self.cidr = f"{self.ip_address}/{prefix_len}"
            except (ValueError, AttributeError):
                # Invalid mask, default to /32 for host
                self.cidr = f"{self.ip_address}/32"
        else:
            # No mask provided, assume host (/32)
            self.cidr = f"{self.ip_address}/32"
    
    def is_host(self) -> bool:
        """Check if endpoint is a single host (/32)."""
        return self.cidr.endswith('/32')
    
    def is_network(self) -> bool:
        """Check if endpoint is a network (not /32)."""
        return not self.is_host()
    
    def add_group_membership(self, group_name: str) -> None:
        """Add object group membership."""
        if group_name and group_name not in self.group_memberships:
            self.group_memberships.append(group_name)
    
    def add_acl_reference(self, acl_name: str) -> None:
        """Add ACL reference."""
        if acl_name and acl_name not in self.acl_references:
            self.acl_references.append(acl_name)
    
    def add_related_interface(self, interface_name: str) -> None:
        """Add related interface."""
        if interface_name and interface_name not in self.related_interfaces:
            self.related_interfaces.append(interface_name)
    
    def add_related_vlan(self, vlan_id: int) -> None:
        """Add related VLAN."""
        if vlan_id and vlan_id not in self.related_vlans:
            self.related_vlans.append(vlan_id)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert endpoint to dictionary for serialization.
        
        Returns:
            Dictionary representation of endpoint
        """
        return {
            'Device': self.device_name,
            'Name': self.name,
            'IP Address': self.ip_address,
            'Subnet Mask': self.subnet_mask,
            'CIDR': self.cidr,
            'Type': self.endpoint_type,
            'Description': self.description,
            'Source': self.source_context,
            'Groups': ';'.join(self.group_memberships) if self.group_memberships else '',
            'ACL References': ';'.join(self.acl_references) if self.acl_references else '',
            'Related Interfaces': ';'.join(self.related_interfaces) if self.related_interfaces else '',
            'Related VLANs': ';'.join([str(v) for v in self.related_vlans]) if self.related_vlans else ''
        }


class AccessControlList:
    """
    Represents an Access Control List (ACL).

    Attributes:
        name: ACL name or number
        acl_type: Type of ACL (standard, extended, named)
        entries: List of ACL entries (ACE objects)
        device_name: Name of the device this ACL is configured on
        applied_interfaces: List of interfaces where this ACL is applied
        direction: Direction of application (in, out)
        referenced_endpoints: List of unique endpoints referenced across all ACEs
        endpoint_count: Number of unique endpoints referenced in this ACL
       """

    def __init__(self, name: str):
        """
        Initialize an ACL object.

        Args:
            name: ACL name or number

        Returns:
            None
        """
        self.name = name
        self.acl_type = "extended"
        self.entries = []
        self.device_name = ""
        self.applied_interfaces = []
        self.direction = ""
        self.referenced_endpoints = []  # NEW: Unique endpoints referenced
        self.endpoint_count = 0  # NEW: Count of referenced endpoints

    def add_entry(self, entry: 'AccessControlEntry') -> None:
        """
        Add an ACE to this ACL.

        Args:
            entry: AccessControlEntry object to add

        Returns:
            None
        """
        self.entries.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ACL object to dictionary for CSV export.

        Returns:
            Dictionary containing all ACL attributes
        """
        return {
            'Device': self.device_name,
            'ACL Name': self.name,
            'Type': self.acl_type,
            'Entry Count': len(self.entries),
            'Applied Interfaces': ';'.join(self.applied_interfaces) if self.applied_interfaces else '',
            'Direction': self.direction,
            'Referenced Endpoints': ';'.join(self.referenced_endpoints) if self.referenced_endpoints else '',
            'Endpoint Count': str(self.endpoint_count)
        }


class AccessControlEntry:
    """
    Represents a single ACL entry (ACE).

    Attributes:
        sequence: Sequence number of the ACE
        action: Action to take (permit, deny)
        protocol: Protocol (ip, tcp, udp, icmp, etc.)
        source: Source IP address or network
        source_wildcard: Source wildcard mask
        source_port: Source port or port range
        destination: Destination IP address or network
        dest_wildcard: Destination wildcard mask
        dest_port: Destination port or port range
        flags: Additional flags (established, log, etc.)
        raw_config: Original configuration line
        referenced_endpoints: List of endpoint names/IPs referenced in this ACE
    """

    def __init__(self):
        """
        Initialize an ACE object.

        Returns:
            None
        """
        self.sequence = None
        self.action = ""
        self.protocol = ""
        self.source = ""
        self.source_wildcard = ""
        self.source_port = ""
        self.destination = ""
        self.dest_wildcard = ""
        self.dest_port = ""
        self.flags = []
        self.raw_config = ""
        self.referenced_endpoints = []  # NEW: Endpoints referenced in this ACE

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ACE object to dictionary for CSV export.

        Returns:
            Dictionary containing all ACE attributes
        """
        return {
            'Sequence': self.sequence if self.sequence is not None else '',
            'Action': self.action,
            'Protocol': self.protocol,
            'Source': self.source,
            'Source Wildcard': self.source_wildcard,
            'Source Port': self.source_port,
            'Destination': self.destination,
            'Dest Wildcard': self.dest_wildcard,
            'Dest Port': self.dest_port,
            'Flags': ';'.join(self.flags) if self.flags else '',
            'Referenced Endpoints': ';'.join(self.referenced_endpoints) if self.referenced_endpoints else '',
            'Raw Config': self.raw_config
        }


class Route:
    """
    Represents a routing table entry.

    Attributes:
        route_type: Type of route (static, connected, ospf, eigrp, bgp, etc.)
        destination: Destination network
        mask: Subnet mask
        next_hop: Next hop IP address
        interface: Outgoing interface
        metric: Route metric
        admin_distance: Administrative distance
        protocol: Routing protocol
        device_name: Name of the device this route is on
    """

    def __init__(self):
        """
        Initialize a Route object.

        Returns:
            None
        """
        self.route_type = ""
        self.destination = ""
        self.mask = ""
        self.next_hop = ""
        self.interface = ""
        self.metric = None
        self.admin_distance = None
        self.protocol = ""
        self.device_name = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Route object to dictionary for CSV export.

        Returns:
            Dictionary containing all route attributes
        """
        return {
            'Device': self.device_name,
            'Type': self.route_type,
            'Destination': self.destination,
            'Mask': self.mask,
            'Next Hop': self.next_hop,
            'Interface': self.interface,
            'Metric': self.metric if self.metric is not None else '',
            'Admin Distance': self.admin_distance if self.admin_distance is not None else '',
            'Protocol': self.protocol
        }


class DeviceConfiguration:
    """
    Represents overall device configuration and administrative settings.

    Attributes:
        device_name: Hostname of the device
        device_type: Type of device (router, switch, firewall, etc.)
        os_version: Operating system version
        model: Hardware model
        serial_number: Device serial number
        uptime: System uptime
        interfaces: List of NetworkInterface objects
        vlans: List of VLAN objects
        endpoints: List of Endpoint objects (servers/hosts)
        acls: List of AccessControlList objects
        routes: List of Route objects
        domain_name: DNS domain name
        ntp_servers: List of NTP server addresses
        logging_servers: List of logging/syslog server addresses
        snmp_community: SNMP community string (if configured)
        aaa_config: AAA configuration details
        banner_motd: Message of the day banner
        banner_login: Login banner
    """

    def __init__(self, device_name: str = ""):
        """
        Initialize a DeviceConfiguration object.

        Args:
            device_name: Hostname of the device

        Returns:
            None
        """
        self.device_name = device_name
        self.hostname = device_name  # Alias for device_name
        self.vendor = ""  # cisco, juniper, paloalto, fortigate, eltex
        self.platform = ""  # ios, nxos, junos, panos, fortios, eltex-mes, etc.
        self.device_type = ""
        self.os_version = ""
        self.model = ""
        self.serial_number = ""
        self.uptime = ""
        self.interfaces = []
        self.vlans = []
        self.endpoints = []  # Network endpoints/servers
        self.acls = []
        self.routes = []
        self.domain_name = ""
        self.name_servers = []  # DNS servers
        self.ntp_servers = []
        self.logging_servers = []
        self.snmp_community = ""
        self.aaa_config = {}
        self.banner_motd = ""
        self.banner_login = ""
        
        # Routing information
        self.default_gateway = ""
        self.routing_info = {}  # Static routes, routing protocols, etc.
        
        # Administration config
        self.admin_config = None  # AdministrationConfig object
        
        # Data monitoring configurations
        self.span_sessions = []  # SPAN/RSPAN/ERSPAN sessions
        self.netflow_configs = []  # NetFlow/IPFIX configurations
        self.monitor_sessions = []  # Generic monitor sessions
        
        # Global Protect VPN (Palo Alto only)
        self.gp_portals = []  # Global Protect portals
        self.gp_gateways = []  # Global Protect gateways
        self.gp_client_configs = []  # Global Protect client configurations
        
        # ENHANCED v3.0: Individual administrative accounts and monitoring configs
        self.admin_accounts = []  # List of AdministrativeAccount objects
        self.monitoring_configs = []  # List of DataMonitoringConfig objects
        self.flow_mappings = []  # List of NetworkFlowMapping objects

    def add_interface(self, interface: NetworkInterface) -> None:
        """
        Add an interface to the device configuration.

        Args:
            interface: NetworkInterface object to add

        Returns:
            None
        """
        self.interfaces.append(interface)

    def add_vlan(self, vlan: VLAN) -> None:
        """
        Add a VLAN to the device configuration.

        Args:
            vlan: VLAN object to add

        Returns:
            None
        """
        self.vlans.append(vlan)

    def add_endpoint(self, endpoint: 'Endpoint') -> None:
        """
        Add an endpoint to the device configuration.

        Args:
            endpoint: Endpoint object to add

        Returns:
            None
        """
        self.endpoints.append(endpoint)

    def add_acl(self, acl: AccessControlList) -> None:
        """
        Add an ACL to the device configuration.

        Args:
            acl: AccessControlList object to add

        Returns:
            None
        """
        self.acls.append(acl)

    def add_route(self, route: Route) -> None:
        """
        Add a route to the device configuration.

        Args:
            route: Route object to add

        Returns:
            None
        """
        self.routes.append(route)

    def to_admin_dict(self) -> Dict[str, Any]:
        """
        Convert administrative configuration to dictionary for CSV export.

        Returns:
            Dictionary containing administrative settings
        """
        return {
            'Device': self.device_name,
            'Device Type': self.device_type,
            'Domain Name': self.domain_name,
            'NTP Servers': ';'.join(self.ntp_servers) if self.ntp_servers else '',
            'Logging Servers': ';'.join(self.logging_servers) if self.logging_servers else '',
            'SNMP Community': self.snmp_community,
            'AAA Config': str(self.aaa_config) if self.aaa_config else '',
            'MOTD Banner': self.banner_motd.replace('\n', ' ')[:100],
            'Login Banner': self.banner_login.replace('\n', ' ')[:100]
        }

    def to_hardware_dict(self) -> Dict[str, Any]:
        """
        Convert hardware/firmware information to dictionary for CSV export.

        Returns:
            Dictionary containing hardware and firmware details
        """
        return {
            'Device': self.device_name,
            'Model': self.model,
            'OS Version': self.os_version,
            'Serial Number': self.serial_number,
            'Uptime': self.uptime
        }


class NetworkTopology:
    """
    Represents the network topology with devices and their connections.

    Attributes:
        devices: Dictionary of device configurations keyed by device name
        connections: List of connections between interfaces
    """

    def __init__(self):
        """
        Initialize a NetworkTopology object.

        Returns:
            None
        """
        self.devices = {}
        self.connections = []

    def add_device(self, device: DeviceConfiguration) -> None:
        """
        Add a device to the topology.

        Args:
            device: DeviceConfiguration object to add

        Returns:
            None
        """
        self.devices[device.device_name] = device

    def add_connection(self, device1: str, interface1: str, device2: str, interface2: str) -> None:
        """
        Add a connection between two device interfaces.

        Args:
            device1: Name of first device
            interface1: Interface name on first device
            device2: Name of second device
            interface2: Interface name on second device

        Returns:
            None
        """
        connection = {
            'device1': device1,
            'interface1': interface1,
            'device2': device2,
            'interface2': interface2
        }
        self.connections.append(connection)

    def get_device(self, device_name: str) -> Optional[DeviceConfiguration]:
        """
        Retrieve a device configuration by name.

        Args:
            device_name: Name of the device to retrieve

        Returns:
            DeviceConfiguration object or None if not found
        """
        return self.devices.get(device_name)


class ParsedConfig:
    """
    Container for parsed configuration data ready for CSV export.

    Attributes:
        interfaces_data: List of interface dictionaries
        vlans_data: List of VLAN dictionaries
        acls_data: List of ACL dictionaries
        acl_entries_data: List of ACE dictionaries
        routes_data: List of route dictionaries
        admin_data: List of administrative configuration dictionaries
        hardware_data: List of hardware/firmware dictionaries
    """

    def __init__(self):
        """
        Initialize a ParsedConfig object.

        Returns:
            None
        """
        self.interfaces_data = []
        self.vlans_data = []
        self.acls_data = []
        self.acl_entries_data = []
        self.routes_data = []
        self.admin_data = []
        self.hardware_data = []

    def add_from_device_config(self, device_config: DeviceConfiguration) -> None:
        """
        Extract data from a DeviceConfiguration and add to parsed data.

        Args:
            device_config: DeviceConfiguration object to extract data from

        Returns:
            None
        """
        # Add interfaces
        for interface in device_config.interfaces:
            self.interfaces_data.append(interface.to_dict())

        # Add VLANs
        for vlan in device_config.vlans:
            self.vlans_data.append(vlan.to_dict())

        # Add ACLs and their entries
        for acl in device_config.acls:
            self.acls_data.append(acl.to_dict())
            for entry in acl.entries:
                entry_dict = entry.to_dict()
                entry_dict['ACL Name'] = acl.name
                entry_dict['Device'] = device_config.device_name
                self.acl_entries_data.append(entry_dict)

        # Add routes
        for route in device_config.routes:
            self.routes_data.append(route.to_dict())

        # Add administrative configuration
        self.admin_data.append(device_config.to_admin_dict())

        # Add hardware information
        self.hardware_data.append(device_config.to_hardware_dict())


# =============================================================================
# ENHANCED v3.0 DATA STRUCTURES
# =============================================================================


class PortChannelMembership:
    """
    Represents port-channel/aggregate interface membership.
    
    CRITICAL v3.0 ENHANCEMENT: Prevents port-channel duplication by tracking
    member relationships explicitly.
    
    Attributes:
        port_channel_name: Name of the port-channel (e.g., 'Port-channel1', 'ae0')
        mode: Membership mode (e.g., 'active', 'passive', 'on', 'desirable', 'auto')
        protocol: Aggregation protocol (e.g., 'LACP', 'PAgP', 'static')
        status: Operational status (e.g., 'bundled', 'suspended', 'down')
    """
    
    def __init__(self, port_channel_name: str, mode: str = '', protocol: str = '', status: str = ''):
        """Initialize port-channel membership."""
        self.port_channel_name = port_channel_name
        self.mode = mode  # active, passive, on, desirable, auto
        self.protocol = protocol  # LACP, PAgP, static, 802.3ad
        self.status = status  # bundled, suspended, down


class AdministrativeAccount:
    """
    Represents an individual administrative account.
    
    CRITICAL v3.0 ENHANCEMENT: Individual account objects instead of concatenated strings.
    Each user, SNMP community, and enable secret gets its own object.
    
    Attributes:
        device_name: Device this account belongs to
        account_type: Type ('user', 'snmp', 'enable', 'tacacs', 'radius')
        username: Username or community string
        privilege_level: Privilege level (0-15, 'RO', 'RW', 'super-user', etc.)
        credential: Password hash or community string
        credential_type: Type of credential ('hash', 'plaintext', 'community', 'none')
        hash_algorithm: Hash algorithm ('md5', 'sha256', 'sha512', 'type7', 'scrypt', etc.)
        access_methods: List of access methods (['ssh', 'telnet', 'console', 'http', 'https'])
        vty_lines: VTY line range (e.g., '0 4')
        acl_name: Access control list name
        source_ips: List of allowed source IPs/networks
        enabled: Whether account is enabled
        description: Account description or purpose
    """
    
    def __init__(self):
        """Initialize administrative account."""
        self.device_name = ''
        self.account_type = ''  # user, snmp, enable, tacacs, radius
        self.username = ''
        self.privilege_level = ''  # 0-15, RO, RW, super-user, etc.
        self.credential = ''  # Hash or community string
        self.credential_type = ''  # hash, plaintext, community, none
        self.hash_algorithm = ''  # md5, sha256, sha512, type7, scrypt, pbkdf2, etc.
        self.access_methods = []  # ssh, telnet, console, http, https, snmp
        self.vty_lines = ''  # VTY line range
        self.acl_name = ''  # Access control list
        self.source_ips = []  # Allowed source IPs/networks
        self.enabled = True
        self.description = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV export."""
        return {
            'Device': self.device_name,
            'Account Type': self.account_type,
            'Username': self.username,
            'Privilege Level': self.privilege_level,
            'Hash Algorithm': self.hash_algorithm,
            'Credential Type': self.credential_type,
            'Access Methods': ', '.join(self.access_methods) if self.access_methods else '',
            'VTY Lines': self.vty_lines,
            'ACL': self.acl_name,
            'Source IPs': ', '.join(self.source_ips) if self.source_ips else '',
            'Enabled': 'Yes' if self.enabled else 'No',
            'Description': self.description
        }


class DataMonitoringConfig:
    """
    Represents an individual data monitoring configuration.
    
    CRITICAL v3.0 ENHANCEMENT: Individual config objects instead of concatenated strings.
    Each SPAN session, NetFlow exporter, jFlow instance gets its own object.
    
    Attributes:
        device_name: Device this config belongs to
        monitoring_type: Type ('span', 'rspan', 'erspan', 'netflow', 'ipfix', 'jflow', 'sflow', 'port_mirror')
        session_name: Session or exporter name
        source_interfaces: List of source interfaces
        source_vlans: List of source VLANs
        destination_interface: Destination interface (for SPAN)
        destination_ip: Destination IP (for NetFlow/jFlow/sFlow)
        destination_port: Destination port
        direction: Traffic direction ('rx', 'tx', 'both')
        flow_version: Flow version (5, 9, 10/IPFIX)
        sampling_rate: Sampling rate (e.g., '1:1000')
        source_address: Source IP for flow exports
        filter_acl: Filter ACL name
        description: Configuration description
    """
    
    def __init__(self):
        """Initialize data monitoring configuration."""
        self.device_name = ''
        self.monitoring_type = ''  # span, rspan, erspan, netflow, ipfix, jflow, sflow
        self.session_name = ''
        self.source_interfaces = []
        self.source_vlans = []
        self.destination_interface = ''
        self.destination_ip = ''
        self.destination_port = None
        self.direction = ''  # rx, tx, both
        self.flow_version = None  # 5, 9, 10
        self.sampling_rate = ''  # e.g., '1:1000'
        self.source_address = ''
        self.filter_acl = ''
        self.description = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV export."""
        return {
            'Device': self.device_name,
            'Type': self.monitoring_type,
            'Session/Name': self.session_name,
            'Source Interfaces': ', '.join(self.source_interfaces) if self.source_interfaces else '',
            'Source VLANs': ', '.join(str(v) for v in self.source_vlans) if self.source_vlans else '',
            'Dest Interface': self.destination_interface,
            'Dest IP': self.destination_ip,
            'Dest Port': str(self.destination_port) if self.destination_port else '',
            'Direction': self.direction,
            'Flow Version': str(self.flow_version) if self.flow_version else '',
            'Sampling Rate': self.sampling_rate,
            'Source Address': self.source_address,
            'Filter ACL': self.filter_acl,
            'Description': self.description
        }


class NetworkFlowMapping:
    """
    Represents network flow mapping data for visualization.
    
    CRITICAL v3.0 ENHANCEMENT: Separated flow mapping for visualizer.py
    Includes routing logic and path tracing capabilities.
    
    Attributes:
        device_name: Device name
        interface_name: Interface name
        interface_type: Type of interface
        description: Interface description
        ip_address: IP address
        subnet_mask: Subnet mask
        network: Network address
        cidr: CIDR notation
        vlan_id: VLAN ID
        input_acls: List of input ACLs
        output_acls: List of output ACLs
        connected_networks: Directly connected networks
        routed_networks: Networks reachable via routing
        admin_status: Administrative status
        protocol_status: Protocol status
        port_channel: Port-channel name if member
        member_interfaces: List of member interfaces if port-channel
        is_port_channel: Whether this is a port-channel
        vrf: VRF name
        routing_protocol: Routing protocol
        next_hop: Next hop for routed traffic
        metric: Routing metric
    """
    
    def __init__(self, device_name: str = '', interface_name: str = ''):
        """Initialize network flow mapping."""
        self.device_name = device_name
        self.interface_name = interface_name
        self.interface_type = ''
        self.description = ''
        self.ip_address = ''
        self.subnet_mask = ''
        self.network = ''
        self.cidr = ''
        self.vlan_id = None
        self.input_acls = []
        self.output_acls = []
        self.connected_networks = []
        self.routed_networks = []
        self.admin_status = ''
        self.protocol_status = ''
        self.port_channel = ''
        self.member_interfaces = []
        self.is_port_channel = False
        self.vrf = ''
        self.routing_protocol = ''
        self.next_hop = ''
        self.metric = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV export."""
        return {
            'Device': self.device_name,
            'Interface': self.interface_name,
            'Type': self.interface_type,
            'Description': self.description,
            'IP Address': self.ip_address,
            'Subnet Mask': self.subnet_mask,
            'Network': self.network,
            'CIDR': self.cidr,
            'VLAN': str(self.vlan_id) if self.vlan_id else '',
            'Input ACLs': ', '.join(self.input_acls) if self.input_acls else '',
            'Output ACLs': ', '.join(self.output_acls) if self.output_acls else '',
            'Connected Networks': ', '.join(self.connected_networks) if self.connected_networks else '',
            'Routed Networks': ', '.join(self.routed_networks) if self.routed_networks else '',
            'Admin Status': self.admin_status,
            'Protocol Status': self.protocol_status,
            'Port-Channel': self.port_channel,
            'Member Interfaces': ', '.join(self.member_interfaces) if self.member_interfaces else '',
            'Is Port-Channel': 'Yes' if self.is_port_channel else 'No',
            'VRF': self.vrf,
            'Routing Protocol': self.routing_protocol,
            'Next Hop': self.next_hop,
            'Metric': str(self.metric) if self.metric else ''
        }


# End of data_structures.py
