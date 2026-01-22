#!/usr/bin/env python3
"""
Synopsis:
    Shared Components Package for Multi-Vendor Network Configuration Analyzer

Description:
    This package contains shared data structures used across the analyzer,
    parsers, and output generators. Includes structures for device configurations,
    network interfaces, VLANs, ACLs, routes, endpoints, monitoring configurations,
    and GlobalProtect VPN data.

Modules:
    - data_structures: Core data model classes
    - monitoring_structures: SPAN, NetFlow, Monitor session classes
    - globalprotect_structures: GlobalProtect VPN configuration data structures and classes (Palo Alto)
    - utilities: Helper functions and parsing utilities
    - constants: Regular expressions and configuration constants

Version: 3.0.0
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import core data structures
from .data_structures import (
    NetworkInterface,
    VLAN,
    Endpoint,
    AccessControlList,
    AccessControlEntry,
    Route,
    DeviceConfiguration,
    NetworkTopology,
    ParsedConfig
)

# Import monitoring structures
from .monitoring_structures import (
    SPANSession,
    NetFlowConfig,
    MonitorSession
)

# Import GlobalProtect structures
from .globalprotect_structures import (
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

# Import utility functions
from .utilities import (
    read_config_file,
    write_config_file,
    parse_hierarchical_config,
    find_parent_config,
    extract_interface_name,
    extract_vlan_id,
    extract_ip_address,
    extract_ipv6_address,
    parse_vlan_list,
    is_valid_ipv4_address,
    is_valid_subnet_mask,
    subnet_mask_to_cidr,
    cidr_to_subnet_mask,
    calculate_network_address,
    normalize_interface_name,
    parse_acl_entry,
    detect_device_type,
    sanitize_filename,
    format_mac_address
)

# Import commonly used constants
from .constants import (
    VERSION,
    DEVICE_TYPE_IOS,
    DEVICE_TYPE_IOSXE,
    DEVICE_TYPE_NXOS,
    DEVICE_TYPE_ASA,
    DEVICE_TYPE_NGFW,
    INTERFACE_PATTERN,
    IP_ADDRESS_PATTERN,
    VLAN_PATTERN,
    ACL_NAMED_PATTERN,
    STATIC_ROUTE_PATTERN,
    HOSTNAME_PATTERN
)

__version__ = '3.0.0'
__all__ = [
    # Core Data Structures
    'NetworkInterface',
    'VLAN',
    'Endpoint',
    'AccessControlList',
    'AccessControlEntry',
    'Route',
    'DeviceConfiguration',
    'NetworkTopology',
    'ParsedConfig',
    
    # Monitoring Structures
    'SPANSession',
    'NetFlowConfig',
    'MonitorSession',
    
    # GlobalProtect Structures
    'GlobalProtectData',
    'GlobalProtectPortal',
    'GlobalProtectGateway',
    'AgentConfiguration',
    'HIPObject',
    'HIPProfile',
    'AuthenticationProfile',
    'CertificateProfile',
    'SSLTLSProfile',
    'TunnelInterface',
    'SecurityPolicy',
    
    # Utilities
    'read_config_file',
    'write_config_file',
    'parse_hierarchical_config',
    'find_parent_config',
    'extract_interface_name',
    'extract_vlan_id',
    'extract_ip_address',
    'extract_ipv6_address',
    'parse_vlan_list',
    'is_valid_ipv4_address',
    'is_valid_subnet_mask',
    'subnet_mask_to_cidr',
    'cidr_to_subnet_mask',
    'calculate_network_address',
    'normalize_interface_name',
    'parse_acl_entry',
    'detect_device_type',
    'sanitize_filename',
    'format_mac_address',
    
    # Constants
    'VERSION',
    'DEVICE_TYPE_IOS',
    'DEVICE_TYPE_IOSXE',
    'DEVICE_TYPE_NXOS',
    'DEVICE_TYPE_ASA',
    'DEVICE_TYPE_NGFW'
]