#!/usr/bin/env python3
"""
Synopsis:
    Constants module for Cisco network configuration analysis

Description:
    This module defines constants, regular expressions, and configuration
    parameters used throughout the Cisco Network Configuration Analyzer project.
    Centralizing these values ensures consistency and simplifies maintenance.

Notes:
    - No external dependencies
    - Regular expressions are pre-compiled for performance
    - Constants are organized by functional category

Version: 1.0.0
"""

import re

# ============================================================================
# Version Information
# ============================================================================
VERSION = "1.0.0"
PROJECT_NAME = "Cisco Network Configuration Analyzer"

# ============================================================================
# File Extensions and Formats
# ============================================================================
CONFIG_EXTENSIONS = ['.txt', '.conf', '.cfg', '']
CSV_EXTENSION = '.csv'
HTML_EXTENSION = '.html'
CSS_EXTENSION = '.css'

# ============================================================================
# CSV Sheet Names
# ============================================================================
CSV_SHEET_INTERFACES = 'Interfaces'
CSV_SHEET_VLANS = 'VLANs'
CSV_SHEET_ACLS = 'ACLs'
CSV_SHEET_ACL_ENTRIES = 'ACL Entries'
CSV_SHEET_ROUTES = 'Routes'
CSV_SHEET_ADMIN = 'Administrative'
CSV_SHEET_HARDWARE = 'Hardware'

# ============================================================================
# Regular Expression Patterns
# ============================================================================

# Interface patterns
INTERFACE_PATTERN = re.compile(r'^interface\s+(\S+)', re.IGNORECASE)
INTERFACE_DESC_PATTERN = re.compile(r'^\s*description\s+(.+)$', re.IGNORECASE)
INTERFACE_SHUTDOWN_PATTERN = re.compile(r'^\s*shutdown\s*$', re.IGNORECASE)
INTERFACE_NO_SHUTDOWN_PATTERN = re.compile(r'^\s*no\s+shutdown\s*$', re.IGNORECASE)

# IP Address patterns
IP_ADDRESS_PATTERN = re.compile(
    r'^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)
IP_ADDRESS_SECONDARY_PATTERN = re.compile(
    r'^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+secondary',
    re.IGNORECASE
)
IPV6_ADDRESS_PATTERN = re.compile(
    r'^\s*ipv6\s+address\s+([0-9a-fA-F:]+(?:/\d+)?)',
    re.IGNORECASE
)

# VLAN patterns
VLAN_PATTERN = re.compile(r'^vlan\s+([\d,\-\s]+)', re.IGNORECASE)
VLAN_NAME_PATTERN = re.compile(r'^\s*name\s+(.+)$', re.IGNORECASE)
SWITCHPORT_ACCESS_VLAN_PATTERN = re.compile(r'^\s*switchport\s+access\s+vlan\s+(\d+)', re.IGNORECASE)
SWITCHPORT_TRUNK_PATTERN = re.compile(r'^\s*switchport\s+mode\s+trunk', re.IGNORECASE)
SWITCHPORT_TRUNK_ALLOWED_PATTERN = re.compile(
    r'^\s*switchport\s+trunk\s+allowed\s+vlan\s+(.+)$',
    re.IGNORECASE
)

# ACL patterns
ACL_STANDARD_PATTERN = re.compile(r'^access-list\s+(\d+)\s+(\w+)\s+(.+)$', re.IGNORECASE)
ACL_EXTENDED_PATTERN = re.compile(r'^access-list\s+(\d+)\s+(\w+)\s+(\w+)\s+(.+)$', re.IGNORECASE)
ACL_NAMED_PATTERN = re.compile(r'^ip\s+access-list\s+(standard|extended)\s+(\S+)', re.IGNORECASE)
ACL_ENTRY_PATTERN = re.compile(
    r'^\s*(?:(\d+)\s+)?(\w+)\s+(\w+)\s+(.+)$',
    re.IGNORECASE
)

# Route patterns
STATIC_ROUTE_PATTERN = re.compile(
    r'^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.+)$',
    re.IGNORECASE
)
ROUTE_MAP_PATTERN = re.compile(r'^route-map\s+(\S+)\s+(\w+)\s+(\d+)', re.IGNORECASE)

# Endpoint and Server patterns
# Object-group network patterns
OBJECT_GROUP_NETWORK_PATTERN = re.compile(r'^object-group\s+network\s+(\S+)', re.IGNORECASE)
OBJECT_NETWORK_PATTERN = re.compile(r'^object\s+network\s+(\S+)', re.IGNORECASE)
NETWORK_OBJECT_HOST_PATTERN = re.compile(r'^\s*(?:network-object\s+)?host\s+(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
NETWORK_OBJECT_SUBNET_PATTERN = re.compile(
    r'^\s*(?:network-object\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)
# NAT patterns (endpoints often appear in NAT configs)
NAT_STATIC_PATTERN = re.compile(
    r'^\s*(?:ip\s+)?nat\s+(?:inside\s+)?(?:source\s+)?static\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)
NAT_POOL_PATTERN = re.compile(
    r'^\s*(?:ip\s+)?nat\s+pool\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)
# Name resolution patterns (endpoints often have names)
IP_HOST_PATTERN = re.compile(r'^ip\s+host\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
# Server farm patterns (load balancer)
SERVER_FARM_PATTERN = re.compile(r'^serverfarm\s+(?:host\s+)?(\S+)', re.IGNORECASE)
REAL_SERVER_PATTERN = re.compile(r'^\s*real\s+(?:server\s+)?(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)

# Speed and duplex patterns
SPEED_PATTERN = re.compile(r'^\s*speed\s+(10|100|1000|10000|auto)', re.IGNORECASE)
DUPLEX_PATTERN = re.compile(r'^\s*duplex\s+(full|half|auto)', re.IGNORECASE)
MTU_PATTERN = re.compile(r'^\s*mtu\s+(\d+)', re.IGNORECASE)

# Administrative patterns
HOSTNAME_PATTERN = re.compile(r'^hostname\s+(\S+)', re.IGNORECASE)
DOMAIN_NAME_PATTERN = re.compile(r'^ip\s+domain-name\s+(\S+)', re.IGNORECASE)
NTP_SERVER_PATTERN = re.compile(r'^ntp\s+server\s+(\S+)', re.IGNORECASE)
LOGGING_PATTERN = re.compile(r'^logging\s+(?:host\s+)?(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
SNMP_COMMUNITY_PATTERN = re.compile(r'^snmp-server\s+community\s+(\S+)', re.IGNORECASE)

# Hardware patterns
VERSION_PATTERN = re.compile(r'^version\s+(\S+)', re.IGNORECASE)
MODEL_PATTERN = re.compile(r'^Model\s+number\s*:\s*(\S+)', re.IGNORECASE)
SERIAL_PATTERN = re.compile(r'^Serial\s+number\s*:\s*(\S+)', re.IGNORECASE)

# VRF patterns
VRF_PATTERN = re.compile(r'^ip\s+vrf\s+(\S+)', re.IGNORECASE)
VRF_FORWARD_PATTERN = re.compile(r'^\s*ip\s+vrf\s+forwarding\s+(\S+)', re.IGNORECASE)

# Port-channel patterns
CHANNEL_GROUP_PATTERN = re.compile(r'^\s*channel-group\s+(\d+)', re.IGNORECASE)

# MAC address pattern
MAC_ADDRESS_PATTERN = re.compile(
    r'([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})|'
    r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})|'
    r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})'
)

# ============================================================================
# Interface Type Mappings
# ============================================================================
INTERFACE_TYPE_PHYSICAL = 'Physical'
INTERFACE_TYPE_LOGICAL = 'Logical'
INTERFACE_TYPE_VIRTUAL = 'Virtual'

INTERFACE_TYPES = {
    'GigabitEthernet': INTERFACE_TYPE_PHYSICAL,
    'FastEthernet': INTERFACE_TYPE_PHYSICAL,
    'TenGigabitEthernet': INTERFACE_TYPE_PHYSICAL,
    'Ethernet': INTERFACE_TYPE_PHYSICAL,
    'Serial': INTERFACE_TYPE_PHYSICAL,
    'Loopback': INTERFACE_TYPE_VIRTUAL,
    'Tunnel': INTERFACE_TYPE_VIRTUAL,
    'Vlan': INTERFACE_TYPE_VIRTUAL,
    'Port-channel': INTERFACE_TYPE_LOGICAL,
    'Null': INTERFACE_TYPE_VIRTUAL
}

# ============================================================================
# Device Type Constants
# ============================================================================
DEVICE_TYPE_IOS = 'ios'
DEVICE_TYPE_IOSXE = 'iosxe'
DEVICE_TYPE_NXOS = 'nxos'
DEVICE_TYPE_ASA = 'asa'
DEVICE_TYPE_NGFW = 'ngfw'
DEVICE_TYPE_UNKNOWN = 'unknown'

# ============================================================================
# Protocol Constants
# ============================================================================
PROTOCOLS = [
    'ip', 'tcp', 'udp', 'icmp', 'igmp', 'esp', 'ah', 'gre', 'ospf', 'eigrp'
]

# Common TCP/UDP ports
COMMON_PORTS = {
    '20': 'FTP Data',
    '21': 'FTP Control',
    '22': 'SSH',
    '23': 'Telnet',
    '25': 'SMTP',
    '53': 'DNS',
    '80': 'HTTP',
    '110': 'POP3',
    '143': 'IMAP',
    '443': 'HTTPS',
    '3389': 'RDP',
    '8080': 'HTTP Alt'
}

# ============================================================================
# Routing Protocol Constants
# ============================================================================
ROUTING_PROTOCOLS = {
    'static': 'Static Route',
    'connected': 'Connected',
    'ospf': 'OSPF',
    'eigrp': 'EIGRP',
    'bgp': 'BGP',
    'rip': 'RIP',
    'isis': 'IS-IS'
}

# Administrative Distances
ADMIN_DISTANCES = {
    'connected': 0,
    'static': 1,
    'eigrp-summary': 5,
    'ebgp': 20,
    'eigrp-internal': 90,
    'igrp': 100,
    'ospf': 110,
    'is-is': 115,
    'rip': 120,
    'eigrp-external': 170,
    'ibgp': 200
}

# ============================================================================
# CSV Export Constants
# ============================================================================
CSV_DELIMITER = ','
CSV_QUOTECHAR = '"'
CSV_ENCODING = 'utf-8'

# ============================================================================
# HTML/CSS Constants
# ============================================================================
HTML_TITLE = 'Network Topology Visualization'
DEFAULT_THEME = 'light'

# Color scheme for light mode
COLORS_LIGHT = {
    'background': '#ffffff',
    'text': '#000000',
    'node_default': '#4a90e2',
    'node_router': '#e74c3c',
    'node_switch': '#3498db',
    'node_firewall': '#e67e22',
    'link_default': '#95a5a6',
    'link_active': '#2ecc71',
    'interface_up': '#2ecc71',
    'interface_down': '#e74c3c'
}

# Color scheme for dark mode
COLORS_DARK = {
    'background': '#1e1e1e',
    'text': '#ffffff',
    'node_default': '#4a90e2',
    'node_router': '#e74c3c',
    'node_switch': '#3498db',
    'node_firewall': '#e67e22',
    'link_default': '#95a5a6',
    'link_active': '#2ecc71',
    'interface_up': '#2ecc71',
    'interface_down': '#e74c3c'
}

# ============================================================================
# Error Messages
# ============================================================================
ERROR_FILE_NOT_FOUND = "Configuration file not found: {path}"
ERROR_FILE_READ = "Error reading file: {error}"
ERROR_FILE_WRITE = "Error writing file: {error}"
ERROR_INVALID_FORMAT = "Invalid configuration format detected"
ERROR_PARSE_FAILED = "Failed to parse configuration: {error}"
ERROR_UNSUPPORTED_DEVICE = "Unsupported device type: {type}"

# ============================================================================
# Success Messages
# ============================================================================
SUCCESS_PARSE_COMPLETE = "Configuration parsed successfully"
SUCCESS_CSV_GENERATED = "CSV file generated: {path}"
SUCCESS_HTML_GENERATED = "HTML visualization generated: {path}"

# ============================================================================
# Logging Constants
# ============================================================================
LOG_LEVEL_DEBUG = 'DEBUG'
LOG_LEVEL_INFO = 'INFO'
LOG_LEVEL_WARNING = 'WARNING'
LOG_LEVEL_ERROR = 'ERROR'
LOG_LEVEL_CRITICAL = 'CRITICAL'

# Default log level
DEFAULT_LOG_LEVEL = LOG_LEVEL_INFO

# ============================================================================
# Validation Constants
# ============================================================================
MAX_VLAN_ID = 4094
MIN_VLAN_ID = 1
MAX_PORT_NUMBER = 65535
MIN_PORT_NUMBER = 0

# IPv4 address ranges
IPV4_PRIVATE_RANGES = [
    ('10.0.0.0', '255.0.0.0'),
    ('172.16.0.0', '255.240.0.0'),
    ('192.168.0.0', '255.255.0.0')
]

# ============================================================================
# Visualization Constants
# ============================================================================
NODE_RADIUS = 30
LINK_WIDTH = 2
CANVAS_WIDTH = 1200
CANVAS_HEIGHT = 800
ZOOM_MIN = 0.1
ZOOM_MAX = 5.0

# Animation constants
ANIMATION_DURATION = 500  # milliseconds
HIGHLIGHT_DURATION = 2000  # milliseconds

# ============================================================================
# End of constants.py
# ============================================================================