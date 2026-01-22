#!/usr/bin/env python3
"""
Synopsis:
    Parser Modules Package for Multi-Vendor Network Configuration Analyzer

Description:
    This package provides device-specific parsers for network equipment
    configurations from multiple vendors. Each parser is optimized for a
    specific vendor/platform while maintaining a consistent interface.

Vendor Support:
    - Cisco: IOS, IOS-XE, NX-OS, ASA, FTD/NGFW
    - Juniper: JunOS (MX, EX, SRX, QFX, PTX series)
    - Palo Alto: PAN-OS (with Global Protect VPN support)
    - Fortigate: FortiOS
    - Eltex: MES, ESR series

Modules:
    Cisco Parsers:
    - ios_parser: Cisco IOS parser (also handles IOS-XE)
    - iosxe_parser: Cisco IOS-XE specific features
    - nxos_parser: Cisco NX-OS (Nexus) parser
    - asa_parser: Cisco ASA firewall parser
    - ngfw_parser: Cisco Next-Generation Firewall parser
    
    Multi-Vendor Parsers:
    - base_parser: Abstract base class for all parsers
    - juniper_parser: Juniper JunOS parser
    - paloalto_parser: Palo Alto PAN-OS parser
    - globalprotect_xml_parser: Palo Alto GlobalProtect VPN parser
    - fortigate_parser: Fortigate FortiOS parser
    - eltex_parser: Eltex MES/ESR parser

Version: 3.0.0
"""

# Cisco parsers
from .ios_parser import IOSParser
from .iosxe_parser import IOSXEParser
from .nxos_parser import NXOSParser
from .asa_parser import ASAParser
from .ngfw_parser import NGFWParser

# Base parser
from .base_parser import BaseParser

# Multi-vendor parsers
from .juniper_parser import JuniperParser
from .paloalto_parser import PaloAltoParser
from .fortigate_parser import FortigateParser
from .eltex_parser import EltexParser

# Import GlobalProtect XML parser from this directory
from .globalprotect_xml_parser import (
    GlobalProtectXMLParser,
    parse_globalprotect_config
)

__version__ = '2.2.0'
__all__ = [
    # Cisco
    'IOSParser',
    'IOSXEParser',
    'NXOSParser',
    'ASAParser',
    'NGFWParser',
    # Base
    'BaseParser',
    # Juniper
    'JuniperParser',
    #Palo Alto
    'PaloAltoParser',
    'GlobalProtectXMLParser',
    'parse_globalprotect_config',
    #Fortigate
    'FortigateParser',
    #Eltex
    'EltexParser'
]