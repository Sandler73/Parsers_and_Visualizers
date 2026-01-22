#!/usr/bin/env python3
"""
Synopsis:
    Comprehensive Cisco Next-Generation Firewall Configuration Parser

Description:
    This module provides complete parsing capabilities for Cisco NGFW
    (Firepower) configurations. Handles security zones, security policies,
    application control, and IPS configurations.

Version: 2.0.0
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .asa_parser import ASAParser


class NGFWParser(ASAParser):
    """
    Comprehensive parser for Cisco Next-Generation Firewall configurations.
    
    Extends ASA parser with NGFW-specific features including security zones,
    security policies, and application-layer controls.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize NGFW parser."""
        super().__init__(verbose)
    
    def log(self, message: str) -> None:
        """Log with NGFW prefix."""
        if self.verbose:
            print(f"[NGFW Parser] {message}")
    
    def parse(self, config_lines):
        """Parse NGFW configuration with advanced security features."""
        # Call parent parse (ASA)
        device_config = super().parse(config_lines)
        
        # Add NGFW-specific parsing
        self.parse_security_zones()
        self.parse_security_policies()
        self.parse_application_filters()
        self.parse_ips_config()
        
        return device_config
    
    def parse_security_zones(self) -> None:
        """Parse security zone definitions."""
        self.log("Parsing security zones")
        
        zones = {}
        current_zone = None
        
        for line in self.config_lines:
            # Security zone declaration
            zone_match = re.match(r'security-zone\s+(\S+)', line, re.IGNORECASE)
            
            if zone_match:
                zone_name = zone_match.group(1)
                current_zone = zone_name
                zones[zone_name] = {
                    'interfaces': [],
                    'policies': []
                }
            
            elif current_zone and line.startswith(' '):
                # Zone configuration
                if 'interface' in line.lower():
                    intf_match = re.search(r'interface\s+(\S+)', line, re.IGNORECASE)
                    if intf_match:
                        zones[current_zone]['interfaces'].append(intf_match.group(1))
            
            else:
                current_zone = None
        
        if zones:
            self.device_config.aaa_config['security_zones'] = zones
            self.log(f"Parsed {len(zones)} security zones")
    
    def parse_security_policies(self) -> None:
        """Parse security policy rules."""
        self.log("Parsing security policies")
        
        policies = []
        
        for line in self.config_lines:
            # Security policy rules
            if 'access-policy' in line.lower() or 'security-policy' in line.lower():
                policies.append(line.strip())
        
        if policies:
            self.device_config.aaa_config['security_policies'] = policies
            self.log(f"Found {len(policies)} security policy entries")
    
    def parse_application_filters(self) -> None:
        """Parse application control filters."""
        self.log("Parsing application filters")
        
        app_filters = []
        
        for line in self.config_lines:
            # Application filters and controls
            if 'class-map' in line.lower() and 'type inspect' in line.lower():
                app_filters.append(line.strip())
        
        if app_filters:
            self.device_config.aaa_config['application_filters'] = app_filters
            self.log(f"Found {len(app_filters)} application filter entries")
    
    def parse_ips_config(self) -> None:
        """Parse IPS (Intrusion Prevention System) configuration."""
        self.log("Parsing IPS configuration")
        
        ips_config = {}
        
        for line in self.config_lines:
            # IPS signature configuration
            if 'ips' in line.lower() or 'intrusion' in line.lower():
                if 'signature' in line.lower():
                    ips_config['signatures'] = ips_config.get('signatures', [])
                    ips_config['signatures'].append(line.strip())
                elif 'policy' in line.lower():
                    ips_config['policies'] = ips_config.get('policies', [])
                    ips_config['policies'].append(line.strip())
        
        if ips_config:
            self.device_config.aaa_config['ips'] = ips_config
            self.log("IPS configuration found")


# End of ngfw_parser.py
