#!/usr/bin/env python3
"""
Synopsis:
    Cisco IOS-XE Configuration Parser

Description:
    Parser for Cisco IOS-XE configurations. Inherits from IOS parser
    as IOS-XE syntax is largely compatible with IOS, with some additional
    features for software-defined networking and programmability.

Version: 2.0.0
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .ios_parser import IOSParser


class IOSXEParser(IOSParser):
    """
    Parser for Cisco IOS-XE configurations.
    
    Extends IOS parser with IOS-XE specific features while maintaining
    backward compatibility with standard IOS configurations.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize IOS-XE parser."""
        super().__init__(verbose)
    
    def log(self, message: str) -> None:
        """Log with IOS-XE prefix."""
        if self.verbose:
            print(f"[IOS-XE Parser] {message}")
    
    def parse(self, config_lines):
        """Parse IOS-XE configuration."""
        # IOS-XE uses the same syntax as IOS for most features
        # Call parent parser
        device_config = super().parse(config_lines)
        
        # Add IOS-XE specific features if needed
        self.parse_application_visibility()
        self.parse_trustsec()
        
        return device_config
    
    def parse_application_visibility(self) -> None:
        """Parse Application Visibility and Control (AVC) configuration."""
        self.log("Parsing Application Visibility configuration")
        
        avc_config = []
        
        for line in self.config_lines:
            if 'ip nbar' in line.lower() or 'application visibility' in line.lower():
                avc_config.append(line.strip())
        
        if avc_config:
            self.device_config.aaa_config['application_visibility'] = avc_config
            self.log(f"Found {len(avc_config)} AVC configuration lines")
    
    def parse_trustsec(self) -> None:
        """Parse TrustSec configuration."""
        self.log("Parsing TrustSec configuration")
        
        trustsec_config = []
        
        for line in self.config_lines:
            if 'cts' in line.lower() and ('role-based' in line.lower() or 'sgt' in line.lower()):
                trustsec_config.append(line.strip())
        
        if trustsec_config:
            self.device_config.aaa_config['trustsec'] = trustsec_config
            self.log(f"Found {len(trustsec_config)} TrustSec configuration lines")


# End of iosxe_parser.py
