#!/usr/bin/env python3
"""
Synopsis:
    XML Generator for Multi-Vendor Network Configuration Analysis

Description:
    Generates well-formed XML output with multiple sections for network
    configuration analysis data. Organized into hierarchical structure with
    separate elements for each data category.
    
    Output includes sections for:
    - Network Flow Mapping
    - Administration
    - Interfaces
    - VLANs
    - Hardware
    - Summary

Notes:
    - Pure Python implementation (no external XML libraries)
    - Well-formed XML with proper escaping
    - Hierarchical structure for easy parsing
    - Optional schema validation support

Version: 2.0.0
"""

import sys
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class XMLGenerator:
    """
    Generates XML output for network configuration analysis.
    
    Creates well-formed XML document with hierarchical structure
    organized by data categories.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize XML generator."""
        self.verbose = verbose
        self.indent_level = 0
        self.indent_string = "  "
    
    def log(self, message: str) -> None:
        """Log message if verbose enabled."""
        if self.verbose:
            print(f"[XML Generator] {message}")
    
    def generate(
        self,
        network_flows: List,
        admin_configs: List,
        interfaces: List,
        vlans: List,
        endpoints: List,
        hardware_configs: List,
        output_path: str,
        parse_section: Optional[str] = None,
        span_sessions: Optional[List] = None,
        netflow_configs: Optional[List] = None,
        globalprotect_portals: Optional[List] = None,
        globalprotect_gateways: Optional[List] = None,
        globalprotect_client_configs: Optional[List] = None
    ) -> None:
        """
        Generate XML output.
        
        Args:
            network_flows: List of NetworkFlowMapping objects
            admin_configs: List of AdministrationConfig objects
            interfaces: List of NetworkInterface objects
            vlans: List of VLAN objects
            endpoints: List of Endpoint objects
            hardware_configs: List of DeviceConfiguration objects
            output_path: Output file path
            parse_section: Optional specific section to include
            span_sessions: Optional list of SPAN session objects
            netflow_configs: Optional list of NetFlow config objects
            globalprotect_portals: Optional list of Global Protect portals
            globalprotect_gateways: Optional list of Global Protect gateways
            globalprotect_client_configs: Optional list of Global Protect client configs
        """
        self.log(f"Generating XML output: {output_path}")
        
        # Ensure output path has .xml extension
        if not output_path.endswith('.xml'):
            output_path += '.xml'
        
        # Convert objects to dictionaries
        flows_data = [flow.to_dict() for flow in network_flows]
        admin_data = [admin.to_dict() for admin in admin_configs]
        interfaces_data = [intf.to_dict() for intf in interfaces]
        vlans_data = [vlan.to_dict() for vlan in vlans]
        endpoints_data = [ep.to_dict() for ep in endpoints]
        hardware_data = [hw.to_hardware_dict() for hw in hardware_configs]
        
        # Convert monitoring data to dictionaries
        span_data = [span.to_dict() for span in (span_sessions or [])]
        netflow_data = [nf.to_dict() for nf in (netflow_configs or [])]
        monitoring_data = span_data + netflow_data  # Combined monitoring data
        
        # Convert Global Protect data to dictionaries
        gp_portal_data = [portal.to_dict() for portal in (globalprotect_portals or [])]
        gp_gateway_data = [gateway.to_dict() for gateway in (globalprotect_gateways or [])]
        gp_client_data = [client.to_dict() for client in (globalprotect_client_configs or [])]
        globalprotect_data = {
            'portals': gp_portal_data,
            'gateways': gp_gateway_data,
            'client_configs': gp_client_data
        }
        
        # Build XML content
        xml_content = self.build_xml(
            flows_data, admin_data, interfaces_data, vlans_data,
            endpoints_data, hardware_data, monitoring_data, parse_section, globalprotect_data
        )
        
        # Write to file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)
            self.log(f"XML output generated: {output_path}")
        except IOError as error:
            raise IOError(f"Failed to write XML file: {error}")
    
    def build_xml(
        self,
        flows_data: List[Dict],
        admin_data: List[Dict],
        interfaces_data: List[Dict],
        vlans_data: List[Dict],
        endpoints_data: List[Dict],
        hardware_data: List[Dict],
        monitoring_data: List[Dict],
        parse_section: Optional[str],
        globalprotect_data: Optional[Dict] = None
    ) -> str:
        """Build complete XML document."""
        self.indent_level = 0
        
        xml_lines = []
        xml_lines.append('<?xml version="1.0" encoding="UTF-8"?>')
        xml_lines.append(self.tag_open('NetworkConfigurationAnalysis', {
            'version': '2.2',
            'generated': datetime.now().isoformat()
        }))
        
        self.indent_level += 1
        
        # Add metadata
        xml_lines.append(self.indent() + self.tag_open('Metadata'))
        self.indent_level += 1
        xml_lines.append(self.indent() + self.tag_element('Generator', 'Multi-Vendor Network Configuration Analyzer'))
        xml_lines.append(self.indent() + self.tag_element('Version', '2.2.0'))
        xml_lines.append(self.indent() + self.tag_element('Timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        xml_lines.append(self.indent() + self.tag_element('TotalDevices', str(self.count_unique_devices(
            flows_data, admin_data, interfaces_data, vlans_data, endpoints_data, hardware_data
        ))))
        self.indent_level -= 1
        xml_lines.append(self.indent() + self.tag_close('Metadata'))
        
        # Determine which sections to include
        include_all = parse_section is None
        
        # Network Flow Mapping section
        if include_all or parse_section == 'flows':
            xml_lines.append(self.build_section('NetworkFlowMappings', flows_data, 'FlowMapping'))
        
        # Administration section
        if include_all or parse_section == 'admin':
            xml_lines.append(self.build_section('Administration', admin_data, 'AdminConfig'))
        
        # Interfaces section
        if include_all or parse_section == 'interfaces':
            xml_lines.append(self.build_section('Interfaces', interfaces_data, 'Interface'))
        
        # VLANs section
        if include_all or parse_section == 'vlans':
            xml_lines.append(self.build_section('VLANs', vlans_data, 'VLAN'))
        
        # Endpoints section
        if include_all or parse_section == 'endpoints':
            xml_lines.append(self.build_section('Endpoints', endpoints_data, 'Endpoint'))
        
        # Data Monitoring section
        if include_all or parse_section == 'monitoring':
            xml_lines.append(self.build_section('DataMonitoring', monitoring_data, 'MonitoringConfig'))
        
        # Global Protect VPN section (if data exists)
        if include_all and globalprotect_data:
            gp_combined = []
            if globalprotect_data.get('portals'):
                gp_combined.extend(globalprotect_data['portals'])
            if globalprotect_data.get('gateways'):
                gp_combined.extend(globalprotect_data['gateways'])
            if globalprotect_data.get('client_configs'):
                gp_combined.extend(globalprotect_data['client_configs'])
            
            if gp_combined:
                xml_lines.append(self.build_section('GlobalProtectVPN', gp_combined, 'GPConfig'))
        
        # Hardware section
        if include_all or parse_section == 'hardware':
            xml_lines.append(self.build_section('Hardware', hardware_data, 'Device'))
        
        # Summary section (always included)
        if include_all:
            summary_data = self.generate_summary(
                flows_data, admin_data, interfaces_data, vlans_data, endpoints_data, hardware_data
            )
            xml_lines.append(self.build_section('Summary', summary_data, 'Metric'))
        
        self.indent_level -= 1
        xml_lines.append(self.tag_close('NetworkConfigurationAnalysis'))
        
        return '\n'.join(xml_lines)
    
    def build_section(self, section_name: str, data: List[Dict], item_name: str) -> str:
        """Build a section of XML with multiple items."""
        lines = []
        
        lines.append(self.indent() + self.tag_open(section_name, {'count': str(len(data))}))
        self.indent_level += 1
        
        for item in data:
            lines.append(self.build_item(item_name, item))
        
        self.indent_level -= 1
        lines.append(self.indent() + self.tag_close(section_name))
        
        return '\n'.join(lines)
    
    def build_item(self, item_name: str, item_data: Dict) -> str:
        """Build a single item with its fields."""
        lines = []
        
        lines.append(self.indent() + self.tag_open(item_name))
        self.indent_level += 1
        
        for key, value in item_data.items():
            # Clean up key name for XML (remove spaces, special chars)
            xml_key = key.replace(' ', '').replace('/', '_').replace('-', '_')
            
            # Handle nested structures
            if isinstance(value, dict):
                lines.append(self.indent() + self.tag_open(xml_key))
                self.indent_level += 1
                for sub_key, sub_value in value.items():
                    sub_xml_key = sub_key.replace(' ', '').replace('/', '_')
                    lines.append(self.indent() + self.tag_element(sub_xml_key, str(sub_value)))
                self.indent_level -= 1
                lines.append(self.indent() + self.tag_close(xml_key))
            elif isinstance(value, list):
                lines.append(self.indent() + self.tag_open(xml_key))
                self.indent_level += 1
                for item in value:
                    lines.append(self.indent() + self.tag_element('Item', str(item)))
                self.indent_level -= 1
                lines.append(self.indent() + self.tag_close(xml_key))
            else:
                lines.append(self.indent() + self.tag_element(xml_key, str(value)))
        
        self.indent_level -= 1
        lines.append(self.indent() + self.tag_close(item_name))
        
        return '\n'.join(lines)
    
    def generate_summary(
        self,
        flows_data: List[Dict],
        admin_data: List[Dict],
        interfaces_data: List[Dict],
        vlans_data: List[Dict],
        endpoints_data: List[Dict],
        hardware_data: List[Dict]
    ) -> List[Dict]:
        """Generate summary statistics."""
        devices = set()
        total_interfaces = len(interfaces_data)
        active_interfaces = sum(1 for intf in interfaces_data if intf.get('Admin Status') == 'Up')
        total_vlans = len(vlans_data)
        total_endpoints = len(endpoints_data)
        total_networks = len(flows_data)
        
        for data in [flows_data, admin_data, interfaces_data, vlans_data, endpoints_data, hardware_data]:
            for item in data:
                if 'Device' in item and item['Device']:
                    devices.add(item['Device'])
        
        return [{
            'Metric': 'Total Devices',
            'Value': str(len(devices)),
            'Description': 'Number of unique devices analyzed'
        }, {
            'Metric': 'Total Interfaces',
            'Value': str(total_interfaces),
            'Description': 'Total number of interfaces'
        }, {
            'Metric': 'Active Interfaces',
            'Value': str(active_interfaces),
            'Description': 'Interfaces in up state'
        }, {
            'Metric': 'Total VLANs',
            'Value': str(total_vlans),
            'Description': 'Number of VLANs configured'
        }, {
            'Metric': 'Endpoints',
            'Value': str(total_endpoints),
            'Description': 'Configured endpoints and servers'
        }, {
            'Metric': 'Network Flows',
            'Value': str(total_networks),
            'Description': 'Unique network flow mappings'
        }]
    
    def count_unique_devices(self, *data_lists) -> int:
        """Count unique devices across all data sets."""
        devices = set()
        for data_list in data_lists:
            for item in data_list:
                if 'Device' in item and item['Device']:
                    devices.add(item['Device'])
        return len(devices)
    
    def indent(self) -> str:
        """Return current indentation string."""
        return self.indent_string * self.indent_level
    
    def tag_open(self, tag_name: str, attributes: Optional[Dict[str, str]] = None) -> str:
        """Create opening XML tag with optional attributes."""
        if attributes:
            attrs = ' '.join([f'{k}="{escape(v)}"' for k, v in attributes.items()])
            return f'<{tag_name} {attrs}>'
        return f'<{tag_name}>'
    
    def tag_close(self, tag_name: str) -> str:
        """Create closing XML tag."""
        return f'</{tag_name}>'
    
    def tag_element(self, tag_name: str, content: str) -> str:
        """Create complete XML element with content."""
        escaped_content = escape(str(content))
        return f'<{tag_name}>{escaped_content}</{tag_name}>'


# End of xml_generator.py