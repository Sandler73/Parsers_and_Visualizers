#!/usr/bin/env python3
"""
Synopsis:
    CSV Workbook Generator for Multi-Vendor Network Configuration Analysis

Description:
    Generates a segmented CSV workbook with multiple sheets/sections in a single
    file. Each section is clearly delimited and labeled for easy parsing and
    import into spreadsheet applications.
    
    Output includes sections for:
    - Network Flow Mapping (for visualization)
    - Administration (management access and credentials)
    - Interfaces (state and type)
    - VLANs
    - Hardware
    - Summary
    
    The CSV format uses sheet separators that are compatible with most
    spreadsheet applications and can be easily split into separate files.

Notes:
    - Pure Python implementation using csv module
    - Single file with multiple clearly delimited sections
    - Compatible with Excel, LibreOffice, and other spreadsheet apps
    - Can be easily split into separate CSV files if needed

Version: 3.0.0
"""

import sys
import os
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class CSVWorkbookGenerator:
    """
    Generates CSV workbook with multiple delimited sections.
    
    Creates a single CSV file with clearly separated sections for each
    data category, making it easy to import into spreadsheet applications.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize CSV generator."""
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Log message if verbose enabled."""
        if self.verbose:
            print(f"[CSV Generator] {message}")
    
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
        Generate CSV workbook.
        
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
        self.log(f"Generating CSV workbook: {output_path}")
        
        # Ensure output path has .csv extension
        if not output_path.endswith('.csv'):
            output_path += '.csv'
        
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
        
        # Generate summary data
        summary_data = self.generate_summary(
            flows_data, admin_data, interfaces_data, vlans_data, endpoints_data, hardware_data
        )
        
        # Build sections based on parse_section
        sections = self.build_sections(
            flows_data, admin_data, interfaces_data, vlans_data,
            endpoints_data, hardware_data, monitoring_data, summary_data, parse_section, globalprotect_data
        )
        
        # Write CSV workbook
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(['# Network Configuration Analysis Workbook'])
                writer.writerow(['# Generated by Cisco Network Configuration Analyzer v2.0'])
                writer.writerow(['# Timestamp:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                writer.writerow([])
                
                # Write each section
                for section_name, section_data in sections.items():
                    self.write_section(writer, section_name, section_data)
                
                # Write footer
                writer.writerow([])
                writer.writerow(['# End of Workbook'])
            
            self.log(f"CSV workbook generated: {output_path}")
            
        except IOError as error:
            raise IOError(f"Failed to write CSV file: {error}")
    
    def build_sections(
        self,
        flows_data: List[Dict],
        admin_data: List[Dict],
        interfaces_data: List[Dict],
        vlans_data: List[Dict],
        endpoints_data: List[Dict],
        hardware_data: List[Dict],
        monitoring_data: List[Dict],
        summary_data: List[Dict],
        parse_section: Optional[str],
        globalprotect_data: Optional[Dict] = None
    ) -> Dict[str, List[Dict]]:
        """Build section data structure."""
        all_sections = {
            'Network Flow Mapping': flows_data,
            'Administration': admin_data,
            'Interfaces': interfaces_data,
            'VLANs': vlans_data,
            'Endpoints': endpoints_data,
            'Data Monitoring': monitoring_data,
            'Hardware': hardware_data,
            'Summary': summary_data
        }
        
        # Add Global Protect sections if data exists
        if globalprotect_data:
            if globalprotect_data.get('portals'):
                all_sections['Global Protect Portals'] = globalprotect_data['portals']
            if globalprotect_data.get('gateways'):
                all_sections['Global Protect Gateways'] = globalprotect_data['gateways']
            if globalprotect_data.get('client_configs'):
                all_sections['Global Protect Client Configs'] = globalprotect_data['client_configs']
        
        # Filter to specific section if requested
        if parse_section:
            section_map = {
                'flows': 'Network Flow Mapping',
                'admin': 'Administration',
                'interfaces': 'Interfaces',
                'vlans': 'VLANs',
                'endpoints': 'Endpoints',
                'hardware': 'Hardware'
            }
            
            section_name = section_map.get(parse_section)
            if section_name and section_name in all_sections:
                return {section_name: all_sections[section_name]}
        
        return all_sections
    
    def write_section(
        self,
        writer: csv.writer,
        section_name: str,
        section_data: List[Dict]
    ) -> None:
        """Write a single section to the CSV file."""
        # Section header
        writer.writerow([])
        writer.writerow([f'### SHEET: {section_name} ###'])
        writer.writerow(['# Row Count:', len(section_data)])
        writer.writerow([])
        
        if not section_data:
            writer.writerow(['No data available'])
            writer.writerow([])
            return
        
        # Get column names from first row
        columns = list(section_data[0].keys())
        
        # Write column headers
        writer.writerow(columns)
        
        # Write data rows
        for row in section_data:
            values = [self.format_cell_value(row.get(col, '')) for col in columns]
            writer.writerow(values)
        
        # Section footer
        writer.writerow([])
        writer.writerow([f'### END OF SHEET: {section_name} ###'])
        writer.writerow([])
    
    def format_cell_value(self, value: Any) -> str:
        """Format a cell value for CSV output."""
        if value is None:
            return ''
        
        if isinstance(value, (list, tuple)):
            return '; '.join(str(v) for v in value)
        
        if isinstance(value, dict):
            return str(value)
        
        return str(value)
    
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
        }, {
            'Metric': 'Analysis Date',
            'Value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Description': 'Timestamp of analysis'
        }]


# End of csv_workbook_generator.py