#!/usr/bin/env python3
"""
Synopsis:
    Network Flow Mapping JSON Generator for Multi-Vendor Network Topology Visualization

Description:
    Generates optimized JSON output containing only Network Flow Mapping data
    for use by the topology visualizer. This separate file reduces load times
    and memory usage by excluding all other configuration data.
    
    The flow mapping data includes:
    - Source device, interface, IP, VLAN
    - Destination device, interface, IP, VLAN
    - Protocol and flow type information
    - Endpoint correlation data

Key Features:
    - Lightweight JSON format for fast parsing
    - Indexed structure for efficient visualization rendering
    - Direct compatibility with visualizer.py
    - Separate from full HTML workbook for performance

Output Format:
    JSON structure optimized for graph visualization:
    {
        "metadata": {...},
        "flows": [...],
        "endpoints": [...],
        "statistics": {...}
    }

Notes:
    - This file is read by visualizer.py for topology generation
    - Much smaller than full HTML workbook
    - Enables faster visualization rendering
    - Can be generated independently of HTML workbook

Version: 3.0.0
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime


class FlowMappingGenerator:
    """
    Generates optimized JSON output for network flow mapping visualization.
    
    Produces a lightweight JSON file containing only the data needed for
    topology visualization, separate from the comprehensive HTML workbook.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize flow mapping generator.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Log message if verbose enabled."""
        if self.verbose:
            print(f"[FlowMappingGenerator] {message}")
    
    def generate_json(
        self,
        output_path: str,
        network_flows: List[Any],
        endpoints: List[Any],
        config_files: Optional[List[str]] = None
    ) -> None:
        """
        Generate JSON file with network flow mapping data.
        
        Args:
            output_path: Path to output JSON file
            network_flows: List of NetworkFlow objects
            endpoints: List of Endpoint objects
            config_files: Optional list of source config files
        """
        self.log(f"Generating flow mapping JSON: {output_path}")
        
        # Convert flows to dictionaries
        flows_data = []
        for flow in network_flows:
            flow_dict = flow.to_dict()
            # Add additional fields for visualization optimization
            flow_dict['_viz_key'] = f"{flow_dict.get('source_device', 'unknown')}_{flow_dict.get('dest_device', 'unknown')}"
            flows_data.append(flow_dict)
        
        # Convert endpoints to dictionaries
        endpoints_data = []
        endpoint_index = {}  # For quick lookup
        
        for idx, endpoint in enumerate(endpoints):
            ep_dict = endpoint.to_dict()
            # Add index for visualization
            ep_dict['_viz_index'] = idx
            endpoints_data.append(ep_dict)
            
            # Build index for fast lookup
            if 'ip_address' in ep_dict:
                endpoint_index[ep_dict['ip_address']] = idx
        
        # Generate statistics
        statistics = self._generate_statistics(flows_data, endpoints_data)
        
        # Build metadata
        metadata = {
            'generated_at': datetime.now().isoformat(),
            'generator': 'FlowMappingGenerator v3.0.0',
            'format_version': '1.0',
            'source_configs': config_files or [],
            'total_flows': len(flows_data),
            'total_endpoints': len(endpoints_data),
            'description': 'Network flow mapping data for topology visualization'
        }
        
        # Assemble complete output structure
        output_data = {
            'metadata': metadata,
            'flows': flows_data,
            'endpoints': endpoints_data,
            'endpoint_index': endpoint_index,
            'statistics': statistics
        }
        
        # Write JSON file with optimized formatting
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.log(f"Successfully generated flow mapping JSON: {output_path}")
            self.log(f"  Flows: {len(flows_data)}")
            self.log(f"  Endpoints: {len(endpoints_data)}")
            self.log(f"  File size: {self._get_file_size(output_path)}")
            
        except Exception as e:
            self.log(f"ERROR: Failed to generate JSON: {e}")
            raise
    
    def _generate_statistics(
        self,
        flows_data: List[Dict[str, Any]],
        endpoints_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate statistics about flow mappings.
        
        Args:
            flows_data: List of flow dictionaries
            endpoints_data: List of endpoint dictionaries
            
        Returns:
            Dictionary of statistics
        """
        stats = {
            'total_flows': len(flows_data),
            'total_endpoints': len(endpoints_data),
            'unique_source_devices': set(),
            'unique_dest_devices': set(),
            'unique_protocols': set(),
            'flow_types': {},
            'endpoint_types': {}
        }
        
        # Analyze flows
        for flow in flows_data:
            # Track devices
            if 'source_device' in flow:
                stats['unique_source_devices'].add(flow['source_device'])
            if 'dest_device' in flow:
                stats['unique_dest_devices'].add(flow['dest_device'])
            
            # Track protocols
            if 'protocol' in flow:
                stats['unique_protocols'].add(flow['protocol'])
            
            # Track flow types
            flow_type = flow.get('flow_type', 'unknown')
            stats['flow_types'][flow_type] = stats['flow_types'].get(flow_type, 0) + 1
        
        # Analyze endpoints
        for endpoint in endpoints_data:
            ep_type = endpoint.get('endpoint_type', 'unknown')
            stats['endpoint_types'][ep_type] = stats['endpoint_types'].get(ep_type, 0) + 1
        
        # Convert sets to counts
        stats['unique_source_devices'] = len(stats['unique_source_devices'])
        stats['unique_dest_devices'] = len(stats['unique_dest_devices'])
        stats['unique_protocols'] = len(stats['unique_protocols'])
        
        return stats
    
    def _get_file_size(self, file_path: str) -> str:
        """
        Get human-readable file size.
        
        Args:
            file_path: Path to file
            
        Returns:
            Human-readable size string
        """
        try:
            import os
            size_bytes = os.path.getsize(file_path)
            
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            
            return f"{size_bytes:.1f} TB"
        except:
            return "unknown"
    
    def generate_csv(
        self,
        output_path: str,
        network_flows: List[Any],
        endpoints: List[Any]
    ) -> None:
        """
        Generate CSV file with network flow mapping data (alternative format).
        
        Args:
            output_path: Path to output CSV file
            network_flows: List of NetworkFlow objects
            endpoints: List of Endpoint objects
        """
        self.log(f"Generating flow mapping CSV: {output_path}")
        
        import csv
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if network_flows:
                    # Get all possible fields from first flow
                    sample_flow = network_flows[0].to_dict()
                    fieldnames = list(sample_flow.keys())
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for flow in network_flows:
                        writer.writerow(flow.to_dict())
                    
                    self.log(f"Successfully generated CSV with {len(network_flows)} flows")
                else:
                    self.log("No flows to write to CSV")
        
        except Exception as e:
            self.log(f"ERROR: Failed to generate CSV: {e}")
            raise


def main():
    """Command-line interface for standalone usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate network flow mapping JSON for visualization'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input HTML/XML workbook file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output JSON file path'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # This would need to import the data loader to extract flows from input
    print("Standalone flow mapping extraction not yet implemented.")
    print("Use analyzer.py with --flow-mapping-only option instead.")
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
