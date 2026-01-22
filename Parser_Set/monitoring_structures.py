#!/usr/bin/env python3
"""
Synopsis:
    Data Monitoring Structures for Network Configuration Analysis

Description:
    This module defines data structures for representing network monitoring
    configurations including SPAN, NetFlow, Flow Monitors, and other
    data monitoring technologies.

Notes:
    - Supports SPAN, RSPAN, ERSPAN
    - NetFlow versions 5, 9, and IPFIX
    - Flow monitors and exporters
    - Packet capture configurations

Version: 1.0.0
"""

from typing import List, Dict, Optional, Any


class SPANSession:
    """
    Represents a SPAN/RSPAN/ERSPAN session configuration.
    
    Attributes:
        session_id: Session identifier
        session_type: Type (local, rspan, erspan)
        description: Session description
        source_interfaces: List of source interfaces
        source_vlans: List of source VLANs
        destination_interface: Destination interface for local SPAN
        destination_vlan: Destination VLAN for RSPAN
        filter_vlans: List of VLANs to filter
        erspan_id: ERSPAN session ID
        erspan_destination_ip: Destination IP for ERSPAN
        erspan_source_ip: Source IP for ERSPAN
        device_name: Name of device where configured
    """
    
    def __init__(self, session_id: str, device_name: str = ""):
        """Initialize SPAN session."""
        self.session_id = session_id
        self.session_type = "local"
        self.description = ""
        self.source_interfaces = []
        self.source_vlans = []
        self.destination_interface = ""
        self.destination_vlan = ""
        self.filter_vlans = []
        self.erspan_id = ""
        self.erspan_destination_ip = ""
        self.erspan_source_ip = ""
        self.device_name = device_name
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for output."""
        return {
            'Device': self.device_name,
            'Session ID': self.session_id,
            'Type': self.session_type,
            'Description': self.description,
            'Source Interfaces': ';'.join(self.source_interfaces),
            'Source VLANs': ';'.join(self.source_vlans),
            'Destination Interface': self.destination_interface,
            'Destination VLAN': self.destination_vlan,
            'Filter VLANs': ';'.join(self.filter_vlans),
            'ERSPAN ID': self.erspan_id,
            'ERSPAN Destination': self.erspan_destination_ip,
            'ERSPAN Source': self.erspan_source_ip
        }


class NetFlowConfig:
    """
    Represents NetFlow/IPFIX configuration.
    
    Attributes:
        flow_record: Flow record name
        flow_version: NetFlow version (5, 9, 10/IPFIX)
        exporter_name: Name of flow exporter
        exporter_destination: Destination IP:port for exports
        source_interface: Source interface for exports
        active_timeout: Active flow timeout
        inactive_timeout: Inactive flow timeout
        applied_interfaces: List of interfaces where applied
        direction: Flow direction (input, output, both)
        device_name: Name of device where configured
    """
    
    def __init__(self, flow_record: str = "", device_name: str = ""):
        """Initialize NetFlow configuration."""
        self.flow_record = flow_record
        self.flow_version = ""
        self.version = ""  # Simplified version field (v5, v9, jflow, sflow, etc.)
        self.exporter_name = ""
        self.exporter_destination = ""
        self.exporter_port = 0  # Port number for exporter destination
        self.collector_ip = ""  # Collector IP address (preferred for endpoint correlation)
        self.collector_port = ""  # Collector port (preferred for endpoint correlation)
        self.source_interface = ""
        self.active_timeout = ""
        self.inactive_timeout = ""
        self.applied_interfaces = []
        self.direction = ""
        self.description = ""  # Description of the flow configuration
        self.device_name = device_name
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for output."""
        return {
            'Device': self.device_name,
            'Flow Record': self.flow_record,
            'Version': self.version or self.flow_version,
            'Exporter': self.exporter_name,
            'Destination': self.exporter_destination,
            'Port': str(self.exporter_port) if self.exporter_port else '',
            'Source Interface': self.source_interface,
            'Active Timeout': self.active_timeout,
            'Inactive Timeout': self.inactive_timeout,
            'Applied Interfaces': ';'.join(self.applied_interfaces),
            'Direction': self.direction,
            'Description': self.description
        }


class MonitorSession:
    """
    Represents a generic monitor session (used by various platforms).
    
    Attributes:
        session_name: Monitor session name
        monitor_type: Type of monitoring (flow, packet, etc)
        source: Source specification
        destination: Destination specification
        filter_config: Filter configuration
        status: Session status (active, inactive)
        device_name: Name of device where configured
    """
    
    def __init__(self, session_name: str, device_name: str = ""):
        """Initialize monitor session."""
        self.session_name = session_name
        self.monitor_type = ""
        self.session_type = ""  # Alias for monitor_type
        self.source = ""
        self.destination = ""
        self.filter_config = ""
        self.description = ""  # Session description
        self.status = "active"
        self.device_name = device_name
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for output."""
        return {
            'Device': self.device_name,
            'Session Name': self.session_name,
            'Type': self.session_type or self.monitor_type,
            'Source': self.source,
            'Destination': self.destination,
            'Filter': self.filter_config,
            'Description': self.description,
            'Status': self.status
        }