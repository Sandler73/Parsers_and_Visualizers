#!/usr/bin/env python3
"""
Synopsis:
    Output Generators Package for Multi-Vendor Network Configuration Analyzer

Description:
    This package contains output generation modules that create reports in
    various formats (HTML, XML, CSV) from parsed network configuration data.
    Includes specialized generators for standard network analysis and
    GlobalProtect VPN reporting.

Modules:
    - html_generator: Interactive HTML workbook generator
    - xml_generator: XML structured output generator
    - csv_workbook_generator: CSV workbook with multiple sections
    - flow_mapping_generator: JSON specific output for use with visualizer utility
    - globalprotect_report_generator: GlobalProtect VPN HTML report generator

Version: 3.0.0
"""

from .html_generator import HTMLWorkbookGenerator
from .xml_generator import XMLGenerator
from .csv_workbook_generator import CSVWorkbookGenerator
from .flow_mapping_generator import FlowMappingGenerator

# Import GlobalProtect report generator from this directory
from .globalprotect_report_generator import (
    GlobalProtectReportGenerator,
    generate_globalprotect_report
)
__version__ = '3.0.0'
__all__ = [
    'HTMLWorkbookGenerator',
    'XMLGenerator',
    'CSVWorkbookGenerator',
    'FlowMappingGenerator',
    'GlobalProtectReportGenerator',
    'generate_globalprotect_report'
]