#!/usr/bin/env python3
"""
Synopsis:
    HTML Workbook Generator with Enhanced Table Features for Multi-Vendor Network Configuration Analysis

Description:
    Generates interactive HTML workbooks from network configuration analysis data.
    Enhanced with advanced table manipulation, column filtering, resizing, and
    performance optimizations for large datasets.
    
    Features:
    - Multi-sheet workbook format with tabs
    - Per-column filtering with modal interface
    - Column visibility toggles
    - Column resizing
    - Row expand/collapse for long content
    - Hardware-accelerated rendering
    - Persistent state (localStorage)
    - Light/dark theme support
    - Client-side filtering and sorting
    - Export functionality
    - Responsive design

Output Format:
    Single self-contained HTML file with embedded:
    - CSS styling
    - JavaScript functionality
    - JSON data
    - All dependencies included (no external files)

Notes:
    - Pure client-side implementation
    - No external dependencies
    - Works offline
    - All data embedded in single HTML file
    - Compatible with all modern browsers

Version: 3.0.0
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


class HTMLWorkbookGenerator:
    """
    Generates enhanced interactive HTML workbooks from network analysis data.
    
    Produces a single self-contained HTML file with advanced table features
    including column filtering, visibility toggles, resizing, and performance
    optimizations for large datasets.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize HTML workbook generator.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Log message if verbose enabled."""
        if self.verbose:
            print(f"[HTMLWorkbookGenerator] {message}")
    
    def generate(
        self,
        network_flows: List[Any],
        admin_configs: List[Any],
        interfaces: List[Any],
        vlans: List[Any],
        endpoints: List[Any],
        hardware_configs: List[Any],
        output_path: str,
        span_sessions: Optional[List[Any]] = None,
        netflow_configs: Optional[List[Any]] = None,
        globalprotect_portals: Optional[List[Any]] = None,
        globalprotect_gateways: Optional[List[Any]] = None,
        globalprotect_client_configs: Optional[List[Any]] = None,
        parse_section: Optional[str] = None
    ) -> None:
        """
        Generate HTML workbook with enhanced table features.
        
        Args:
            network_flows: List of NetworkFlowMapping objects
            admin_configs: List of AdministrativeConfig objects
            interfaces: List of NetworkInterface objects
            vlans: List of VLAN objects
            endpoints: List of Endpoint objects
            hardware_configs: List of DeviceConfiguration objects
            output_path: Path to output HTML file
            span_sessions: Optional list of SPANSession objects
            netflow_configs: Optional list of NetFlow config objects
            globalprotect_portals: Optional list of GlobalProtect portal configs
            globalprotect_gateways: Optional list of GlobalProtect gateway configs
            globalprotect_client_configs: Optional list of GlobalProtect client configs
            parse_section: Optional specific section to parse
        """
        self.log(f"Generating enhanced HTML workbook: {output_path}")
        
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
        monitoring_data = span_data + netflow_data
        
        # Convert Global Protect data to dictionaries
        gp_portal_data = [portal.to_dict() for portal in (globalprotect_portals or [])]
        gp_gateway_data = [gateway.to_dict() for gateway in (globalprotect_gateways or [])]
        gp_client_data = [client.to_dict() for client in (globalprotect_client_configs or [])]
        
        # Prepare sheets data
        sheets_data = {
            'Network Flow Mapping': flows_data,
            'Administration': admin_data,
            'Interfaces': interfaces_data,
            'VLANs': vlans_data,
            'Endpoints': endpoints_data,
            'Data Monitoring': monitoring_data,
            'Hardware': hardware_data
        }
        
        # Add Global Protect sheets if data exists
        if gp_portal_data or gp_gateway_data or gp_client_data:
            sheets_data['GlobalProtect Portals'] = gp_portal_data
            sheets_data['GlobalProtect Gateways'] = gp_gateway_data
            sheets_data['GlobalProtect Clients'] = gp_client_data
        
        # Generate summary stats
        summary_data = [self._generate_summary(
            flows_data, interfaces_data, vlans_data, endpoints_data, hardware_data
        )]
        sheets_data['Summary'] = summary_data
        
        # Generate HTML
        html = self._generate_html(sheets_data)
        
        # Write to file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            self.log(f"Successfully generated HTML workbook: {output_path}")
        except Exception as e:
            self.log(f"ERROR: Failed to write HTML file: {e}")
            raise
    
    def _generate_summary(
        self,
        flows_data: List[Dict],
        interfaces_data: List[Dict],
        vlans_data: List[Dict],
        endpoints_data: List[Dict],
        hardware_data: List[Dict]
    ) -> Dict[str, Any]:
        """Generate summary statistics."""
        devices = set(hw.get('Device', '') for hw in hardware_data if hw.get('Device'))
        interfaces_up = sum(1 for intf in interfaces_data if intf.get('Status', '').lower() == 'up')
        
        return {
            'Metric': 'Devices',
            'Value': len(devices),
            'Description': 'Number of unique devices analyzed'
        } if devices else {
            'Metric': 'Interfaces',
            'Value': len(interfaces_data),
            'Description': 'Total number of interfaces'
        }
    
    def _generate_html(self, sheets_data: Dict[str, List[Dict]]) -> str:
        """Generate complete HTML document with all enhancements embedded."""
        import json
        
        css = self.get_css()
        javascript = self.get_javascript()
        
        # Prepare JSON data for embedding
        json_data = json.dumps(sheets_data, indent=2, ensure_ascii=False)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Configuration Analysis - Enhanced</title>
    <style>
{css}
    </style>
</head>
<body class="theme-light">
    <div class="workbook-container">
        <!-- Header -->
        <div class="workbook-header">
            <div>
                <h1>Network Configuration Analysis</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <div class="controls">
                <button id="themeToggle" class="btn"><span class="icon">🌙</span> Toggle Theme</button>
                <button id="columnToggle" class="btn btn-small"><span class="icon">☰</span> Columns</button>
                <button id="exportSheet" class="btn"><span class="icon">📥</span> Export Sheet</button>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="tabs" id="sheetTabs"></div>
        
        <!-- Toolbar -->
        <div class="toolbar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search in current sheet..." class="search-input">
                <button id="searchBtn" class="btn btn-small">Search</button>
                <button id="clearSearch" class="btn btn-small">Clear</button>
            </div>
            <div class="filter-controls">
                <select id="filterColumn" class="filter-select">
                    <option value="">Select column to filter...</option>
                </select>
                <select id="filterMode" class="filter-select">
                    <option value="include">Include</option>
                    <option value="exclude">Exclude</option>
                </select>
                <input type="text" id="filterValue" placeholder="Filter value..." class="filter-input">
                <button id="applyFilter" class="btn btn-small">Apply Filter</button>
                <button id="clearFilters" class="btn btn-small">Clear All Filters</button>
            </div>
            <div class="active-filters" id="activeFilters"></div>
        </div>
        
        <!-- Column Toggle Panel -->
        <div class="column-toggle-panel" id="columnTogglePanel">
            <div class="column-toggle-header">
                <strong>Show/Hide Columns</strong>
                <button id="closeColumnPanel" class="column-toggle-close">×</button>
            </div>
            <div class="column-toggle-body" id="columnToggleBody"></div>
        </div>
        
        <!-- Column Filter Modal -->
        <div class="column-filter-modal" id="columnFilterModal">
            <div class="column-filter-content">
                <div class="column-filter-header">
                    <h3 id="filterColumnName">Filter Column</h3>
                    <button id="closeFilterModal" class="column-toggle-close">×</button>
                </div>
                <div class="column-filter-body">
                    <select id="filterModeColumn" class="filter-mode-select">
                        <option value="include">Include selected values</option>
                        <option value="exclude">Exclude selected values</option>
                    </select>
                    <div class="filter-values-container" id="filterValuesContainer"></div>
                </div>
                <div class="column-filter-footer">
                    <button id="applyColumnFilter" class="btn">Apply</button>
                    <button id="cancelColumnFilter" class="btn">Cancel</button>
                </div>
            </div>
        </div>
        
        <!-- Content -->
        <div class="content">
            <div class="table-wrapper">
                <table id="dataTable" class="data-table">
                    <thead id="tableHead"></thead>
                    <tbody id="tableBody"></tbody>
                </table>
            </div>
            <div class="table-info" id="tableInfo"></div>
        </div>
        
        <!-- Footer -->
        <div class="workbook-footer">
            <span id="footerInfo"></span>
        </div>
    </div>

    <script>
        // Embedded data
        const sheetsData = {json_data};

{javascript}
    </script>
</body>
</html>"""
        
        return html
    
    def get_css(self) -> str:
        """Get complete CSS styling including enhancements."""
        return """
/* Global Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    transition: background-color 0.3s, color 0.3s;
}

/* Light Theme */
.theme-light {
    background-color: #f5f7fa;
    color: #2c3e50;
}

.theme-light .workbook-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.theme-light .data-table {
    background: white;
    color: #2c3e50;
}

.theme-light .data-table thead {
    background: #34495e;
    color: white;
}

.theme-light .data-table tbody tr:nth-child(even) {
    background: #f8f9fa;
}

.theme-light .data-table tbody tr:hover {
    background: #e9ecef;
}

.theme-light .tabs {
    background: white;
    border-bottom: 2px solid #dee2e6;
}

.theme-light .tab {
    background: transparent;
    color: #6c757d;
    border-bottom: 3px solid transparent;
}

.theme-light .tab:hover {
    background: #f8f9fa;
    color: #495057;
}

.theme-light .tab.active {
    color: #667eea;
    border-bottom-color: #667eea;
    background: #f8f9fa;
}

.theme-light .toolbar {
    background: white;
    border-bottom: 1px solid #dee2e6;
}

.theme-light .search-input,
.theme-light .filter-select,
.theme-light .filter-input {
    background: white;
    color: #2c3e50;
    border: 1px solid #ced4da;
}

.theme-light .btn {
    background: #667eea;
    color: white;
}

.theme-light .btn:hover {
    background: #5568d3;
}

/* Dark Theme */
.theme-dark {
    background-color: #1a1d23;
    color: #e9ecef;
}

.theme-dark .workbook-header {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: white;
}

.theme-dark .data-table {
    background: #2d2d2d;
    color: #e9ecef;
}

.theme-dark .data-table thead {
    background: #1a1d23;
    color: #e9ecef;
}

.theme-dark .data-table tbody tr:nth-child(even) {
    background: #3a3a3a;
}

.theme-dark .data-table tbody tr:hover {
    background: #4a4a4a;
}

.theme-dark .tabs {
    background: #2d2d2d;
    border-bottom: 2px solid #444;
}

.theme-dark .tab {
    background: transparent;
    color: #adb5bd;
    border-bottom: 3px solid transparent;
}

.theme-dark .tab:hover {
    background: #3a3a3a;
    color: #e9ecef;
}

.theme-dark .tab.active {
    color: #667eea;
    border-bottom-color: #667eea;
    background: #3a3a3a;
}

.theme-dark .toolbar {
    background: #2d2d2d;
    border-bottom: 1px solid #444;
}

.theme-dark .search-input,
.theme-dark .filter-select,
.theme-dark .filter-input {
    background: #3a3a3a;
    color: #e9ecef;
    border: 1px solid #555;
}

.theme-dark .btn {
    background: #667eea;
    color: white;
}

.theme-dark .btn:hover {
    background: #5568d3;
}

/* Workbook Layout */
.workbook-container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.workbook-header {
    padding: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.workbook-header h1 {
    font-size: 2rem;
    margin-bottom: 0.5rem;
}

.workbook-header p {
    opacity: 0.9;
}

.controls {
    display: flex;
    gap: 0.5rem;
}

/* Tabs */
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 0 2rem;
}

.tab {
    padding: 1rem 1.5rem;
    cursor: pointer;
    font-weight: 500;
    transition: all 0.2s;
    border: none;
    font-size: 0.95rem;
    white-space: nowrap;
}

/* Toolbar */
.toolbar {
    padding: 1.5rem 2rem;
}

.search-box {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.search-input {
    flex: 1;
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.95rem;
}

.filter-controls {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.filter-select,
.filter-input {
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.95rem;
}

.filter-select {
    min-width: 200px;
}

.filter-input {
    flex: 1;
    min-width: 200px;
}

.active-filters {
    margin-top: 1rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.filter-tag {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.25rem 0.75rem;
    background: #667eea;
    color: white;
    border-radius: 4px;
    font-size: 0.85rem;
}

.filter-tag button {
    background: none;
    border: none;
    color: white;
    cursor: pointer;
    font-size: 1.2rem;
    padding: 0;
    margin-left: 0.25rem;
}

/* Content */
.content {
    flex: 1;
    padding: 0 2rem 2rem;
}

.table-wrapper {
    overflow-x: auto;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}

.data-table thead th {
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    cursor: pointer;
    user-select: none;
    position: relative;
}

.data-table thead th:hover {
    opacity: 0.8;
}

.data-table thead th.sort-asc::after {
    content: ' ▲';
}

.data-table thead th.sort-desc::after {
    content: ' ▼';
}

.data-table tbody td {
    padding: 0.75rem 1rem;
    border-top: 1px solid;
}

.theme-light .data-table tbody td {
    border-color: #dee2e6;
}

.theme-dark .data-table tbody td {
    border-color: #444;
}

.table-info {
    margin-top: 1rem;
    font-size: 0.9rem;
    opacity: 0.7;
}

/* Buttons */
.btn {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 500;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}

.btn:active {
    transform: translateY(0);
}

.btn-small {
    padding: 0.375rem 0.75rem;
    font-size: 0.85rem;
}

.icon {
    font-size: 1rem;
}

.workbook-footer {
    padding: 1rem 2rem;
    text-align: center;
    font-size: 0.85rem;
    opacity: 0.6;
    border-top: 1px solid rgba(0,0,0,0.1);
}

/* Responsive Design */
@media (max-width: 768px) {
    .workbook-header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }

    .toolbar {
        padding: 1rem;
    }

    .filter-controls {
        flex-direction: column;
    }

    .filter-select, .filter-input {
        width: 100%;
    }
}

/* Scrollbar Styling */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

.theme-light ::-webkit-scrollbar-track {
    background: #f1f1f1;
}

.theme-light ::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
}

.theme-dark ::-webkit-scrollbar-track {
    background: #2d2d2d;
}

.theme-dark ::-webkit-scrollbar-thumb {
    background: #555;
    border-radius: 4px;
}

/* ====================================================================
   ENHANCED TABLE FEATURES - Task 2 Enhancements
   ==================================================================== */

/* Hardware Acceleration for Performance */
.table-wrapper {
    transform: translateZ(0);
    -webkit-transform: translateZ(0);
    will-change: transform;
    backface-visibility: hidden;
    -webkit-backface-visibility: hidden;
}

.data-table {
    transform: translate3d(0, 0, 0);
    -webkit-transform: translate3d(0, 0, 0);
}

/* Enhanced Table Header with Per-Column Filters */
.data-table thead th .header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
}

.data-table thead th .header-label {
    flex: 1;
    cursor: pointer;
}

.data-table thead th .column-filter-btn {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 0.85rem;
    padding: 0.25rem 0.4rem;
    border-radius: 3px;
    opacity: 0.5;
    transition: all 0.2s;
}

.data-table thead th .column-filter-btn:hover {
    opacity: 1;
    background: rgba(255,255,255,0.1);
}

.data-table thead th.has-filter .column-filter-btn {
    opacity: 1;
    color: #4da3ff;
    font-weight: bold;
}

/* Column Resize Handle */
.data-table thead th .resize-handle {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 4px;
    cursor: col-resize;
    background: transparent;
    transition: background 0.2s;
}

.data-table thead th .resize-handle:hover {
    background: rgba(77, 163, 255, 0.5);
}

.data-table thead th .resize-handle:active {
    background: #4da3ff;
}

/* Column Toggle Panel */
.column-toggle-panel {
    position: absolute;
    top: 140px;
    right: 20px;
    width: 250px;
    max-height: 400px;
    background: white;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    z-index: 1000;
    overflow: hidden;
    display: none;
}

.theme-dark .column-toggle-panel {
    background: #2d2d2d;
    border-color: #444;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

.column-toggle-panel.active {
    display: block;
}

.column-toggle-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #f8f9fa;
    border-bottom: 1px solid #dee2e6;
}

.theme-dark .column-toggle-header {
    background: #3a3a3a;
    border-color: #444;
}

.column-toggle-header strong {
    font-size: 0.95rem;
}

.column-toggle-close {
    background: none;
    border: none;
    font-size: 1.5rem;
    color: #6c757d;
    cursor: pointer;
    padding: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
    transition: background 0.2s;
}

.column-toggle-close:hover {
    background: #e9ecef;
}

.theme-dark .column-toggle-close:hover {
    background: #4a4a4a;
}

.column-toggle-body {
    padding: 0.5rem;
    max-height: 350px;
    overflow-y: auto;
}

.column-toggle-item {
    display: flex;
    align-items: center;
    padding: 0.5rem;
    gap: 0.5rem;
    cursor: pointer;
    border-radius: 4px;
    transition: background 0.2s;
    user-select: none;
}

.column-toggle-item:hover {
    background: #f8f9fa;
}

.theme-dark .column-toggle-item:hover {
    background: #3a3a3a;
}

.column-toggle-item input[type="checkbox"] {
    cursor: pointer;
    width: 16px;
    height: 16px;
}

/* Column Filter Modal */
.column-filter-modal {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    backdrop-filter: blur(4px);
}

.column-filter-modal.active {
    display: flex;
}

.column-filter-content {
    background: white;
    border-radius: 8px;
    width: 90%;
    max-width: 500px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.theme-dark .column-filter-content {
    background: #2d2d2d;
}

.column-filter-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid #dee2e6;
}

.theme-dark .column-filter-header {
    border-color: #444;
}

.column-filter-header h3 {
    margin: 0;
    font-size: 1.1rem;
}

.column-filter-body {
    padding: 1.5rem;
    overflow-y: auto;
    flex: 1;
}

.filter-mode-select {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    background: white;
    color: #2c3e50;
    font-size: 0.95rem;
    margin-bottom: 1rem;
}

.theme-dark .filter-mode-select {
    background: #3a3a3a;
    color: #e9ecef;
    border-color: #444;
}

.filter-values-container {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.5rem;
    background: #f8f9fa;
    border-radius: 4px;
    max-height: 300px;
    overflow-y: auto;
}

.theme-dark .filter-values-container {
    background: #3a3a3a;
}

.filter-value-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    cursor: pointer;
    border-radius: 4px;
    transition: background 0.2s;
    user-select: none;
}

.filter-value-item:hover {
    background: white;
}

.theme-dark .filter-value-item:hover {
    background: #4a4a4a;
}

.filter-value-item input[type="checkbox"] {
    cursor: pointer;
    width: 16px;
    height: 16px;
}

.column-filter-footer {
    display: flex;
    gap: 0.75rem;
    padding: 1.25rem 1.5rem;
    border-top: 1px solid #dee2e6;
    justify-content: flex-end;
}

.theme-dark .column-filter-footer {
    border-color: #444;
}

/* Expandable Cell Content */
.cell-truncated {
    cursor: pointer;
    color: #0d6efd;
    position: relative;
}

.theme-dark .cell-truncated {
    color: #4da3ff;
}

.cell-truncated:hover {
    text-decoration: underline;
}

/* Active Filter Badges */
.active-filter-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.25rem 0.5rem;
    background: #0d6efd;
    color: white;
    border-radius: 4px;
    font-size: 0.85rem;
    margin-right: 0.5rem;
    margin-bottom: 0.5rem;
}

.active-filter-badge .remove-filter {
    background: none;
    border: none;
    color: white;
    cursor: pointer;
    font-size: 1rem;
    padding: 0;
    margin-left: 0.25rem;
}

/* Mobile Responsive Enhancements */
@media (max-width: 768px) {
    .column-toggle-panel {
        right: 10px;
        left: 10px;
        width: auto;
    }
    
    .column-filter-content {
        width: 95%;
        max-height: 90vh;
    }
    
    .data-table {
        font-size: 0.85rem;
    }
}
"""
    
    def get_javascript(self) -> str:
        """Get complete JavaScript including all enhancements."""
        return """
        // ====================================================================
        // CORE STATE MANAGEMENT
        // ====================================================================
        
        let currentSheet = null;
        let currentData = [];
        let filteredData = [];
        let activeFilters = [];
        let sortColumn = null;
        let sortDirection = 'asc';
        
        // Enhanced state for Task 2 features
        let columnFilters = {};
        let hiddenColumns = new Set();
        let expandedRows = new Set();
        let columnWidths = {};
        let currentFilterColumn = null;
        
        // ====================================================================
        // INITIALIZATION
        // ====================================================================
        
        document.addEventListener('DOMContentLoaded', function() {
            loadEnhancedState();
            initializeTabs();
            setupEventListeners();
            
            const firstSheet = Object.keys(sheetsData)[0];
            if (firstSheet) {
                loadSheet(firstSheet);
            }
        });
        
        // ====================================================================
        // ENHANCED STATE PERSISTENCE
        // ====================================================================
        
        function loadEnhancedState() {
            const saved = localStorage.getItem('networkAnalyzerTableState');
            if (saved) {
                try {
                    const state = JSON.parse(saved);
                    hiddenColumns = new Set(state.hiddenColumns || []);
                    columnWidths = state.columnWidths || {};
                } catch(e) {
                    console.error('Failed to load saved state:', e);
                }
            }
        }
        
        function saveEnhancedState() {
            const state = {
                hiddenColumns: Array.from(hiddenColumns),
                columnWidths: columnWidths
            };
            try {
                localStorage.setItem('networkAnalyzerTableState', JSON.stringify(state));
            } catch(e) {
                console.error('Failed to save state:', e);
            }
        }
        
        // ====================================================================
        // TAB MANAGEMENT
        // ====================================================================
        
        function initializeTabs() {
            const tabsContainer = document.getElementById('sheetTabs');
            
            for (const sheetName in sheetsData) {
                const tab = document.createElement('button');
                tab.className = 'tab';
                tab.textContent = sheetName;
                tab.onclick = () => loadSheet(sheetName);
                tabsContainer.appendChild(tab);
            }
        }
        
        // ====================================================================
        // EVENT LISTENERS
        // ====================================================================
        
        function setupEventListeners() {
            document.getElementById('themeToggle').onclick = toggleTheme;
            document.getElementById('exportSheet').onclick = exportCurrentSheet;
            document.getElementById('searchBtn').onclick = performSearch;
            document.getElementById('clearSearch').onclick = clearSearch;
            document.getElementById('applyFilter').onclick = applyFilter;
            document.getElementById('clearFilters').onclick = clearAllFilters;
            
            document.getElementById('searchInput').onkeypress = function(e) {
                if (e.key === 'Enter') performSearch();
            };
            
            document.getElementById('filterValue').onkeypress = function(e) {
                if (e.key === 'Enter') applyFilter();
            };
            
            // Enhanced features
            document.getElementById('columnToggle').onclick = toggleColumnPanel;
            document.getElementById('closeColumnPanel').onclick = () => {
                document.getElementById('columnTogglePanel').classList.remove('active');
            };
            document.getElementById('closeFilterModal').onclick = closeColumnFilterModal;
            document.getElementById('cancelColumnFilter').onclick = closeColumnFilterModal;
            document.getElementById('applyColumnFilter').onclick = applyColumnFilterFromModal;
        }
        
        // ====================================================================
        // SHEET LOADING
        // ====================================================================
        
        function loadSheet(sheetName) {
            currentSheet = sheetName;
            currentData = sheetsData[sheetName] || [];
            filteredData = [...currentData];
            activeFilters = [];
            columnFilters = {};
            sortColumn = null;
            sortDirection = 'asc';
            expandedRows.clear();
            
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.toggle('active', tab.textContent === sheetName);
            });
            
            updateFilterColumns();
            renderTable();
            updateTableInfo();
            updateFooterInfo();
        }
        
        function updateFilterColumns() {
            const select = document.getElementById('filterColumn');
            select.innerHTML = '<option value="">Select column to filter...</option>';
            
            if (currentData.length > 0) {
                const columns = Object.keys(currentData[0]);
                columns.forEach(col => {
                    const option = document.createElement('option');
                    option.value = col;
                    option.textContent = col;
                    select.appendChild(option);
                });
            }
        }
        
        // ====================================================================
        // ENHANCED TABLE RENDERING
        // ====================================================================
        
        function renderTable() {
            const thead = document.getElementById('tableHead');
            const tbody = document.getElementById('tableBody');
            
            thead.innerHTML = '';
            tbody.innerHTML = '';
            
            if (filteredData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="100" style="text-align:center;padding:2rem;">No data to display</td></tr>';
                return;
            }
            
            const allColumns = Object.keys(filteredData[0]);
            const visibleColumns = allColumns.filter(col => !hiddenColumns.has(col));
            
            // Create header with enhanced features
            const headerRow = document.createElement('tr');
            
            visibleColumns.forEach(col => {
                const th = document.createElement('th');
                th.style.position = 'relative';
                
                if (columnWidths[col]) {
                    th.style.width = columnWidths[col];
                    th.style.minWidth = columnWidths[col];
                }
                
                const headerContent = document.createElement('div');
                headerContent.className = 'header-content';
                
                const headerLabel = document.createElement('span');
                headerLabel.className = 'header-label';
                headerLabel.textContent = col;
                headerLabel.onclick = () => sortByColumn(col);
                
                if (sortColumn === col) {
                    headerLabel.textContent += sortDirection === 'asc' ? ' ▲' : ' ▼';
                }
                
                const filterBtn = document.createElement('button');
                filterBtn.className = 'column-filter-btn';
                filterBtn.innerHTML = '⚙';
                filterBtn.title = `Filter ${col}`;
                filterBtn.onclick = (e) => {
                    e.stopPropagation();
                    showColumnFilterModal(col);
                };
                
                if (columnFilters[col]) {
                    th.classList.add('has-filter');
                }
                
                headerContent.appendChild(headerLabel);
                headerContent.appendChild(filterBtn);
                th.appendChild(headerContent);
                
                const resizeHandle = document.createElement('div');
                resizeHandle.className = 'resize-handle';
                resizeHandle.onmousedown = (e) => startResize(e, col, th);
                th.appendChild(resizeHandle);
                
                headerRow.appendChild(th);
            });
            
            thead.appendChild(headerRow);
            
            // Create body rows with truncation support
            filteredData.forEach((row, idx) => {
                const tr = document.createElement('tr');
                
                visibleColumns.forEach(col => {
                    const td = document.createElement('td');
                    const value = String(row[col] || '');
                    const maxLength = 100;
                    
                    if (value.length > maxLength && !expandedRows.has(idx)) {
                        td.textContent = value.substring(0, maxLength) + '...';
                        td.className = 'cell-truncated';
                        td.title = 'Click to expand';
                        td.onclick = function() {
                            expandedRows.add(idx);
                            renderTable();
                        };
                    } else {
                        td.textContent = value;
                        if (expandedRows.has(idx) && value.length > maxLength) {
                            td.className = 'cell-truncated';
                            td.title = 'Click to collapse';
                            td.onclick = function() {
                                expandedRows.delete(idx);
                                renderTable();
                            };
                        }
                    }
                    
                    tr.appendChild(td);
                });
                
                tbody.appendChild(tr);
            });
            
            updateTableInfo();
        }
        
        // ====================================================================
        // COLUMN RESIZING
        // ====================================================================
        
        function startResize(e, column, th) {
            e.preventDefault();
            e.stopPropagation();
            
            const startX = e.pageX;
            const startWidth = th.offsetWidth;
            
            function onMouseMove(e) {
                const newWidth = startWidth + (e.pageX - startX);
                if (newWidth > 80) {
                    columnWidths[column] = newWidth + 'px';
                    th.style.width = newWidth + 'px';
                    th.style.minWidth = newWidth + 'px';
                }
            }
            
            function onMouseUp() {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                saveEnhancedState();
            }
            
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        }
        
        // ====================================================================
        // COLUMN TOGGLE PANEL
        // ====================================================================
        
        function toggleColumnPanel() {
            const panel = document.getElementById('columnTogglePanel');
            const isActive = panel.classList.contains('active');
            
            if (!isActive) {
                populateColumnTogglePanel();
            }
            
            panel.classList.toggle('active');
        }
        
        function populateColumnTogglePanel() {
            if (currentData.length === 0) return;
            
            const columns = Object.keys(currentData[0]);
            const body = document.getElementById('columnToggleBody');
            body.innerHTML = '';
            
            columns.forEach(col => {
                const item = document.createElement('div');
                item.className = 'column-toggle-item';
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = !hiddenColumns.has(col);
                checkbox.id = 'col-toggle-' + col;
                checkbox.onchange = function() {
                    if (this.checked) {
                        hiddenColumns.delete(col);
                    } else {
                        hiddenColumns.add(col);
                    }
                    saveEnhancedState();
                    renderTable();
                };
                
                const label = document.createElement('label');
                label.htmlFor = 'col-toggle-' + col;
                label.textContent = col;
                label.style.cursor = 'pointer';
                label.style.flex = '1';
                
                item.appendChild(checkbox);
                item.appendChild(label);
                body.appendChild(item);
            });
        }
        
        // ====================================================================
        // COLUMN FILTER MODAL
        // ====================================================================
        
        function showColumnFilterModal(column) {
            currentFilterColumn = column;
            
            const modal = document.getElementById('columnFilterModal');
            const title = document.getElementById('filterColumnName');
            const container = document.getElementById('filterValuesContainer');
            const modeSelect = document.getElementById('filterModeColumn');
            
            title.textContent = `Filter: ${column}`;
            
            const uniqueValues = [...new Set(currentData.map(row => String(row[column] || '')))].sort();
            
            container.innerHTML = '';
            uniqueValues.forEach(value => {
                if (!value) return;
                
                const item = document.createElement('div');
                item.className = 'filter-value-item';
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.value = value;
                checkbox.id = 'filter-val-' + value;
                
                if (columnFilters[column]) {
                    checkbox.checked = columnFilters[column].values.includes(value);
                }
                
                const label = document.createElement('label');
                label.htmlFor = 'filter-val-' + value;
                label.textContent = value;
                label.style.cursor = 'pointer';
                label.style.flex = '1';
                
                item.appendChild(checkbox);
                item.appendChild(label);
                container.appendChild(item);
            });
            
            if (columnFilters[column]) {
                modeSelect.value = columnFilters[column].mode;
            } else {
                modeSelect.value = 'include';
            }
            
            modal.classList.add('active');
        }
        
        function closeColumnFilterModal() {
            document.getElementById('columnFilterModal').classList.remove('active');
            currentFilterColumn = null;
        }
        
        function applyColumnFilterFromModal() {
            if (!currentFilterColumn) return;
            
            const container = document.getElementById('filterValuesContainer');
            const checkboxes = container.querySelectorAll('input[type="checkbox"]:checked');
            const mode = document.getElementById('filterModeColumn').value;
            
            const selectedValues = Array.from(checkboxes).map(cb => cb.value);
            
            if (selectedValues.length > 0) {
                columnFilters[currentFilterColumn] = {
                    mode: mode,
                    values: selectedValues
                };
            } else {
                delete columnFilters[currentFilterColumn];
            }
            
            applyAllFilters();
            closeColumnFilterModal();
            renderTable();
        }
        
        // ====================================================================
        // FILTERING
        // ====================================================================
        
        function applyAllFilters() {
            filteredData = [...currentData];
            
            Object.keys(columnFilters).forEach(column => {
                const filter = columnFilters[column];
                filteredData = filteredData.filter(row => {
                    const cellValue = String(row[column] || '').toLowerCase();
                    const matches = filter.values.some(val => 
                        cellValue.includes(val.toLowerCase())
                    );
                    return filter.mode === 'include' ? matches : !matches;
                });
            });
            
            activeFilters.forEach(filter => {
                filteredData = filteredData.filter(row => {
                    const cellValue = String(row[filter.column] || '').toLowerCase();
                    const filterValue = filter.value.toLowerCase();
                    const matches = cellValue.includes(filterValue);
                    return filter.mode === 'include' ? matches : !matches;
                });
            });
        }
        
        function sortByColumn(column) {
            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'asc';
            }
            
            filteredData.sort((a, b) => {
                const aVal = a[column];
                const bVal = b[column];
                
                if (aVal === bVal) return 0;
                if (aVal === null || aVal === undefined) return 1;
                if (bVal === null || bVal === undefined) return -1;
                
                const comparison = aVal < bVal ? -1 : 1;
                return sortDirection === 'asc' ? comparison : -comparison;
            });
            
            renderTable();
        }
        
        function performSearch() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            if (!searchTerm) {
                clearSearch();
                return;
            }
            
            filteredData = currentData.filter(row => {
                return Object.values(row).some(val => 
                    String(val).toLowerCase().includes(searchTerm)
                );
            });
            
            renderTable();
            updateTableInfo();
        }
        
        function clearSearch() {
            document.getElementById('searchInput').value = '';
            filteredData = [...currentData];
            applyAllFilters();
            renderTable();
            updateTableInfo();
        }
        
        function applyFilter() {
            const column = document.getElementById('filterColumn').value;
            const mode = document.getElementById('filterMode').value;
            const value = document.getElementById('filterValue').value;
            
            if (!column || !value) return;
            
            activeFilters.push({ column, mode, value });
            
            applyAllFilters();
            renderTable();
            updateActiveFilters();
            updateTableInfo();
            
            document.getElementById('filterValue').value = '';
        }
        
        function clearAllFilters() {
            activeFilters = [];
            columnFilters = {};
            filteredData = [...currentData];
            renderTable();
            updateActiveFilters();
            updateTableInfo();
        }
        
        function removeFilter(index) {
            activeFilters.splice(index, 1);
            applyAllFilters();
            renderTable();
            updateActiveFilters();
            updateTableInfo();
        }
        
        function updateActiveFilters() {
            const container = document.getElementById('activeFilters');
            container.innerHTML = '';
            
            activeFilters.forEach((filter, index) => {
                const tag = document.createElement('div');
                tag.className = 'filter-tag';
                tag.innerHTML = `
                    ${filter.column}: ${filter.mode} "${filter.value}"
                    <button onclick="removeFilter(${index})">×</button>
                `;
                container.appendChild(tag);
            });
        }
        
        // ====================================================================
        // THEME MANAGEMENT
        // ====================================================================
        
        function toggleTheme() {
            const body = document.body;
            if (body.classList.contains('theme-light')) {
                body.classList.remove('theme-light');
                body.classList.add('theme-dark');
                localStorage.setItem('theme', 'dark');
            } else {
                body.classList.remove('theme-dark');
                body.classList.add('theme-light');
                localStorage.setItem('theme', 'light');
            }
        }
        
        // ====================================================================
        // EXPORT
        // ====================================================================
        
        function exportCurrentSheet() {
            if (!currentSheet || filteredData.length === 0) return;
            
            const columns = Object.keys(filteredData[0]);
            let csv = columns.join(',') + '\\n';
            
            filteredData.forEach(row => {
                const values = columns.map(col => {
                    const val = row[col] || '';
                    return `"${String(val).replace(/"/g, '""')}"`;
                });
                csv += values.join(',') + '\\n';
            });
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${currentSheet}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        
        // ====================================================================
        // UI UPDATES
        // ====================================================================
        
        function updateTableInfo() {
            const info = document.getElementById('tableInfo');
            const total = currentData.length;
            const showing = filteredData.length;
            
            if (showing === total) {
                info.textContent = `Showing ${total} rows`;
            } else {
                info.textContent = `Showing ${showing} of ${total} rows`;
            }
        }
        
        function updateFooterInfo() {
            const info = document.getElementById('footerInfo');
            const deviceCount = new Set(currentData.map(row => row.Device).filter(d => d)).size;
            info.textContent = `Sheet: ${currentSheet} | Devices: ${deviceCount}`;
        }
        
        // Load saved theme on page load
        (function() {
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme === 'dark') {
                document.body.classList.remove('theme-light');
                document.body.classList.add('theme-dark');
            }
        })();
"""


# End of html_generator.py
