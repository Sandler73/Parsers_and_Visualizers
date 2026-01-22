# Network Configuration Visualization Components

**Version**: 2.2.4  
**Last Updated**: January 14, 2026  
**Status**: Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Output Generators](#output-generators)
4. [Visualization Modules](#visualization-modules)
5. [Features](#features)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Output Formats](#output-formats)
9. [Customization](#customization)
10. [Troubleshooting](#troubleshooting)
11. [Version History](#version-history)

---

## Overview

The Network Configuration Visualization Components transform parsed network device configurations into rich, interactive visual and tabular outputs. The system supports multiple output formats with comprehensive data presentation, filtering, and analysis capabilities.

### Key Capabilities

- ✅ **Multiple Output Formats**: HTML, XML, CSV workbooks
- ✅ **Interactive HTML**: Filtering, sorting, search, light/dark themes
- ✅ **Comprehensive Data Presentation**: 8 analysis tabs
- ✅ **Network Topology Visualization**: Node/edge graphs (graph builder ready)
- ✅ **Endpoint Correlation Display**: Bidirectional interface-endpoint links
- ✅ **Multi-Device Support**: Topology-wide analysis
- ✅ **Self-Contained Output**: Single-file HTML with embedded CSS/JavaScript

---

## Architecture

### Component Overview

```
Parsed Configuration Data
         ↓
  ┌──────────────────┐
  │ Output Selection │
  └──────────────────┘
         ↓
  ┌──────┴──────┬──────────────┐
  ↓             ↓              ↓
HTML         XML            CSV
Generator    Generator      Generator
  ↓             ↓              ↓
Interactive  Structured    Workbook
Workbook     Data          Files
```

### Modules

```
output_generators/
├── __init__.py
├── html_generator.py          # Interactive HTML workbook
├── xml_generator.py           # Structured XML output
└── csv_workbook_generator.py  # Multi-sheet CSV

visualization_modules/
├── __init__.py
├── data_loader.py             # Data preparation
├── graph_builder.py           # Network topology graphs
└── layout_engine.py           # Node positioning

visualization_support/
├── __init__.py
└── subnet_matcher.py          # Subnet matching utilities

visualization_templates/
├── styles.css                 # Visualization styles
└── template.html              # HTML template
```

---

## Output Generators

### 1. HTML Workbook Generator

**Module**: `output_generators/html_generator.py`  
**Version**: 2.2.4

**Features**:
- Interactive multi-tab workbook (8 tabs)
- Client-side filtering (inclusion/exclusion)
- Column sorting (ascending/descending)
- Full-text search
- Light/Dark theme toggle
- Export to CSV (per-tab)
- Responsive design
- Self-contained (no external dependencies)

**Tabs**:

| Tab # | Name | Description |
|-------|------|-------------|
| 1 | Network Flow Mapping | Interfaces/VLANs with connected endpoints |
| 2 | Administration | System config, NTP, DNS, syslog, SNMP |
| 3 | Interfaces | Interface details and status |
| 4 | VLANs | VLAN configurations and gateways |
| 5 | Endpoints | Servers/endpoints with interface links |
| 6 | Data Monitoring | SPAN, NetFlow, jFlow, sFlow configs |
| 7 | Hardware | Device hardware information |
| 8 | Summary | Statistics and overview |

**Usage**:
```python
from output_generators.html_generator import HTMLWorkbookGenerator

generator = HTMLWorkbookGenerator(verbose=True)
generator.generate(
    device_configs=[config1, config2],
    flow_mappings=[flows1, flows2],
    output_file='network_analysis.html'
)
```

**Output**: Single HTML file with embedded CSS and JavaScript

---

### 2. XML Generator

**Module**: `output_generators/xml_generator.py`  
**Version**: 2.0.0

**Features**:
- Structured XML output
- Hierarchical data representation
- Schema-compliant format
- Multi-device support
- Easy parsing for automation

**Structure**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<NetworkConfiguration>
  <Devices>
    <Device name="ROUTER-01" vendor="cisco" type="ios">
      <Interfaces>
        <Interface name="GigabitEthernet0/0/0">
          <IPAddress>192.168.1.1</IPAddress>
          <SubnetMask>255.255.255.0</SubnetMask>
          <Description>WAN Link</Description>
          <AdminStatus>up</AdminStatus>
        </Interface>
      </Interfaces>
      <VLANs>...</VLANs>
      <Routes>...</Routes>
      <ACLs>...</ACLs>
      <Endpoints>...</Endpoints>
    </Device>
  </Devices>
</NetworkConfiguration>
```

**Usage**:
```python
from output_generators.xml_generator import XMLGenerator

generator = XMLGenerator(verbose=True)
generator.generate(
    device_configs=[config],
    output_file='network.xml'
)
```

---

### 3. CSV Workbook Generator

**Module**: `output_generators/csv_workbook_generator.py`  
**Version**: 2.0.0

**Features**:
- Multiple CSV files (one per data category)
- Excel-compatible format
- UTF-8 encoding with BOM
- Flat data structure for easy analysis

**Output Files**:
```
network_analysis/
├── flows.csv              # Network flow mappings
├── administration.csv     # Admin configuration
├── interfaces.csv         # Interface details
├── vlans.csv             # VLAN configurations
├── endpoints.csv         # Endpoint/server list
├── monitoring.csv        # Data monitoring configs
├── hardware.csv          # Hardware inventory
└── summary.csv           # Statistics
```

**Usage**:
```python
from output_generators.csv_workbook_generator import CSVWorkbookGenerator

generator = CSVWorkbookGenerator(verbose=True)
generator.generate(
    device_configs=[config],
    flow_mappings=[flows],
    output_directory='./output'
)
```

---

## Visualization Modules

### Data Loader

**Module**: `visualization_modules/data_loader.py`

**Purpose**: Prepares parsed data for visualization

**Functions**:
- Convert device configurations to visualization format
- Normalize data structures
- Apply filters
- Aggregate multi-device data

**Usage**:
```python
from visualization_modules.data_loader import DataLoader

loader = DataLoader(verbose=True)
viz_data = loader.prepare_data(device_configs, flow_mappings)
```

---

### Graph Builder

**Module**: `visualization_modules/graph_builder.py`

**Purpose**: Constructs network topology graphs

**Features**:
- Device nodes, interface nodes, endpoint nodes
- Subnet-based connections
- Neighbor device detection
- Edge types (interface-device, interface-endpoint, subnet-link)
- Ready for D3.js, Cytoscape.js, vis.js integration

**Node Types**:

| Type | Shape | Color | Description |
|------|-------|-------|-------------|
| device | square | blue | Network device |
| interface | circle | green | Interface/VLAN |
| endpoint | triangle | orange | Server/endpoint |

**Usage**:
```python
from visualization_modules.graph_builder import GraphBuilder

builder = GraphBuilder(verbose=True)
graph = builder.build_graph(
    flows=flow_data,
    endpoints=endpoint_data
)

# Graph structure:
{
  'nodes': [
    {'id': 0, 'type': 'device', 'label': 'ROUTER-01'},
    {'id': 1, 'type': 'interface', 'label': 'Gi0/0/0', 'device': 'ROUTER-01'},
    {'id': 2, 'type': 'endpoint', 'label': 'NTP-10.1.1.10'}
  ],
  'edges': [
    {'source': 0, 'target': 1, 'type': 'interface-device'},
    {'source': 1, 'target': 2, 'type': 'interface-endpoint'}
  ],
  'device_count': 1,
  'interface_count': 1,
  'endpoint_count': 1
}
```

**Endpoint Integration**:
- Reads `endpoint.related_interfaces` for connections
- Creates edges from interfaces to endpoints
- Supports endpoint filtering by type
- Zero orphaned endpoint nodes (all linked)

---

### Layout Engine

**Module**: `visualization_modules/layout_engine.py`

**Purpose**: Positions nodes for optimal visualization

**Algorithms**:
- Force-directed layout
- Hierarchical layout
- Circular layout
- Custom positioning

**Usage**:
```python
from visualization_modules.layout_engine import LayoutEngine

engine = LayoutEngine(verbose=True)
positioned_graph = engine.apply_layout(
    graph=graph_data,
    algorithm='force-directed',
    width=1200,
    height=800
)
```

---

### Subnet Matcher

**Module**: `visualization_support/subnet_matcher.py`

**Purpose**: Intelligent subnet matching for visualization filtering

**Features**:
- IP address to subnet membership checking
- Most-specific subnet matching
- Subnet overlap detection
- CIDR parsing and validation
- Network flow filtering by IP

**Class**: `SubnetMatcher`

**Methods**:

```python
class SubnetMatcher:
    def parse_ip(ip_string: str) -> int
    def parse_cidr(cidr_string: str) -> Tuple[int, int, int]
    def ip_in_subnet(ip_address: str, subnet_cidr: str) -> bool
    def find_matching_subnets(ip: str, subnets: List[str]) -> List[str]
    def find_most_specific_subnet(ip: str, subnets: List[str]) -> str
    def get_subnet_range(subnet_cidr: str) -> Tuple[str, str]
    def subnets_overlap(subnet1: str, subnet2: str) -> bool
    def filter_flows_by_ip(flows: List, src_ip: str, dst_ip: str) -> List
```

**Example - Most-Specific Matching**:
```python
from visualization_support.subnet_matcher import SubnetMatcher

matcher = SubnetMatcher()

# Multiple overlapping subnets
subnets = ["10.10.20.0/24", "10.10.20.128/25"]

# Find most specific match for IP
best_match = matcher.find_most_specific_subnet("10.10.20.243", subnets)
# Returns: "10.10.20.128/25" (more specific than /24)
```

**Use Cases**:
- Filtering flows by source/destination IP
- Endpoint-to-subnet correlation
- Subnet overlap analysis
- Network visualization filtering

---

## Features

### Interactive HTML Workbook

**Filtering**:
```
Inclusion Filter: Show only rows containing text
Exclusion Filter: Hide rows containing text
Combined: Apply both filters simultaneously
```

**Example**:
- Inclusion: "VLAN" → Shows only VLAN-related entries
- Exclusion: "down" → Hides interfaces that are down
- Combined: Include "Gigabit", Exclude "disabled"

**Sorting**:
- Click column header to sort ascending
- Click again to sort descending
- Multi-column sorting not supported (single column at a time)

**Search**:
- Full-text search across all visible columns
- Case-insensitive
- Real-time filtering as you type

**Themes**:
- Light mode (default): White background, black text
- Dark mode: Dark background, light text
- Toggle with theme button in top-right
- Preference saved in browser

**Export**:
- Export current tab to CSV
- Respects active filters
- One-click download
- Filename: `<SheetName>_<Timestamp>.csv`

### Network Flow Mapping Tab

**Purpose**: Show interfaces/VLANs with their connected elements

**Columns**:

| Column | Description |
|--------|-------------|
| Device | Device hostname |
| Interface/VLAN | Interface or VLAN name |
| Description | Interface description |
| IP Address | Primary IPv4 address |
| Subnet Mask | Subnet mask |
| Network | Network address |
| CIDR | Network in CIDR notation |
| VLAN ID | VLAN identifier (for SVIs) |
| Input ACLs | Inbound access lists |
| Output ACLs | Outbound access lists |
| Connected Networks | Peer networks on same subnet |
| Routed Networks | Networks reachable via routes |
| **Connected Endpoints** | **Linked servers/endpoints** |
| **Endpoint Count** | **Number of endpoints** |
| Neighbor Devices | Connected devices |
| Admin Status | Administrative state |
| Protocol Status | Protocol state |
| Interface Type | physical/vlan/loopback |
| Security Zone | Security zone (firewalls) |

**Endpoint Correlation**:
- Shows all endpoints linked to each interface
- Format: `"NTP-10.1.1.10 (10.1.1.10); DNS-10.1.1.20 (10.1.1.20)"`
- Endpoint Count provides quick summary
- Correlation uses 7-tier matching system

**Example**:
```
Interface: ge-0/0/0.0
IP Address: 203.0.113.1
Connected Endpoints: NTP-10.1.1.10 (10.1.1.10); NTP-10.1.1.11 (10.1.1.11); 
                     DNS-10.1.1.20 (10.1.1.20); DNS-10.1.1.21 (10.1.1.21)
Endpoint Count: 4
```

### Endpoints Tab

**Purpose**: Show all endpoints/servers with their connections

**Columns**:

| Column | Description |
|--------|-------------|
| Device | Parent device |
| Name | Endpoint identifier |
| IP Address | Endpoint IP |
| Subnet Mask | Subnet mask (if applicable) |
| CIDR | CIDR notation |
| Type | NTP Server/DNS Server/Syslog/etc |
| Description | Endpoint description |
| Source | Configuration source |
| Groups | Group membership |
| ACL References | Related ACLs |
| **Related Interfaces** | **Connected interfaces** |
| **Related VLANs** | **Connected VLANs** |

**Interface Linkage**:
- Shows which interface(s) the endpoint connects through
- Format: `"ge-0/0/0.0; ge-0/0/1.0"`
- Multiple interfaces possible (redundant paths)
- Empty if endpoint couldn't be correlated

**Example**:
```
Endpoint: NTP-10.1.1.10
IP Address: 10.1.1.10
Type: NTP Server
Related Interfaces: ge-0/0/0.0
Related VLANs: (empty)
```

**Bidirectional Linking**:
- Network Flow Mapping: Interface → Endpoints
- Endpoints Tab: Endpoint → Interfaces
- Same relationship shown from both perspectives

### Administration Tab

**Purpose**: System configuration and management access

**Columns**:

| Column | Description |
|--------|-------------|
| Device | Device hostname |
| Domain Name | DNS domain |
| NTP Servers | Time sync servers (semicolon-separated) |
| DNS Servers | Name resolution servers |
| Logging Servers | Syslog destinations |
| SNMP Communities | Community strings with RO/RW |
| Management IPs | Management interface IPs |
| Admin Users | Administrative usernames |
| User Privileges | User access levels |
| Credential Hashes | Password hashes |
| Access Methods | Enabled access (SSH/Telnet/HTTPS) |
| Management ACLs | ACLs restricting admin access |

**Note**: "Not configured" appears for fields not explicitly set in configuration.

### Data Monitoring Tab

**Purpose**: Traffic monitoring and analysis configurations

**Columns**:

| Column | Description |
|--------|-------------|
| Device | Device hostname |
| Type | SPAN/NetFlow/jFlow/sFlow/Packet Capture |
| Session/Collector | Session ID or collector IP:port |
| Description | Configuration description |
| Source | Source interfaces/VLANs |
| Destination | Destination interface or collector |
| Details | Additional configuration (version, sampling) |

**Types**:

**SPAN (Switched Port Analyzer)**:
```
Device: SWITCH-01
Type: SPAN
Session: 1
Source: GigabitEthernet1/0/1, VLAN 10
Destination: GigabitEthernet1/0/24
Details: Direction: both
```

**NetFlow**:
```
Device: ROUTER-01
Type: NetFlow
Collector: 10.1.100.10:2055
Source: GigabitEthernet0/0/0
Details: Version 9
```

**jFlow (Juniper)**:
```
Device: JUNIPER-MX-01
Type: jFlow
Collector: 10.1.100.10:2055; 10.1.100.11:2055
Details: Sampling rate: 1/1000
```

**sFlow (Fortigate)**:
```
Device: FORTIGATE-FW-01
Type: sFlow
Collector: 10.1.100.10:6343
Details: Collector IP and port
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- No external dependencies (uses standard library)

### Quick Start

```bash
# Generate HTML output (default)
python3 analyzer.py --config device.cfg --output analysis.html

# Generate XML output
python3 analyzer.py --config device.cfg --output analysis.xml --format xml

# Generate CSV workbook
python3 analyzer.py --config device.cfg --output-dir ./csv_output --format csv

# All formats
python3 analyzer.py --config device.cfg \
    --output analysis.html \
    --output analysis.xml \
    --output-dir ./csv_output
```

---

## Usage

### HTML Generation

```python
from analyzer import ConfigurationAnalyzer
from output_generators.html_generator import HTMLWorkbookGenerator

# Parse configurations
analyzer = ConfigurationAnalyzer(verbose=True)
configs = analyzer.analyze_configurations(['router1.cfg', 'router2.cfg'])

# Generate flow mappings
flow_mappings = []
for config in configs:
    flows = analyzer.build_flow_mappings(config)
    flow_mappings.append(flows)

# Generate HTML
generator = HTMLWorkbookGenerator(verbose=True)
generator.generate(
    device_configs=configs,
    flow_mappings=flow_mappings,
    output_file='network_topology.html'
)
```

### XML Generation

```python
from output_generators.xml_generator import XMLGenerator

generator = XMLGenerator(verbose=True)
generator.generate(
    device_configs=configs,
    output_file='network_data.xml'
)
```

### CSV Generation

```python
from output_generators.csv_workbook_generator import CSVWorkbookGenerator

generator = CSVWorkbookGenerator(verbose=True)
generator.generate(
    device_configs=configs,
    flow_mappings=flow_mappings,
    output_directory='./network_csv'
)
```

### Network Topology Graph

```python
from visualization_modules.graph_builder import GraphBuilder
from visualization_modules.layout_engine import LayoutEngine

# Build graph
builder = GraphBuilder(verbose=True)
graph = builder.build_graph(
    flows=flow_data,
    endpoints=endpoint_data
)

# Apply layout
engine = LayoutEngine(verbose=True)
positioned_graph = engine.apply_layout(
    graph=graph,
    algorithm='force-directed',
    width=1200,
    height=800
)

# Graph ready for D3.js, Cytoscape.js, etc.
```

---

## Output Formats

### HTML Workbook

**File Type**: `.html`  
**Size**: Typically 100KB - 2MB (depending on data)  
**Compatibility**: Any modern web browser  
**JavaScript**: Embedded (no external dependencies)  
**CSS**: Embedded  
**Portability**: 100% self-contained

**Benefits**:
- Interactive filtering and sorting
- No server required (client-side only)
- Email-friendly (single file)
- Works offline
- Cross-platform (Windows, Mac, Linux)

### XML Output

**File Type**: `.xml`  
**Size**: Typically 50KB - 1MB  
**Compatibility**: Any XML parser  
**Schema**: Custom schema (documented)  
**Encoding**: UTF-8

**Benefits**:
- Machine-readable
- Easy automation
- Integration with other tools
- Structured query support (XPath)
- Version control friendly

### CSV Workbook

**File Type**: Multiple `.csv` files in directory  
**Size**: Typically 10KB - 500KB per file  
**Compatibility**: Excel, LibreOffice, Google Sheets  
**Encoding**: UTF-8 with BOM

**Benefits**:
- Spreadsheet import
- Quick data analysis
- Pivot tables
- Formula support
- Easy filtering in Excel

---

## Customization

### HTML Themes

Modify `visualization_templates/styles.css` or override in generated HTML:

```css
/* Light Mode */
:root {
    --bg-primary: #ffffff;
    --text-primary: #1f2937;
    --accent: #3b82f6;
}

/* Dark Mode */
body.dark-mode {
    --bg-primary: #1e293b;
    --text-primary: #f1f5f9;
    --accent: #60a5fa;
}

/* Custom Theme */
body.custom-theme {
    --bg-primary: #f0f9ff;
    --text-primary: #1e40af;
    --accent: #7c3aed;
}
```

### Column Visibility

Edit HTML generator to hide/show columns:

```python
# html_generator.py

VISIBLE_COLUMNS = {
    'flows': ['Device', 'Interface/VLAN', 'IP Address', 'Connected Endpoints'],
    'endpoints': ['Name', 'IP Address', 'Type', 'Related Interfaces'],
    # ... customize per tab
}
```

### Export Formats

Add custom export format:

```python
# output_generators/custom_generator.py

class CustomGenerator:
    def generate(self, device_configs, output_file):
        """Generate custom format output."""
        with open(output_file, 'w') as f:
            # Custom format logic
            pass
```

---

## Troubleshooting

### HTML Not Displaying Data

**Issue**: HTML file opens but shows empty tables

**Solutions**:
1. Check browser console for JavaScript errors (F12)
2. Verify data was parsed correctly (`--verbose` flag)
3. Check that flow mappings were generated
4. Ensure endpoints were created by parser

**Verification**:
```bash
python3 analyzer.py --config device.cfg --output test.html --verbose | grep "SUCCESS"
```

Expected output:
```
[INFO] SUCCESS: All 10 endpoints successfully linked to interfaces
```

### Filtering Not Working

**Issue**: Filter buttons don't respond

**Solutions**:
1. Ensure JavaScript is enabled in browser
2. Clear browser cache
3. Try different browser (Chrome, Firefox, Edge)
4. Check for AdBlocker interference

### Theme Toggle Not Saving

**Issue**: Dark mode resets on page reload

**Solutions**:
1. Enable browser localStorage
2. Check private/incognito mode (localStorage disabled)
3. Allow cookies/storage for file:// URLs

### Missing Endpoints

**Issue**: Endpoints tab is empty

**Causes**:
1. Parser doesn't create administrative endpoints
2. Configuration lacks system settings (NTP, DNS, syslog)
3. Monitoring configurations not present

**Solutions**:
```bash
# Verify parser creates endpoints
python3 << 'EOF'
from analyzer import ConfigurationAnalyzer
analyzer = ConfigurationAnalyzer(verbose=True)
configs = analyzer.analyze_configurations(['device.cfg'])
print(f"Endpoints found: {len(configs[0].endpoints)}")
for ep in configs[0].endpoints:
    print(f"  - {ep.name} ({ep.endpoint_type})")
EOF
```

### Endpoints Not Linked to Interfaces

**Issue**: "Related Interfaces" column is empty

**Causes**:
1. No interfaces have IP addresses
2. Routing configuration missing for external endpoints
3. Correlation failed

**Solutions**:
```bash
# Check correlation with verbose logging
python3 analyzer.py --config device.cfg --output test.html --verbose 2>&1 | \
    grep -E "Correlating|Matched endpoint|SUCCESS.*endpoints"

# Look for:
[INFO] Correlating 10 endpoints with interfaces/VLANs
[DEBUG] Matched endpoint NTP-10.1.1.10 to interface ge-0/0/0.0 via routing
[INFO] SUCCESS: All 10 endpoints successfully linked to interfaces
```

---

## Version History

### v2.2.4 (2026-01-14)
- ✅ Endpoint correlation verification complete
- ✅ Graph builder endpoint integration confirmed
- ✅ Subnet matcher most-specific matching added
- ✅ HTML output endpoint display verified
- ✅ Bidirectional endpoint-interface linking working

### v2.2.3 (2026-01-14)
- ✅ Multi-vendor HTML output support
- ✅ Vendor-specific data monitoring tab
- ✅ Global Protect VPN display (Palo Alto)
- ✅ Enhanced endpoint display

### v2.2.0 (2026-01-13)
- ✅ Data Monitoring tab added
- ✅ Endpoint tab added
- ✅ Multi-device topology support
- ✅ Neighbor device correlation in flows
- ✅ Enhanced administration tab

### v2.0.0 (2026-01-11)
- ✅ Initial release
- ✅ HTML, XML, CSV generators
- ✅ Interactive HTML workbook
- ✅ Network Flow Mapping tab
- ✅ 7-tab structure
- ✅ Filtering and sorting
- ✅ Light/dark themes

---

## Future Enhancements

### Planned Features

- [ ] Interactive network topology visualization (D3.js integration)
- [ ] Path tracing visualization
- [ ] ACL impact analysis visualization
- [ ] Timeline view for configuration changes
- [ ] Comparison mode (config diff visualization)
- [ ] Custom report templates
- [ ] PDF export
- [ ] Real-time collaboration features

---

## Support

For visualization issues:

1. Check browser compatibility (Chrome 90+, Firefox 88+, Edge 90+)
2. Review generated HTML source for data presence
3. Enable verbose logging during generation
4. Verify input data is correctly parsed
5. Test with provided test configurations

---

## License

Network Configuration Visualization Components  
Copyright (c) 2026  
All Rights Reserved

---

**Version**: 2.2.4  
**Last Updated**: January 14, 2026  
**Status**: Production Ready
