# Network Configuration Parser Modules

**Version**: 2.2.4  
**Last Updated**: January 14, 2026  
**Status**: Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Vendors & Platforms](#supported-vendors--platforms)
3. [Architecture](#architecture)
4. [Parser Modules](#parser-modules)
5. [Features](#features)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Configuration Examples](#configuration-examples)
9. [Data Structures](#data-structures)
10. [Extension Guide](#extension-guide)
11. [Troubleshooting](#troubleshooting)
12. [Version History](#version-history)

---

## Overview

The Network Configuration Parser Modules provide comprehensive parsing capabilities for network device configurations across multiple vendors. The parsers extract structured data including:

- System configuration (hostname, domain, NTP, DNS, syslog)
- Network interfaces with IPv4/IPv6 addresses
- VLANs and Layer 3 interfaces
- Static routes and dynamic routing configuration
- Access Control Lists (ACLs)
- Administrative access credentials and user accounts
- Data monitoring configurations (SPAN, NetFlow, jFlow, sFlow)
- Security zones and policies
- VPN configurations (site-to-site and remote access)
- Hardware inventory

### Key Capabilities

- ✅ **Multi-Vendor Support**: 5 vendors, 10+ platforms
- ✅ **Comprehensive Parsing**: 15+ configuration categories
- ✅ **Administrative Endpoint Creation**: Automatic NTP, DNS, syslog server extraction
- ✅ **Data Monitoring Detection**: SPAN, NetFlow, jFlow, sFlow, packet capture
- ✅ **Intelligent Correlation**: Endpoint-to-interface mapping via routing
- ✅ **Production Ready**: Extensively tested with real-world configurations

---

## Supported Vendors & Platforms

### Cisco Systems
| Platform | Parser Module | Version | Status |
|----------|---------------|---------|--------|
| IOS | `ios_parser.py` | 2.2.0 | ✅ Production |
| IOS-XE | `iosxe_parser.py` | 2.2.0 | ✅ Production |
| NX-OS | `nxos_parser.py` | 2.2.0 | ✅ Production |
| ASA | `asa_parser.py` | 2.2.0 | ✅ Production |
| Firepower (NGFW) | `ngfw_parser.py` | 2.2.0 | ✅ Production |

### Juniper Networks
| Platform | Parser Module | Version | Status |
|----------|---------------|---------|--------|
| JunOS | `juniper_parser.py` | 2.2.3 | ✅ Production |

### Palo Alto Networks
| Platform | Parser Module | Version | Status |
|----------|---------------|---------|--------|
| PAN-OS | `paloalto_parser.py` | 2.2.3 | ✅ Production |

### Fortinet
| Platform | Parser Module | Version | Status |
|----------|---------------|---------|--------|
| FortiOS | `fortigate_parser.py` | 2.2.4 | ✅ Production |

### Eltex
| Platform | Parser Module | Version | Status |
|----------|---------------|---------|--------|
| MES Series | `eltex_parser.py` | 2.2.2 | ✅ Production |

---

## Architecture

### Base Parser

All parser modules inherit from `BaseParser` which provides:

```python
class BaseParser:
    """Base class for all configuration parsers."""
    
    def __init__(self, config_lines: List[str], device_name: str, verbose: bool)
    def parse(self) -> DeviceConfiguration
    def log(self, message: str, level: str = 'INFO')
```

### Common Methods

All parsers implement these core methods:

- `parse_interfaces()` - Extract interface configurations
- `parse_vlans()` - Extract VLAN configurations  
- `parse_routes()` - Extract routing information
- `parse_acls()` - Extract access control lists
- `parse_endpoints()` - Extract endpoint/server information
- `parse_administrative_access()` - Extract admin credentials
- `parse_monitoring_configs()` - Extract SPAN/NetFlow/sFlow

### Data Flow

```
Configuration File
      ↓
  Vendor Detection
      ↓
  Parser Selection
      ↓
  Parser.parse()
      ↓
  DeviceConfiguration Object
      ↓
  Output Generation
```

---

## Parser Modules

### 1. Cisco IOS Parser (`ios_parser.py`)

**Version**: 2.2.0  
**Platform**: Cisco IOS  
**Features**:
- Interface parsing (physical, VLAN, loopback)
- VLAN database extraction
- Static and dynamic routing
- Standard/Extended ACLs (numbered and named)
- SPAN session configuration
- NetFlow configuration
- Administrative users and line configurations
- SNMP communities
- Endpoint extraction (NTP, DNS, syslog, NetFlow collectors)

**Configuration Format**: CLI text format

**Example**:
```bash
python3 analyzer.py --config ROUTER-01_ios.cfg --vendor cisco
```

**Key Features**:
- ✅ Multiple SNMP community accumulation
- ✅ Endpoint-to-interface correlation via routing
- ✅ VLAN interface gateway extraction
- ✅ NetFlow collector identification

---

### 2. Cisco IOS-XE Parser (`iosxe_parser.py`)

**Version**: 2.2.0  
**Platform**: Cisco IOS-XE (Catalyst 9000, ISR 4000, ASR 1000)  
**Features**: Identical to IOS parser with XE-specific enhancements

**Configuration Format**: CLI text format

**Key Differences from IOS**:
- Enhanced security features
- Platform-specific hardware detection
- Advanced QoS parsing

---

### 3. Cisco NX-OS Parser (`nxos_parser.py`)

**Version**: 2.2.0  
**Platform**: Cisco Nexus switches  
**Features**:
- SVI (VLAN interface) parsing
- VRF support
- VXLAN configuration
- NX-OS specific ACL format
- Enhanced SPAN configuration
- NetFlow with multiple exporters

**Configuration Format**: CLI text format

**Key Features**:
- ✅ VRF-aware interface parsing
- ✅ VXLAN EVPN support
- ✅ Multi-exporter NetFlow
- ✅ SVI IP address extraction with proper subnet masks

---

### 4. Cisco ASA Parser (`asa_parser.py`)

**Version**: 2.2.0  
**Platform**: Cisco Adaptive Security Appliance  
**Features**:
- Security level parsing
- Object and object-group extraction
- NAT rules (network object NAT, twice NAT)
- Site-to-site VPN (crypto maps, tunnel groups)
- Security context support
- Failover configuration
- ASDM access configuration

**Configuration Format**: CLI text format

**Key Features**:
- ✅ Security context isolation
- ✅ Object-group expansion
- ✅ NAT policy extraction
- ✅ VPN tunnel identification

---

### 5. Cisco Firepower (NGFW) Parser (`ngfw_parser.py`)

**Version**: 2.2.0  
**Platform**: Cisco Firepower Threat Defense  
**Features**:
- Security zones
- Access control policies
- Network objects and groups
- Threat inspection policies
- FlexConfig parsing
- Management center configuration

**Configuration Format**: CLI text format

**Key Features**:
- ✅ Zone-based policy extraction
- ✅ Threat intelligence integration
- ✅ FlexConfig support

---

### 6. Juniper JunOS Parser (`juniper_parser.py`)

**Version**: 2.2.3  
**Platform**: Juniper routers, switches, firewalls (MX, EX, SRX, QFX)  
**Features**:
- Hierarchical configuration parsing
- Interface units (e.g., ge-0/0/0.0)
- Routing instance support
- jFlow configuration with multiple collectors
- Sampling configuration
- Security zones and policies
- Administrative endpoints (NTP, DNS, syslog)

**Configuration Format**: JunOS set commands or hierarchical format

**Example**:
```bash
python3 analyzer.py --config JUNIPER-MX-01_junos.cfg --vendor juniper
```

**Key Features**:
- ✅ jFlow with sampling rate detection
- ✅ Multiple collector support
- ✅ IPv6 full support
- ✅ Interface unit parsing
- ✅ Nested configuration block handling

**JunOS Specifics**:
```
Configuration Structure:
  system {
      host-name JUNIPER-MX-RTR-01
      domain-name corp.example.com
      time-zone UTC
      ntp {
          server 10.1.1.10
      }
  }
  interfaces {
      ge-0/0/0 {
          unit 0 {
              family inet {
                  address 203.0.113.1/30
              }
          }
      }
  }
```

---

### 7. Palo Alto PAN-OS Parser (`paloalto_parser.py`)

**Version**: 2.2.3  
**Platform**: Palo Alto Networks firewalls (PA-Series, VM-Series)  
**Features**:
- XML configuration parsing
- Zone-based security policies
- Address objects and groups
- Service objects
- NAT policies
- Global Protect VPN configuration
- Packet capture configuration
- Administrative endpoints

**Configuration Format**: XML format

**Example**:
```bash
python3 analyzer.py --config PA-FW-01_panos.xml --vendor paloalto
```

**Key Features**:
- ✅ XML parsing with ElementTree
- ✅ Global Protect portal and gateway configuration
- ✅ Packet capture monitoring detection
- ✅ Multi-vsys support
- ✅ Zone-based policy extraction

**XML Structure**:
```xml
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-FW-01</hostname>
          <domain>corp.example.com</domain>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>10.1.1.10</ntp-server-address>
            </primary-ntp-server>
          </ntp-servers>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
```

**Global Protect Support**:
- Portal configuration
- Gateway configuration
- Client settings
- Authentication profiles
- Split tunneling rules

---

### 8. Fortigate FortiOS Parser (`fortigate_parser.py`)

**Version**: 2.2.4  
**Platform**: Fortinet FortiGate firewalls  
**Features**:
- Nested configuration block parsing
- Interface and VLAN parsing
- Static routes
- Security zones
- Firewall policies
- sFlow configuration
- NetFlow configuration
- Administrative endpoints

**Configuration Format**: FortiOS CLI format

**Example**:
```bash
python3 analyzer.py --config FORTIGATE-FW-01_fortios.cfg --vendor fortigate
```

**Key Features**:
- ✅ Nested block depth tracking (critical for SNMP)
- ✅ sFlow collector identification
- ✅ NetFlow collector identification
- ✅ Multiple SNMP community accumulation
- ✅ IPv6 support
- ✅ MTU parsing
- ✅ VLAN parent interface linking

**FortiOS Specifics**:
```
Configuration Structure:
  config system global
      set hostname "FORTIGATE-FW-01"
      set admin-sport 443
  end
  config system interface
      edit "port1"
          set vdom "root"
          set ip 203.0.113.1 255.255.255.252
          set type physical
      next
  end
  config system snmp community
      edit 1
          set name "public"
          config hosts
              edit 1
                  set ip 10.1.1.0 255.255.255.0
              next
          end
      next
      edit 2
          set name "private"
      next
  end
```

**Critical Fix**: Nested block handling for SNMP ensures all communities are parsed correctly (not just the first one).

---

### 9. Eltex MES Parser (`eltex_parser.py`)

**Version**: 2.2.2  
**Platform**: Eltex MES series switches  
**Features**:
- Interface and VLAN parsing
- Static routes
- ACL parsing
- SPAN sessions
- NetFlow configuration
- SNMP communities
- Administrative endpoints
- MTU parsing

**Configuration Format**: Eltex CLI format

**Example**:
```bash
python3 analyzer.py --config ELTEX-SW-01_eltex.cfg --vendor eltex
```

**Key Features**:
- ✅ Multiple SNMP community accumulation
- ✅ NetFlow interface name parsing
- ✅ Endpoint correlation via routing
- ✅ VLAN interface gateway extraction
- ✅ MTU parsing

**Eltex Specifics**:
```
Configuration Structure:
  hostname ELTEX-SW-CORE-01
  
  interface vlan 10
    ip address 10.10.1.1 255.255.255.0
    name "Management VLAN"
  !
  
  interface gigabitethernet 1/0/1
    description "Uplink to Core"
    switchport mode trunk
    switchport trunk allowed vlan add 10,20,30
  !
  
  ip route 0.0.0.0 0.0.0.0 10.10.1.254
  
  snmp-server community public ro
  snmp-server community private rw
```

---

## Features

### System Configuration Extraction

All parsers extract:
- **Hostname**: Device name
- **Domain Name**: DNS domain
- **NTP Servers**: Time synchronization servers (IPv4 and IPv6)
- **DNS Servers**: Name resolution servers
- **Syslog Servers**: Logging destinations
- **SNMP Communities**: Community strings with RO/RW permissions

### Interface Parsing

Extracts detailed interface information:
- **Physical Interfaces**: Ethernet, GigabitEthernet, TenGigabitEthernet
- **Logical Interfaces**: VLAN interfaces (SVIs), loopbacks, tunnels
- **IP Addresses**: IPv4 and IPv6 with subnet masks
- **Descriptions**: Interface descriptions
- **Administrative Status**: up/down/administratively down
- **Protocol Status**: up/down
- **MTU**: Maximum transmission unit
- **VLAN Membership**: Access and trunk port configurations

### VLAN Parsing

Extracts VLAN configurations:
- **VLAN ID**: Numeric identifier
- **Name**: VLAN description
- **Gateway IP**: Layer 3 gateway (if configured)
- **Member Interfaces**: Ports assigned to VLAN

### Routing Parsing

Extracts routing information:
- **Static Routes**: Destination, next-hop, interface, metric
- **Default Routes**: 0.0.0.0/0 or ::/0
- **Route Descriptions**: Administrative comments

### ACL Parsing

Extracts access control lists:
- **Standard ACLs**: Source-based filtering
- **Extended ACLs**: Source, destination, protocol, port filtering
- **Named ACLs**: Human-readable ACL names
- **ACL References**: Which interfaces apply which ACLs

### Administrative Endpoint Creation

Automatically creates endpoint objects for:
- **NTP Servers**: Extracted from system configuration
- **DNS Servers**: Primary and secondary DNS
- **Syslog Servers**: Logging destinations
- **SNMP Hosts**: SNMP trap receivers (vendor-specific)
- **Flow Collectors**: NetFlow, jFlow, sFlow destinations

**Endpoint Attributes**:
```python
class Endpoint:
    name: str              # e.g., "NTP-10.1.1.10"
    ip_address: str        # e.g., "10.1.1.10"
    endpoint_type: str     # e.g., "NTP Server"
    description: str       # e.g., "Network Time Protocol Server"
    source: str            # e.g., "System Configuration"
    related_interfaces: [] # Correlated interface names
    related_vlans: []      # Correlated VLAN IDs
```

### Data Monitoring Configuration

Extracts monitoring configurations:

**SPAN (Switched Port Analyzer)**:
- Session ID
- Source interfaces/VLANs
- Destination interface
- Direction (ingress/egress/both)

**NetFlow**:
- Exporter IP and port
- Version (5, 9, IPFIX)
- Source interface
- Interfaces with NetFlow enabled

**jFlow (Juniper)**:
- Collector IP and port
- Sampling rate
- Interfaces with sampling enabled

**sFlow (Fortigate)**:
- Collector IP and port
- Sampling rate
- Agent address

**Packet Capture (Palo Alto)**:
- Capture settings
- Trigger conditions

### Endpoint-to-Interface Correlation

Intelligent correlation of administrative endpoints to interfaces:

**Method 1**: Direct subnet matching
- Endpoint IP is in interface subnet → Direct link

**Method 2**: Routing-based correlation
- Endpoint not in local subnet → Find interface to default gateway
- Used for external services (public NTP, DNS)

**Method 3**: VLAN context matching
- Endpoint configuration mentions VLAN → Link to VLAN interface

**Example**:
```
NTP Server: 10.1.1.10 (external)
Default Route: 0.0.0.0/0 via 203.0.113.2
Interface: ge-0/0/0.0 with 203.0.113.1/30

Correlation: NTP-10.1.1.10 → ge-0/0/0.0 (via routing)
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- No external dependencies required (uses standard library only)

### Quick Start

```bash
# Clone or extract the analyzer
cd multi_vendor_network_analyzer_v2.2.0

# Verify parsers are present
ls -la parser_modules/

# Run analyzer with auto-detection
python3 analyzer.py --config device.cfg --output result.html
```

### Directory Structure

```
multi_vendor_network_analyzer_v2.2.0/
├── analyzer.py                    # Main analyzer engine
├── parser_modules/                # Parser implementations
│   ├── __init__.py
│   ├── base_parser.py            # Base parser class
│   ├── ios_parser.py             # Cisco IOS
│   ├── iosxe_parser.py           # Cisco IOS-XE
│   ├── nxos_parser.py            # Cisco NX-OS
│   ├── asa_parser.py             # Cisco ASA
│   ├── ngfw_parser.py            # Cisco Firepower
│   ├── juniper_parser.py         # Juniper JunOS
│   ├── paloalto_parser.py        # Palo Alto PAN-OS
│   ├── fortigate_parser.py       # Fortinet FortiOS
│   └── eltex_parser.py           # Eltex MES
├── shared_components/             # Shared data structures
├── output_generators/             # HTML, XML, CSV generators
└── test_configs/                  # Test configurations
```

---

## Usage

### Basic Usage

```bash
# Auto-detect vendor and device type
python3 analyzer.py --config DEVICE-01.cfg --output result.html

# Specify vendor explicitly
python3 analyzer.py --config ROUTER-01.cfg --vendor cisco --output cisco_analysis.html

# Specify device type (for Cisco)
python3 analyzer.py --config ASA-01.cfg --vendor cisco --device-type asa --output asa_report.html

# Enable verbose logging
python3 analyzer.py --config SWITCH-01.cfg --output switch.html --verbose

# Analyze multiple devices
python3 analyzer.py --config ROUTER-*.cfg --output topology.html
```

### Vendor-Specific Examples

**Cisco IOS**:
```bash
python3 analyzer.py --config ROUTER-01_ios.cfg --vendor cisco --device-type ios --output router.html
```

**Juniper JunOS**:
```bash
python3 analyzer.py --config JUNIPER-MX-01_junos.cfg --vendor juniper --output juniper.html
```

**Palo Alto (XML)**:
```bash
python3 analyzer.py --config PA-FW-01_panos.xml --vendor paloalto --output paloalto.html
```

**Fortigate**:
```bash
python3 analyzer.py --config FORTIGATE-FW-01_fortios.cfg --vendor fortigate --output fortigate.html
```

**Eltex**:
```bash
python3 analyzer.py --config ELTEX-SW-01_eltex.cfg --vendor eltex --output eltex.html
```

### Auto-Detection

The analyzer automatically detects vendor and device type based on:

1. **File Extension**:
   - `.xml` → Palo Alto
   - Others → Text-based config

2. **Configuration Markers**:
   - `version 15.` or `IOS` → Cisco IOS
   - `nx-os` → Cisco NX-OS
   - `ASA Version` → Cisco ASA
   - `hostname` with `set` → Juniper
   - `config system global` → Fortigate
   - `interface vlan` → Eltex

3. **Device Type** (Cisco):
   - `ASA` in config → asa
   - `nx-os` → nxos
   - `firepower` → ngfw
   - Default → ios

---

## Configuration Examples

### Test Configurations

The `test_configs/` directory contains comprehensive test configurations:

```
test_configs/
├── CISCO-ROUTER-01_ios.cfg           # Cisco IOS router
├── CISCO-SWITCH-01_iosxe.cfg         # Cisco IOS-XE switch
├── CISCO-DC-SW-01_nxos.cfg           # Cisco Nexus switch
├── CISCO-ASA-01_asa.cfg              # Cisco ASA firewall
├── CISCO-FTD-01_ngfw.cfg             # Cisco Firepower
├── JUNIPER-MX-RTR-01_junos.cfg       # Juniper router
├── PA-FW-01_panos.xml                # Palo Alto firewall
├── FORTIGATE-FW-01_fortios.cfg       # Fortigate firewall
└── ELTEX-SW-CORE-01_eltex.cfg        # Eltex switch
```

Each test configuration includes:
- Multiple interfaces (physical and VLAN)
- VLANs with gateways
- Static routes
- ACLs
- Administrative endpoints (NTP, DNS, syslog)
- Data monitoring (SPAN/NetFlow/jFlow/sFlow)
- SNMP communities
- Example network topology

---

## Data Structures

### DeviceConfiguration

Main configuration object returned by parsers:

```python
class DeviceConfiguration:
    device_name: str                    # Hostname
    vendor: str                         # cisco/juniper/paloalto/fortigate/eltex
    device_type: str                    # ios/nxos/asa/ngfw/junos/panos/fortios/eltex
    interfaces: List[Interface]         # All interfaces
    vlans: List[VLAN]                   # All VLANs
    routes: List[Route]                 # Static routes
    acls: List[ACL]                     # Access control lists
    endpoints: List[Endpoint]           # Servers/endpoints
    admin_config: AdministrationConfig  # Admin access
    monitoring_configs: List[MonitoringConfig]  # SPAN/NetFlow/etc
    vpn_configs: List[VPNConfig]       # VPN tunnels (vendor-specific)
    hardware_info: HardwareInfo         # Device hardware
```

### Interface

```python
class Interface:
    name: str                  # e.g., "GigabitEthernet0/0/0"
    description: str           # Interface description
    ip_address: str           # Primary IPv4 address
    subnet_mask: str          # Subnet mask
    ipv6_addresses: List[str] # IPv6 addresses
    vlan_id: Optional[int]    # VLAN ID (for SVI/VLAN interfaces)
    admin_status: str         # up/down/admin-down
    protocol_status: str      # up/down
    mtu: Optional[int]        # Maximum transmission unit
    interface_type: str       # physical/vlan/loopback/tunnel
    parent_interface: str     # For sub-interfaces/VLANs
    input_acls: List[str]     # Inbound ACLs
    output_acls: List[str]    # Outbound ACLs
    security_zone: str        # Security zone (firewall-specific)
```

### VLAN

```python
class VLAN:
    vlan_id: int             # VLAN ID (1-4094)
    name: str                # VLAN name
    gateway_ip: str          # Layer 3 gateway (if configured)
    gateway_mask: str        # Gateway subnet mask
    member_interfaces: []    # Assigned interfaces
    description: str         # VLAN description
```

### Route

```python
class Route:
    destination: str         # Destination network
    mask: str               # Subnet mask
    next_hop: str           # Next-hop IP
    interface: str          # Outgoing interface
    metric: int             # Route metric
    description: str        # Route description
```

### Endpoint

```python
class Endpoint:
    device: str             # Parent device
    name: str               # Endpoint name (e.g., "NTP-10.1.1.10")
    ip_address: str         # IP address
    endpoint_type: str      # NTP Server/DNS Server/Syslog Server/etc
    description: str        # Description
    source: str             # Where extracted from
    related_interfaces: []  # Connected interfaces
    related_vlans: []       # Connected VLANs
    connection_type: str    # direct/routed/ipv6/fallback
```

### MonitoringConfig

```python
class MonitoringConfig:
    device: str             # Parent device
    monitoring_type: str    # SPAN/NetFlow/jFlow/sFlow/Packet Capture
    session_id: str         # Session identifier
    source_interfaces: []   # Source interfaces/VLANs
    destination: str        # Destination interface or collector IP
    collector_port: int     # Collector port (for NetFlow/jFlow/sFlow)
    version: str            # NetFlow version
    sampling_rate: int      # Sampling rate (jFlow/sFlow)
    description: str        # Configuration description
```

---

## Extension Guide

### Adding a New Vendor

1. **Create Parser Module**:
```python
# parser_modules/newvendor_parser.py

from .base_parser import BaseParser
from shared_components.device_configuration import DeviceConfiguration

class NewVendorParser(BaseParser):
    """Parser for NewVendor devices."""
    
    def __init__(self, config_lines, device_name, verbose=False):
        super().__init__(config_lines, device_name, verbose)
        self.vendor = "newvendor"
        self.device_type = "newvendor"
    
    def parse(self) -> DeviceConfiguration:
        """Parse NewVendor configuration."""
        self.log("Parsing NewVendor configuration")
        
        # Create configuration object
        config = DeviceConfiguration(
            self.device_name,
            self.vendor,
            self.device_type
        )
        
        # Parse sections
        self.parse_system_config(config)
        self.parse_interfaces(config)
        self.parse_vlans(config)
        self.parse_routes(config)
        # ... etc
        
        return config
    
    def parse_system_config(self, config):
        """Parse system configuration."""
        for line in self.config_lines:
            if line.startswith('hostname '):
                config.device_name = line.split()[1]
            # ... parse other system config
```

2. **Register in analyzer.py**:
```python
# analyzer.py

PARSER_MAP = {
    'cisco': {...},
    'juniper': JuniperParser,
    'paloalto': PaloAltoParser,
    'fortigate': FortigateParser,
    'eltex': EltexParser,
    'newvendor': NewVendorParser  # Add here
}
```

3. **Add Detection Logic**:
```python
def detect_vendor(config_lines):
    """Auto-detect vendor."""
    config_str = '\n'.join(config_lines).lower()
    
    if 'newvendor-os' in config_str:
        return 'newvendor'
    # ... existing detection logic
```

4. **Create Test Configuration**:
```
test_configs/NEWVENDOR-01.cfg
```

5. **Test Thoroughly**:
```bash
python3 analyzer.py --config test_configs/NEWVENDOR-01.cfg \
    --output newvendor_test.html --verbose
```

### Implementing New Features

**Example: Adding BGP Parsing**

```python
class Route:
    # Add new fields
    protocol: str           # static/bgp/ospf/eigrp
    as_path: str           # BGP AS path
    next_hop_as: int       # Next-hop AS number

def parse_bgp(self, config):
    """Parse BGP configuration."""
    bgp_config = BGPConfig(self.device_name)
    
    in_bgp = False
    for line in self.config_lines:
        if line.startswith('router bgp'):
            in_bgp = True
            bgp_config.asn = line.split()[2]
        elif in_bgp and line.startswith('neighbor'):
            # Parse BGP neighbors
            neighbor = self.parse_bgp_neighbor(line)
            bgp_config.neighbors.append(neighbor)
    
    return bgp_config
```

---

## Troubleshooting

### Common Issues

**Issue**: Parser not detecting vendor correctly
```
Solution: Check file extension and configuration markers
  - XML files → Palo Alto
  - "config system global" → Fortigate
  - "set" commands → Juniper
  Use --vendor flag to specify explicitly
```

**Issue**: Missing administrative data in output
```
Solution: Verify parser extracts admin_config
  - Check Administration tab in HTML output
  - Enable --verbose to see parsing logs
  - Verify configuration has system settings
```

**Issue**: Endpoints not linked to interfaces
```
Solution: Check endpoint correlation
  - Enable --verbose to see matching logs
  - Verify interfaces have IP addresses
  - Check routing configuration for external endpoints
```

**Issue**: VLAN parsing incomplete
```
Solution: Different vendors use different VLAN syntax
  - Cisco: "interface Vlan10"
  - Juniper: "unit 0 family inet" on interface
  - Fortigate: Separate VLAN interface config
  - Check parser VLAN extraction logic
```

**Issue**: NetFlow/SPAN not detected
```
Solution: Verify monitoring configuration syntax
  - Cisco: "ip flow-export" or "monitor session"
  - Juniper: "sampling" under forwarding-options
  - Fortigate: "config system sflow"
  - Enable --verbose to see monitoring extraction
```

### Debug Mode

Enable verbose logging for detailed parser output:

```bash
python3 analyzer.py --config device.cfg --output debug.html --verbose
```

Verbose output shows:
- Parser selection and initialization
- Configuration section detection
- Data extraction progress
- Endpoint correlation details
- Warning messages for unparsed sections

### Validation

Verify parser output:

```bash
# Check parsed data
python3 << 'EOF'
from analyzer import ConfigurationAnalyzer
analyzer = ConfigurationAnalyzer(verbose=True)
configs = analyzer.analyze_configurations(['device.cfg'])
config = configs[0]

print(f"Device: {config.device_name}")
print(f"Vendor: {config.vendor}")
print(f"Interfaces: {len(config.interfaces)}")
print(f"VLANs: {len(config.vlans)}")
print(f"Routes: {len(config.routes)}")
print(f"Endpoints: {len(config.endpoints)}")
EOF
```

---

## Version History

### v2.2.4 (2026-01-14)
- ✅ Fortigate parser comprehensive rewrite
- ✅ Critical fix: Nested block handling for SNMP
- ✅ sFlow and NetFlow detection
- ✅ Multiple SNMP community accumulation
- ✅ IPv6 and MTU parsing
- ✅ VLAN parent interface linking

### v2.2.3 (2026-01-14)
- ✅ Juniper parser complete implementation
- ✅ Palo Alto parser XML support
- ✅ jFlow with sampling rate detection
- ✅ Packet capture configuration extraction
- ✅ Global Protect VPN support (Palo Alto)
- ✅ File extension auto-detection fixes

### v2.2.2 (2026-01-14)
- ✅ Eltex parser comprehensive fixes
- ✅ Multiple SNMP community accumulation
- ✅ Endpoint-to-interface routing correlation
- ✅ NetFlow interface name parsing
- ✅ Administration tab field clarification

### v2.2.0 (2026-01-13)
- ✅ Multi-vendor support (Juniper, Palo Alto, Fortigate, Eltex)
- ✅ Administrative endpoint creation
- ✅ Data monitoring extraction (SPAN, NetFlow, jFlow, sFlow)
- ✅ Vendor-specific monitoring configurations

### v2.0.0 (2026-01-11)
- ✅ Initial release with Cisco support
- ✅ IOS, IOS-XE, NX-OS, ASA, NGFW parsers
- ✅ Comprehensive parsing framework
- ✅ Output generators (HTML, XML, CSV)

---

## Support

For issues, feature requests, or contributions:

1. Check existing test configurations in `test_configs/`
2. Review parser-specific documentation
3. Enable verbose logging for debugging
4. Verify configuration format matches expected syntax

---

## License

Network Configuration Parser Modules  
Copyright (c) 2026  
All Rights Reserved

---

**Version**: 2.2.4  
**Last Updated**: January 14, 2026  
**Status**: Production Ready
