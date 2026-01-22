# README.md: Multi-Vendor Network Configuration Analyzer (Parser_Set)

## Overview

The **Parser_Set** is a comprehensive Python-based toolset for analyzing network device configurations from multiple vendors. It parses configuration files to extract key elements such as interfaces, VLANs, ACLs, routes, and administrative settings. The analyzer correlates this data into network flow maps for visualization and analysis, supporting outputs in HTML, XML, and CSV formats. This project is designed for network engineers, security analysts, and IT professionals to gain insights into complex multi-vendor environments without relying on external libraries beyond Python's standard library.

Key capabilities include:
- Automatic vendor and device type detection.
- Intelligent correlation of network elements (e.g., endpoints to interfaces, ACLs to endpoints).
- Support for GlobalProtect VPN parsing (Palo Alto specific).
- Deduplication of endpoints while preserving multi-device legitimacy.
- Generation of interactive reports and JSON for topology visualization.

The project is hosted at [https://github.com/Sandler73/Parsers_and_Visualizers/tree/main/Parser_Set](https://github.com/Sandler73/Parsers_and_Visualizers/tree/main/Parser_Set).

## Features

- **Multi-Vendor Support**:
  - Cisco: IOS, IOS-XE, NX-OS, ASA, FTD/NGFW.
  - Juniper: JunOS (MX, EX, SRX, QFX, PTX series).
  - Palo Alto: PAN-OS (with optional GlobalProtect VPN parsing).
  - Fortigate: FortiOS.
  - Eltex: MES, ESR series.

- **Parsing Capabilities**:
  - Interfaces: IP addresses, subnets, MTU, descriptions, status.
  - VLANs/Zones: Names, IDs, associated interfaces.
  - Routes: Static and dynamic routes with next-hops.
  - ACLs: Entries with source/destination, actions, correlations to endpoints.
  - Administrative Settings: Users, privileges, hashes, access methods (SSH/Telnet), SNMP, NTP/DNS/logging servers.
  - Endpoints: Deduplicated list with IP, name, type (e.g., NTP/DNS servers), ACL references.
  - Data Monitoring: SPAN/NetFlow configurations.
  - Hardware: Device info, OS version.

- **Analysis and Correlation**:
  - Network flow mapping: Correlates interfaces, ACLs, subnets, routes, and endpoints for traffic flow visualization.
  - Cross-device endpoint correlation: Links endpoints discovered on one device to interfaces on others.
  - Neighbor device detection: Via subnet matching and interface descriptions.
  - Path tracing: Simulates traffic paths between endpoints using routing info.

- **GlobalProtect VPN Parsing (Palo Alto Specific)**:
  - Extracts portals, gateways, HIP objects/profiles, authentication/certificate profiles.
  - Correlates security policies and network access.
  - Dedicated HTML report for VPN configurations.

- **Output Formats**:
  - **HTML Workbook**: Interactive with filtering, themes, and tables.
  - **XML**: Structured data export.
  - **CSV**: Multi-sheet segmented data.
  - **JSON Flow Mapping**: For topology visualization tools.

- **Selective Parsing**: Parse specific sections (e.g., interfaces, VLANs) for focused analysis.

- **Pure Python**: No external dependencies beyond standard library.

## Installation

1. Clone the repository:
git clone https://github.com/Sandler73/Parsers_and_Visualizers.git
cd Parsers_and_Visualizers/Parser_Set

2. Ensure Python 3.8+ is installed.

3. No additional packages required (uses standard library only).

## Usage

Run the analyzer with command-line arguments:

### Basic Commands

- Analyze a single file (auto-detect vendor):
python3 analyzer.py --config router.cfg --output analysis.html

- Specify vendor:
python3 analyzer.py --config device.cfg --vendor juniper --output analysis.html

- Palo Alto with GlobalProtect VPN:
python3 analyzer.py --config paloalto.cfg --vendor paloalto --parse-globalprotect --output gp_report.html

- Analyze directory of configs:
python3 analyzer.py --config-dir ./configs --output combined_analysis.html

- Parse specific section:
python3 analyzer.py --config switch.cfg --parse interfaces --output interfaces.csv

- Specify output format:
python3 analyzer.py --config device.cfg --output result --format xml

- Verbose mode:
python3 analyzer.py --config device.cfg --output result.html --verbose

### Arguments

- `--config`: Path to single config file.
- `--config-dir`: Directory of config files.
- `--output`: Output file path.
- `--output-dir`: Output directory (for multi-file).
- `--format`: html/xml/csv (default: html).
- `--parse`: Specific section (interfaces/vlans/acls/routes/admin/hardware/flows).
- `--vendor`: cisco/juniper/paloalto/fortigate/eltex/auto (default: auto).
- `--device-type`: Force device type (e.g., ios/junos/panos).
- `--parse-globalprotect`: Enable GlobalProtect parsing (Palo Alto only).
- `--verbose`: Enable detailed logging.
- `--version`: Show version.

For mixed-vendor directories, outputs are combined into a single file.

## Project Structure

- **analyzer.py**: Main script for parsing and analysis.
- **parser_modules/**: Vendor-specific parsers (e.g., paloalto_parser.py, ios_parser.py).
- **output_generators/**: Generators for HTML, XML, CSV, and GlobalProtect reports.
- **shared_components/**: Common data structures and utilities.
- **constants.py**: Device type constants.

## How It Works

1. **Input**: Single file or directory of configs.
2. **Detection**: Auto-detects vendor/device type.
3. **Parsing**: Vendor-specific parsers extract data into structured objects.
4. **Analysis**:
 - Builds flow mappings.
 - Correlates endpoints, neighbors, routes.
 - Deduplicates data.
5. **Output**: Generates reports in chosen format, plus optional JSON for visualization.

For GlobalProtect: When enabled, parses VPN elements from Palo Alto XML configs and generates a dedicated report.

## Dependencies

- Python 3.8+ (standard library only).
- No pip installs required.

## Limitations

- GlobalProtect parsing requires XML format (not set commands).
- Assumes IPv4 primarily; IPv6 support is partial.
- No real-time device access—offline config analysis only.

## Contributing

Fork the repo, create a branch, and submit a PR. Focus on new vendor parsers or output enhancements.

## License

MIT License. See LICENSE file.

For questions, open an issue on GitHub.
