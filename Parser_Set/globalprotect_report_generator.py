#!/usr/bin/env python3
"""
Synopsis:
    GlobalProtect VPN Configuration Report Generator

Description:
    Generates a comprehensive, interactive HTML report for Palo Alto GlobalProtect
    VPN configurations. The report includes detailed tables for portals, gateways,
    HIP objects/profiles, authentication settings, network access rules, and
    supporting infrastructure.
    
    The HTML output matches the style and functionality of html_generator.py with:
    - Interactive tables with sorting and filtering
    - Light/dark theme support
    - Responsive design
    - Export capabilities
    - Detailed network access information (ACLs, zones, accessible networks)

Notes:
    - Self-contained HTML file with embedded CSS and JavaScript
    - No external dependencies
    - Client-side interactivity
    - Follows same design patterns as html_generator.py

Version: 3.0.0
"""

import sys
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared_components.globalprotect_structures import GlobalProtectData


class GlobalProtectReportGenerator:
    """
    Generates interactive HTML report for GlobalProtect VPN configurations.
    
    Creates a self-contained HTML file with comprehensive GlobalProtect data
    presented in organized, interactive tables.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize GlobalProtect report generator."""
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Log message if verbose enabled."""
        if self.verbose:
            print(f"[GP Report Generator] {message}")
    
    def generate(
        self,
        gp_data_list: List[GlobalProtectData],
        output_path: str
    ) -> None:
        """
        Generate GlobalProtect HTML report.
        
        Args:
            gp_data_list: List of GlobalProtectData objects (one per device)
            output_path: Output file path
        """
        self.log(f"Generating GlobalProtect report: {output_path}")
        
        if not gp_data_list:
            self.log("No GlobalProtect data to generate report")
            # Create empty report
            gp_data_list = [GlobalProtectData(device_name="No Data")]
        
        # Build report sections
        html_content = self.build_html_report(gp_data_list)
        
        # Write to file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.log(f"GlobalProtect report generated: {output_path}")
        except IOError as error:
            raise IOError(f"Failed to write HTML file: {error}")
    
    def build_html_report(self, gp_data_list: List[GlobalProtectData]) -> str:
        """Build complete HTML report."""
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Aggregate data from all devices
        all_portals = []
        all_gateways = []
        all_hip_objects = []
        all_hip_profiles = []
        all_auth_profiles = []
        all_cert_profiles = []
        all_ssl_profiles = []
        all_tunnel_interfaces = []
        all_policies = []
        
        for gp_data in gp_data_list:
            all_portals.extend(gp_data.portals)
            all_gateways.extend(gp_data.gateways)
            all_hip_objects.extend(gp_data.hip_objects)
            all_hip_profiles.extend(gp_data.hip_profiles)
            all_auth_profiles.extend(gp_data.authentication_profiles)
            all_cert_profiles.extend(gp_data.certificate_profiles)
            all_ssl_profiles.extend(gp_data.ssl_tls_profiles)
            all_tunnel_interfaces.extend(gp_data.tunnel_interfaces)
            all_policies.extend(gp_data.security_policies)
        
        # Generate HTML sections
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GlobalProtect VPN Configuration Report</title>
    {self._get_css_styles()}
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="report-header">
            <h1>🔒 GlobalProtect VPN Configuration Report</h1>
            <div class="header-info">
                <p><strong>Generated:</strong> {timestamp}</p>
                <p><strong>Devices:</strong> {len(gp_data_list)}</p>
                <p><strong>Portals:</strong> {len(all_portals)} | <strong>Gateways:</strong> {len(all_gateways)} | <strong>HIP Objects:</strong> {len(all_hip_objects)}</p>
            </div>
            <button id="themeToggle" class="theme-toggle">🌓 Toggle Theme</button>
        </header>

        <!-- Navigation -->
        <nav class="nav-tabs">
            <button class="nav-tab active" data-section="summary">📊 Summary</button>
            <button class="nav-tab" data-section="portals">🌐 Portals</button>
            <button class="nav-tab" data-section="gateways">🚪 Gateways</button>
            <button class="nav-tab" data-section="hip">🔍 HIP Objects & Profiles</button>
            <button class="nav-tab" data-section="auth">🔐 Authentication</button>
            <button class="nav-tab" data-section="network">🌎 Network Access</button>
            <button class="nav-tab" data-section="infrastructure">⚙️ Infrastructure</button>
        </nav>

        <!-- Content Sections -->
        <div class="content">
            {self._build_summary_section(gp_data_list, all_portals, all_gateways)}
            {self._build_portals_section(all_portals)}
            {self._build_gateways_section(all_gateways)}
            {self._build_hip_section(all_hip_objects, all_hip_profiles)}
            {self._build_auth_section(all_auth_profiles, all_cert_profiles)}
            {self._build_network_access_section(all_portals, all_gateways, all_policies)}
            {self._build_infrastructure_section(all_ssl_profiles, all_tunnel_interfaces)}
        </div>

        <!-- Footer -->
        <footer class="report-footer">
            <p>Network Configuration Analyzer - GlobalProtect VPN Report v1.0.0</p>
        </footer>
    </div>

    {self._get_javascript()}
</body>
</html>'''
        
        return html
    
    def _build_summary_section(self, gp_data_list: List[GlobalProtectData], 
                                all_portals: List, all_gateways: List) -> str:
        """Build summary section."""
        html = '''
        <section id="summary" class="section active">
            <h2>📊 Configuration Summary</h2>
            
            <div class="summary-grid">'''
        
        for gp_data in gp_data_list:
            html += f'''
                <div class="summary-card">
                    <h3>{gp_data.device_name}</h3>
                    <p><strong>Hostname:</strong> {gp_data.hostname}</p>
                    <p><strong>Management IP:</strong> {gp_data.management_ip or 'N/A'}</p>
                    <div class="summary-stats">
                        <div class="stat">
                            <span class="stat-value">{gp_data.total_portals}</span>
                            <span class="stat-label">Portals</span>
                        </div>
                        <div class="stat">
                            <span class="stat-value">{gp_data.total_gateways}</span>
                            <span class="stat-label">Gateways</span>
                        </div>
                        <div class="stat">
                            <span class="stat-value">{gp_data.total_hip_objects}</span>
                            <span class="stat-label">HIP Objects</span>
                        </div>
                        <div class="stat">
                            <span class="stat-value">{gp_data.total_hip_profiles}</span>
                            <span class="stat-label">HIP Profiles</span>
                        </div>
                    </div>
                </div>'''
        
        html += '''
            </div>
            
            <h3>Overall Statistics</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Count</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>'''
        
        html += f'''
                    <tr>
                        <td>Total Portals</td>
                        <td>{len(all_portals)}</td>
                        <td><span class="badge badge-info">Configured</span></td>
                    </tr>
                    <tr>
                        <td>Total Gateways</td>
                        <td>{len(all_gateways)}</td>
                        <td><span class="badge badge-info">Configured</span></td>
                    </tr>'''
        
        enabled_portals = sum(1 for p in all_portals if p.enabled)
        enabled_gateways = sum(1 for g in all_gateways if g.enabled)
        
        html += f'''
                    <tr>
                        <td>Enabled Portals</td>
                        <td>{enabled_portals}</td>
                        <td><span class="badge badge-success">Active</span></td>
                    </tr>
                    <tr>
                        <td>Enabled Gateways</td>
                        <td>{enabled_gateways}</td>
                        <td><span class="badge badge-success">Active</span></td>
                    </tr>
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_portals_section(self, portals: List) -> str:
        """Build portals section."""
        html = '''
        <section id="portals" class="section">
            <h2>🌐 GlobalProtect Portals</h2>
            <p class="section-desc">Portal configurations manage client authentication and agent distribution.</p>
            
            <div class="table-controls">
                <input type="text" class="search-box" placeholder="Search portals..." data-table="portals-table">
                <button class="export-btn" data-table="portals-table">📥 Export CSV</button>
            </div>
            
            <table class="data-table sortable" id="portals-table">
                <thead>
                    <tr>
                        <th data-sort="string">Portal Name</th>
                        <th data-sort="string">Interface</th>
                        <th data-sort="string">IPv4 Address</th>
                        <th data-sort="string">FQDN</th>
                        <th data-sort="number">Port</th>
                        <th data-sort="string">Status</th>
                        <th data-sort="string">Auth Profile</th>
                        <th data-sort="string">SSL/TLS Profile</th>
                        <th data-sort="string">Accessible Networks</th>
                        <th data-sort="string">Applied Zones</th>
                        <th data-sort="string">Applied ACLs</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for portal in portals:
            status_badge = '<span class="badge badge-success">Enabled</span>' if portal.enabled else '<span class="badge badge-warning">Disabled</span>'
            accessible_nets = '<br>'.join(portal.accessible_networks[:5]) if portal.accessible_networks else 'N/A'
            if len(portal.accessible_networks) > 5:
                accessible_nets += f'<br><em>... and {len(portal.accessible_networks) - 5} more</em>'
            
            zones = ', '.join(portal.applied_zones) if portal.applied_zones else 'N/A'
            acls = '<br>'.join(portal.applied_acls[:3]) if portal.applied_acls else 'N/A'
            if len(portal.applied_acls) > 3:
                acls += f'<br><em>... and {len(portal.applied_acls) - 3} more</em>'
            
            html += f'''
                    <tr>
                        <td><strong>{portal.name}</strong></td>
                        <td>{portal.interface or 'N/A'}</td>
                        <td>{portal.ipv4_address or 'N/A'}</td>
                        <td>{portal.fqdn or 'N/A'}</td>
                        <td>{portal.port}</td>
                        <td>{status_badge}</td>
                        <td>{portal.authentication_profile or 'N/A'}</td>
                        <td>{portal.ssl_tls_profile or 'N/A'}</td>
                        <td>{accessible_nets}</td>
                        <td>{zones}</td>
                        <td>{acls}</td>
                    </tr>'''
        
        if not portals:
            html += '''
                    <tr>
                        <td colspan="11" class="no-data">No portals configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Portal Agent Configurations</h3>
            <table class="data-table" id="portal-agents-table">
                <thead>
                    <tr>
                        <th>Portal</th>
                        <th>Config Name</th>
                        <th>OS Filter</th>
                        <th>User Groups</th>
                        <th>Connect Method</th>
                        <th>External Gateways</th>
                        <th>Internal Gateways</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for portal in portals:
            for agent_config in portal.agent_configs:
                os_filter = ', '.join(agent_config.get('os_filter', [])) or 'Any'
                user_groups = '<br>'.join(agent_config.get('user_groups', [])[:3]) or 'Any'
                ext_gws = ', '.join([gw.get('name', '') for gw in agent_config.get('external_gateways', [])])
                int_gws = ', '.join([gw.get('name', '') for gw in agent_config.get('internal_gateways', [])])
                
                html += f'''
                    <tr>
                        <td>{portal.name}</td>
                        <td><strong>{agent_config.get('name', 'N/A')}</strong></td>
                        <td>{os_filter}</td>
                        <td>{user_groups}</td>
                        <td>{agent_config.get('connect_method', 'N/A')}</td>
                        <td>{ext_gws or 'None'}</td>
                        <td>{int_gws or 'None'}</td>
                    </tr>'''
        
        if not any(p.agent_configs for p in portals):
            html += '''
                    <tr>
                        <td colspan="7" class="no-data">No agent configurations</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_gateways_section(self, gateways: List) -> str:
        """Build gateways section."""
        html = '''
        <section id="gateways" class="section">
            <h2>🚪 GlobalProtect Gateways</h2>
            <p class="section-desc">Gateway configurations manage VPN tunnels and client connectivity.</p>
            
            <div class="table-controls">
                <input type="text" class="search-box" placeholder="Search gateways..." data-table="gateways-table">
                <button class="export-btn" data-table="gateways-table">📥 Export CSV</button>
            </div>
            
            <table class="data-table sortable" id="gateways-table">
                <thead>
                    <tr>
                        <th data-sort="string">Gateway Name</th>
                        <th data-sort="string">Interface</th>
                        <th data-sort="string">IPv4 Address</th>
                        <th data-sort="number">Port</th>
                        <th data-sort="string">Status</th>
                        <th data-sort="string">Tunnel Interface</th>
                        <th data-sort="string">IP Pools</th>
                        <th data-sort="string">DNS Servers</th>
                        <th data-sort="string">Accessible Networks</th>
                        <th data-sort="string">Applied Zones</th>
                        <th data-sort="string">Applied ACLs</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for gateway in gateways:
            status_badge = '<span class="badge badge-success">Enabled</span>' if gateway.enabled else '<span class="badge badge-warning">Disabled</span>'
            
            ip_pools = '<br>'.join(gateway.ipv4_pools[:3]) if gateway.ipv4_pools else 'N/A'
            if len(gateway.ipv4_pools) > 3:
                ip_pools += f'<br><em>... and {len(gateway.ipv4_pools) - 3} more</em>'
            
            dns_servers = f'{gateway.dns_primary}<br>{gateway.dns_secondary}' if gateway.dns_primary else 'N/A'
            
            accessible_nets = '<br>'.join(gateway.accessible_networks[:5]) if gateway.accessible_networks else 'N/A'
            if len(gateway.accessible_networks) > 5:
                accessible_nets += f'<br><em>... and {len(gateway.accessible_networks) - 5} more</em>'
            
            zones = ', '.join(gateway.applied_zones) if gateway.applied_zones else 'N/A'
            acls = '<br>'.join(gateway.applied_acls[:3]) if gateway.applied_acls else 'N/A'
            if len(gateway.applied_acls) > 3:
                acls += f'<br><em>... and {len(gateway.applied_acls) - 3} more</em>'
            
            html += f'''
                    <tr>
                        <td><strong>{gateway.name}</strong></td>
                        <td>{gateway.interface or 'N/A'}</td>
                        <td>{gateway.ipv4_address or 'N/A'}</td>
                        <td>{gateway.port}</td>
                        <td>{status_badge}</td>
                        <td>{gateway.tunnel_interface or 'N/A'}</td>
                        <td>{ip_pools}</td>
                        <td>{dns_servers}</td>
                        <td>{accessible_nets}</td>
                        <td>{zones}</td>
                        <td>{acls}</td>
                    </tr>'''
        
        if not gateways:
            html += '''
                    <tr>
                        <td colspan="11" class="no-data">No gateways configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Gateway Split Tunnel Configuration</h3>
            <table class="data-table" id="split-tunnel-table">
                <thead>
                    <tr>
                        <th>Gateway</th>
                        <th>Include Routes</th>
                        <th>Exclude Routes</th>
                        <th>Include Domains</th>
                        <th>Exclude Domains</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for gateway in gateways:
            inc_routes = '<br>'.join(gateway.split_tunnel_include_routes[:5]) or 'None'
            if len(gateway.split_tunnel_include_routes) > 5:
                inc_routes += f'<br><em>... and {len(gateway.split_tunnel_include_routes) - 5} more</em>'
            
            exc_routes = '<br>'.join(gateway.split_tunnel_exclude_routes[:5]) or 'None'
            if len(gateway.split_tunnel_exclude_routes) > 5:
                exc_routes += f'<br><em>... and {len(gateway.split_tunnel_exclude_routes) - 5} more</em>'
            
            inc_domains = '<br>'.join(gateway.split_tunnel_include_domains[:3]) or 'None'
            exc_domains = '<br>'.join(gateway.split_tunnel_exclude_domains[:3]) or 'None'
            
            html += f'''
                    <tr>
                        <td><strong>{gateway.name}</strong></td>
                        <td>{inc_routes}</td>
                        <td>{exc_routes}</td>
                        <td>{inc_domains}</td>
                        <td>{exc_domains}</td>
                    </tr>'''
        
        if not gateways:
            html += '''
                    <tr>
                        <td colspan="5" class="no-data">No gateways configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_hip_section(self, hip_objects: List, hip_profiles: List) -> str:
        """Build HIP objects and profiles section."""
        html = '''
        <section id="hip" class="section">
            <h2>🔍 Host Information Profile (HIP)</h2>
            <p class="section-desc">HIP enforces endpoint compliance requirements before granting VPN access.</p>
            
            <h3>HIP Objects</h3>
            <div class="table-controls">
                <input type="text" class="search-box" placeholder="Search HIP objects..." data-table="hip-objects-table">
                <button class="export-btn" data-table="hip-objects-table">📥 Export CSV</button>
            </div>
            
            <table class="data-table sortable" id="hip-objects-table">
                <thead>
                    <tr>
                        <th data-sort="string">Object Name</th>
                        <th data-sort="string">Description</th>
                        <th data-sort="string">OS Requirements</th>
                        <th data-sort="string">Antivirus</th>
                        <th data-sort="string">Security Software</th>
                        <th data-sort="string">System Requirements</th>
                        <th data-sort="string">Custom Checks</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for hip_obj in hip_objects:
            os_req = f'{hip_obj.os_vendor} {hip_obj.os_version}' if hip_obj.os_vendor else 'Any'
            av_req = f'{hip_obj.antivirus_vendor} {hip_obj.antivirus_version}' if hip_obj.antivirus_vendor else 'N/A'
            
            security = []
            if hip_obj.antimalware_vendor:
                security.append(f'Anti-Malware: {hip_obj.antimalware_vendor}')
            if hip_obj.antispyware_vendor:
                security.append(f'Anti-Spyware: {hip_obj.antispyware_vendor}')
            security_sw = '<br>'.join(security) if security else 'N/A'
            
            sys_reqs = []
            if hip_obj.firewall_enabled:
                sys_reqs.append('Firewall')
            if hip_obj.disk_encryption_enabled:
                sys_reqs.append('Disk Encryption')
            if hip_obj.disk_backup_enabled:
                sys_reqs.append('Disk Backup')
            if hip_obj.patch_management_enabled:
                sys_reqs.append('Patch Management')
            sys_requirements = '<br>'.join(sys_reqs) if sys_reqs else 'None'
            
            custom = []
            if hip_obj.process_list:
                custom.append(f'Processes: {len(hip_obj.process_list)}')
            if hip_obj.registry_keys:
                custom.append(f'Registry Keys: {len(hip_obj.registry_keys)}')
            if hip_obj.plist_entries:
                custom.append(f'Plist Entries: {len(hip_obj.plist_entries)}')
            if hip_obj.file_checks:
                custom.append(f'File Checks: {len(hip_obj.file_checks)}')
            custom_checks = '<br>'.join(custom) if custom else 'None'
            
            html += f'''
                    <tr>
                        <td><strong>{hip_obj.name}</strong></td>
                        <td>{hip_obj.description or 'N/A'}</td>
                        <td>{os_req}</td>
                        <td>{av_req}</td>
                        <td>{security_sw}</td>
                        <td>{sys_requirements}</td>
                        <td>{custom_checks}</td>
                    </tr>'''
        
        if not hip_objects:
            html += '''
                    <tr>
                        <td colspan="7" class="no-data">No HIP objects configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>HIP Profiles</h3>
            <table class="data-table" id="hip-profiles-table">
                <thead>
                    <tr>
                        <th>Profile Name</th>
                        <th>Description</th>
                        <th>Match Logic</th>
                        <th>HIP Objects</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for profile in hip_profiles:
            hip_objs = '<br>'.join(profile.hip_objects) if profile.hip_objects else 'None'
            match_logic_badge = f'<span class="badge badge-info">{profile.match_logic.upper()}</span>'
            
            html += f'''
                    <tr>
                        <td><strong>{profile.name}</strong></td>
                        <td>{profile.description or 'N/A'}</td>
                        <td>{match_logic_badge}</td>
                        <td>{hip_objs}</td>
                    </tr>'''
        
        if not hip_profiles:
            html += '''
                    <tr>
                        <td colspan="4" class="no-data">No HIP profiles configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_auth_section(self, auth_profiles: List, cert_profiles: List) -> str:
        """Build authentication section."""
        html = '''
        <section id="auth" class="section">
            <h2>🔐 Authentication Infrastructure</h2>
            <p class="section-desc">Authentication and certificate profiles used by GlobalProtect.</p>
            
            <h3>Authentication Profiles</h3>
            <table class="data-table sortable" id="auth-profiles-table">
                <thead>
                    <tr>
                        <th data-sort="string">Profile Name</th>
                        <th data-sort="string">Method</th>
                        <th data-sort="string">Server Profile</th>
                        <th data-sort="string">Allowed Groups</th>
                        <th data-sort="string">Denied Groups</th>
                        <th data-sort="string">Multi-Factor</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for auth_prof in auth_profiles:
            allowed = '<br>'.join(auth_prof.allow_groups[:5]) if auth_prof.allow_groups else 'Any'
            if len(auth_prof.allow_groups) > 5:
                allowed += f'<br><em>... and {len(auth_prof.allow_groups) - 5} more</em>'
            
            denied = '<br>'.join(auth_prof.deny_groups[:5]) if auth_prof.deny_groups else 'None'
            
            mfa = auth_prof.factor_profile if auth_prof.factor_profile else 'N/A'
            
            html += f'''
                    <tr>
                        <td><strong>{auth_prof.name}</strong></td>
                        <td>{auth_prof.method or 'N/A'}</td>
                        <td>{auth_prof.server_profile or 'N/A'}</td>
                        <td>{allowed}</td>
                        <td>{denied}</td>
                        <td>{mfa}</td>
                    </tr>'''
        
        if not auth_profiles:
            html += '''
                    <tr>
                        <td colspan="6" class="no-data">No authentication profiles configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Certificate Profiles</h3>
            <table class="data-table" id="cert-profiles-table">
                <thead>
                    <tr>
                        <th>Profile Name</th>
                        <th>CA Certificates</th>
                        <th>OCSP</th>
                        <th>CRL</th>
                        <th>Username Field</th>
                        <th>Domain</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for cert_prof in cert_profiles:
            ca_certs = '<br>'.join(cert_prof.ca_certificates[:3]) if cert_prof.ca_certificates else 'None'
            if len(cert_prof.ca_certificates) > 3:
                ca_certs += f'<br><em>... and {len(cert_prof.ca_certificates) - 3} more</em>'
            
            ocsp = '<span class="badge badge-success">Yes</span>' if cert_prof.use_ocsp else '<span class="badge badge-secondary">No</span>'
            crl = '<span class="badge badge-success">Yes</span>' if cert_prof.use_crl else '<span class="badge badge-secondary">No</span>'
            
            html += f'''
                    <tr>
                        <td><strong>{cert_prof.name}</strong></td>
                        <td>{ca_certs}</td>
                        <td>{ocsp}</td>
                        <td>{crl}</td>
                        <td>{cert_prof.username_field or 'N/A'}</td>
                        <td>{cert_prof.domain or 'N/A'}</td>
                    </tr>'''
        
        if not cert_profiles:
            html += '''
                    <tr>
                        <td colspan="6" class="no-data">No certificate profiles configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_network_access_section(self, portals: List, gateways: List, policies: List) -> str:
        """Build network access section showing what networks are accessible."""
        html = '''
        <section id="network" class="section">
            <h2>🌎 Network Access Control</h2>
            <p class="section-desc">Networks, subnets, and resources accessible via GlobalProtect.</p>
            
            <h3>Portal Network Access</h3>
            <table class="data-table sortable" id="portal-access-table">
                <thead>
                    <tr>
                        <th data-sort="string">Portal Name</th>
                        <th data-sort="string">Security Zones</th>
                        <th data-sort="string">Accessible Networks</th>
                        <th data-sort="string">Applied ACLs (Security Policies)</th>
                        <th data-sort="string">VLANs</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for portal in portals:
            zones = '<br>'.join(portal.applied_zones) if portal.applied_zones else 'N/A'
            
            networks = '<br>'.join(portal.accessible_networks[:10]) if portal.accessible_networks else 'N/A'
            if len(portal.accessible_networks) > 10:
                networks += f'<br><em>... and {len(portal.accessible_networks) - 10} more</em>'
            
            acls = '<br>'.join(portal.applied_acls[:5]) if portal.applied_acls else 'N/A'
            if len(portal.applied_acls) > 5:
                acls += f'<br><em>... and {len(portal.applied_acls) - 5} more</em>'
            
            html += f'''
                    <tr>
                        <td><strong>{portal.name}</strong></td>
                        <td>{zones}</td>
                        <td>{networks}</td>
                        <td>{acls}</td>
                        <td>N/A (Zone-based)</td>
                    </tr>'''
        
        if not portals:
            html += '''
                    <tr>
                        <td colspan="5" class="no-data">No portals configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Gateway Network Access</h3>
            <table class="data-table sortable" id="gateway-access-table">
                <thead>
                    <tr>
                        <th data-sort="string">Gateway Name</th>
                        <th data-sort="string">Security Zones</th>
                        <th data-sort="string">Accessible Networks</th>
                        <th data-sort="string">Applied ACLs (Security Policies)</th>
                        <th data-sort="string">Split Tunnel Routes</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for gateway in gateways:
            zones = '<br>'.join(gateway.applied_zones) if gateway.applied_zones else 'N/A'
            
            networks = '<br>'.join(gateway.accessible_networks[:10]) if gateway.accessible_networks else 'N/A'
            if len(gateway.accessible_networks) > 10:
                networks += f'<br><em>... and {len(gateway.accessible_networks) - 10} more</em>'
            
            acls = '<br>'.join(gateway.applied_acls[:5]) if gateway.applied_acls else 'N/A'
            if len(gateway.applied_acls) > 5:
                acls += f'<br><em>... and {len(gateway.applied_acls) - 5} more</em>'
            
            split_routes = '<br>'.join(gateway.split_tunnel_include_routes[:5]) if gateway.split_tunnel_include_routes else 'All Traffic'
            if len(gateway.split_tunnel_include_routes) > 5:
                split_routes += f'<br><em>... and {len(gateway.split_tunnel_include_routes) - 5} more</em>'
            
            html += f'''
                    <tr>
                        <td><strong>{gateway.name}</strong></td>
                        <td>{zones}</td>
                        <td>{networks}</td>
                        <td>{acls}</td>
                        <td>{split_routes}</td>
                    </tr>'''
        
        if not gateways:
            html += '''
                    <tr>
                        <td colspan="5" class="no-data">No gateways configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Security Policies Affecting GlobalProtect</h3>
            <table class="data-table sortable" id="policies-table">
                <thead>
                    <tr>
                        <th data-sort="string">Policy Name</th>
                        <th data-sort="string">Source Zones</th>
                        <th data-sort="string">Destination Zones</th>
                        <th data-sort="string">Source Addresses</th>
                        <th data-sort="string">Destination Addresses</th>
                        <th data-sort="string">Action</th>
                        <th data-sort="string">HIP Profiles</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for policy in policies[:20]:  # Limit to first 20 policies for readability
            src_zones = ', '.join(policy.source_zones) if policy.source_zones else 'any'
            dst_zones = ', '.join(policy.destination_zones) if policy.destination_zones else 'any'
            src_addrs = '<br>'.join(policy.source_addresses[:3]) if policy.source_addresses else 'any'
            dst_addrs = '<br>'.join(policy.destination_addresses[:3]) if policy.destination_addresses else 'any'
            
            action_badge = '<span class="badge badge-success">Allow</span>' if policy.action == 'allow' else '<span class="badge badge-danger">Deny</span>'
            
            hip_profs = '<br>'.join(policy.hip_profiles) if policy.hip_profiles else 'N/A'
            
            html += f'''
                    <tr>
                        <td><strong>{policy.name}</strong></td>
                        <td>{src_zones}</td>
                        <td>{dst_zones}</td>
                        <td>{src_addrs}</td>
                        <td>{dst_addrs}</td>
                        <td>{action_badge}</td>
                        <td>{hip_profs}</td>
                    </tr>'''
        
        if not policies:
            html += '''
                    <tr>
                        <td colspan="7" class="no-data">No security policies found</td>
                    </tr>'''
        elif len(policies) > 20:
            html += f'''
                    <tr>
                        <td colspan="7" class="info-message"><em>Showing 20 of {len(policies)} security policies</em></td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _build_infrastructure_section(self, ssl_profiles: List, tunnel_interfaces: List) -> str:
        """Build infrastructure section."""
        html = '''
        <section id="infrastructure" class="section">
            <h2>⚙️ Supporting Infrastructure</h2>
            <p class="section-desc">SSL/TLS profiles and tunnel interfaces supporting GlobalProtect.</p>
            
            <h3>SSL/TLS Service Profiles</h3>
            <table class="data-table" id="ssl-profiles-table">
                <thead>
                    <tr>
                        <th>Profile Name</th>
                        <th>Min TLS Version</th>
                        <th>Max TLS Version</th>
                        <th>Certificate</th>
                        <th>Cipher Suites</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for ssl_prof in ssl_profiles:
            cipher_suites = '<br>'.join(ssl_prof.cipher_suites[:5]) if ssl_prof.cipher_suites else 'Default'
            if len(ssl_prof.cipher_suites) > 5:
                cipher_suites += f'<br><em>... and {len(ssl_prof.cipher_suites) - 5} more</em>'
            
            html += f'''
                    <tr>
                        <td><strong>{ssl_prof.name}</strong></td>
                        <td>{ssl_prof.min_version}</td>
                        <td>{ssl_prof.max_version}</td>
                        <td>{ssl_prof.certificate or 'N/A'}</td>
                        <td>{cipher_suites}</td>
                    </tr>'''
        
        if not ssl_profiles:
            html += '''
                    <tr>
                        <td colspan="5" class="no-data">No SSL/TLS profiles configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
            
            <h3>Tunnel Interfaces</h3>
            <table class="data-table" id="tunnel-interfaces-table">
                <thead>
                    <tr>
                        <th>Interface</th>
                        <th>IPv4 Address</th>
                        <th>IPv6 Address</th>
                        <th>MTU</th>
                        <th>Security Zone</th>
                        <th>Virtual Router</th>
                        <th>Comment</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for tunnel in tunnel_interfaces:
            html += f'''
                    <tr>
                        <td><strong>{tunnel.name}</strong></td>
                        <td>{tunnel.ip_address or 'N/A'}</td>
                        <td>{tunnel.ipv6_address or 'N/A'}</td>
                        <td>{tunnel.mtu}</td>
                        <td>{tunnel.zone or 'N/A'}</td>
                        <td>{tunnel.virtual_router or 'N/A'}</td>
                        <td>{tunnel.comment or 'N/A'}</td>
                    </tr>'''
        
        if not tunnel_interfaces:
            html += '''
                    <tr>
                        <td colspan="7" class="no-data">No tunnel interfaces configured</td>
                    </tr>'''
        
        html += '''
                </tbody>
            </table>
        </section>'''
        
        return html
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the report (matches html_generator.py style)."""
        return '''
    <style>
        /* Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
            color: #333;
            transition: background 0.3s ease;
        }
        
        body.dark-theme {
            background: linear-gradient(135deg, #1e3a5f 0%, #2d1b4e 100%);
            color: #e0e0e0;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        body.dark-theme .container {
            background: #1a1a1a;
        }
        
        /* Header */
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            position: relative;
        }
        
        .report-header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .header-info {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .header-info p {
            margin: 5px 0;
        }
        
        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 20px;
            padding: 10px 20px;
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .theme-toggle:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        
        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            flex-wrap: wrap;
            background: #f5f5f5;
            border-bottom: 2px solid #ddd;
            overflow-x: auto;
        }
        
        body.dark-theme .nav-tabs {
            background: #2a2a2a;
            border-bottom-color: #444;
        }
        
        .nav-tab {
            padding: 15px 20px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 0.95rem;
            color: #666;
            transition: all 0.3s ease;
            white-space: nowrap;
        }
        
        body.dark-theme .nav-tab {
            color: #aaa;
        }
        
        .nav-tab:hover {
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
        }
        
        .nav-tab.active {
            background: white;
            color: #667eea;
            border-bottom: 3px solid #667eea;
        }
        
        body.dark-theme .nav-tab.active {
            background: #1a1a1a;
            color: #667eea;
        }
        
        /* Content */
        .content {
            padding: 30px;
        }
        
        .section {
            display: none;
        }
        
        .section.active {
            display: block;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        
        body.dark-theme .section h2 {
            color: #8b9eea;
            border-bottom-color: #444;
        }
        
        .section h3 {
            margin-top: 30px;
            margin-bottom: 15px;
            color: #764ba2;
            font-size: 1.3rem;
        }
        
        body.dark-theme .section h3 {
            color: #9a6fba;
        }
        
        .section-desc {
            color: #666;
            margin-bottom: 20px;
            font-size: 0.95rem;
        }
        
        body.dark-theme .section-desc {
            color: #aaa;
        }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        body.dark-theme .summary-card {
            background: linear-gradient(135deg, #2a2a2a 0%, #3a3a3a 100%);
        }
        
        .summary-card h3 {
            margin-top: 0;
            margin-bottom: 10px;
            color: #667eea;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-value {
            display: block;
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        
        body.dark-theme .stat-value {
            color: #8b9eea;
        }
        
        .stat-label {
            display: block;
            font-size: 0.85rem;
            color: #666;
            margin-top: 5px;
        }
        
        body.dark-theme .stat-label {
            color: #aaa;
        }
        
        /* Tables */
        .table-controls {
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .search-box {
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 0.9rem;
            width: 300px;
        }
        
        body.dark-theme .search-box {
            background: #2a2a2a;
            border-color: #444;
            color: #e0e0e0;
        }
        
        .export-btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .export-btn:hover {
            background: #5568d3;
            transform: translateY(-2px);
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        body.dark-theme .data-table {
            background: #2a2a2a;
        }
        
        .data-table thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .data-table th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }
        
        .data-table th:hover {
            background: rgba(255,255,255,0.1);
        }
        
        .data-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        body.dark-theme .data-table td {
            border-bottom-color: #444;
        }
        
        .data-table tbody tr:hover {
            background: rgba(102, 126, 234, 0.05);
        }
        
        body.dark-theme .data-table tbody tr:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        .no-data {
            text-align: center;
            color: #999;
            font-style: italic;
            padding: 30px !important;
        }
        
        .info-message {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 15px !important;
        }
        
        body.dark-theme .info-message {
            color: #aaa;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .badge-success {
            background: #10b981;
            color: white;
        }
        
        .badge-warning {
            background: #f59e0b;
            color: white;
        }
        
        .badge-danger {
            background: #ef4444;
            color: white;
        }
        
        .badge-info {
            background: #3b82f6;
            color: white;
        }
        
        .badge-secondary {
            background: #6b7280;
            color: white;
        }
        
        /* Footer */
        .report-footer {
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
            border-top: 1px solid #ddd;
        }
        
        body.dark-theme .report-footer {
            background: #2a2a2a;
            border-top-color: #444;
            color: #aaa;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container {
                margin: 0;
                border-radius: 0;
            }
            
            .report-header h1 {
                font-size: 1.5rem;
            }
            
            .nav-tab {
                font-size: 0.85rem;
                padding: 12px 15px;
            }
            
            .content {
                padding: 15px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .data-table {
                font-size: 0.85rem;
            }
            
            .data-table th,
            .data-table td {
                padding: 10px;
            }
            
            .search-box {
                width: 100%;
                margin-bottom: 10px;
            }
            
            .table-controls {
                flex-direction: column;
                align-items: stretch;
            }
        }
    </style>
    '''
    
    def _get_javascript(self) -> str:
        """Get JavaScript for report interactivity."""
        return '''
    <script>
        // Theme Management
        const themeToggle = document.getElementById('themeToggle');
        const body = document.body;
        
        // Load saved theme
        const savedTheme = localStorage.getItem('gp-report-theme') || 'light';
        if (savedTheme === 'dark') {
            body.classList.add('dark-theme');
        }
        
        themeToggle.addEventListener('click', () => {
            body.classList.toggle('dark-theme');
            const theme = body.classList.contains('dark-theme') ? 'dark' : 'light';
            localStorage.setItem('gp-report-theme', theme);
        });
        
        // Tab Navigation
        const navTabs = document.querySelectorAll('.nav-tab');
        const sections = document.querySelectorAll('.section');
        
        navTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const sectionId = tab.dataset.section;
                
                // Update active tab
                navTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // Update active section
                sections.forEach(s => s.classList.remove('active'));
                document.getElementById(sectionId).classList.add('active');
                
                // Save active section
                localStorage.setItem('gp-active-section', sectionId);
            });
        });
        
        // Restore active section
        const activeSectionId = localStorage.getItem('gp-active-section') || 'summary';
        const activeTab = document.querySelector(`[data-section="${activeSectionId}"]`);
        if (activeTab) {
            activeTab.click();
        }
        
        // Table Sorting
        document.querySelectorAll('.sortable th[data-sort]').forEach(header => {
            header.addEventListener('click', () => {
                const table = header.closest('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const columnIndex = Array.from(header.parentNode.children).indexOf(header);
                const sortType = header.dataset.sort;
                const currentOrder = header.dataset.order || 'asc';
                const newOrder = currentOrder === 'asc' ? 'desc' : 'asc';
                
                // Remove all sort indicators
                table.querySelectorAll('th').forEach(th => {
                    delete th.dataset.order;
                    th.textContent = th.textContent.replace(' ▲', '').replace(' ▼', '');
                });
                
                // Sort rows
                rows.sort((a, b) => {
                    const aCell = a.cells[columnIndex];
                    const bCell = b.cells[columnIndex];
                    
                    if (!aCell || !bCell) return 0;
                    
                    let aValue = aCell.textContent.trim();
                    let bValue = bCell.textContent.trim();
                    
                    if (sortType === 'number') {
                        aValue = parseFloat(aValue) || 0;
                        bValue = parseFloat(bValue) || 0;
                        return newOrder === 'asc' ? aValue - bValue : bValue - aValue;
                    } else {
                        return newOrder === 'asc' 
                            ? aValue.localeCompare(bValue)
                            : bValue.localeCompare(aValue);
                    }
                });
                
                // Update table
                rows.forEach(row => tbody.appendChild(row));
                
                // Update sort indicator
                header.dataset.order = newOrder;
                header.textContent += newOrder === 'asc' ? ' ▲' : ' ▼';
            });
        });
        
        // Table Search
        document.querySelectorAll('.search-box').forEach(searchBox => {
            searchBox.addEventListener('input', (e) => {
                const searchTerm = e.target.value.toLowerCase();
                const tableId = e.target.dataset.table;
                const table = document.getElementById(tableId);
                if (!table) return;
                
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            });
        });
        
        // CSV Export
        document.querySelectorAll('.export-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tableId = btn.dataset.table;
                const table = document.getElementById(tableId);
                if (!table) return;
                
                let csv = [];
                
                // Headers
                const headers = Array.from(table.querySelectorAll('thead th'))
                    .map(th => th.textContent.replace(' ▲', '').replace(' ▼', '').trim())
                    .map(escapeCSV);
                csv.push(headers.join(','));
                
                // Rows
                table.querySelectorAll('tbody tr').forEach(row => {
                    if (row.style.display === 'none') return; // Skip hidden rows
                    const cells = Array.from(row.cells)
                        .map(cell => cell.textContent.replace(/\\n/g, ' ').trim())
                        .map(escapeCSV);
                    csv.push(cells.join(','));
                });
                
                // Download
                const csvContent = csv.join('\\n');
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${tableId}_export.csv`;
                link.click();
                URL.revokeObjectURL(link.href);
            });
        });
        
        function escapeCSV(text) {
            if (text.includes(',') || text.includes('"') || text.includes('\\n')) {
                return '"' + text.replace(/"/g, '""') + '"';
            }
            return text;
        }
    </script>
    '''


# Convenience function for generating report from GlobalProtectData list
def generate_globalprotect_report(
    gp_data_list: List[GlobalProtectData],
    output_path: str,
    verbose: bool = False
) -> None:
    """
    Generate GlobalProtect HTML report from data objects.
    
    Args:
        gp_data_list: List of GlobalProtectData objects
        output_path: Output file path
        verbose: Enable verbose logging
    """
    generator = GlobalProtectReportGenerator(verbose=verbose)
    generator.generate(gp_data_list, output_path)
