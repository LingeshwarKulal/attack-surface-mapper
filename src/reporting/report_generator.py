"""
Report Generator Module
Creates HTML and PDF reports from scan results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate HTML and formatted reports from scan results."""
    
    def __init__(self):
        """Initialize report generator."""
        self.template = None
    
    def generate_html_report(self, 
                            google_results: Dict[str, Any],
                            github_results: Dict[str, Any],
                            correlation_results: Dict[str, Any],
                            subdomain_results: Dict[str, Any] = None,
                            port_scan_results: List[Dict[str, Any]] = None,
                            output_path: str = None) -> str:
        """
        Generate comprehensive HTML report.
        
        Args:
            google_results: Google reconnaissance results
            github_results: GitHub leak scanning results
            correlation_results: Correlation analysis results
            subdomain_results: Subdomain enumeration results
            port_scan_results: Port scanning results
            output_path: Path to save HTML report
            
        Returns:
            HTML report content
        """
        target = google_results.get('target', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Reconnaissance Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            margin: -30px -30px 30px -30px;
            border-radius: 5px 5px 0 0;
        }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        h2 {{ 
            color: #667eea;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        h3 {{ color: #764ba2; margin: 20px 0 10px 0; }}
        .meta-info {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .severity-critical {{ 
            background: #dc3545;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-high {{ 
            background: #fd7e14;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-medium {{ 
            background: #ffc107;
            color: #333;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .severity-low {{ 
            background: #28a745;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .finding {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            border-radius: 3px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ font-size: 0.9em; opacity: 0.9; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        tr:hover {{ background: #f5f5f5; }}
        .url {{ 
            color: #667eea;
            word-break: break-all;
            font-family: monospace;
        }}
        .recommendation {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Security Reconnaissance Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Generated:</strong> {timestamp}</p>
        </div>
        
        <div class="meta-info">
            <strong>Report Type:</strong> Attack Surface Reconnaissance & Leak Detection<br>
            <strong>Scan Coverage:</strong> Google OSINT, GitHub Leaks, Correlation Analysis{', Subdomain Enumeration' if subdomain_results else ''}{', Port Scanning' if port_scan_results else ''}
        </div>
"""
        
        # Executive Summary Statistics
        google_total = sum(len(v) for v in google_results.get('categories', {}).values() if isinstance(v, list))
        github_total = sum(len(r.get('findings', [])) for r in github_results.get('repositories', []))
        correlation_total = len(correlation_results.get('correlations', []))
        subdomain_total = subdomain_results.get('total_subdomains', 0) if subdomain_results else 0
        
        html += f"""
        <h2>📊 Executive Summary</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{google_total}</div>
                <div class="stat-label">Google Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{github_total}</div>
                <div class="stat-label">GitHub Leaks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{correlation_total}</div>
                <div class="stat-label">Correlations</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{subdomain_total}</div>
                <div class="stat-label">Subdomains</div>
            </div>
        </div>
"""
        
        # Google Reconnaissance Results
        html += self._generate_google_section(google_results)
        
        # GitHub Leak Results
        html += self._generate_github_section(github_results)
        
        # Subdomain Results
        if subdomain_results:
            html += self._generate_subdomain_section(subdomain_results)
        
        # Port Scan Results
        if port_scan_results:
            html += self._generate_portscan_section(port_scan_results)
        
        # Correlation Results
        html += self._generate_correlation_section(correlation_results)
        
        # Recommendations
        html += self._generate_recommendations(correlation_results)
        
        html += """
    </div>
</body>
</html>
"""
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html)
                logger.info(f"HTML report saved to {output_path}")
            except Exception as e:
                logger.error(f"Failed to save HTML report: {str(e)}")
        
        return html
    
    def _generate_google_section(self, results: Dict[str, Any]) -> str:
        """Generate Google reconnaissance section."""
        html = "<h2>🔎 Google Reconnaissance Results</h2>"
        
        categories = results.get('categories', {})
        total = sum(len(v) for v in categories.values() if isinstance(v, list))
        
        if total == 0:
            html += '<div class="no-findings">✅ No concerning findings from Google search</div>'
            return html
        
        for category, findings in categories.items():
            if not findings or not isinstance(findings, list):
                continue
            
            html += f"<h3>{category.replace('_', ' ').title()} ({len(findings)} findings)</h3>"
            
            for finding in findings:
                severity = finding.get('severity', 'low')
                html += f"""
                <div class="finding">
                    <span class="severity-{severity}">{severity.upper()}</span>
                    <h4>{finding.get('title', 'N/A')}</h4>
                    <p><strong>URL:</strong> <a href="{finding.get('url', '#')}" class="url" target="_blank">{finding.get('url', 'N/A')}</a></p>
                    <p><strong>Snippet:</strong> {finding.get('snippet', 'N/A')}</p>
                    <p><strong>Risk Indicators:</strong> {', '.join(finding.get('risk_indicators', []))}</p>
                </div>
                """
        
        return html
    
    def _generate_github_section(self, results: Dict[str, Any]) -> str:
        """Generate GitHub leaks section."""
        html = "<h2>🐙 GitHub Leak Detection Results</h2>"
        
        repositories = results.get('repositories', [])
        
        if not repositories:
            html += '<div class="no-findings">✅ No secret leaks detected in public repositories</div>'
            return html
        
        for repo in repositories:
            findings = repo.get('findings', [])
            if not findings:
                continue
            
            html += f"""
            <h3>Repository: {repo.get('name', 'Unknown')}</h3>
            <p><strong>URL:</strong> <a href="{repo.get('url', '#')}" target="_blank">{repo.get('url', 'N/A')}</a></p>
            """
            
            for finding in findings:
                html += f"""
                <div class="finding">
                    <span class="severity-{finding.get('severity', 'low')}">{finding.get('severity', 'low').upper()}</span>
                    <p><strong>Type:</strong> {finding.get('type', 'N/A')}</p>
                    <p><strong>Secret Type:</strong> {finding.get('secret_type', 'N/A')}</p>
                    <p><strong>Pattern:</strong> <code>{finding.get('matched_pattern', 'N/A')}</code></p>
                </div>
                """
        
        return html
    
    def _generate_subdomain_section(self, results: Dict[str, Any]) -> str:
        """Generate subdomain enumeration section."""
        html = "<h2>🌐 Subdomain Enumeration Results</h2>"
        
        total = results.get('total_subdomains', 0)
        if total == 0:
            html += '<div class="no-findings">No subdomains discovered</div>'
            return html
        
        html += f"<p><strong>Total Subdomains Found:</strong> {total}</p>"
        html += f"<p><strong>Wildcard DNS:</strong> {'⚠️ Yes' if results.get('has_wildcard') else '✅ No'}</p>"
        
        categorized = results.get('categorized', {})
        
        for category, subdomains in categorized.items():
            html += f"<h3>{category.title()} ({len(subdomains)})</h3><ul>"
            for sub in subdomains[:20]:  # Limit display
                html += f"<li><code>{sub}</code></li>"
            if len(subdomains) > 20:
                html += f"<li><em>... and {len(subdomains) - 20} more</em></li>"
            html += "</ul>"
        
        return html
    
    def _generate_portscan_section(self, results: List[Dict[str, Any]]) -> str:
        """Generate port scan section."""
        html = "<h2>🔌 Port Scanning Results</h2>"
        
        if not results:
            html += '<div class="no-findings">No port scans performed</div>'
            return html
        
        html += """
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for result in results:
            host = result.get('host', 'Unknown')
            for port_info in result.get('open_ports', []):
                html += f"""
                <tr>
                    <td><code>{host}</code></td>
                    <td>{port_info.get('port', 'N/A')}</td>
                    <td>{port_info.get('service', 'Unknown')}</td>
                    <td><code>{port_info.get('banner', 'N/A')[:50]}</code></td>
                </tr>
                """
        
        html += "</tbody></table>"
        return html
    
    def _generate_correlation_section(self, results: Dict[str, Any]) -> str:
        """Generate correlation analysis section."""
        html = "<h2>🔗 Correlation Analysis</h2>"
        
        correlations = results.get('correlations', [])
        
        if not correlations:
            html += '<div class="no-findings">✅ No high-risk correlations found</div>'
            return html
        
        for corr in correlations:
            html += f"""
            <div class="finding">
                <span class="severity-{corr.get('severity', 'low')}">{corr.get('severity', 'low').upper()}</span>
                <p><strong>Risk Score:</strong> {corr.get('risk_score', 0)}/100</p>
                <p><strong>Type:</strong> {corr.get('correlation_type', 'N/A')}</p>
                <p><strong>Details:</strong> {corr.get('details', 'N/A')}</p>
            </div>
            """
        
        return html
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> str:
        """Generate security recommendations."""
        html = "<h2>💡 Security Recommendations</h2>"
        
        recommendations = results.get('recommendations', [])
        
        if not recommendations:
            recommendations = [
                {
                    'priority': 'HIGH',
                    'title': 'Implement GitHub Secret Scanning',
                    'description': 'Enable GitHub secret scanning and commit signing to prevent future leaks.'
                },
                {
                    'priority': 'MEDIUM',
                    'title': 'Review Search Engine Indexing',
                    'description': 'Configure robots.txt to prevent sensitive pages from being indexed.'
                }
            ]
        
        for rec in recommendations:
            html += f"""
            <div class="recommendation">
                <strong>[{rec.get('priority', 'MEDIUM')}]</strong> {rec.get('title', 'N/A')}
                <p>{rec.get('description', 'N/A')}</p>
            </div>
            """
        
        return html
