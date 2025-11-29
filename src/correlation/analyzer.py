"""
Correlation Engine for linking Google OSINT findings with GitHub leaks.
Identifies high-risk exposure patterns and generates actionable intelligence.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
import json
from collections import defaultdict

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlates findings from Google dorking and GitHub scanning."""
    
    def __init__(self):
        """Initialize correlation engine."""
        self.google_results = {}
        self.github_results = {}
        self.correlations = []
        self.risk_scores = {}
    
    def correlate_findings(
        self,
        google_results: Dict[str, Any],
        github_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Correlate findings from both sources to identify critical exposures.
        
        Args:
            google_results: Results from Google dorking
            github_results: Results from GitHub scanning
            
        Returns:
            Dictionary containing correlated findings and risk analysis
        """
        self.google_results = google_results
        self.github_results = github_results
        
        logger.info("Starting correlation analysis...")
        
        correlated_report = {
            'target': google_results.get('target', ''),
            'timestamp': datetime.utcnow().isoformat(),
            'correlations': [],
            'risk_summary': {},
            'recommendations': []
        }
        
        # Perform various correlation analyses
        self.correlations = []
        
        # 1. API endpoint + leaked credentials correlation
        api_cred_correlations = self.correlate_api_credentials()
        self.correlations.extend(api_cred_correlations)
        
        # 2. Login panels + exposed emails/passwords
        login_correlations = self.correlate_login_exposures()
        self.correlations.extend(login_correlations)
        
        # 3. Cloud storage + configuration files
        cloud_correlations = self.correlate_cloud_exposures()
        self.correlations.extend(cloud_correlations)
        
        # 4. Exposed files + GitHub code references
        file_correlations = self.correlate_file_exposures()
        self.correlations.extend(file_correlations)
        
        # 5. Error messages + leaked database info
        db_correlations = self.correlate_database_exposures()
        self.correlations.extend(db_correlations)
        
        # Calculate risk scores
        for correlation in self.correlations:
            risk_score = self.calculate_risk_score(correlation)
            correlation['risk_score'] = risk_score
            correlation['severity'] = self.map_risk_to_severity(risk_score)
        
        # Sort by risk score (highest first)
        self.correlations.sort(key=lambda x: x['risk_score'], reverse=True)
        
        correlated_report['correlations'] = self.correlations
        correlated_report['risk_summary'] = self.generate_risk_summary()
        correlated_report['recommendations'] = self.generate_recommendations()
        
        logger.info(f"Correlation complete. Found {len(self.correlations)} correlated findings")
        
        return correlated_report
    
    def correlate_api_credentials(self) -> List[Dict[str, Any]]:
        """
        Correlate API endpoints found via Google with leaked credentials in GitHub.
        
        Returns:
            List of correlation dictionaries
        """
        correlations = []
        
        # Extract API endpoints from Google results
        api_endpoints = []
        for category, findings in self.google_results.get('categories', {}).items():
            if category == 'api_endpoints':
                api_endpoints.extend(findings)
        
        # Extract API credentials from GitHub results
        api_credentials = []
        for repo in self.github_results.get('repositories', []):
            for finding in repo.get('findings', []):
                secret_type = finding.get('secret_type', '')
                if 'api' in secret_type or 'key' in secret_type or 'token' in secret_type:
                    api_credentials.append({
                        'finding': finding,
                        'repository': repo['name']
                    })
        
        for leak in self.github_results.get('code_leaks', []):
            for secret in leak.get('secrets', []):
                if 'api' in secret['type'] or 'key' in secret['type'] or 'token' in secret['type']:
                    api_credentials.append({
                        'finding': secret,
                        'repository': leak['repository'],
                        'file_path': leak['file_path']
                    })
        
        # Create correlations
        if api_endpoints and api_credentials:
            for endpoint in api_endpoints[:5]:  # Limit correlations
                for cred in api_credentials[:5]:
                    correlations.append({
                        'type': 'api_endpoint_credential_leak',
                        'description': 'Exposed API endpoint with leaked credentials',
                        'google_finding': {
                            'url': endpoint['url'],
                            'title': endpoint['title'],
                            'category': endpoint['category']
                        },
                        'github_finding': {
                            'repository': cred['repository'],
                            'secret_type': cred['finding'].get('type', cred['finding'].get('secret_type', 'unknown')),
                            'file_path': cred.get('file_path', 'N/A')
                        },
                        'impact': 'Attackers can potentially access the API using leaked credentials',
                        'base_severity': 'critical'
                    })
        
        return correlations
    
    def correlate_login_exposures(self) -> List[Dict[str, Any]]:
        """
        Correlate login panels with leaked passwords or email formats.
        
        Returns:
            List of correlation dictionaries
        """
        correlations = []
        
        # Extract login panels
        login_panels = []
        for category, findings in self.google_results.get('categories', {}).items():
            for finding in findings:
                if 'login' in finding['url'].lower() or 'login' in finding['title'].lower():
                    login_panels.append(finding)
        
        # Extract password leaks
        password_leaks = []
        for repo in self.github_results.get('repositories', []):
            for finding in repo.get('findings', []):
                if finding.get('secret_type', '') == 'password':
                    password_leaks.append({
                        'finding': finding,
                        'repository': repo['name']
                    })
        
        # Create correlations
        if login_panels and password_leaks:
            for panel in login_panels[:3]:
                for leak in password_leaks[:3]:
                    correlations.append({
                        'type': 'login_panel_password_leak',
                        'description': 'Public login panel with leaked password',
                        'google_finding': {
                            'url': panel['url'],
                            'title': panel['title']
                        },
                        'github_finding': {
                            'repository': leak['repository'],
                            'secret_type': 'password'
                        },
                        'impact': 'Leaked credentials may grant unauthorized access to login panel',
                        'base_severity': 'high'
                    })
        
        return correlations
    
    def correlate_cloud_exposures(self) -> List[Dict[str, Any]]:
        """
        Correlate cloud storage URLs with configuration files in GitHub.
        
        Returns:
            List of correlation dictionaries
        """
        correlations = []
        
        # Extract cloud storage findings
        cloud_findings = []
        for category, findings in self.google_results.get('categories', {}).items():
            if category == 'cloud_exposure':
                cloud_findings.extend(findings)
        
        # Extract config file leaks
        config_leaks = []
        for leak in self.github_results.get('code_leaks', []):
            if any(ext in leak.get('file_path', '') for ext in ['.env', '.config', '.yml', '.yaml']):
                config_leaks.append(leak)
        
        # Create correlations
        if cloud_findings and config_leaks:
            for cloud in cloud_findings[:3]:
                for config in config_leaks[:3]:
                    correlations.append({
                        'type': 'cloud_storage_config_leak',
                        'description': 'Exposed cloud storage with leaked configuration',
                        'google_finding': {
                            'url': cloud['url'],
                            'title': cloud['title']
                        },
                        'github_finding': {
                            'repository': config['repository'],
                            'file_path': config['file_path']
                        },
                        'impact': 'Configuration files may contain cloud access credentials',
                        'base_severity': 'critical'
                    })
        
        return correlations
    
    def correlate_file_exposures(self) -> List[Dict[str, Any]]:
        """
        Correlate exposed files from Google with GitHub code that references them.
        
        Returns:
            List of correlation dictionaries
        """
        correlations = []
        
        # Extract exposed files
        exposed_files = []
        for category, findings in self.google_results.get('categories', {}).items():
            if category in ['exposed_files', 'config_files']:
                exposed_files.extend(findings)
        
        # If we have exposed files and GitHub repos, create general correlation
        if exposed_files and self.github_results.get('repositories', []):
            for exposed in exposed_files[:5]:
                correlations.append({
                    'type': 'exposed_file_github_reference',
                    'description': 'Publicly indexed file with potential GitHub references',
                    'google_finding': {
                        'url': exposed['url'],
                        'title': exposed['title'],
                        'category': exposed['category']
                    },
                    'github_finding': {
                        'repositories_found': len(self.github_results.get('repositories', []))
                    },
                    'impact': 'Exposed files may reveal internal paths or configurations referenced in code',
                    'base_severity': exposed['severity']
                })
        
        return correlations
    
    def correlate_database_exposures(self) -> List[Dict[str, Any]]:
        """
        Correlate database-related findings across both sources.
        
        Returns:
            List of correlation dictionaries
        """
        correlations = []
        
        # Extract database findings from Google
        db_findings = []
        for category, findings in self.google_results.get('categories', {}).items():
            if category == 'database' or category == 'error_messages':
                db_findings.extend(findings)
        
        # Extract database credentials from GitHub
        db_credentials = []
        for repo in self.github_results.get('repositories', []):
            for finding in repo.get('findings', []):
                if 'database' in finding.get('secret_type', ''):
                    db_credentials.append({
                        'finding': finding,
                        'repository': repo['name']
                    })
        
        for leak in self.github_results.get('code_leaks', []):
            for secret in leak.get('secrets', []):
                if 'database' in secret['type']:
                    db_credentials.append({
                        'finding': secret,
                        'repository': leak['repository']
                    })
        
        # Create correlations
        if db_findings and db_credentials:
            for db_finding in db_findings[:3]:
                for cred in db_credentials[:3]:
                    correlations.append({
                        'type': 'database_exposure_credential_leak',
                        'description': 'Database exposure with leaked credentials',
                        'google_finding': {
                            'url': db_finding['url'],
                            'title': db_finding['title']
                        },
                        'github_finding': {
                            'repository': cred['repository'],
                            'secret_type': cred['finding'].get('type', cred['finding'].get('secret_type', 'database'))
                        },
                        'impact': 'Database may be accessible with leaked credentials',
                        'base_severity': 'critical'
                    })
        
        return correlations
    
    def calculate_risk_score(self, correlation: Dict[str, Any]) -> int:
        """
        Calculate numerical risk score (0-100) for a correlation.
        
        Args:
            correlation: Correlation dictionary
            
        Returns:
            Risk score (0-100)
        """
        # Base severity mapping
        severity_map = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        }
        
        base_score = severity_map.get(correlation.get('base_severity', 'medium'), 50)
        
        # Adjust based on correlation type
        type_weights = {
            'api_endpoint_credential_leak': 1.0,
            'database_exposure_credential_leak': 1.0,
            'cloud_storage_config_leak': 0.95,
            'login_panel_password_leak': 0.9,
            'exposed_file_github_reference': 0.7
        }
        
        weight = type_weights.get(correlation['type'], 0.8)
        final_score = int(base_score * weight)
        
        return min(100, max(0, final_score))
    
    def map_risk_to_severity(self, risk_score: int) -> str:
        """
        Map numerical risk score to severity level.
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            Severity level string
        """
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def generate_risk_summary(self) -> Dict[str, Any]:
        """
        Generate overall risk summary.
        
        Returns:
            Risk summary dictionary
        """
        summary = {
            'total_correlations': len(self.correlations),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': defaultdict(int),
            'average_risk_score': 0,
            'highest_risk': None
        }
        
        total_score = 0
        for correlation in self.correlations:
            severity = correlation.get('severity', 'low')
            summary['by_severity'][severity] += 1
            
            corr_type = correlation.get('type', 'unknown')
            summary['by_type'][corr_type] += 1
            
            total_score += correlation.get('risk_score', 0)
        
        if self.correlations:
            summary['average_risk_score'] = round(total_score / len(self.correlations), 2)
            summary['highest_risk'] = self.correlations[0] if self.correlations else None
        
        summary['by_type'] = dict(summary['by_type'])
        
        return summary
    
    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate security recommendations based on correlations.
        
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Analyze correlation types and generate specific recommendations
        type_counts = defaultdict(int)
        for corr in self.correlations:
            type_counts[corr['type']] += 1
        
        if type_counts.get('api_endpoint_credential_leak', 0) > 0:
            recommendations.append({
                'priority': 'critical',
                'title': 'Rotate API Credentials Immediately',
                'description': 'API credentials have been leaked in public GitHub repositories. Rotate all API keys and implement secret management.',
                'affected_count': type_counts['api_endpoint_credential_leak']
            })
        
        if type_counts.get('database_exposure_credential_leak', 0) > 0:
            recommendations.append({
                'priority': 'critical',
                'title': 'Secure Database Access',
                'description': 'Database credentials are exposed. Change database passwords, restrict access, and review access logs.',
                'affected_count': type_counts['database_exposure_credential_leak']
            })
        
        if type_counts.get('login_panel_password_leak', 0) > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Reset User Passwords',
                'description': 'User passwords have been leaked. Force password resets and implement MFA.',
                'affected_count': type_counts['login_panel_password_leak']
            })
        
        if type_counts.get('cloud_storage_config_leak', 0) > 0:
            recommendations.append({
                'priority': 'critical',
                'title': 'Review Cloud Storage Permissions',
                'description': 'Cloud storage buckets may be misconfigured. Review permissions and audit access.',
                'affected_count': type_counts['cloud_storage_config_leak']
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'high',
            'title': 'Implement GitHub Secret Scanning',
            'description': 'Enable GitHub secret scanning and commit signing to prevent future leaks.',
            'affected_count': len(self.github_results.get('repositories', []))
        })
        
        recommendations.append({
            'priority': 'medium',
            'title': 'Review robots.txt and Search Engine Indexing',
            'description': 'Prevent sensitive pages from being indexed by search engines.',
            'affected_count': sum(len(f) for f in self.google_results.get('categories', {}).values())
        })
        
        return recommendations
    
    def save_report(self, report: Dict[str, Any], output_path: str):
        """
        Save correlation report to JSON file.
        
        Args:
            report: Report dictionary
            output_path: Path to output file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"Report saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")