"""
Main entry point for the Attack Surface Reconnaissance tool.
Orchestrates Google dorking, GitHub scanning, and correlation analysis.
"""

import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconnaissance.google_dorking import GoogleDorking
from github.leak_scanner import LeakScanner
from correlation.analyzer import CorrelationEngine
from utils.config import Config
from subdomain.subdomain_enum import SubdomainEnumerator
from ports.port_scanner import PortScanner
from reporting.report_generator import ReportGenerator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_tool.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def print_banner():
    """Print tool banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   Google-Powered Attack Surface Reconnaissance Tool              ║
    ║   & GitHub Leak Correlator                                       ║
    ║                                                                   ║
    ║   OSINT-Driven Security Intelligence Platform                    ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Attack Surface Reconnaissance & Leak Correlation Tool'
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain or organization name (e.g., example.com)'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file (optional)',
        default=None
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output directory for reports',
        default='output'
    )
    
    parser.add_argument(
        '--skip-google',
        action='store_true',
        help='Skip Google dorking reconnaissance'
    )
    
    parser.add_argument(
        '--skip-github',
        action='store_true',
        help='Skip GitHub leak scanning'
    )
    
    parser.add_argument(
        '--google-only',
        action='store_true',
        help='Run only Google dorking (no correlation)'
    )
    
    parser.add_argument(
        '--github-only',
        action='store_true',
        help='Run only GitHub scanning (no correlation)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--with-subdomains',
        action='store_true',
        help='Enable subdomain enumeration'
    )
    
    parser.add_argument(
        '--with-portscan',
        action='store_true',
        help='Enable port scanning on discovered subdomains'
    )
    
    parser.add_argument(
        '--html-report',
        action='store_true',
        help='Generate HTML report'
    )
    
    return parser.parse_args()


def run_google_reconnaissance(config: Config, target: str, output_dir: Path) -> dict:
    """
    Run Google dorking reconnaissance.
    
    Args:
        config: Configuration object
        target: Target domain/organization
        output_dir: Output directory for results
        
    Returns:
        Google reconnaissance results
    """
    logger.info("=" * 70)
    logger.info("PHASE 1: Google Custom Search Reconnaissance")
    logger.info("=" * 70)
    
    google_scanner = GoogleDorking(config)
    google_results = google_scanner.perform_dorking(target)
    
    # Save results
    output_file = output_dir / f"google_recon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    google_scanner.save_results(str(output_file))
    
    # Print summary
    summary = google_scanner.get_summary()
    logger.info("\n[SUMMARY] Google Reconnaissance Summary:")
    logger.info(f"   Target: {summary.get('target', 'N/A')}")
    logger.info(f"   Total Findings: {summary.get('total_findings', 0)}")
    logger.info(f"   By Severity:")
    for severity, count in summary.get('by_severity', {}).items():
        logger.info(f"      {severity.upper()}: {count}")
    
    return google_results


def run_github_scanning(config: Config, target: str, output_dir: Path) -> dict:
    """
    Run GitHub leak scanning.
    
    Args:
        config: Configuration object
        target: Target domain/organization
        output_dir: Output directory for results
        
    Returns:
        GitHub scanning results
    """
    logger.info("\n" + "=" * 70)
    logger.info("PHASE 2: GitHub Leak & Secret Scanning")
    logger.info("=" * 70)
    
    github_scanner = LeakScanner(config)
    github_results = github_scanner.scan_repositories(target)
    
    # Save results
    output_file = output_dir / f"github_leaks_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    github_scanner.save_results(str(output_file))
    
    # Print summary
    summary = github_scanner.get_summary()
    logger.info("\n[SUMMARY] GitHub Scanning Summary:")
    logger.info(f"   Target: {summary.get('target', 'N/A')}")
    logger.info(f"   Repositories Scanned: {summary.get('repositories_scanned', 0)}")
    logger.info(f"   Total Leaks: {summary.get('total_leaks', 0)}")
    logger.info(f"   By Severity:")
    for severity, count in summary.get('by_severity', {}).items():
        logger.info(f"      {severity.upper()}: {count}")
    
    return github_results


def run_correlation(google_results: dict, github_results: dict, output_dir: Path, target: str) -> dict:
    """
    Run correlation analysis.
    
    Args:
        google_results: Google reconnaissance results
        github_results: GitHub scanning results
        output_dir: Output directory for results
        target: Target domain/organization
        
    Returns:
        Correlation report
    """
    logger.info("\n" + "=" * 70)
    logger.info("PHASE 3: Correlation & Risk Analysis")
    logger.info("=" * 70)
    
    correlation_engine = CorrelationEngine()
    correlation_report = correlation_engine.correlate_findings(google_results, github_results)
    
    # Save report
    output_file = output_dir / f"correlated_report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    correlation_engine.save_report(correlation_report, str(output_file))
    
    # Print summary
    risk_summary = correlation_report.get('risk_summary', {})
    logger.info("\n[SUMMARY] Correlation Analysis Summary:")
    logger.info(f"   Total Correlations: {risk_summary.get('total_correlations', 0)}")
    logger.info(f"   Average Risk Score: {risk_summary.get('average_risk_score', 0)}/100")
    logger.info(f"   By Severity:")
    for severity, count in risk_summary.get('by_severity', {}).items():
        logger.info(f"      {severity.upper()}: {count}")
    
    # Print recommendations
    recommendations = correlation_report.get('recommendations', [])
    if recommendations:
        logger.info("\n[RECOMMENDATIONS] Top Security Recommendations:")
        for i, rec in enumerate(recommendations[:5], 1):
            logger.info(f"   {i}. [{rec['priority'].upper()}] {rec['title']}")
            logger.info(f"      {rec['description']}")
    
    return correlation_report


def run_subdomain_enumeration(config: Config, target: str, output_dir: Path) -> dict:
    """
    Run subdomain enumeration.
    
    Args:
        config: Configuration object
        target: Target domain
        output_dir: Output directory for results
        
    Returns:
        Subdomain enumeration results
    """
    logger.info("=" * 70)
    logger.info("PHASE 4: Subdomain Enumeration")
    logger.info("=" * 70)
    
    enumerator = SubdomainEnumerator(config)
    subdomain_results = enumerator.enumerate_subdomains(target)
    
    # Save results
    output_file = output_dir / f"subdomains_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    enumerator.save_results(str(output_file))
    
    # Print summary
    summary = enumerator.get_summary()
    logger.info("\n[SUMMARY] Subdomain Enumeration Summary:")
    logger.info(f"   Target: {summary.get('target', 'N/A')}")
    logger.info(f"   Total Subdomains: {summary.get('total_subdomains', 0)}")
    logger.info(f"   Wildcard DNS: {summary.get('has_wildcard', False)}")
    logger.info(f"   By Category:")
    for category, count in summary.get('categories', {}).items():
        logger.info(f"      {category}: {count}")
    
    return subdomain_results


def run_port_scanning(subdomain_results: dict, output_dir: Path) -> list:
    """
    Run port scanning on discovered subdomains.
    
    Args:
        subdomain_results: Results from subdomain enumeration
        output_dir: Output directory for results
        
    Returns:
        Port scanning results
    """
    logger.info("=" * 70)
    logger.info("PHASE 5: Port Scanning")
    logger.info("=" * 70)
    
    subdomains = subdomain_results.get('subdomains', [])[:10]  # Limit to first 10
    
    if not subdomains:
        logger.warning("No subdomains to scan")
        return []
    
    logger.info(f"Scanning ports on {len(subdomains)} subdomains...")
    
    scanner = PortScanner(timeout=2, max_workers=10)
    scan_results = scanner.scan_multiple_hosts(subdomains)
    
    # Save results
    output_file = output_dir / f"port_scan_{subdomain_results.get('target', 'target').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    scanner.save_results(str(output_file))
    
    # Print summary
    summary = scanner.get_summary()
    logger.info("\n[SUMMARY] Port Scanning Summary:")
    logger.info(f"   Hosts Scanned: {summary.get('total_hosts_scanned', 0)}")
    logger.info(f"   Total Open Ports: {summary.get('total_open_ports', 0)}")
    logger.info(f"   Services Found:")
    for service, count in summary.get('services_found', {}).items():
        logger.info(f"      {service}: {count}")
    
    return scan_results


def generate_html_report(google_results: dict, github_results: dict, 
                        correlation_results: dict, subdomain_results: dict,
                        port_scan_results: list, output_dir: Path, target: str):
    """
    Generate HTML report.
    
    Args:
        google_results: Google reconnaissance results
        github_results: GitHub scanning results
        correlation_results: Correlation analysis results
        subdomain_results: Subdomain enumeration results
        port_scan_results: Port scanning results
        output_dir: Output directory
        target: Target domain
    """
    logger.info("=" * 70)
    logger.info("Generating HTML Report")
    logger.info("=" * 70)
    
    generator = ReportGenerator()
    output_file = output_dir / f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    generator.generate_html_report(
        google_results,
        github_results,
        correlation_results,
        subdomain_results,
        port_scan_results,
        str(output_file)
    )
    
    logger.info(f"\n[REPORT] HTML report generated: {output_file}")
    logger.info(f"[VIEW] Open {output_file} in your browser to view the report")


def main():
    """Main execution function."""
    try:
        print_banner()
        args = parse_arguments()
        
        # Set logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Initialize configuration
        logger.info("Initializing configuration...")
        config = Config(config_file=args.config)
        
        # Validate configuration
        if not config.validate():
            logger.error("[ERROR] Configuration validation failed!")
            logger.error("Please set the following environment variables:")
            logger.error("  - GOOGLE_API_KEY: Your Google Custom Search API key")
            logger.error("  - GOOGLE_CSE_ID: Your Google Custom Search Engine ID")
            logger.error("  - GITHUB_TOKEN: Your GitHub Personal Access Token")
            logger.error("\nAlternatively, provide a config file with --config")
            sys.exit(1)
        
        logger.info("[OK] Configuration validated successfully")
        
        # Create output directory
        output_dir = Path(args.output)
        output_dir.mkdir(exist_ok=True)
        logger.info(f"[OK] Output directory: {output_dir}")
        
        target = args.target
        logger.info(f"[TARGET] {target}")
        logger.info("")
        
        # Execute phases
        google_results = None
        github_results = None
        
        # Phase 1: Google Reconnaissance
        if not args.skip_google and not args.github_only:
            google_results = run_google_reconnaissance(config, target, output_dir)
        
        # Phase 2: GitHub Scanning
        if not args.skip_github and not args.google_only:
            github_results = run_github_scanning(config, target, output_dir)
        
        # Phase 3: Correlation Analysis
        if google_results and github_results and not args.google_only and not args.github_only:
            correlation_report = run_correlation(google_results, github_results, output_dir, target)
        
        # Phase 4: Subdomain Enumeration (Optional)
        subdomain_results = None
        if args.with_subdomains:
            subdomain_results = run_subdomain_enumeration(config, target, output_dir)
        
        # Phase 5: Port Scanning (Optional)
        port_scan_results = None
        if args.with_portscan and subdomain_results:
            port_scan_results = run_port_scanning(subdomain_results, output_dir)
        
        # Generate HTML Report (Optional)
        if args.html_report:
            generate_html_report(
                google_results or {},
                github_results or {},
                correlation_report if 'correlation_report' in locals() else {},
                subdomain_results,
                port_scan_results,
                output_dir,
                target
            )
        
        # Final summary
        logger.info("\n" + "="*70)
        logger.info("[COMPLETE] RECONNAISSANCE COMPLETE")
        logger.info("="*70)
        logger.info(f"\n[OUTPUT] Results saved to: {output_dir}")
        logger.info("\n[NEXT STEPS] Next Steps:")
        logger.info("   1. Review the generated JSON reports")
        logger.info("   2. Prioritize findings by severity")
        logger.info("   3. Implement security recommendations")
        logger.info("   4. Monitor and remediate identified vulnerabilities")
        logger.info("")
        
    except KeyboardInterrupt:
        logger.warning("\n\n[CANCELLED] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"\n[ERROR] Error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()