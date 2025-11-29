"""
Example script demonstrating how to use the Attack Surface Recon tool programmatically.
"""

import logging
from pathlib import Path
from src.reconnaissance.google_dorking import GoogleDorking
from src.github.leak_scanner import LeakScanner
from src.correlation.analyzer import CorrelationEngine
from src.utils.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def example_google_dorking():
    """Example: Run Google dorking reconnaissance."""
    print("\n" + "="*70)
    print("EXAMPLE 1: Google Dorking Reconnaissance")
    print("="*70)
    
    # Initialize config
    config = Config()
    
    if not config.google_api_key or not config.google_cse_id:
        print("⚠️  Please configure Google API credentials in .env file")
        return
    
    # Create Google dorking instance
    scanner = GoogleDorking(config)
    
    # Perform reconnaissance
    target = "example.com"
    print(f"\n🔍 Scanning target: {target}")
    
    results = scanner.perform_dorking(target)
    
    # Display summary
    summary = scanner.get_summary()
    print(f"\n📊 Results:")
    print(f"   Total findings: {summary.get('total_findings', 0)}")
    print(f"   Critical: {summary.get('by_severity', {}).get('critical', 0)}")
    print(f"   High: {summary.get('by_severity', {}).get('high', 0)}")
    print(f"   Medium: {summary.get('by_severity', {}).get('medium', 0)}")
    print(f"   Low: {summary.get('by_severity', {}).get('low', 0)}")
    
    # Save results
    output_path = Path("output/example_google_results.json")
    output_path.parent.mkdir(exist_ok=True)
    scanner.save_results(str(output_path))
    print(f"\n✅ Results saved to: {output_path}")
    
    return results


def example_github_scanning():
    """Example: Run GitHub leak scanning."""
    print("\n" + "="*70)
    print("EXAMPLE 2: GitHub Leak Scanning")
    print("="*70)
    
    # Initialize config
    config = Config()
    
    if not config.github_token:
        print("⚠️  Please configure GitHub token in .env file")
        return
    
    # Create GitHub scanner instance
    scanner = LeakScanner(config)
    
    # Perform scanning
    target = "example"
    print(f"\n🔍 Scanning GitHub for: {target}")
    
    results = scanner.scan_repositories(target)
    
    # Display summary
    summary = scanner.get_summary()
    print(f"\n📊 Results:")
    print(f"   Repositories scanned: {summary.get('repositories_scanned', 0)}")
    print(f"   Total leaks: {summary.get('total_leaks', 0)}")
    print(f"   Critical: {summary.get('by_severity', {}).get('critical', 0)}")
    print(f"   High: {summary.get('by_severity', {}).get('high', 0)}")
    
    # Save results
    output_path = Path("output/example_github_results.json")
    output_path.parent.mkdir(exist_ok=True)
    scanner.save_results(str(output_path))
    print(f"\n✅ Results saved to: {output_path}")
    
    return results


def example_correlation():
    """Example: Correlate findings from both sources."""
    print("\n" + "="*70)
    print("EXAMPLE 3: Correlation Analysis")
    print("="*70)
    
    # Sample data for demonstration
    google_results = {
        'target': 'example.com',
        'timestamp': '2025-11-29T12:00:00Z',
        'categories': {
            'api_endpoints': [
                {
                    'url': 'https://api.example.com/v1/',
                    'title': 'Example API Documentation',
                    'snippet': 'REST API for Example service',
                    'category': 'api_endpoints',
                    'severity': 'high'
                }
            ],
            'exposed_files': [
                {
                    'url': 'https://example.com/config.env',
                    'title': 'Environment Configuration',
                    'snippet': 'Configuration file',
                    'category': 'exposed_files',
                    'severity': 'critical'
                }
            ]
        }
    }
    
    github_results = {
        'target': 'example.com',
        'timestamp': '2025-11-29T12:00:00Z',
        'repositories': [
            {
                'name': 'example/api-client',
                'url': 'https://github.com/example/api-client',
                'findings': [
                    {
                        'type': 'commit_message',
                        'secret_type': 'generic_api_key',
                        'commit_sha': 'abc123',
                        'severity': 'high',
                        'matched_pattern': 'api_key=sk_live_...'
                    }
                ]
            }
        ],
        'code_leaks': []
    }
    
    # Create correlation engine
    engine = CorrelationEngine()
    
    # Perform correlation
    print("\n🔗 Correlating findings...")
    report = engine.correlate_findings(google_results, github_results)
    
    # Display results
    risk_summary = report.get('risk_summary', {})
    print(f"\n📊 Correlation Results:")
    print(f"   Total correlations: {risk_summary.get('total_correlations', 0)}")
    print(f"   Average risk score: {risk_summary.get('average_risk_score', 0)}/100")
    print(f"\n   By severity:")
    for severity, count in risk_summary.get('by_severity', {}).items():
        print(f"      {severity.upper()}: {count}")
    
    # Display top recommendations
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\n🔒 Top Recommendations:")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. [{rec['priority'].upper()}] {rec['title']}")
    
    # Save report
    output_path = Path("output/example_correlation_report.json")
    output_path.parent.mkdir(exist_ok=True)
    engine.save_report(report, str(output_path))
    print(f"\n✅ Report saved to: {output_path}")
    
    return report


def example_custom_dork_query():
    """Example: Run a custom Google dork query."""
    print("\n" + "="*70)
    print("EXAMPLE 4: Custom Dork Query")
    print("="*70)
    
    config = Config()
    
    if not config.google_api_key or not config.google_cse_id:
        print("⚠️  Please configure Google API credentials")
        return
    
    scanner = GoogleDorking(config)
    
    # Custom query
    query = 'site:example.com filetype:pdf "confidential"'
    print(f"\n🔍 Executing custom query: {query}")
    
    results = scanner.search(query, num_results=5)
    
    print(f"\n📊 Found {len(results)} results")
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result.get('title', 'No title')}")
        print(f"   URL: {result.get('link', 'No URL')}")
        print(f"   {result.get('snippet', 'No description')[:100]}...")


def main():
    """Run all examples."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   Attack Surface Reconnaissance - Usage Examples             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Check configuration
    config = Config()
    print("\n🔧 Configuration Status:")
    print(f"   Google API configured: {'✅' if config.google_api_key else '❌'}")
    print(f"   GitHub token configured: {'✅' if config.github_token else '❌'}")
    
    if not config.validate():
        print("\n⚠️  Warning: Some API credentials are missing.")
        print("   Examples will run with limited functionality.")
        print("   Please configure credentials in .env file.\n")
    
    # Run examples (uncomment the ones you want to run)
    
    # Example 1: Google Dorking
    # example_google_dorking()
    
    # Example 2: GitHub Scanning
    # example_github_scanning()
    
    # Example 3: Correlation (works without API keys)
    example_correlation()
    
    # Example 4: Custom dork query
    # example_custom_dork_query()
    
    print("\n" + "="*70)
    print("✅ Examples completed!")
    print("="*70)
    print("\nTip: Uncomment examples in main() to run them individually")
    print("Check the 'output/' directory for saved results\n")


if __name__ == "__main__":
    main()
