"""
Subdomain Enumeration Module
Uses multiple techniques to discover subdomains of the target domain.
"""

import requests
import dns.resolver
import logging
import json
from typing import List, Dict, Any, Set
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Subdomain enumeration using multiple sources."""
    
    def __init__(self, config):
        """
        Initialize subdomain enumerator.
        
        Args:
            config: Configuration object
        """
        self.timeout = config.request_timeout
        self.results = []
        
    def enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Enumerate subdomains using multiple techniques.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing discovered subdomains
        """
        logger.info(f"Starting subdomain enumeration for: {domain}")
        
        all_subdomains = set()
        
        # Technique 1: crt.sh (Certificate Transparency Logs)
        crtsh_subdomains = self._query_crtsh(domain)
        all_subdomains.update(crtsh_subdomains)
        logger.info(f"Found {len(crtsh_subdomains)} subdomains from crt.sh")
        
        # Technique 2: DNS brute force (common subdomains)
        bruteforce_subdomains = self._dns_bruteforce(domain)
        all_subdomains.update(bruteforce_subdomains)
        logger.info(f"Found {len(bruteforce_subdomains)} subdomains from DNS bruteforce")
        
        # Technique 3: Check for wildcard DNS
        has_wildcard = self._check_wildcard_dns(domain)
        
        results = {
            'target': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'total_subdomains': len(all_subdomains),
            'has_wildcard': has_wildcard,
            'subdomains': list(all_subdomains),
            'categorized': self._categorize_subdomains(list(all_subdomains))
        }
        
        self.results = results
        return results
    
    def _query_crtsh(self, domain: str) -> Set[str]:
        """
        Query crt.sh certificate transparency logs.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle wildcard and multiple domains
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*', '')
                        if subdomain and subdomain.endswith(domain):
                            subdomains.add(subdomain.lower())
            
            time.sleep(1)  # Be respectful to the API
            
        except Exception as e:
            logger.debug(f"Error querying crt.sh: {str(e)}")
        
        return subdomains
    
    def _dns_bruteforce(self, domain: str) -> Set[str]:
        """
        Brute force common subdomain names.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of valid subdomains
        """
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev',
            'staging', 'test', 'api', 'admin', 'portal', 'vpn', 'remote', 'ssh', 'blog',
            'shop', 'store', 'app', 'cdn', 'static', 'img', 'images', 'video', 'media'
        ]
        
        valid_subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    valid_subdomains.add(subdomain.lower())
                    logger.debug(f"Found: {subdomain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                logger.debug(f"DNS error for {subdomain}: {str(e)}")
        
        return valid_subdomains
    
    def _check_wildcard_dns(self, domain: str) -> bool:
        """
        Check if domain has wildcard DNS configured.
        
        Args:
            domain: Target domain
            
        Returns:
            True if wildcard DNS is detected
        """
        import random
        import string
        
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=20))
        test_domain = f"{random_subdomain}.{domain}"
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            answers = resolver.resolve(test_domain, 'A')
            if answers:
                logger.warning(f"Wildcard DNS detected for {domain}")
                return True
        except:
            pass
        
        return False
    
    def _categorize_subdomains(self, subdomains: List[str]) -> Dict[str, List[str]]:
        """
        Categorize subdomains by purpose.
        
        Args:
            subdomains: List of subdomains
            
        Returns:
            Dictionary of categorized subdomains
        """
        categories = {
            'admin': [],
            'development': [],
            'api': [],
            'mail': [],
            'cdn': [],
            'vpn': [],
            'other': []
        }
        
        admin_keywords = ['admin', 'panel', 'cpanel', 'whm', 'portal', 'manage']
        dev_keywords = ['dev', 'test', 'staging', 'demo', 'qa', 'uat']
        api_keywords = ['api', 'rest', 'graphql', 'ws', 'service']
        mail_keywords = ['mail', 'smtp', 'pop', 'imap', 'webmail', 'email']
        cdn_keywords = ['cdn', 'static', 'assets', 'img', 'images', 'media']
        vpn_keywords = ['vpn', 'remote', 'citrix', 'rdp']
        
        for subdomain in subdomains:
            sub_lower = subdomain.lower()
            
            if any(keyword in sub_lower for keyword in admin_keywords):
                categories['admin'].append(subdomain)
            elif any(keyword in sub_lower for keyword in dev_keywords):
                categories['development'].append(subdomain)
            elif any(keyword in sub_lower for keyword in api_keywords):
                categories['api'].append(subdomain)
            elif any(keyword in sub_lower for keyword in mail_keywords):
                categories['mail'].append(subdomain)
            elif any(keyword in sub_lower for keyword in cdn_keywords):
                categories['cdn'].append(subdomain)
            elif any(keyword in sub_lower for keyword in vpn_keywords):
                categories['vpn'].append(subdomain)
            else:
                categories['other'].append(subdomain)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def save_results(self, output_path: str):
        """
        Save enumeration results to JSON file.
        
        Args:
            output_path: Path to output file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            logger.info(f"Subdomain results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of enumeration results.
        
        Returns:
            Dictionary containing summary statistics
        """
        if not self.results:
            return {}
        
        summary = {
            'target': self.results.get('target', ''),
            'total_subdomains': self.results.get('total_subdomains', 0),
            'has_wildcard': self.results.get('has_wildcard', False),
            'categories': {}
        }
        
        categorized = self.results.get('categorized', {})
        for category, subdomains in categorized.items():
            summary['categories'][category] = len(subdomains)
        
        return summary
