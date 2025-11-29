"""
Google Custom Search API module for OSINT reconnaissance.
Performs intelligent Google dorking and classifies findings by severity.
"""

import requests
import time
import logging
from typing import List, Dict, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class GoogleDorking:
    """Google Custom Search API reconnaissance engine."""
    
    def __init__(self, config):
        """
        Initialize Google Dorking module.
        
        Args:
            config: Configuration object containing API keys
        """
        self.api_key = config.google_api_key
        self.cse_id = config.google_cse_id
        self.base_url = config.google_search_url
        self.timeout = config.request_timeout
        self.results = []
        self.rate_limit_delay = 2  # seconds between requests (increased from 1)
    
    def search(self, query: str, num_results: int = 10) -> List[Dict[str, Any]]:
        """
        Perform a Google Custom Search query.
        
        Args:
            query: Search query string
            num_results: Number of results to retrieve
            
        Returns:
            List of search result dictionaries
        """
        results = []
        start_index = 1
        
        try:
            while len(results) < num_results:
                params = {
                    'key': self.api_key,
                    'cx': self.cse_id,
                    'q': query,
                    'start': start_index,
                    'num': min(10, num_results - len(results))
                }
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        break
                    
                    results.extend(items)
                    start_index += 10
                    
                    # Rate limiting
                    time.sleep(self.rate_limit_delay)
                    
                elif response.status_code == 429 or response.status_code == 403:
                    logger.warning(f"Rate limit exceeded (HTTP {response.status_code}). Skipping remaining results for this query.")
                    break  # Skip to next query instead of waiting
                else:
                    logger.error(f"Search failed: {response.status_code} - {response.text}")
                    break
                    
        except Exception as e:
            logger.error(f"Error during search: {str(e)}")
        
        return results[:num_results]
    
    def perform_dorking(self, target: str, categories: List[str] = None, exclude_social: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive Google dorking on target with improved filtering.
        
        Args:
            target: Target domain or organization
            categories: List of dork categories to run (default: all)
            exclude_social: Exclude social media results (default: True)
            
        Returns:
            Dictionary containing categorized results
        """
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from utils.config import DORK_QUERIES
        
        if categories is None:
            categories = DORK_QUERIES.keys()
        
        all_results = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'categories': {}
        }
        
        logger.info(f"Starting Google dorking for target: {target}")
        
        for category in categories:
            if category not in DORK_QUERIES:
                logger.warning(f"Unknown category: {category}")
                continue
            
            category_results = []
            queries = DORK_QUERIES[category]
            
            logger.info(f"Running {len(queries)} queries for category: {category}")
            
            for query_template in queries:
                query = query_template.format(target=target)
                
                # Add exclusions for social media if enabled
                if exclude_social:
                    query += ' -site:facebook.com -site:twitter.com -site:linkedin.com -site:instagram.com'
                
                logger.debug(f"Executing query: {query}")
                
                search_results = self.search(query, num_results=10)
                
                for result in search_results:
                    normalized = self.normalize_result(result, category, query)
                    
                    # Filter out irrelevant results
                    if self.is_relevant_result(normalized, target):
                        category_results.append(normalized)
            
            # Remove duplicates based on URL
            seen_urls = set()
            unique_results = []
            for result in category_results:
                url = result['url']
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_results.append(result)
            
            all_results['categories'][category] = unique_results
            logger.info(f"Found {len(unique_results)} unique results for {category}")
        
        # Store results
        self.results = all_results
        return all_results
        
        # Store results
        self.results = all_results
        return all_results
    
    def normalize_result(self, result: Dict[str, Any], category: str, query: str) -> Dict[str, Any]:
        """
        Normalize and enrich search result.
        
        Args:
            result: Raw search result from API
            category: Category of the dork query
            query: Original query that produced this result
            
        Returns:
            Normalized result dictionary
        """
        normalized = {
            'title': result.get('title', ''),
            'url': result.get('link', ''),
            'snippet': result.get('snippet', ''),
            'display_url': result.get('displayLink', ''),
            'category': category,
            'query': query,
            'severity': self.classify_severity(category, result),
            'risk_indicators': self.extract_risk_indicators(result),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return normalized
    
    def is_relevant_result(self, result: Dict[str, Any], target: str) -> bool:
        """
        Check if search result is actually relevant to the target.
        
        Args:
            result: Normalized search result
            target: Target domain
            
        Returns:
            True if relevant, False otherwise
        """
        url = result['url'].lower()
        title = result['title'].lower()
        snippet = result['snippet'].lower()
        
        # Must contain target domain in some form
        target_base = target.split('.')[0] if '.' in target else target
        
        # Direct domain match
        if target in url:
            return True
        
        # Check if it's actually about the target (not just mentioning it)
        if target_base in url or target_base in title:
            return True
        
        # Exclude obvious false positives
        false_positive_domains = ['facebook.com/public', 'linkedin.com', 'twitter.com', 'instagram.com']
        if any(fp in url for fp in false_positive_domains):
            return False
        
        return True
    
    def classify_severity(self, category: str, result: Dict[str, Any]) -> str:
        """
        Classify severity of finding based on category and content.
        
        Args:
            category: Category of the finding
            result: Search result data
            
        Returns:
            Severity level: critical, high, medium, low
        """
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from utils.config import SEVERITY_WEIGHTS
        
        weight = SEVERITY_WEIGHTS.get(category, 5)
        
        # Check for critical keywords in snippet
        snippet = result.get('snippet', '').lower()
        title = result.get('title', '').lower()
        
        critical_keywords = ['password', 'credential', 'api key', 'secret', 'token', 'private key']
        high_keywords = ['admin', 'database', 'config', 'backup', 'sql']
        
        if any(kw in snippet or kw in title for kw in critical_keywords):
            weight += 2
        elif any(kw in snippet or kw in title for kw in high_keywords):
            weight += 1
        
        # Severity mapping
        if weight >= 9:
            return 'critical'
        elif weight >= 7:
            return 'high'
        elif weight >= 5:
            return 'medium'
        else:
            return 'low'
    
    def extract_risk_indicators(self, result: Dict[str, Any]) -> List[str]:
        """
        Extract risk indicators from result content.
        
        Args:
            result: Search result data
            
        Returns:
            List of risk indicator strings
        """
        indicators = []
        snippet = result.get('snippet', '').lower()
        title = result.get('title', '').lower()
        url = result.get('link', '').lower()
        
        # Check for various risk indicators
        if 'admin' in url or 'admin' in title:
            indicators.append('admin_interface')
        
        if 'login' in url or 'login' in title:
            indicators.append('login_page')
        
        if any(ext in url for ext in ['.env', '.sql', '.bak', '.log']):
            indicators.append('sensitive_file_extension')
        
        if 'password' in snippet or 'credential' in snippet:
            indicators.append('credential_mention')
        
        if 'api' in url:
            indicators.append('api_endpoint')
        
        if 's3.amazonaws.com' in url or 'storage.googleapis.com' in url:
            indicators.append('cloud_storage')
        
        return indicators
    
    def save_results(self, output_path: str):
        """
        Save results to JSON file.
        
        Args:
            output_path: Path to output file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of reconnaissance results.
        
        Returns:
            Dictionary containing summary statistics
        """
        if not self.results:
            return {}
        
        summary = {
            'target': self.results.get('target', ''),
            'timestamp': self.results.get('timestamp', ''),
            'total_findings': 0,
            'by_category': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        for category, findings in self.results.get('categories', {}).items():
            summary['by_category'][category] = len(findings)
            summary['total_findings'] += len(findings)
            
            for finding in findings:
                severity = finding.get('severity', 'low')
                summary['by_severity'][severity] += 1
        
        return summary