"""
GitHub API scanner for detecting secrets and sensitive information leaks.
Scans public repositories, commits, and code for exposed credentials.
"""

import requests
import re
import logging
import time
from typing import List, Dict, Any
from datetime import datetime
import json
import base64

logger = logging.getLogger(__name__)


class LeakScanner:
    """GitHub repository and commit scanner for secret detection."""
    
    def __init__(self, config):
        """
        Initialize GitHub leak scanner.
        
        Args:
            config: Configuration object containing GitHub token
        """
        self.token = config.github_token
        self.base_url = config.github_api_url
        self.timeout = config.github_timeout
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.results = []
        self.rate_limit_delay = 0.5
    
    def search_repositories(self, query: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search GitHub repositories.
        
        Args:
            query: Search query (e.g., organization name, domain)
            max_results: Maximum number of repositories to return
            
        Returns:
            List of repository dictionaries
        """
        repos = []
        page = 1
        per_page = 30
        
        try:
            while len(repos) < max_results:
                url = f"{self.base_url}/search/repositories"
                params = {
                    'q': query,
                    'page': page,
                    'per_page': per_page,
                    'sort': 'updated'
                }
                
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        break
                    
                    repos.extend(items)
                    page += 1
                    
                    time.sleep(self.rate_limit_delay)
                elif response.status_code == 403:
                    logger.warning("Rate limit exceeded. Waiting...")
                    time.sleep(60)
                else:
                    logger.error(f"Repository search failed: {response.status_code}")
                    break
                    
        except Exception as e:
            logger.error(f"Error searching repositories: {str(e)}")
        
        return repos[:max_results]
    
    def search_code(self, query: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search GitHub code content.
        
        Args:
            query: Code search query
            max_results: Maximum results to return
            
        Returns:
            List of code match dictionaries
        """
        results = []
        page = 1
        
        try:
            while len(results) < max_results:
                url = f"{self.base_url}/search/code"
                params = {
                    'q': query,
                    'page': page,
                    'per_page': 30
                }
                
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        break
                    
                    results.extend(items)
                    page += 1
                    
                    time.sleep(self.rate_limit_delay)
                elif response.status_code == 403:
                    logger.warning("Rate limit exceeded. Waiting...")
                    time.sleep(60)
                else:
                    logger.error(f"Code search failed: {response.status_code}")
                    break
                    
        except Exception as e:
            logger.error(f"Error searching code: {str(e)}")
        
        return results[:max_results]
    
    def scan_repositories(self, target: str, search_queries: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive repository scanning for a target.
        
        Args:
            target: Target organization or domain
            search_queries: Custom search queries (optional)
            
        Returns:
            Dictionary containing all leak findings
        """
        all_findings = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'repositories': [],
            'code_leaks': [],
            'commit_leaks': []
        }
        
        logger.info(f"Starting GitHub scan for target: {target}")
        
        # Search for repositories
        repo_query = f"{target} in:name,description"
        repos = self.search_repositories(repo_query, max_results=50)
        logger.info(f"Found {len(repos)} repositories")
        
        # Scan each repository
        for repo in repos[:10]:  # Limit to prevent rate limiting
            repo_data = self.scan_repository(repo)
            if repo_data:
                all_findings['repositories'].append(repo_data)
        
        # Search code for secrets
        from src.utils.config import SECRET_PATTERNS
        
        # Enhanced search queries with better targeting
        secret_queries = [
            f'"{target}" password language:java',
            f'"{target}" password language:python',
            f'"{target}" api_key OR apikey',
            f'"{target}" secret OR SECRET_KEY',
            f'"{target}" token OR access_token',
            f'"{target}" credentials extension:env',
            f'"{target}" extension:properties',
            f'"{target}" smtp password',
            f'@{target} password'
        ]
        
        for query in secret_queries:
            logger.info(f"Searching code: {query}")
            code_results = self.search_code(query, max_results=15)
            
            for result in code_results:
                # Filter for relevance to target domain
                leak = self.analyze_code_content(result, target)
                if leak and self.is_relevant_to_target(leak, target):
                    all_findings['code_leaks'].append(leak)
        
        self.results = all_findings
        return all_findings
    
    def scan_repository(self, repo: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan a single repository for sensitive information.
        
        Args:
            repo: Repository data from GitHub API
            
        Returns:
            Dictionary containing repository scan results
        """
        repo_data = {
            'name': repo.get('full_name', ''),
            'url': repo.get('html_url', ''),
            'description': repo.get('description', ''),
            'private': repo.get('private', False),
            'updated_at': repo.get('updated_at', ''),
            'findings': []
        }
        
        # Check repository description for secrets
        desc = repo.get('description', '') or ''
        secrets_in_desc = self.detect_secrets(desc)
        if secrets_in_desc:
            repo_data['findings'].extend(secrets_in_desc)
        
        # Scan recent commits
        commits_url = repo.get('commits_url', '').replace('{/sha}', '')
        if commits_url:
            commits = self.get_recent_commits(commits_url, limit=10)
            for commit in commits:
                commit_findings = self.analyze_commit(commit)
                if commit_findings:
                    repo_data['findings'].extend(commit_findings)
        
        return repo_data if repo_data['findings'] else None
    
    def get_recent_commits(self, commits_url: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent commits from a repository.
        
        Args:
            commits_url: URL to fetch commits
            limit: Maximum number of commits to retrieve
            
        Returns:
            List of commit dictionaries
        """
        try:
            response = requests.get(
                commits_url,
                headers=self.headers,
                params={'per_page': limit},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.debug(f"Failed to fetch commits: {response.status_code}")
                
        except Exception as e:
            logger.debug(f"Error fetching commits: {str(e)}")
        
        return []
    
    def analyze_commit(self, commit: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a commit for sensitive information.
        
        Args:
            commit: Commit data from GitHub API
            
        Returns:
            List of findings from this commit
        """
        findings = []
        
        commit_message = commit.get('commit', {}).get('message', '')
        commit_sha = commit.get('sha', '')
        commit_url = commit.get('html_url', '')
        author = commit.get('commit', {}).get('author', {}).get('name', 'Unknown')
        
        # Check commit message for secrets
        secrets = self.detect_secrets(commit_message)
        for secret in secrets:
            findings.append({
                'type': 'commit_message',
                'secret_type': secret['type'],
                'commit_sha': commit_sha,
                'commit_url': commit_url,
                'author': author,
                'message_preview': commit_message[:100],
                'matched_pattern': secret['match'],
                'severity': self.classify_secret_severity(secret['type']),
                'timestamp': commit.get('commit', {}).get('author', {}).get('date', '')
            })
        
        return findings
    
    def analyze_code_content(self, code_result: Dict[str, Any], target_domain: str = None) -> Dict[str, Any]:
        """
        Analyze code search result for secrets with improved accuracy.
        
        Args:
            code_result: Code search result from GitHub API
            target_domain: Target domain for relevance filtering
            
        Returns:
            Finding dictionary if secrets detected, None otherwise
        """
        repo_name = code_result.get('repository', {}).get('full_name', '')
        file_path = code_result.get('path', '')
        file_url = code_result.get('html_url', '')
        
        # Fetch file content
        content_url = code_result.get('url', '')
        try:
            response = requests.get(
                content_url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                content = base64.b64decode(data.get('content', '')).decode('utf-8', errors='ignore')
                
                # Check if target domain is actually referenced in the content
                if target_domain:
                    domain_variations = [target_domain, target_domain.replace('.', '_'), target_domain.replace('.', '-')]
                    if not any(var.lower() in content.lower() for var in domain_variations):
                        return None  # Not relevant to target
                
                # Detect secrets with context validation
                secrets = self.detect_secrets_with_context(content)
                
                # Filter out false positives
                secrets = self.filter_false_positives(secrets, content, file_path)
                
                if secrets:
                    return {
                        'type': 'code_file',
                        'repository': repo_name,
                        'file_path': file_path,
                        'file_url': file_url,
                        'secrets': secrets,
                        'severity': max([self.classify_secret_severity(s['type']) for s in secrets], key=lambda x: ['low', 'medium', 'high', 'critical'].index(x)),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
        except Exception as e:
            logger.debug(f"Error analyzing code content: {str(e)}")
        
        return None
    
    def is_relevant_to_target(self, leak: Dict[str, Any], target: str) -> bool:
        """
        Check if a leak is actually relevant to the target organization.
        
        Args:
            leak: Leak dictionary
            target: Target domain
            
        Returns:
            True if relevant, False otherwise
        """
        repo = leak.get('repository', '').lower()
        file_path = leak.get('file_path', '').lower()
        
        # Check if repository name contains target
        if target.replace('.com', '') in repo or target.replace('.', '') in repo:
            return True
        
        # Check file path relevance
        if target in file_path:
            return True
        
        # Check if it's a real project file (not docs/examples)
        non_relevant_paths = ['example', 'sample', 'test', 'demo', 'readme', 'doc', 'tutorial']
        if any(keyword in file_path for keyword in non_relevant_paths):
            return False
        
        return True
    
    def detect_secrets(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect secrets in text content using regex patterns.
        
        Args:
            content: Text content to scan
            
        Returns:
            List of detected secret dictionaries
        """
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from utils.config import SECRET_PATTERNS
        
        secrets = []
        
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secrets.append({
                    'type': secret_type,
                    'match': match.group(0)[:50],  # Truncate for safety
                    'position': match.start()
                })
        
        return secrets
    
    def detect_secrets_with_context(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect secrets in text content using regex patterns (alias for backward compatibility).
        
        Args:
            content: Text content to scan
            
        Returns:
            List of detected secret dictionaries
        """
        return self.detect_secrets(content)
    
    def classify_secret_severity(self, secret_type: str) -> str:
        """
        Classify severity of detected secret.
        
        Args:
            secret_type: Type of secret detected
            
        Returns:
            Severity level: critical, high, medium, low
        """
        critical_types = ['aws_access_key', 'aws_secret_key', 'private_key', 'database_url']
        high_types = ['github_token', 'stripe_key', 'password', 'google_api']
        medium_types = ['generic_api_key', 'slack_token', 'jwt_token']
        
        if secret_type in critical_types:
            return 'critical'
        elif secret_type in high_types:
            return 'high'
        elif secret_type in medium_types:
            return 'medium'
        else:
            return 'low'
    
    def save_results(self, output_path: str):
        """
        Save scan results to JSON file.
        
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
        Get summary statistics of scan results.
        
        Returns:
            Dictionary containing summary statistics
        """
        if not self.results:
            return {}
        
        summary = {
            'target': self.results.get('target', ''),
            'timestamp': self.results.get('timestamp', ''),
            'repositories_scanned': len(self.results.get('repositories', [])),
            'total_leaks': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {}
        }
        
        # Count findings
        for repo in self.results.get('repositories', []):
            for finding in repo.get('findings', []):
                summary['total_leaks'] += 1
                severity = finding.get('severity', 'low')
                summary['by_severity'][severity] += 1
                
                secret_type = finding.get('secret_type', 'unknown')
                summary['by_type'][secret_type] = summary['by_type'].get(secret_type, 0) + 1
        
        for leak in self.results.get('code_leaks', []):
            summary['total_leaks'] += len(leak.get('secrets', []))
            severity = leak.get('severity', 'low')
            summary['by_severity'][severity] += 1
        
        return summary