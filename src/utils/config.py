"""
Configuration management for the Attack Surface Recon tool.
Loads API keys and settings from environment variables or config file.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Configuration class for managing API keys and settings."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to JSON config file (optional)
        """
        self.config_file = config_file
        self._load_config()
    
    def _load_config(self):
        """Load configuration from environment or file."""
        # API Keys
        self.google_api_key = os.getenv('GOOGLE_API_KEY', '')
        self.google_cse_id = os.getenv('GOOGLE_CSE_ID', '')
        self.github_token = os.getenv('GITHUB_TOKEN', '')
        
        # Load from file if provided
        if self.config_file and Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
                self.google_api_key = file_config.get('google_api_key', self.google_api_key)
                self.google_cse_id = file_config.get('google_cse_id', self.google_cse_id)
                self.github_token = file_config.get('github_token', self.github_token)
        
        # API Endpoints
        self.google_search_url = "https://www.googleapis.com/customsearch/v1"
        self.github_api_url = "https://api.github.com"
        
        # Rate Limiting
        self.google_rate_limit = 100  # requests per day
        self.github_rate_limit = 5000  # requests per hour
        
        # Timeouts
        self.request_timeout = 30
        self.github_timeout = 45
        
        # Output Settings
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
        # Logging
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    def validate(self) -> bool:
        """
        Validate that required API keys are present.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        if not self.google_api_key:
            print("⚠️  Warning: GOOGLE_API_KEY not set")
            return False
        if not self.google_cse_id:
            print("⚠️  Warning: GOOGLE_CSE_ID not set")
            return False
        if not self.github_token:
            print("⚠️  Warning: GITHUB_TOKEN not set")
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary (excluding sensitive data)."""
        return {
            'google_api_configured': bool(self.google_api_key),
            'github_token_configured': bool(self.github_token),
            'output_dir': str(self.output_dir),
            'log_level': self.log_level
        }


# Google Dorking Patterns
DORK_QUERIES = {
    'admin_panels': [
        'site:{target} inurl:admin',
        'site:{target} inurl:login',
        'site:{target} inurl:dashboard',
        'site:{target} inurl:wp-admin',
        'site:{target} intitle:"Admin Panel"',
    ],
    'exposed_files': [
        'site:{target} filetype:pdf',
        'site:{target} filetype:xls',
        'site:{target} filetype:doc',
        'site:{target} filetype:env',
        'site:{target} filetype:sql',
        'site:{target} filetype:log',
        'site:{target} filetype:bak',
    ],
    'directory_listing': [
        'site:{target} intitle:"index of"',
        'site:{target} intitle:"directory listing"',
    ],
    'config_files': [
        'site:{target} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg',
        'site:{target} inurl:config',
    ],
    'database': [
        'site:{target} ext:sql | ext:dbf | ext:mdb',
        'site:{target} inurl:database',
    ],
    'cloud_exposure': [
        'site:s3.amazonaws.com {target}',
        'site:blob.core.windows.net {target}',
        'site:storage.googleapis.com {target}',
    ],
    'api_endpoints': [
        'site:{target} inurl:api',
        'site:{target} intitle:"api documentation"',
        'site:{target} inurl:/v1/ | inurl:/v2/ | inurl:/api/v1/',
    ],
    'error_messages': [
        'site:{target} intext:"sql syntax near" | intext:"syntax error has occurred"',
        'site:{target} intext:"Warning: mysql_" | intext:"Error: pg_"',
    ]
}

# GitHub Secret Patterns
SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'aws_secret_access_key[\s]*=[\s]*[\'"][0-9a-zA-Z/+]{40}[\'"]',
    'generic_api_key': r'[aA][pP][iI][-_]?[kK][eE][yY][\s]*[:=][\s]*[\'"]?[a-zA-Z0-9_\-]{20,}[\'"]?',
    'generic_secret': r'[sS][eE][cC][rR][eE][tT][\s]*[:=][\s]*[\'"]?[a-zA-Z0-9_\-]{20,}[\'"]?',
    'password': r'[pP][aA][sS][sS][wW][oO][rR][dD][\s]*[:=][\s]*[\'"][^\'"]{8,}[\'"]',
    'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'github_token': r'gh[ps]_[a-zA-Z0-9]{36,}',
    'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}',
    'stripe_key': r'sk_live_[a-zA-Z0-9]{24,}',
    'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
    'heroku_api': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'mailgun_api': r'key-[0-9a-zA-Z]{32}',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'database_url': r'(mysql|postgres|mongodb):\/\/[^\s]+',
}

# Severity Scoring
SEVERITY_WEIGHTS = {
    'admin_panels': 8,
    'exposed_files': 6,
    'config_files': 9,
    'database': 10,
    'api_endpoints': 7,
    'error_messages': 5,
    'cloud_exposure': 9,
    'directory_listing': 4,
    'aws_access_key': 10,
    'private_key': 10,
    'password': 9,
    'database_url': 10,
    'api_key': 8,
}