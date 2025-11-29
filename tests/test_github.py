import unittest
from src.github.leak_scanner import LeakScanner

class TestLeakScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = LeakScanner()

    def test_scan_repositories(self):
        # Test scanning of repositories for sensitive information
        result = self.scanner.scan_repositories(['test_repo'])
        self.assertIsInstance(result, list)
        # Add more assertions based on expected results

    def test_analyze_commits(self):
        # Test analysis of commits for sensitive information
        result = self.scanner.analyze_commits('test_repo')
        self.assertIsInstance(result, dict)
        # Add more assertions based on expected results

if __name__ == '__main__':
    unittest.main()