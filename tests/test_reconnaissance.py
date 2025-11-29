import unittest
from src.reconnaissance.google_dorking import GoogleDorking

class TestGoogleDorking(unittest.TestCase):

    def setUp(self):
        self.dorking = GoogleDorking()

    def test_perform_dorking(self):
        query = "site:example.com"
        results = self.dorking.perform_dorking(query)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_normalize_results(self):
        raw_results = [
            {"title": "Example Title", "link": "http://example.com"},
            {"title": "Another Title", "link": "http://another.com"}
        ]
        normalized = self.dorking.normalize_results(raw_results)
        self.assertIsInstance(normalized, list)
        self.assertEqual(len(normalized), 2)
        self.assertIn("title", normalized[0])
        self.assertIn("link", normalized[0])

if __name__ == '__main__':
    unittest.main()