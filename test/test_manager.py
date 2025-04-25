import unittest
import os
import sys
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.manager import ThreatAlertManager

class TestThreatAlertManager(unittest.TestCase):
    """
    Test cases for the ThreatAlertManager class.
    """
    
    def setUp(self):
        """
        Set up test fixtures.
        """
        self.manager = ThreatAlertManager()
        
        # Sample alerts for testing
        self.sample_alerts = [
            {
                "title": "Critical Remote Code Execution in Apache Struts",
                "description": "A critical vulnerability allows remote attackers to execute arbitrary code via crafted HTTP requests.",
                "url": "https://example.com/cve-2023-1234",
                "source": "CVE"
            },
            {
                "title": "SQL Injection in WordPress Plugin",
                "description": "A SQL injection vulnerability in the XYZ WordPress plugin allows attackers to access sensitive data.",
                "url": "https://example.com/cve-2023-5678",
                "source": "CVE"
            },
            {
                "title": "Duplicate Alert",
                "description": "This is a duplicate alert that should be filtered out.",
                "url": "https://example.com/duplicate",
                "source": "Test"
            },
            {
                "title": "Duplicate Alert",
                "description": "This is a duplicate alert that should be filtered out.",
                "url": "https://example.com/duplicate",
                "source": "Test"
            }
        ]
    
    def test_add_alerts(self):
        """
        Test adding alerts to the manager.
        """
        self.manager.add_alerts(self.sample_alerts, "Test")
        self.assertEqual(len(self.manager.alerts), 4)
        
        # Check that timestamp was added
        for alert in self.manager.alerts:
            self.assertIn("timestamp", alert)
            
        # Check that source was set
        for alert in self.manager.alerts:
            self.assertEqual(alert["source"], "Test")
    
    def test_normalize_alerts(self):
        """
        Test normalizing alerts.
        """
        self.manager.add_alerts(self.sample_alerts, "Test")
        self.manager.normalize_alerts()
        
        # Should have 3 normalized alerts (one duplicate filtered out)
        self.assertEqual(len(self.manager.normalized_alerts), 3)
        
        # Check normalized structure
        for alert in self.manager.normalized_alerts:
            self.assertIn("id", alert)
            self.assertIn("title", alert)
            self.assertIn("description", alert)
            self.assertIn("url", alert)
            self.assertIn("source", alert)
            self.assertIn("timestamp", alert)
            self.assertIn("raw", alert)
    
    def test_score_alerts(self):
        """
        Test scoring alerts.
        """
        self.manager.add_alerts(self.sample_alerts, "Test")
        self.manager.normalize_alerts()
        self.manager.score_alerts()
        
        # Check that all alerts have a score
        for alert in self.manager.normalized_alerts:
            self.assertIn("score", alert)
            self.assertIsInstance(alert["score"], float)
            
        # RCE alert should have a higher score than SQL injection
        rce_alert = next((a for a in self.manager.normalized_alerts if "Remote Code Execution" in a["title"]), None)
        sql_alert = next((a for a in self.manager.normalized_alerts if "SQL Injection" in a["title"]), None)
        
        if rce_alert and sql_alert:
            self.assertGreater(rce_alert["score"], sql_alert["score"])
    
    def test_format_telegram_message(self):
        """
        Test formatting alerts for Telegram.
        """
        alert = {
            "title": "Test Alert",
            "description": "This is a test alert.",
            "url": "https://example.com/test",
            "source": "Test",
            "score": 7.5,
            "classification": {
                "attack_types": ["Remote Code Execution"],
                "tech_stacks": ["Apache"],
                "confidence": 0.8
            }
        }
        
        message = self.manager.format_telegram_message(alert)
        
        # Check that the message contains key elements
        self.assertIn("Test Alert", message)
        self.assertIn("This is a test alert", message)
        self.assertIn("Remote Code Execution", message)
        self.assertIn("Apache", message)
        self.assertIn("https://example.com/test", message)
        self.assertIn("Test", message)
        
        # Check for severity stars
        self.assertIn("⭐⭐⭐", message)

if __name__ == "__main__":
    unittest.main()
