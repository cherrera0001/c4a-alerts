import os
import sys
from dotenv import load_dotenv
from src.logger import logger, info, warning, error
from src.sources.mitre import fetch_mitre_techniques
from src.sources.cisa import fetch_cisa_alerts
from src.sources.stepsecurity import fetch_stepsecurity_posts
from src.sources.cert import fetch_cert_alerts
from src.sources.threatfeeds import fetch_threat_feeds
from src.sources.reddit import fetch_reddit_posts
from src.sources.exploitdb import fetch_exploitdb_alerts
from src.collector import get_latest_cves, get_latest_pocs
from src.manager import ThreatAlertManager
from src.telegram_bot import TelegramBot

# Load environment variables
load_dotenv()

def run_alerts() -> None:
    """
    Main function to fetch, process, and send alerts.
    """
    info("🚀 Starting C4A Alerts system...")
    
    # Initialize the alert manager
    manager = ThreatAlertManager()
    
    # Fetch alerts from all sources
    try:
        # Core sources (CVEs and PoCs)
        cve_data = get_latest_cves(limit=10)
        poc_data = get_latest_pocs(limit=10)
        
        # New sources
        mitre_data = fetch_mitre_techniques(limit=5)
        cisa_data = fetch_cisa_alerts(limit=5)
        stepsecurity_data = fetch_stepsecurity_posts(limit=3)
        cert_data = fetch_cert_alerts(limit=10)
        threatfeeds_data = fetch_threat_feeds(limit=10)
        reddit_data = fetch_reddit_posts(limit=5)
        exploitdb_data = fetch_exploitdb_alerts(limit=5)
        
        # Add all alerts to the manager
        manager.add_alerts(cve_data, "CVE")
        manager.add_alerts(poc_data, "PoC")
        manager.add_alerts(mitre_data, "MITRE ATT&CK")
        manager.add_alerts(cisa_data, "CISA")
        manager.add_alerts(stepsecurity_data, "StepSecurity")
        manager.add_alerts(cert_data, "CERT")
        manager.add_alerts(threatfeeds_data, "ThreatFeeds")
        manager.add_alerts(reddit_data, "Reddit")
        manager.add_alerts(exploitdb_data, "ExploitDB")
        
        # Process and send alerts
        manager.process_and_send(min_score=5.0)
        
        info("✅ Alert processing completed successfully.")
        
    except Exception as e:
        error(f"❌ Error in alert processing: {e}")
        sys.exit(1)

def handle_command(command: str, args: list = None) -> None:
    """
    Handle a command-line command.
    """
    if args is None:
        args = []
        
    bot = TelegramBot()
    
    if command == "test":
        # Send a test message
        test_message = "🧪 *Test Message*\n\nThis is a test message from the C4A Alerts system."
        if bot.send_message(test_message):
            info("✅ Test message sent successfully.")
        else:
            error("❌ Failed to send test message.")
            
    elif command == "help":
        # Show help message
        print("C4A Alerts - Command Line Interface")
        print("-----------------------------------")
        print("Available commands:")
        print("  run       - Run the alert system")
        print("  test      - Send a test message to Telegram")
        print("  help      - Show this help message")
        
    else:
        print(f"Unknown command: {command}")
        print("Use 'help' to see available commands.")

if __name__ == "__main__":
    # Check for command-line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        args = sys.argv[2:]
        handle_command(command, args)
    else:
        # Default: run alerts
        run_alerts()
