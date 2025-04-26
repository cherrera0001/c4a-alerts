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

# Disable Hugging Face telemetry and progress bars
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

# Load environment variables
load_dotenv()

def main() -> None:
    info("🚀 Starting C4A Alerts system...")

    manager = ThreatAlertManager()

    # Define alert sources
    sources = {
        "CVE": lambda: get_latest_cves(limit=10),
        "PoC": lambda: get_latest_pocs(limit=10),
        "MITRE ATT&CK": lambda: fetch_mitre_techniques(limit=5),
        "CISA": lambda: fetch_cisa_alerts(limit=5),
        "StepSecurity": lambda: fetch_stepsecurity_posts(limit=3),
        "CERT": lambda: fetch_cert_alerts(limit=10),
        "ThreatFeeds": lambda: fetch_threat_feeds(limit=10),
        "Reddit": lambda: fetch_reddit_posts(limit=5),
        "ExploitDB": lambda: fetch_exploitdb_alerts(limit=5),
    }

    success_sources = 0

    for name, fetch_func in sources.items():
        try:
            alerts = fetch_func()
            if alerts:
                manager.add_alerts(alerts, name)
                success_sources += 1
        except Exception as e:
            error(f"❌ Error fetching alerts from {name}: {e}")

    if success_sources > 0:
        try:
            manager.process_and_send(min_score=5.0)
            info("✅ Alert processing completed successfully.")
        except Exception as e:
            error(f"❌ Failed to process or send alerts: {e}")
    else:
        warning("⚠️ No alerts collected from any source. Skipping processing.")

def handle_command(command: str, args: list = None) -> None:
    if args is None:
        args = []

    bot = TelegramBot()

    if command == "test":
        test_message = "🧪 *Test Message*\n\nThis is a test message from the C4A Alerts system."
        if bot.send_message(test_message):
            info("✅ Test message sent successfully.")
        else:
            error("❌ Failed to send test message.")

    elif command == "help":
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
    if len(sys.argv) > 1:
        command = sys.argv[1]
        args = sys.argv[2:]
        handle_command(command, args)
    else:
        main()
