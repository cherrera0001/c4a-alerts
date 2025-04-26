import os
import sys
import logging
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

# Cargar variables de entorno
load_dotenv()

# Forzar configuración para Huggingface Hub
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

CRITICAL_KEYWORDS = ["rce", "remote code execution", "bypass", "0day", "zero-day", "privesc", "privilege escalation", "exploit", "critical"]

def run_alerts() -> None:
    info("🚀 Starting C4A Alerts system...")

    manager = ThreatAlertManager()

    all_sources = {
        "CVE": get_latest_cves,
        "PoC": get_latest_pocs,
        "MITRE ATT&CK": fetch_mitre_techniques,
        "CISA": fetch_cisa_alerts,
        "StepSecurity": fetch_stepsecurity_posts,
        "CERT": fetch_cert_alerts,
        "ThreatFeeds": fetch_threat_feeds,
        "Reddit": fetch_reddit_posts,
        "ExploitDB": fetch_exploitdb_alerts
    }

    for source_name, fetch_func in all_sources.items():
        try:
            alerts = fetch_func(limit=10)
            manager.add_alerts(alerts, source_name)
            info(f"✅ Fetched {len(alerts)} alerts from {source_name}")
        except Exception as e:
            warning(f"⚠️ Failed fetching {source_name}: {e}")

    # Procesar alertas
    manager.normalize_alerts()
    manager.score_alerts()
    manager.enrich_alerts()

    # Aplicar nueva lógica
    critical_alerts = []
    for alert in manager.normalized_alerts:
        title = alert.get("title", "").lower()
        desc = alert.get("description", "").lower()
        combined_text = f"{title} {desc}"
        if any(word in combined_text for word in CRITICAL_KEYWORDS):
            critical_alerts.append(alert)

    if critical_alerts:
        for alert in critical_alerts:
            try:
                message = manager.format_telegram_message(alert)
                TelegramBot().send_message(message)
                info(f"✅ Critical alert sent: {alert.get('title')}")
            except Exception as e:
                error(f"❌ Failed to send critical alert: {e}")
    else:
        # Fallback: enviar solo alertas normales con score >= 3
        manager.process_and_send(min_score=3.0)

    info("✅ Alert processing completed successfully.")

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
        run_alerts()
