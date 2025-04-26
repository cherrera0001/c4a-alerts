import os
import logging
from src.manager import ThreatAlertManager

# Configuraciones para minimizar advertencias de librerías
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("c4a-alerts")

def main():
    logger.info("🚀 Starting C4A Alerts system...")

    alert_manager = ThreatAlertManager()
    successful_sources = 0

    sources = {
        "CVE": alert_manager.fetch_cve_alerts,
        "CERT": alert_manager.fetch_cert_alerts,
        "Reddit": alert_manager.fetch_reddit_alerts,
    }

    for source_name, fetch_function in sources.items():
        try:
            if fetch_function():
                successful_sources += 1
                logger.info(f"✅ {source_name} alerts fetched successfully.")
            else:
                logger.warning(f"⚠️ {source_name} returned no alerts.")
        except Exception as e:
            logger.error(f"❌ Error fetching {source_name} alerts: {e}")

    if successful_sources == 0:
        logger.critical("❌ No alerts retrieved from any source. Sending critical error notification...")
        alert_manager.notify_critical_error("❌ Todas las fuentes de alertas fallaron.")
    else:
        logger.info(f"✅ Successfully processed alerts from {successful_sources} sources.")

if __name__ == "__main__":
    main()
