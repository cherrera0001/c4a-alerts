import os
import logging
from src.manager import ThreatAlertManager

# Configuraciones para minimizar advertencias de librerías
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("c4a-alerts")

def main():
    logger.info("\U0001F680 Starting C4A Alerts system...")

    alert_manager = ThreatAlertManager()

    successful_sources = 0

    # Procesar cada fuente de alertas de manera segura
    if alert_manager.fetch_cve_alerts():
        successful_sources += 1
    if alert_manager.fetch_cert_alerts():
        successful_sources += 1
    if alert_manager.fetch_reddit_alerts():
        successful_sources += 1

    # Validar si al menos una fuente fue exitosa
    if successful_sources == 0:
        logger.error("❌ No se pudo recuperar información de ninguna fuente.")
        alert_manager.notify_critical_error("❌ Todas las fuentes de alertas fallaron.")

    logger.info("✅ Alert processing completed successfully.")

if __name__ == "__main__":
    main()
