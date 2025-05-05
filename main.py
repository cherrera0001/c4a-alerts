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
from src.sources.github_advisories import fetch_github_advisories
from src.collector import get_latest_cves, get_latest_pocs
from src.manager import ThreatAlertManager
from src.telegram_bot import TelegramBot
from src.secure_storage import load_sent_ids, save_sent_ids
from tools.sync_to_looker import send_to_looker

# Cargar variables de entorno
load_dotenv()

# Configuración extra para Huggingface Hub
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

CRITICAL_KEYWORDS = [
    "rce", "remote code execution", "bypass", "0day", "zero-day",
    "privesc", "privilege escalation", "exploit", "critical", "crítico",
    "falabella", "sodimac", "tottus", "linio", "banco falabella"
]


def run_alerts() -> None:
    try:
        info("🚀 Iniciando C4A Alerts system...")

        # 1. Cargar historial de IDs enviados
        sent_ids = load_sent_ids()
        if sent_ids:
            info(f"✅ Historial cargado correctamente: {len(sent_ids)} IDs.")
        else:
            warning("⚠️ No se pudo cargar historial anterior o historial vacío. Se considerarán todas las alertas como nuevas.")

        # 2. Inicializar manager y fuentes
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
            "ExploitDB": fetch_exploitdb_alerts,
            "GitHub Advisories": fetch_github_advisories,
            "CSIRT Chile": fetch_csirt_cl_alerts  # ← esta línea nueva
        }


        info("🔎 Consultando todas las fuentes configuradas...")
        for source_name, fetch_func in all_sources.items():
            try:
                alerts = fetch_func(limit=10)
                manager.add_alerts(alerts, source_name)
                info(f"✅ {len(alerts)} alertas obtenidas desde {source_name}")
            except Exception as e:
                warning(f"⚠️ Error consultando {source_name}: {e}")

        # 3. Procesar alertas
        manager.normalize_alerts()
        manager.score_alerts()
        manager.enrich_alerts()

        # 4. Filtrar alertas críticas
        critical_alerts = []
        for alert in manager.normalized_alerts:
            title = alert.get("title", "").lower()
            desc = alert.get("description", "").lower()
            combined_text = f"{title} {desc}"
            if any(word in combined_text for word in CRITICAL_KEYWORDS):
                critical_alerts.append(alert)

        bot = TelegramBot()

        if critical_alerts:
            info(f"🚨 Detectadas {len(critical_alerts)} alertas críticas para envío.")
            for alert in critical_alerts:
                alert_id = alert.get("id") or alert.get("title")
                if not alert_id:
                    warning("⚠️ Alerta sin ID ni título definido, omitida para control de duplicados.")
                    continue

                if alert_id not in sent_ids:
                    try:
                        message = manager.format_telegram_message(alert)
                        if message and bot.send_message(message):
                            sent_ids.add(alert_id)
                            info(f"✅ Alerta crítica enviada: {alert.get('title')}")
                        else:
                            error(f"❌ Fallo al enviar alerta crítica: {alert.get('title')}")
                    except Exception as e:
                        error(f"❌ Error enviando alerta crítica: {e}")
                else:
                    info(f"ℹ️ Alerta ya enviada previamente: {alert.get('title')} — omitida.")
        else:
            info("⚠️ No se encontraron alertas críticas por keywords. Aplicando fallback...")
            manager.process_and_send(min_score=3.0)

        # 5. Guardar historial solo si el proceso fue exitoso
        save_sent_ids(sent_ids)

        # 6. Exportar todo a Looker Studio con alertas completas
        if manager.alerts:
            send_to_looker(manager.alerts)

        info("✅ Ejecución de alertas completada exitosamente.")

    except KeyboardInterrupt:
        warning("⛔ Interrupción manual detectada. No se guardará historial.")
    except Exception as e:
        error(f"❌ Error inesperado durante ejecución de run_alerts: {e}")
    finally:
        info("🏁 Fin de ejecución de C4A Alerts system.")

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
