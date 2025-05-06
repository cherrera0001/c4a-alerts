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
from src.sources.csirtcl import fetch_csirt_cl_alerts
from src.collector import get_latest_cves, get_latest_pocs
from src.manager import ThreatAlertManager
from src.telegram_bot import TelegramBot
from src.secure_storage import load_sent_ids, save_sent_ids
from tools.sync_to_looker import send_to_looker

# Cargar variables de entorno
load_dotenv()

# HuggingFace configuración silenciosa
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

        sent_ids = load_sent_ids()
        info(f"✅ Historial cargado correctamente: {len(sent_ids)} IDs.")

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
            "CSIRT Chile": fetch_csirt_cl_alerts
        }

        info("🔎 Consultando todas las fuentes configuradas...")
        for source_name, fetch_func in all_sources.items():
            try:
                alerts = fetch_func(limit=15)
                manager.add_alerts(alerts, source_name)
                info(f"✅ {len(alerts)} alertas obtenidas desde {source_name}")
            except Exception as e:
                warning(f"⚠️ Error al consultar {source_name}: {e}")

        manager.normalize_alerts()
        manager.score_alerts()
        manager.enrich_alerts()

        critical_alerts = []
        for alert in manager.normalized_alerts:
            title = alert.get("title", "").lower()
            desc = alert.get("description", "").lower()
            if any(keyword in f"{title} {desc}" for keyword in CRITICAL_KEYWORDS):
                critical_alerts.append(alert)

        bot = TelegramBot()
        sent_counter = 0

        if critical_alerts:
            info(f"🚨 {len(critical_alerts)} alertas críticas detectadas.")
            for alert in critical_alerts:
                alert_id = alert.get("id") or alert.get("title")
                if not alert_id:
                    warning("⚠️ Alerta sin ID. Omitida.")
                    continue
                if alert_id not in sent_ids:
                    try:
                        message = manager.format_telegram_message(alert)
                        if message and bot.send_message(message):
                            sent_ids.add(alert_id)
                            sent_counter += 1
                            info(f"✅ Enviada: {alert.get('title')}")
                        else:
                            error(f"❌ No se envió: {alert.get('title')}")
                    except Exception as e:
                        error(f"❌ Error enviando alerta: {e}")
                else:
                    info(f"🔁 Ya enviada: {alert.get('title')}")
        else:
            warning("⚠️ No se detectaron alertas críticas. Aplicando fallback...")
            manager.process_and_send(min_score=3.0)

        save_sent_ids(sent_ids)

        if manager.alerts:
            send_to_looker(manager.alerts)

        info(f"📤 Envío completado. Total nuevas enviadas: {sent_counter}")
        info("✅ Sistema finalizado correctamente.")

    except KeyboardInterrupt:
        warning("⛔ Interrupción manual. Historial no guardado.")
    except Exception as e:
        error(f"❌ Error inesperado: {e}")
    finally:
        info("🏁 Fin del proceso de C4A Alerts.")

def handle_command(command: str, args: list = None) -> None:
    if args is None:
        args = []

    bot = TelegramBot()

    if command == "test":
        msg = "🧪 *Mensaje de prueba*\nEste es un test del sistema C4A Alerts."
        if bot.send_message(msg):
            info("✅ Mensaje de prueba enviado.")
        else:
            error("❌ No se envió mensaje de prueba.")
    elif command == "help":
        print("C4A Alerts CLI - Comandos disponibles:")
        print("  run       - Ejecuta el sistema completo")
        print("  test      - Envía un mensaje de prueba a Telegram")
        print("  help      - Muestra esta ayuda")
    else:
        print(f"Comando desconocido: {command}\nUsa 'help' para opciones.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        args = sys.argv[2:]
        handle_command(command, args)
    else:
        run_alerts()
