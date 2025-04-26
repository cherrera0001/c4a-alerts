import logging
import json
import hashlib
from typing import List, Dict, Any, Set
from datetime import datetime
from src.secure_storage import load_sent_ids, save_sent_ids
from src.notifier import send_telegram
from src.nlp_processor import process_alert
from src.threatfeeds import fetch_threat_feeds  # Nueva integración

class ThreatAlertManager:
    def __init__(self):
        self.sent_ids = load_sent_ids()
        self.alerts = []
        self.normalized_alerts = []

    def add_alerts(self, alerts: List[Dict[str, Any]], source: str) -> None:
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            if "source" not in alert:
                alert["source"] = source
            alert["timestamp"] = datetime.now().isoformat()
            self.alerts.append(alert)

    def normalize_alerts(self) -> None:
        self.normalized_alerts = []
        for alert in self.alerts:
            alert_id = self._generate_alert_id(alert)
            if alert_id in self.sent_ids:
                logging.info(f"⏭️ Skipping duplicate alert: {alert.get('title', 'Unknown')}")
                continue
            normalized = {
                "id": alert_id,
                "title": alert.get("title", ""),
                "description": alert.get("description", alert.get("summary", "")),
                "url": alert.get("url", ""),
                "source": alert.get("source", "Unknown"),
                "timestamp": alert.get("timestamp", datetime.now().isoformat()),
                "raw": alert
            }
            if normalized["title"] or normalized["description"]:
                try:
                    normalized = process_alert(normalized)
                except Exception as e:
                    logging.warning(f"⚠️ NLP processing failed: {e}")
            self.normalized_alerts.append(normalized)

    def score_alerts(self) -> None:
        for alert in self.normalized_alerts:
            score = 0.0
            classification = alert.get("classification", {})
            score += classification.get("confidence", 0) * 3
            attack_types = classification.get("attack_types", [])
            high_severity_types = ["Remote Code Execution", "Privilege Escalation", "Authentication Bypass"]
            if any(attack in high_severity_types for attack in attack_types):
                score += 2.0
            tech_stacks = classification.get("tech_stacks", [])
            if tech_stacks:
                score += 1.0
            critical_keywords = ["critical", "severe", "high", "urgent", "emergency", "zero-day", "0day"]
            text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
            if any(keyword in text for keyword in critical_keywords):
                score += 2.0
            if "CVE-" in alert.get("title", "") or "CVE-" in alert.get("description", ""):
                score += 1.5
            alert["score"] = min(10.0, score)

    def enrich_alerts(self) -> None:
        for alert in self.normalized_alerts:
            classification = alert.get("classification", {})
            attack_types = classification.get("attack_types", [])
            if attack_types:
                mitre_references = []
                for attack_type in attack_types:
                    if attack_type == "Remote Code Execution":
                        mitre_references.append("https://attack.mitre.org/techniques/T1190/")
                    elif attack_type == "Privilege Escalation":
                        mitre_references.append("https://attack.mitre.org/tactics/TA0004/")
                    elif attack_type == "Authentication Bypass":
                        mitre_references.append("https://attack.mitre.org/techniques/T1212/")
                if mitre_references:
                    alert["mitre_references"] = mitre_references

    def format_telegram_message(self, alert: Dict[str, Any]) -> str:
        source_emoji = {
            "MITRE ATT&CK": "🎯",
            "CISA": "🏛️",
            "StepSecurity": "🔒",
            "EU-CERT": "🇪🇺",
            "INCIBE-ES": "🇪🇸",
            "JPCERT": "🇯🇵",
            "NCSC-UK": "🇬🇧",
            "ThreatPost": "📰",
            "HackerNews": "💻",
            "BleepingComputer": "🖥️",
            "KrebsOnSecurity": "🔍",
            "DarkReading": "📚",
            "Reddit": "🗣️",
            "ExploitDB": "🧨",
            "PoC": "💣",
            "CVE": "📄"
        }
        emoji = source_emoji.get(alert.get("source", ""), "🔔")
        score = alert.get("score", 0)
        stars = "⭐" * min(5, max(1, int(score / 2)))
        message = f"{emoji} *{alert.get('title', 'Alert')}*\n\n"
        if "ai_summary" in alert:
            message += f"📝 {alert['ai_summary']}\n\n"
        elif alert.get("description"):
            desc = alert["description"]
            if len(desc) > 200:
                desc = desc[:197] + "..."
            message += f"📝 {desc}\n\n"
        classification = alert.get("classification", {})
        attack_types = classification.get("attack_types", [])
        tech_stacks = classification.get("tech_stacks", [])
        if attack_types:
            message += f"🔴 *Attack Types:* {', '.join(attack_types)}\n"
        if tech_stacks:
            message += f"🔧 *Tech Stack:* {', '.join(tech_stacks)}\n"
        if "mitre_references" in alert:
            message += f"🎯 *MITRE ATT&CK:* {alert['mitre_references'][0]}\n"
        message += f"📊 *Severity:* {stars} ({score:.1f}/10)\n"
        message += f"🔍 *Source:* {alert.get("source", "Unknown")}\n"
        if alert.get("url"):
            message += f"🔗 {alert['url']}\n"
        return message

    def process_and_send(self, min_score: float = 3.0) -> None:
        self.normalize_alerts()
        self.score_alerts()
        self.enrich_alerts()
        self.normalized_alerts.sort(key=lambda x: x.get("score", 0), reverse=True)
        new_sent_ids = set()
        for alert in self.normalized_alerts:
            score = alert.get("score", 0)
            try:
                if score >= min_score:
                    message = self.format_telegram_message(alert)
                    send_telegram(message)
                    new_sent_ids.add(alert["id"])
                    logging.info(f"✅ Sent alert: {alert.get('title', 'Unknown')} (Score: {score:.1f})")
                else:
                    logging.info(f"⏭️ Skipping low-score alert: {alert.get('title', 'Unknown')} (Score: {score:.1f})")
            except Exception as e:
                logging.error(f"❌ Failed to send alert: {e}")
        if new_sent_ids:
            self.sent_ids.update(new_sent_ids)
            save_sent_ids(self.sent_ids)

    def _generate_alert_id(self, alert: Dict[str, Any]) -> str:
        id_string = f"{alert.get('title', '')}{alert.get('url', '')}{alert.get('source', '')}"
        return hashlib.sha256(id_string.encode()).hexdigest()[:16]

# Nota importante: Para activar threatfeeds en main.py recuerda usar:
# threatfeeds_data = fetch_threat_feeds(limit=10)
# manager.add_alerts(threatfeeds_data, "ThreatFeeds")
