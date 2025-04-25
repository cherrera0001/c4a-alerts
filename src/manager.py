import logging
import json
import hashlib
from typing import List, Dict, Any, Set
from datetime import datetime
from src.secure_storage import load_sent_ids, save_sent_ids
from src.notifier import send_telegram
from src.nlp_processor import process_alert

class ThreatAlertManager:
    """
    Manages threat alerts from multiple sources, normalizes them,
    removes duplicates, scores criticality, and enriches context.
    """
    
    def __init__(self):
        self.sent_ids = load_sent_ids()
        self.alerts = []
        self.normalized_alerts = []
        
    def add_alerts(self, alerts: List[Dict[str, Any]], source: str) -> None:
        """
        Add alerts from a specific source to the manager.
        """
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
                
            # Ensure source is set
            if "source" not in alert:
                alert["source"] = source
                
            # Add timestamp
            alert["timestamp"] = datetime.now().isoformat()
            
            self.alerts.append(alert)
    
    def normalize_alerts(self) -> None:
        """
        Normalize alerts to a standard format.
        """
        self.normalized_alerts = []
        
        for alert in self.alerts:
            # Generate a unique ID for the alert
            alert_id = self._generate_alert_id(alert)
            
            # Skip if we've already sent this alert
            if alert_id in self.sent_ids:
                logging.info(f"⏭️ Skipping duplicate alert: {alert.get('title', 'Unknown')}")
                continue
                
            # Normalize the alert structure
            normalized = {
                "id": alert_id,
                "title": alert.get("title", ""),
                "description": alert.get("description", alert.get("summary", "")),
                "url": alert.get("url", ""),
                "source": alert.get("source", "Unknown"),
                "timestamp": alert.get("timestamp", datetime.now().isoformat()),
                "raw": alert  # Keep the original data
            }
            
            # Process with NLP if content exists
            if normalized["title"] or normalized["description"]:
                normalized = process_alert(normalized)
                
            self.normalized_alerts.append(normalized)
    
    def score_alerts(self) -> None:
        """
        Score alerts based on criticality factors.
        """
        for alert in self.normalized_alerts:
            score = 0.0
            
            # Base score from classification confidence
            classification = alert.get("classification", {})
            score += classification.get("confidence", 0) * 3
            
            # Score based on attack types
            attack_types = classification.get("attack_types", [])
            high_severity_types = ["Remote Code Execution", "Privilege Escalation", "Authentication Bypass"]
            if any(attack in high_severity_types for attack in attack_types):
                score += 2.0
                
            # Score based on tech stacks
            tech_stacks = classification.get("tech_stacks", [])
            if tech_stacks:
                score += 1.0
                
            # Score based on keywords in title/description
            critical_keywords = ["critical", "severe", "high", "urgent", "emergency", "zero-day", "0day"]
            text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
            if any(keyword in text for keyword in critical_keywords):
                score += 2.0
                
            # CVE specific scoring
            if "CVE-" in alert.get("title", "") or "CVE-" in alert.get("description", ""):
                score += 1.5
                
            # Cap the score at 10
            alert["score"] = min(10.0, score)
    
    def enrich_alerts(self) -> None:
        """
        Enrich alerts with additional context.
        """
        for alert in self.normalized_alerts:
            # Add MITRE ATT&CK reference if applicable
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
        """
        Format an alert for Telegram.
        """
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
            "ExploitDB": "🧨"
        }
        
        # Get emoji for source or default
        emoji = source_emoji.get(alert.get("source", ""), "🔔")
        
        # Format score as stars
        score = alert.get("score", 0)
        stars = "⭐" * min(5, max(1, int(score / 2)))
        
        # Build the message
        message = f"{emoji} *{alert.get('title', 'Alert')}*\n\n"
        
        # Add AI summary if available
        if "ai_summary" in alert:
            message += f"📝 {alert['ai_summary']}\n\n"
        elif alert.get("description"):
            # Truncate description if too long
            desc = alert["description"]
            if len(desc) > 200:
                desc = desc[:197] + "..."
            message += f"📝 {desc}\n\n"
            
        # Add classification info
        classification = alert.get("classification", {})
        attack_types = classification.get("attack_types", [])
        tech_stacks = classification.get("tech_stacks", [])
        
        if attack_types:
            message += f"🔴 *Attack Types:* {', '.join(attack_types)}\n"
            
        if tech_stacks:
            message += f"🔧 *Tech Stack:* {', '.join(tech_stacks)}\n"
            
        # Add MITRE references
        if "mitre_references" in alert:
            message += f"🎯 *MITRE ATT&CK:* {alert['mitre_references'][0]}\n"
            
        # Add severity score
        message += f"📊 *Severity:* {stars} ({score:.1f}/10)\n"
        
        # Add source and URL
        message += f"🔍 *Source:* {alert.get('source', 'Unknown')}\n"
        if alert.get("url"):
            message += f"🔗 {alert['url']}\n"
            
        return message
    
    def process_and_send(self, min_score: float = 3.0) -> None:
        """
        Process all alerts and send them if they meet the minimum score.
        """
        # Normalize, score, and enrich alerts
        self.normalize_alerts()
        self.score_alerts()
        self.enrich_alerts()
        
        # Sort by score (highest first)
        self.normalized_alerts.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        # Track new sent IDs
        new_sent_ids = set()
        
        # Send alerts that meet the minimum score
        for alert in self.normalized_alerts:
            score = alert.get("score", 0)
            if score >= min_score:
                message = self.format_telegram_message(alert)
                send_telegram(message)
                new_sent_ids.add(alert["id"])
                logging.info(f"✅ Sent alert: {alert.get('title', 'Unknown')} (Score: {score:.1f})")
            else:
                logging.info(f"⏭️ Skipping low-score alert: {alert.get('title', 'Unknown')} (Score: {score:.1f})")
        
        # Update sent IDs
        if new_sent_ids:
            self.sent_ids.update(new_sent_ids)
            save_sent_ids(self.sent_ids)
    
    def _generate_alert_id(self, alert: Dict[str, Any]) -> str:
        """
        Generate a unique ID for an alert based on its content.
        """
        # Create a string with the most important fields
        id_string = f"{alert.get('title', '')}{alert.get('url', '')}{alert.get('source', '')}"
        
        # Hash it to create a unique ID
        return hashlib.sha256(id_string.encode()).hexdigest()[:16]
