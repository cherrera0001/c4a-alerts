import os
import logging
import json
import re
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

class TelegramBot:
    """
    Enhanced Telegram bot with interactive commands.
    """
    
    def __init__(self, token: str = None, chat_id: str = None):
        self.token = token or TELEGRAM_TOKEN
        self.chat_id = chat_id or CHAT_ID
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        
        if not self.token or not self.chat_id:
            logging.error("❌ TELEGRAM_TOKEN or CHAT_ID not configured.")
    
    def send_message(self, text: str, parse_mode: str = "MarkdownV2") -> bool:
        """
        Send a message to the configured chat.
        """
        if not self.token or not self.chat_id:
            return False
            
        url = f"{self.base_url}/sendMessage"
        
        # Escape special characters for MarkdownV2
        if parse_mode == "MarkdownV2":
            text = self._escape_markdown(text)
            
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode
        }
        
        try:
            response = requests.post(url, data=payload, timeout=10)
            result = response.json()
            
            if not result.get("ok"):
                logging.error(f"❌ Telegram rejected the message: {result}")
                return False
                
            logging.info("📬 Message sent successfully to Telegram.")
            return True
            
        except Exception as e:
            logging.error(f"❌ Error sending message: {e}")
            return False
    
    def process_command(self, command: str, args: List[str] = None) -> Optional[str]:
        """
        Process a command and return a response.
        """
        if args is None:
            args = []
            
        if command == "/threats":
            # Get recent threats, optionally filtered by date
            if args and args[0].lower() in ["today", "yesterday", "week"]:
                time_filter = args[0].lower()
                return self._get_recent_threats(time_filter)
            else:
                return self._get_recent_threats("today")
                
        elif command == "/summary" and args:
            # Get summary for a specific CVE
            cve_id = args[0]
            if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
                return self._get_cve_summary(cve_id)
            else:
                return "⚠️ Invalid CVE ID format. Please use the format CVE-YYYY-NNNNN."
                
        elif command == "/source" and args:
            # Get threats from a specific source
            source = args[0].lower()
            return self._get_threats_by_source(source)
            
        elif command == "/help":
            # Show help message
            return self._get_help_message()
            
        else:
            return None
    
    def _get_recent_threats(self, time_filter: str) -> str:
        """
        Get recent threats filtered by time.
        """
        # This would normally query your database or storage
        # For now, return a placeholder message
        return f"🔍 *Recent Threats ({time_filter})*\n\n" + \
               "No threats found for this time period. Try again later."
    
    def _get_cve_summary(self, cve_id: str) -> str:
        """
        Get summary for a specific CVE.
        """
        # This would normally query a CVE database
        # For now, return a placeholder message
        return f"📝 *Summary for {cve_id}*\n\n" + \
               "No information found for this CVE. Try another ID."
    
    def _get_threats_by_source(self, source: str) -> str:
        """
        Get threats from a specific source.
        """
        # This would normally filter threats by source
        # For now, return a placeholder message
        return f"🔍 *Threats from {source}*\n\n" + \
               "No threats found from this source. Try another source."
    
    def _get_help_message(self) -> str:
        """
        Get help message with available commands.
        """
        return "🤖 *C4A Alerts Bot Commands*\n\n" + \
               "/threats [today|yesterday|week] - Get recent threats\n" + \
               "/summary CVE-YYYY-NNNNN - Get summary for a specific CVE\n" + \
               "/source [source_name] - Get threats from a specific source\n" + \
               "/help - Show this help message"
    
    def _escape_markdown(self, text: str) -> str:
        """
        Escape special characters for Telegram's MarkdownV2 format.
        """
        escape_chars = r"_*[]()~`>#+-=|{}.!"
        return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)

# Function to handle webhook updates (for future implementation)
def handle_webhook_update(update_json: Dict[str, Any]) -> Optional[str]:
    """
    Handle a webhook update from Telegram.
    """
    try:
        message = update_json.get("message", {})
        text = message.get("text", "")
        
        if text.startswith("/"):
            # Split command and arguments
            parts = text.split()
            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            bot = TelegramBot()
            response = bot.process_command(command, args)
            
            if response:
                bot.send_message(response)
                
        return "OK"
        
    except Exception as e:
        logging.error(f"❌ Error handling webhook update: {e}")
        return None
