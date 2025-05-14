"""
Central configuration management for C4A Alerts
"""
import os
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Database Configuration
DB_CONFIG = {
    "url": os.getenv("POSTGRES_URL"),
    "prisma_url": os.getenv("POSTGRES_PRISMA_URL"),
    "host": os.getenv("POSTGRES_HOST"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "database": os.getenv("POSTGRES_DATABASE"),
    "non_pooling": os.getenv("POSTGRES_URL_NON_POOLING")
}

# Supabase Configuration
SUPABASE_CONFIG = {
    "url": os.getenv("SUPABASE_URL"),
    "anon_key": os.getenv("SUPABASE_ANON_KEY"),
    "service_role_key": os.getenv("SUPABASE_SERVICE_ROLE_KEY"),
    "jwt_secret": os.getenv("SUPABASE_JWT_SECRET")
}

# Telegram Configuration
TELEGRAM_CONFIG = {
    "token": os.getenv("TELEGRAM_TOKEN"),
    "chat_id": os.getenv("CHAT_ID")
}

# Security Configuration
SECURITY_CONFIG = {
    "encryption_key": os.getenv("ENCRYPTION_KEY"),
    "gist_token": os.getenv("GIST_TOKEN"),
    "gist_id": os.getenv("GIST_ID")
}

# API Configuration
API_CONFIG = {
    "ghsa_token": os.getenv("GHSA_TOKEN"),
    "reddit_client_id": os.getenv("REDDIT_CLIENT_ID"),
    "reddit_client_secret": os.getenv("REDDIT_CLIENT_SECRET"),
    "reddit_user_agent": os.getenv("REDDIT_USER_AGENT")
}

# Feature Flags
FEATURE_FLAGS = {
    "enable_openai": os.getenv("ENABLE_OPENAI", "false").lower() == "true",
    "disable_telemetry": os.getenv("HF_HUB_DISABLE_TELEMETRY", "1") == "1",
    "disable_progress_bars": os.getenv("HF_HUB_DISABLE_PROGRESS_BARS", "1") == "1"
}

def validate_config() -> Dict[str, Any]:
    """
    Validates that all required environment variables are set
    """
    missing_vars = []
    
    # Check critical configurations
    if not TELEGRAM_CONFIG["token"]:
        missing_vars.append("TELEGRAM_TOKEN")
    if not TELEGRAM_CONFIG["chat_id"]:
        missing_vars.append("CHAT_ID")
    if not SECURITY_CONFIG["encryption_key"]:
        missing_vars.append("ENCRYPTION_KEY")
    
    return {
        "is_valid": len(missing_vars) == 0,
        "missing_variables": missing_vars
    }