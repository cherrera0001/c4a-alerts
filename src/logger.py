import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger

# Configure loguru
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Remove default handler
logger.remove()

# Add console handler with custom format
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level=LOG_LEVEL,
    colorize=True
)

# Add file handler for persistent logs
log_file = os.getenv("LOG_FILE", "logs/c4a-alerts.log")
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logger.add(
    log_file,
    rotation="1 day",
    retention="7 days",
    compression="zip",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level=LOG_LEVEL
)

# Add GitHub Actions annotations for warnings and errors
def add_github_annotation(level: str, message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    """
    Add a GitHub Actions annotation for warnings and errors.
    """
    if os.getenv("GITHUB_ACTIONS") == "true":
        annotation_level = level.upper()
        if annotation_level not in ["WARNING", "ERROR"]:
            return
            
        file_info = f"file={file}" if file else ""
        line_info = f",line={line}" if line else ""
        location = f",{file_info}{line_info}" if file_info or line_info else ""
        
        print(f"::{annotation_level}{location}::{message}")

# Custom log function with structured logging and GitHub annotations
def log(
    level: str,
    message: str,
    extra: Dict[str, Any] = None,
    file: Optional[str] = None,
    line: Optional[int] = None
) -> None:
    """
    Log a message with structured data and GitHub annotations.
    """
    # Create structured log data
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message
    }
    
    if extra:
        log_data.update(extra)
    
    # Log using loguru
    getattr(logger, level.lower())(json.dumps(log_data))
    
    # Add GitHub annotation for warnings and errors
    if level.upper() in ["WARNING", "ERROR"]:
        add_github_annotation(level, message, file, line)

# Convenience functions
def info(message: str, extra: Dict[str, Any] = None) -> None:
    log("INFO", message, extra)

def warning(message: str, extra: Dict[str, Any] = None, file: Optional[str] = None, line: Optional[int] = None) -> None:
    log("WARNING", message, extra, file, line)

def error(message: str, extra: Dict[str, Any] = None, file: Optional[str] = None, line: Optional[int] = None) -> None:
    log("ERROR", message, extra, file, line)

def critical(message: str, extra: Dict[str, Any] = None, file: Optional[str] = None, line: Optional[int] = None) -> None:
    log("CRITICAL", message, extra, file, line)
