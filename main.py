import os
import sys
import asyncio
import logging
from typing import Optional, List

# Set up environment before other imports
from dotenv import load_dotenv
load_dotenv()

# Configure HuggingFace to be silent
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

# Core imports
from src.core.orchestrator import (
    ThreatIntelligenceOrchestrator, 
    OrchestrationConfig,
    PipelineMode,
    create_orchestrator,
    create_test_orchestrator
)
from src.logger import logger, info, warning, error

# Version info
__version__ = "4.0.0"
__author__ = "C4A Team"


async def run_alerts() -> None:
    """Main alert processing function."""
    try:
        info(f"🚀 Starting C4A Alerts v{__version__}")
        
        # Create and run orchestrator
        orchestrator = create_orchestrator(PipelineMode.PRODUCTION)
        result = await orchestrator.execute_pipeline()
        
        # Log results
        if result.success:
            info(f"✅ Pipeline completed successfully:")
            info(f"  📊 Collected: {result.alerts_collected} alerts")
            info(f"  ⚙️ Processed: {result.alerts_processed} alerts") 
            info(f"  📤 Sent: {result.alerts_sent} notifications")
            info(f"  🚨 Critical: {result.critical_alerts_count} alerts")
            info(f"  ⏱️ Duration: {result.execution_time_seconds:.1f}s")
        else:
            error(f"❌ Pipeline failed:")
            for err in result.errors:
                error(f"  - {err}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        warning("⛔ Pipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        error(f"💥 Unexpected error: {e}")
        sys.exit(1)


async def test_pipeline() -> None:
    """Test the pipeline with safe settings."""
    try:
        info("🧪 Running pipeline in test mode...")
        
        orchestrator = create_test_orchestrator()
        result = await orchestrator.execute_pipeline()
        
        if result.success:
            info("✅ Test completed successfully")
            print(f"📊 Test Results:")
            print(f"  Collected: {result.alerts_collected}")
            print(f"  Processed: {result.alerts_processed}")
            print(f"  Duration: {result.execution_time_seconds:.1f}s")
        else:
            error("❌ Test failed")
            for err in result.errors:
                error(f"  - {err}")
            
    except Exception as e:
        error(f"❌ Test error: {e}")


async def send_test_message() -> None:
    """Send a test message to Telegram."""
    try:
        from src.telegram_bot import TelegramBot
        
        bot = TelegramBot()
        test_msg = f"🧪 *C4A Alerts v{__version__} Test*\n\nSistema funcionando correctamente."
        
        if bot.send_message(test_msg):
            info("✅ Test message sent successfully")
        else:
            error("❌ Failed to send test message")
            
    except ImportError:
        error("❌ TelegramBot not available")
    except Exception as e:
        error(f"❌ Test message error: {e}")


async def show_status() -> None:
    """Show system status."""
    try:
        orchestrator = create_orchestrator()
        status = orchestrator.get_status()
        
        print(f"🔍 C4A Alerts v{__version__} Status:")
        print(f"  Pipeline Mode: {status['config']['pipeline_mode']}")
        print(f"  Sources: {status['sources']['enabled']}/{status['sources']['total']} enabled")
        print(f"  Healthy Sources: {status['sources']['healthy']}")
        print(f"  Sent IDs: {status['current_session']['sent_ids_count']}")
        
        print(f"\n📡 Source Status:")
        for name, source_info in status['sources']['details'].items():
            status_icon = "✅" if source_info['healthy'] and source_info['enabled'] else "❌"
            print(f"  {status_icon} {name}: {'enabled' if source_info['enabled'] else 'disabled'}")
            
    except Exception as e:
        error(f"❌ Status error: {e}")


def show_help() -> None:
    """Show help information."""
    print(f"C4A Alerts v{__version__} - Threat Intelligence Pipeline")
    print(f"")
    print(f"Usage: python main.py [COMMAND] [OPTIONS]")
    print(f"")
    print(f"Commands:")
    print(f"  run          Run the complete threat intelligence pipeline (default)")
    print(f"  test         Run pipeline in test mode (safe, no notifications)")
    print(f"  test-msg     Send a test message to Telegram")
    print(f"  status       Show system status and source health")
    print(f"  help         Show this help message")
    print(f"")
    print(f"Environment Variables:")
    print(f"  PIPELINE_MODE           production|testing|dry_run (default: production)")
    print(f"  SOURCE_EXECUTION_MODE   parallel|sequential|hybrid (default: parallel)")
    print(f"  MAX_PARALLEL_SOURCES    Maximum parallel sources (default: 5)")
    print(f"  MIN_CRITICAL_SCORE      Minimum score for critical alerts (default: 7.0)")
    print(f"  ENABLE_TELEGRAM         Enable Telegram notifications (default: true)")
    print(f"  ENABLE_LOOKER_SYNC      Enable dashboard sync (default: true)")
    print(f"")
    print(f"Examples:")
    print(f"  python main.py                    # Run normal pipeline")
    print(f"  python main.py test              # Run in test mode")
    print(f"  python main.py test-msg          # Send test message")
    print(f"  python main.py status            # Show status")
    print(f"")
    print(f"For more information: https://github.com/c4a-team/c4a-alerts")


async def handle_command(command: str, args: List[str]) -> None:
    """Handle CLI commands."""
    command = command.lower()
    
    if command in ["run", ""]:
        await run_alerts()
    elif command == "test":
        await test_pipeline()
    elif command in ["test-msg", "test-message"]:
        await send_test_message()
    elif command == "status":
        await show_status()
    elif command in ["help", "-h", "--help"]:
        show_help()
    elif command in ["version", "-v", "--version"]:
        print(f"C4A Alerts v{__version__}")
    else:
        error(f"Unknown command: {command}")
        print(f"Use 'python main.py help' for available commands.")
        sys.exit(1)


def setup_logging() -> None:
    """Setup logging configuration."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Configure basic logging
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Silence noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def validate_environment() -> bool:
    """Validate required environment variables."""
    required_vars = ["TELEGRAM_TOKEN", "CHAT_ID"]
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        error(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        error(f"Please check your .env file or environment configuration.")
        return False
    
    return True


async def main() -> None:
    """Main entry point."""
    # Setup
    setup_logging()
    
    # Validate environment
    if not validate_environment():
        sys.exit(1)
    
    # Parse command line arguments
    command = sys.argv[1] if len(sys.argv) > 1 else "run"
    args = sys.argv[2:] if len(sys.argv) > 2 else []
    
    # Handle command
    await handle_command(command, args)


if __name__ == "__main__":
    # Run main with proper asyncio handling
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⛔ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)