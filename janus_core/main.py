# janus_core/main.py
import os
import sys
import logging

current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_dir = os.path.abspath(os.path.join(current_script_dir, '..'))
sys.path.insert(0, project_root_dir)

from janus_data.database import init_db
from janus_network.sniffer import Sniffer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main():
    logger.info("Running database initialization and sniffer test...")
    try:
        init_db()  # Ensure tables are created
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}", exc_info=True)
        sys.exit(1)

    sniffer = Sniffer(interface='wlo1')
    try:
        logger.info(f"Starting sniffer on interface '{sniffer.interface}'...")
        sniffer.start(count=50)  # Capture 50 packets for a test
        logger.info("Sniffer test finished.")
    except PermissionError:
        logger.error("Permission denied. Try running 'main.py' with administrator privileges (sudo).")
        logger.error("Example: sudo ./.venv/bin/python janus_core/main.py")
    except Exception as e:
        logger.error(f"An unexpected error occurred during sniffing: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
