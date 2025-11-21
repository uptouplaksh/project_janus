import os
import sys
import logging

current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_dir = os.path.abspath(os.path.join(current_script_dir, '..'))
sys.path.insert(0, project_root_dir)

from janus_data.database import init_db
from janus_ui.menu import run_cli

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def main():
    logger.info("Initializing database for Project JANUS...")
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}", exc_info=True)
        sys.exit(1)

    # Launch CLI
    run_cli()


if __name__ == "__main__":
    main()
