# janus_core/main.py
from janus_data.database import init_db
from janus_network.sniffer import Sniffer # Import your new Sniffer class
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("Running database initialization and sniffer test...")
    init_db() # Ensure tables are created

    # Start the sniffer
    # You might need to run main.py with sudo for this to work
    sniffer = Sniffer(interface='wlo1') # IMPORTANT: Use your actual interface name
    try:
        sniffer.start(count=50) # Capture 50 packets for a test
    except PermissionError:
        logger.error("Permission denied. Try running 'main.py' with administrator privileges (sudo).")
    except Exception as e:
        logger.error(f"An unexpected error occurred during sniffing: {e}", exc_info=True)

    logger.info("Sniffer test finished.")

if __name__ == "__main__":
    main()