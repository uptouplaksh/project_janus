from scapy.all import sniff, AsyncSniffer  # type: ignore
from scapy.packet import Packet  # type: ignore

from janus_data.database import init_db
from janus_packet_analyzer.storage import store_packet_with_hosts

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Sniffer:
    """
    Packet sniffer.

    Responsibilities:
      - Bind to an interface
      - Capture packets (blocking or background)
      - Forward each packet to storage/analyzer layer

    It does NOT handle any DB logic directly.
    """

    def __init__(self, interface: str = "wlo1"):
        self.interface = interface
        self._async_sniffer: AsyncSniffer | None = None
        logger.info(f"Sniffer initialized on interface: {self.interface}")

    # -----------------------
    # Scapy callback
    # -----------------------
    @staticmethod
    def _packet_callback(packet: Packet) -> None:
        """
        Callback for each captured packet.
        Delegates storage to janus_packet_analyzer.storage.
        """
        logger.debug(f"Packet captured: {packet.summary()}")
        store_packet_with_hosts(packet)

    # -----------------------
    # Public API
    # -----------------------
    def start(self, count: int = 0) -> None:
        """
        Blocking sniff (used by 'Passive sniffing' menu).
        """
        logger.info(
            f"Starting packet sniffing on {self.interface} "
            f"(count={count if count else 'infinite'})..."
        )
        init_db()

        sniff(
            iface=self.interface,
            prn=self._packet_callback,
            store=0,
            count=count if count else 0,
        )

        logger.info("Sniffing stopped.")

    def start_background(self, count: int = 0) -> None:
        """
        Background sniffing with AsyncSniffer.
        Used during an active MITM session.
        """
        if self._async_sniffer is not None:
            logger.warning("Background sniffer already running.")
            return

        init_db()

        self._async_sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            count=count if count else 0,
        )
        self._async_sniffer.start()

        logger.info(
            f"Background packet sniffing started on {self.interface} "
            f"(count={count if count else 'infinite'})."
        )

    def stop_background(self) -> None:
        """
        Stop AsyncSniffer if running.
        """
        if self._async_sniffer is None:
            return

        try:
            self._async_sniffer.stop()
            logger.info("Background packet sniffing stopped.")
        except Exception as e:
            logger.error(f"Error while stopping background sniffer: {e}", exc_info=True)
        finally:
            self._async_sniffer = None


if __name__ == "__main__":
    # For direct testing:
    #   sudo python janus_network/sniffer.py
    sniffer = Sniffer(interface="wlo1")
    try:
        sniffer.start(count=10)
    except PermissionError:
        logger.error("Permission denied. Try running with sudo.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
