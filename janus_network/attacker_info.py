import logging
import socket
from scapy.all import get_if_hwaddr  # type: ignore

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def detect_attacker_ip() -> str | None:
    """
    Try to detect the attacker's IP address on the active interface
    by opening a dummy UDP socket. This uses the system routing table.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually send packets, just uses routing info
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.error(f"Failed to auto-detect attacker IP: {e}", exc_info=True)
        return None


def detect_attacker_mac(interface: str) -> str | None:
    """
    Detect the MAC address of the given network interface using scapy.
    """
    try:
        mac = get_if_hwaddr(interface)
        return mac
    except Exception as e:
        logger.error(
            f"Failed to auto-detect attacker MAC for interface {interface}: {e}",
            exc_info=True,
        )
        return None
