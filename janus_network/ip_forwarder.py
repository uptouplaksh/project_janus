import logging
from pathlib import Path

logger = logging.getLogger(__name__)

IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


def is_ip_forwarding_enabled() -> bool:
    """
    Checks if Linux IP forwarding is currently enabled.
    Returns True if enabled, False otherwise.
    """
    try:
        if not IP_FORWARD_PATH.exists():
            logger.error(f"IP forwarding path not found: {IP_FORWARD_PATH}")
            return False

        value = IP_FORWARD_PATH.read_text().strip()
        return value == "1"
    except PermissionError:
        logger.error(
            "Permission denied while checking IP forwarding. "
            "Try running as root."
        )
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking IP forwarding: {e}", exc_info=True)
        return False


def enable_ip_forwarding() -> bool:
    """
    Enables IP forwarding on Linux by writing '1' to /proc/sys/net/ipv4/ip_forward.
    Returns True on success, False on failure.
    """
    try:
        if not IP_FORWARD_PATH.exists():
            logger.error(f"IP forwarding path not found: {IP_FORWARD_PATH}")
            return False

        IP_FORWARD_PATH.write_text("1\n")
        logger.info("IP forwarding ENABLED (/proc/sys/net/ipv4/ip_forward = 1).")
        return True
    except PermissionError:
        logger.error(
            "Permission denied while enabling IP forwarding. "
            "Run the program with sudo/root privileges."
        )
        return False
    except Exception as e:
        logger.error(f"Failed to enable IP forwarding: {e}", exc_info=True)
        return False


def disable_ip_forwarding() -> bool:
    """
    Disables IP forwarding on Linux by writing '0' to /proc/sys/net/ipv4/ip_forward.
    Returns True on success, False on failure.
    """
    try:
        if not IP_FORWARD_PATH.exists():
            logger.error(f"IP forwarding path not found: {IP_FORWARD_PATH}")
            return False

        IP_FORWARD_PATH.write_text("0\n")
        logger.info("IP forwarding DISABLED (/proc/sys/net/ipv4/ip_forward = 0).")
        return True
    except PermissionError:
        logger.error(
            "Permission denied while disabling IP forwarding. "
            "Run the program with sudo/root privileges."
        )
        return False
    except Exception as e:
        logger.error(f"Failed to disable IP forwarding: {e}", exc_info=True)
        return False
