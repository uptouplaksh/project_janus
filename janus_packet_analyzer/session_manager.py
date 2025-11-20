import logging
from datetime import datetime, timezone
from typing import Optional

from janus_data.database import SessionLocal
from janus_data.models import AttackSession, Host
from janus_network.ip_forwarder import enable_ip_forwarding, disable_ip_forwarding
from janus_network.arp_handler import ARPHandler

logger = logging.getLogger(__name__)


class AttackSessionManager:
    """
    Manages the lifecycle of MITM Attack Sessions:
    - Create session
    - Start attack (enable forwarding + ARP spoof)
    - Stop attack (restore ARP + disable forwarding)
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.db = SessionLocal()
        self.active_session: Optional[AttackSession] = None
        self.arp_handler: Optional[ARPHandler] = None

    def create_session(self, attacker_ip: str, attacker_mac: str,
                       victim_ip: str, gateway_ip: str) -> Optional[AttackSession]:
        """
        Create a new AttackSession record in the DB.
        """

        victim_host = self.db.query(Host).filter_by(host_ip_address=victim_ip).first()
        gateway_host = self.db.query(Host).filter_by(host_ip_address=gateway_ip).first()

        if not victim_host or not gateway_host:
            logger.error("[MITM] Cannot create new session — victim or gateway not found in database.")
            return None

        session = AttackSession(
            start_time=datetime.now(timezone.utc),
            is_session_active=True,
            victim_host_id=victim_host.id,
            gateway_host_id=gateway_host.id,
            attacker_ip_address=attacker_ip,
            attacker_mac_address=attacker_mac,
        )

        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        self.active_session = session

        logger.info(
            f"[MITM] New attack session created — ID={session.id}, "
            f"victim={victim_ip}, gateway={gateway_ip}"
        )
        return session

    def start_session(self, attacker_ip: str, attacker_mac: str,
                      victim_ip: str, gateway_ip: str) -> Optional[AttackSession]:
        """
        Full start sequence:
        - create AttackSession
        - enable IP forwarding
        - start ARP spoofing loop
        """

        session = self.create_session(attacker_ip, attacker_mac, victim_ip, gateway_ip)
        if not session:
            return None

        if enable_ip_forwarding():
            logger.info("[MITM] IP forwarding enabled.")
        else:
            logger.error("[MITM] Failed to enable IP forwarding.")
            return None

        self.arp_handler = ARPHandler(interface=self.interface)
        if self.arp_handler.start_spoofing(victim_ip=victim_ip, gateway_ip=gateway_ip):
            logger.info("[MITM] ARP spoofing started successfully.")
        else:
            logger.error("[MITM] Failed to start ARP spoofing. Stopping session.")
            self.stop_session()
            return None

        logger.info(f"[MITM] Attack session ID={session.id} is ACTIVE.")
        return session

    def stop_session(self) -> bool:
        """
        Stop current MITM session and restore network configuration.
        """

        if not self.active_session:
            logger.warning("[MITM] No active attack session to stop.")
            return False

        victim = self.active_session.victim_host
        gateway = self.active_session.gateway_host

        if self.arp_handler and victim and gateway:
            self.arp_handler.stop_spoofing_and_restore(
                victim_ip=victim.host_ip_address,
                gateway_ip=gateway.host_ip_address,
                victim_mac=victim.host_mac_address,
                gateway_mac=gateway.host_mac_address,
            )

        disable_ip_forwarding()

        self.active_session.is_session_active = False
        self.active_session.end_time = datetime.now(timezone.utc)
        self.db.commit()

        logger.info(f"[MITM] Attack Session ID={self.active_session.id} stopped and restored.")
        self.active_session = None
        self.arp_handler = None

        return True

    def list_sessions(self):
        return self.db.query(AttackSession).all()

    def get_active_session(self) -> Optional[AttackSession]:
        return self.active_session
