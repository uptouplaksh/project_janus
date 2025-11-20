import logging
from datetime import datetime, timezone
from janus_data.database import SessionLocal
from janus_data.models import AttackSession, Host

logger = logging.getLogger(__name__)


class AttackSessionManager:
    """
    Manages the lifecycle of MITM Attack Sessions:
    - Create
    - Start
    - Stop (Restore)
    - List existing sessions
    """

    def __init__(self):
        self.db = SessionLocal()
        self.active_session = None  # in-memory pointer to currently active attack session

    def create_session(self, attacker_ip, attacker_mac, victim_ip, gateway_ip):
        """
        Creates a new attack session by locating the Victim & Gateway host entries in DB.
        Matches Sequence Diagram Step: "Create New AttackSession()"
        """

        victim_host = self.db.query(Host).filter_by(host_ip_address=victim_ip).first()
        gateway_host = self.db.query(Host).filter_by(host_ip_address=gateway_ip).first()

        if not victim_host or not gateway_host:
            logger.error("Failed to create session: victim or gateway host not found in DB.")
            return None

        session = AttackSession(
            start_time=datetime.now(timezone.utc),
            is_session_active=True,
            victim_host_id=victim_host.id,
            gateway_host_id=gateway_host.id,
            attacker_ip_address=attacker_ip,
            attacker_mac_address=attacker_mac
        )

        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        self.active_session = session

        logger.info(f"[MITM] Attack session created with ID={session.id}")
        return session

    def stop_session(self):
        """
        Stops current session and restores network behavior.
        Matches Activity + Sequence Diagram Step: "stopSpoofingAttack"
        """

        if not self.active_session:
            logger.warning("No active MITM session to stop.")
            return False

        self.active_session.is_session_active = False
        self.active_session.end_time = datetime.now(timezone.utc)

        self.db.commit()

        logger.info(
            f"[MITM] Attack session ID={self.active_session.id} marked inactive and closed."
        )

        self.active_session = None
        return True

    def get_active_session(self):
        """Return active session object, if any"""
        return self.active_session

    def list_sessions(self):
        """Return all attack sessions from DB"""
        return self.db.query(AttackSession).all()
