import logging

from janus_data.database import SessionLocal
from janus_data.models import PacketData, ARPEntry, Host, AttackSession

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run_clear_captured_data():
    """
    Clears packet_data, arp_entry and host tables so that
    the next attack / sniff starts with a fresh view.


    Delete order respects foreign key constraints:
        PacketData -> AttackSession -> Host
        ARPEntry   -> Host
    Uses ORM deletes instead of TRUNCATE to avoid lock weirdness.
    """
    db = SessionLocal()
    try:
        deleted_packets = db.query(PacketData).delete()
        deleted_arp = db.query(ARPEntry).delete()
        deleted_sessions = db.query(AttackSession).delete()
        deleted_hosts = db.query(Host).delete()
        db.commit()

        logger.info(
            f"[DB] Cleared packet_data ({deleted_packets}), "
            f"arp_entry ({deleted_arp}) ,"
            f"attack_session ({deleted_sessions}) ,"
            f"and host ({deleted_hosts}) rows."
        )
        print("\n[+] Cleared captured hosts and packet logs.\n")
    except Exception as e:
        logger.error(f"[DB] Failed to clear tables: {e}", exc_info=True)
        db.rollback()
        print("\n[!] Failed to clear captured data. Check logs.\n")
    finally:
        db.close()
