import logging
from datetime import datetime, timezone

from scapy.layers.l2 import Ether  # type: ignore
from scapy.layers.inet import IP  # type: ignore
from scapy.packet import Packet  # type: ignore

from janus_data.database import SessionLocal
from janus_data.models import Host, PacketData
from janus_utils.network_utils import is_private_ipv4

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _store_host_observation(mac_address: str, ip_address: str) -> None:
    """
    Insert/update a host row when we see traffic from/to it.
    Only records private IPv4 hosts (LAN devices).
    """
    if not ip_address or not is_private_ipv4(ip_address):
        return

    db = SessionLocal()
    try:
        host = db.query(Host).filter_by(host_mac_address=mac_address).first()
        now = utcnow()

        if host:
            # Always update last_seen
            host.last_seen = now

            if host.host_ip_address != ip_address:
                logger.debug(
                    f"Host {mac_address} IP updated from "
                    f"{host.host_ip_address} to {ip_address}"
                )
                host.host_ip_address = ip_address
        else:
            host = Host(
                host_mac_address=mac_address,
                host_ip_address=ip_address,
                last_seen=now,
            )
            db.add(host)
            logger.info(f"New host added: MAC={mac_address}, IP={ip_address}")

        db.commit()
    except Exception as e:
        logger.error(f"Error storing host data: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()


def store_packet_with_hosts(packet: Packet) -> None:
    """
    Extracts info from a Scapy packet, updates Host table for
    private IPs, and stores PacketData row.
    """
    db = SessionLocal()
    try:
        src_mac = packet[Ether].src if Ether in packet else None
        dst_mac = packet[Ether].dst if Ether in packet else None
        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        protocol = packet[IP].proto if IP in packet else None

        # Update host observations for private IPs
        if src_mac and src_ip and is_private_ipv4(src_ip):
            _store_host_observation(src_mac, src_ip)
        if dst_mac and dst_ip and is_private_ipv4(dst_ip):
            _store_host_observation(dst_mac, dst_ip)

        packet_record = PacketData(
            timestamp=utcnow(),
            source_mac=src_mac,
            dest_mac=dst_mac,
            source_ip=src_ip,
            dest_ip=dst_ip,
            protocol=str(protocol) if protocol is not None else None,
            raw_data=bytes(packet),
        )
        db.add(packet_record)
        db.commit()

        logger.debug(
            f"Stored packet from {src_ip or src_mac} to {dst_ip or dst_mac}"
        )
    except Exception as e:
        logger.error(f"Error storing packet data: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()
