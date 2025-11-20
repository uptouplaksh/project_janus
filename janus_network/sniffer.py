from scapy.all import sniff  # type: ignore
from scapy.layers.l2 import ARP, Ether  # type: ignore
from scapy.layers.inet import IP  # type: ignore
from scapy.packet import Packet  # type: ignore
from janus_data.database import SessionLocal, init_db
from janus_data.models import Host, PacketData
from datetime import datetime, timezone
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def utcnow():
    return datetime.now(timezone.utc)


class Sniffer:
    def __init__(self, interface: str = 'wlo1'):
        self.interface = interface
        logger.info(f"Sniffer initialized on interface: {self.interface}")

    def _store_host_data(self, mac_address: str, ip_address: str):
        """
        Stores or updates host information in the database.
        """
        db = SessionLocal()
        try:
            host = db.query(Host).filter_by(host_mac_address=mac_address).first()
            now = utcnow()
            if host:
                if host.host_ip_address != ip_address:
                    logger.info(
                        f"Host {mac_address} IP updated from {host.host_ip_address} to {ip_address}"
                    )
                    host.host_ip_address = ip_address
                host.last_seen = now
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

    def _store_packet_data(self, packet: Packet):
        """
        Stores raw packet data and basic info in the database.
        """
        db = SessionLocal()
        try:
            src_mac = packet[Ether].src if Ether in packet else None
            dst_mac = packet[Ether].dst if Ether in packet else None
            src_ip = packet[IP].src if IP in packet else None
            dst_ip = packet[IP].dst if IP in packet else None
            protocol = packet[IP].proto if IP in packet else None

            if src_mac and src_ip:
                self._store_host_data(src_mac, src_ip)
            if dst_mac and dst_ip:
                self._store_host_data(dst_mac, dst_ip)

            packet_record = PacketData(
                # 👇 timestamp is auto default, but we set it explicitly for clarity
                timestamp=utcnow(),
                source_mac=src_mac,
                dest_mac=dst_mac,
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol=str(protocol) if protocol is not None else None,
                raw_data=bytes(packet),  # Store raw packet bytes
                # session_id stays None in passive sniff mode
            )
            db.add(packet_record)
            db.commit()
            logger.debug(f"Stored packet from {src_ip or src_mac} to {dst_ip or dst_mac}")
        except Exception as e:
            logger.error(f"Error storing packet data: {e}", exc_info=True)
            db.rollback()
        finally:
            db.close()

    def _packet_callback(self, packet: Packet):
        """Callback function for each captured packet."""
        logger.debug(f"Packet captured: {packet.summary()}")
        self._store_packet_data(packet)

    def start(self, count: int = 0):
        """
        Starts sniffing packets.

        :param count: number of packets to capture. 0 = infinite.
        """
        logger.info(
            f"Starting packet sniffing on {self.interface} "
            f"(count={count if count else 'infinite'})..."
        )
        # Ensure the database tables exist before sniffing
        init_db()
        sniff(iface=self.interface, prn=self._packet_callback, store=0, count=count)
        logger.info("Sniffing stopped.")


if __name__ == "__main__":
    sniffer = Sniffer(interface='wlo1')  # Use your actual interface name
    try:
        sniffer.start(count=10)
    except PermissionError:
        logger.error("Permission denied. Try running with 'sudo python janus_network/sniffer.py'")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
