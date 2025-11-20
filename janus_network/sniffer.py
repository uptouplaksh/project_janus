# janus_network/sniffer.py
from scapy.all import sniff, ARP, IP, Ether, Packet
from janus_data.database import SessionLocal, engine, init_db
from janus_data.models import Host, PacketData
from datetime import datetime
import logging
import os # For potentially getting the interface from config later

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Sniffer:
    def __init__(self, interface: str = 'wlo1'): # Default to wlo1
        self.interface = interface
        logger.info(f"Sniffer initialized on interface: {self.interface}")

    def _store_host_data(self, mac_address: str, ip_address: str):
        """Stores or updates host information in the database."""
        db = SessionLocal()
        try:
            host = db.query(Host).filter_by(mac_address=mac_address).first()
            if host:
                if host.ip_address != ip_address:
                    logger.info(f"Host {mac_address} IP updated from {host.ip_address} to {ip_address}")
                    host.ip_address = ip_address
                    host.last_seen = datetime.now()
            else:
                host = Host(mac_address=mac_address, ip_address=ip_address, last_seen=datetime.now())
                db.add(host)
                logger.info(f"New host added: MAC={mac_address}, IP={ip_address}")
            db.commit()
        except Exception as e:
            logger.error(f"Error storing host data: {e}", exc_info=True)
            db.rollback()
        finally:
            db.close()

    def _store_packet_data(self, packet: Packet):
        """Stores raw packet data and basic info in the database."""
        db = SessionLocal()
        try:
            src_mac = packet[Ether].src if Ether in packet else None
            dst_mac = packet[Ether].dst if Ether in packet else None
            src_ip = packet[IP].src if IP in packet else None
            dst_ip = packet[IP].dst if IP in packet else None
            protocol = packet[IP].proto if IP in packet else None
            packet_len = len(packet)

            # Store sender/receiver as hosts if they have MAC/IP
            if src_mac and src_ip:
                self._store_host_data(src_mac, src_ip)
            if dst_mac and dst_ip:
                self._store_host_data(dst_mac, dst_ip)

            packet_record = PacketData(
                timestamp=datetime.now(),
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                length=packet_len,
                raw_data=bytes(packet) # Store raw packet bytes
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
        """Starts sniffing packets."""
        logger.info(f"Starting packet sniffing on {self.interface} (count={count if count else 'infinite'})...")
        # Ensure the database tables exist before sniffing
        init_db()
        sniff(iface=self.interface, prn=self._packet_callback, store=0, count=count)
        logger.info("Sniffing stopped.")

if __name__ == "__main__":
    # This block is for testing the sniffer directly
    # You might need to run this with sudo for raw socket access
    # Example: sudo python janus_network/sniffer.py
    sniffer = Sniffer(interface='wlo1') # Use your actual interface
    try:
        # Capture 10 packets for a quick test
        sniffer.start(count=10)
    except PermissionError:
        logger.error("Permission denied. Try running with 'sudo python janus_network/sniffer.py'")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)