import logging
from datetime import datetime

from scapy.all import Ether, DNS  # type: ignore

from janus_data.database import SessionLocal
from janus_data.models import PacketData, AttackSession

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run_analyze_recent_dns():
    """
    Show ALL DNS queries stored in packet_data so far.
    Data is only removed when the user explicitly clears it.
    """
    db = SessionLocal()
    try:
        print("\n--- DNS Query Analysis (full history) ---\n")

        # Get ALL packets ordered by time
        packets = (
            db.query(PacketData)
            .order_by(PacketData.timestamp.asc())
            .all()
        )

        if not packets:
            print("[!] No packets found in database. Run sniffing/MITM first.\n")
            return

        dns_count = 0

        for record in packets:
            try:
                pkt = Ether(record.raw_data)

                if DNS in pkt:
                    dns_layer = pkt[DNS]

                    # qr == 0 => query; qr == 1 => response
                    if dns_layer.qr == 0 and dns_layer.qd:
                        qname = dns_layer.qd.qname.decode(errors="ignore")
                        ts = record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        src_ip = record.source_ip or "Unknown"
                        print(f"[{ts}] {src_ip} → DNS query for {qname}")
                        dns_count += 1
            except Exception as e:
                logger.debug(f"Failed to parse packet {record.id}: {e}")

        if dns_count == 0:
            print("No DNS queries found in captured packets.\n")
        else:
            print(f"\n[+] DNS analysis complete. Total DNS queries: {dns_count}\n")
    finally:
        db.close()


def run_basic_traffic_summary(limit: int = 500):
    """
    Print a simple summary of recent traffic: counts by protocol and top destinations.
    """
    db = SessionLocal()
    try:
        print("\n--- Basic Traffic Summary (recent packets) ---\n")

        packets = (
            db.query(PacketData)
            .order_by(PacketData.timestamp.desc())
            .limit(limit)
            .all()
        )

        if not packets:
            print("[!] No packets found in database.\n")
            return

        proto_counts: dict[str, int] = {}
        dest_counts: dict[str, int] = {}

        for record in packets:
            proto = record.protocol or "UNKNOWN"
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

            if record.dest_ip:
                dest_counts[record.dest_ip] = dest_counts.get(record.dest_ip, 0) + 1

        print("Packets by protocol:")
        for proto, count in proto_counts.items():
            print(f"  {proto}: {count}")

        print("\nTop destination IPs:")
        for ip, count in sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count} packets")

        print("\n[+] Traffic summary complete.\n")
    finally:
        db.close()
