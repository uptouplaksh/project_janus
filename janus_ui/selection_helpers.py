import logging
from janus_data.database import SessionLocal
from janus_data.models import Host
from janus_network.attacker_info import detect_attacker_ip, detect_attacker_mac

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def fetch_hosts_from_db():
    """
    Fetch all known hosts from the database.
    """
    db = SessionLocal()
    try:
        hosts = db.query(Host).all()
        return hosts
    finally:
        db.close()


def choose_host_ip(role: str, attacker_ip: str | None = None) -> str | None:
    """
    Show a numbered list of hosts and let the user choose one.
    If attacker_ip is given, that host is excluded from the list.
    """
    hosts = fetch_hosts_from_db()

    if attacker_ip:
        hosts = [h for h in hosts if h.host_ip_address != attacker_ip]

    if not hosts:
        print(f"[!] No hosts found — run passive sniff first.\n")
        return None

    print(f"\n--- Select {role} Host ---")
    print(f"{'#':<3} {'IP Address':<16} {'MAC Address':<20} {'Is Gateway':<11} {'Last Seen'}")
    print("-" * 80)

    for idx, h in enumerate(hosts, start=1):
        is_gw = "Yes" if h.is_gateway else "No"
        last_seen = h.last_seen.strftime("%Y-%m-%d %H:%M:%S") if h.last_seen else "N/A"
        print(f"{idx:<3} {h.host_ip_address:<16} {h.host_mac_address:<20} {is_gw:<11} {last_seen}")

    while True:
        choice = input(f"{role} host # (or 'c' to cancel)> ").strip().lower()

        if choice == "c":
            print("Cancelled.\n")
            return None

        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(hosts):
                h = hosts[idx - 1]
                print(f"[+] Selected {h.host_ip_address} ({h.host_mac_address})\n")
                return h.host_ip_address

        print("Invalid option. Try again.")


def get_attacker_details(interface: str) -> tuple[str | None, str | None]:
    """
    Detect attacker IP/MAC and allow user to override or confirm.
    Returns (attacker_ip, attacker_mac) which may be None if cannot determine.
    """
    detected_ip = detect_attacker_ip()
    detected_mac = detect_attacker_mac(interface)

    print("\nAuto-detected attacker details:")
    print(f"  IP  : {detected_ip or 'Unknown'}")
    print(f"  MAC : {detected_mac or 'Unknown'}")

    attacker_ip_input = input(
        "Enter attacker IP (press Enter to use detected): "
    ).strip()
    attacker_mac_input = input(
        "Enter attacker MAC (press Enter to use detected): "
    ).strip()

    attacker_ip = attacker_ip_input or detected_ip
    attacker_mac = attacker_mac_input or detected_mac

    if not attacker_ip or not attacker_mac:
        print("[!] Unable to determine attacker IP/MAC.\n")
        return None, None

    return attacker_ip, attacker_mac
