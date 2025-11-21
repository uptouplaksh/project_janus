import logging
from janus_attack_manager.session_manager import AttackSessionManager
from janus_ui.selection_helpers import choose_host_ip, get_attacker_details

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run_start_mitm(attack_manager: AttackSessionManager):
    print("\n--- Start MITM Attack Session ---")
    interface = attack_manager.interface
    print(f"Interface: {interface}")

    # 1) Get attacker info (auto-detect + override)
    attacker_ip, attacker_mac = get_attacker_details(interface)

    if not attacker_ip or not attacker_mac:
        print("[!] Aborting MITM start due to missing attacker info.\n")
        return

    # 2) Choose victim & gateway, excluding attacker IP from selection
    victim_ip = choose_host_ip("victim", attacker_ip=attacker_ip)
    if victim_ip is None:
        return

    gateway_ip = choose_host_ip("gateway", attacker_ip=attacker_ip)
    if gateway_ip is None:
        return

    # 3) Start session via manager
    session = attack_manager.start_session(
        attacker_ip=attacker_ip,
        attacker_mac=attacker_mac,
        victim_ip=victim_ip,
        gateway_ip=gateway_ip,
    )

    if session:
        print(
            f"\n[+] MITM attack session started successfully!\n"
            f"    Session ID : {session.id}\n"
            f"    Victim IP  : {victim_ip}\n"
            f"    Gateway IP : {gateway_ip}\n"
            "    Remember to STOP the session when done.\n"
        )
    else:
        print("\n[!] Failed to start MITM session.\n")


def run_stop_mitm(attack_manager: AttackSessionManager):
    print("\n--- Stop MITM Session ---")

    ok = attack_manager.stop_session()
    if ok:
        print("[+] MITM Session stopped & restored.\n")
    else:
        print("[!] No active session.\n")


def run_list_sessions(attack_manager: AttackSessionManager):
    print("\n--- Attack Sessions ---")
    sessions = attack_manager.list_sessions()

    if not sessions:
        print("No sessions found.\n")
        return

    print(
        f"{'ID':<5} {'Active':<8} {'Victim IP':<16} {'Gateway IP':<16} "
        f"{'Start Time':<25} {'End Time':<25}"
    )
    print("-" * 100)

    for s in sessions:
        v = s.victim_host.host_ip_address if s.victim_host else "N/A"
        g = s.gateway_host.host_ip_address if s.gateway_host else "N/A"
        start = s.start_time.strftime("%Y-%m-%d %H:%M:%S") if s.start_time else "N/A"
        end = s.end_time.strftime("%Y-%m-%d %H:%M:%S") if s.end_time else "N/A"
        print(f"{s.id:<5} {str(s.is_session_active):<8} {v:<16} {g:<16} {start:<25} {end:<25}")

    print()
