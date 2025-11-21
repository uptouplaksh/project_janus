import logging
from scapy.all import get_if_list  # type: ignore

from janus_attack_manager.session_manager import AttackSessionManager
from janus_ui.sniff_commands import run_passive_sniff
from janus_ui.mitm_commands import (
    run_start_mitm,
    run_stop_mitm,
    run_list_sessions,
)
from janus_ui.analyzer_commands import (
    run_analyze_recent_dns,
    run_basic_traffic_summary,
)
from janus_ui.db_commands import run_clear_captured_data

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _choose_interface() -> str:
    """
    Show interfaces as a numbered list and return the selected one.
    """
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  [{idx}] {iface}")

    while True:
        choice = input("\nSelect interface #> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            selected = interfaces[int(choice) - 1]
            print(f"\n[+] Using interface: {selected}\n")
            return selected

        print("Invalid choice, try again.")


def run_cli():
    """
    Main interactive CLI for Project JANUS.
    Handles Ctrl+C to gracefully stop any active MITM session.
    """
    print("\n=== Project JANUS - ARP Spoofing MITM Toolkit (CLI) ===\n")

    interface = _choose_interface()
    attack_manager = AttackSessionManager(interface=interface)

    try:
        while True:
            print("Select an option:")
            print("  [1] Passive sniffing (discover hosts & log packets)")
            print("  [2] Start MITM attack session")
            print("  [3] Stop active MITM session")
            print("  [4] List attack sessions")
            print("  [5] Analyze recent DNS queries")
            print("  [6] Show basic traffic summary")
            print("  [7] Clear captured hosts and packet logs")
            print("  [0] Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                run_passive_sniff()
            elif choice == "2":
                run_start_mitm(attack_manager)
            elif choice == "3":
                run_stop_mitm(attack_manager)
            elif choice == "4":
                run_list_sessions(attack_manager)
            elif choice == "5":
                run_analyze_recent_dns()
            elif choice == "6":
                run_basic_traffic_summary()
            elif choice == "7":
                run_clear_captured_data()
            elif choice == "0":
                print("\nExiting Project JANUS CLI. Goodbye.\n")
                break
            else:
                print("Invalid choice, try again.\n")
    except KeyboardInterrupt:
        print("\n\n[!] Ctrl+C detected. Cleaning up...")

        try:
            if attack_manager.get_active_session() is not None:
                attack_manager.stop_session()
        except Exception as e:
            logger.error(f"Error while stopping active MITM session on Ctrl+C: {e}", exc_info=True)

        print("[+] Cleanup complete. Exiting gracefully.\n")
