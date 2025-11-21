import logging
from scapy.all import get_if_list  # type: ignore
from janus_network.sniffer import Sniffer

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _input_with_default(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default


def _choose_interface_for_sniff() -> str:
    """
    Show interfaces as a numbered list and return the selected one.
    Used specifically for passive sniffing.
    """
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  [{idx}] {iface}")

    # default to first interface if user just presses enter
    default_index = 1

    while True:
        choice = _input_with_default("Select interface #", str(default_index))

        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                selected = interfaces[idx - 1]
                print(f"\n[+] Using interface for sniffing: {selected}\n")
                return selected

        print("Invalid choice, try again.")


def run_passive_sniff():
    """
    Runs the sniffer in passive mode (no MITM, no session binding).
    """
    print("\n--- Passive Packet Sniffing ---")

    interface = _choose_interface_for_sniff()
    count_str = _input_with_default("Number of packets to capture (0 = infinite)", "50")

    try:
        count = int(count_str)
    except ValueError:
        print("Invalid input, defaulting to 50.")
        count = 50

    sniffer = Sniffer(interface=interface)
    print(f"\n[+] Starting passive sniffing on {interface} (count={count})...")
    sniffer.start(count=count)
    print("[+] Passive sniffing finished.\n")
