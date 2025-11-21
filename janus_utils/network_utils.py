import ipaddress


def is_private_ipv4(ip: str) -> bool:
    """
    Returns True if IP is a private/local IPv4 address.
    Used to filter broadcast, multicast and public internet IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except Exception:
        return False
