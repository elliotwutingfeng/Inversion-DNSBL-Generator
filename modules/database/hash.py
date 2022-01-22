"""
URL and IP Address hashing utilities
"""

from hashlib import sha256
import socket
import struct

def compute_url_hash(url: str) -> bytes:
    """Computes sha256 hash of `url` as specified by Safe Browsing API.

    Args:
        url (str): URL to be hashed

    Returns:
        bytes: sha256 hash of `url` as specified by Safe Browsing API.
    """
    return sha256(f"{url}/".encode()).digest()


def int_addr_to_ip_and_hash(int_addr: int) -> tuple[str, bytes]:
    """Convert integer representation of ipv4 address
    to `ip_address` string and its Safe Browsing API sha256 `ip_hash`

    Args:
        int_addr (int): integer representation of ipv4 address

    Returns:
        tuple[str, bytes]: `ip_address` string and its Safe Browsing API sha256 `ip_hash`
    """
    ip_address = socket.inet_ntoa(struct.pack("!I", int_addr))
    ip_hash = compute_url_hash(ip_address)
    return (ip_address, ip_hash)
