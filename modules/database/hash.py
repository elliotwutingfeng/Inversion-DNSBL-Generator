"""
URL and IP Address hashing utilities
"""

import base64
import socket
import struct
from hashlib import sha256


def compute_url_hash(url: str) -> str:
    """Compute b64 encoded sha256 hash of `url` as specified by Safe Browsing API.

    Args:
        url (str): URL to be hashed

    Returns:
        str: b64 encoded sha256 hash of `url` as specified by Safe Browsing API.
    """
    return base64.b64encode(sha256(f"{url}/".encode()).digest()).decode()


def int_addr_to_ip_and_hash(int_addr: int) -> tuple[str, str]:
    """Convert integer representation of ipv4 address
    to `ip_address` string and its Safe Browsing API b64 encoded sha256 `ip_hash`

    Args:
        int_addr (int): integer representation of ipv4 address

    Returns:
        tuple[str, str]: `ip_address` string and its
        Safe Browsing API b64 encoded sha256 `ip_hash`
    """
    ip_address = socket.inet_ntoa(struct.pack("!I", int_addr))
    ip_hash = compute_url_hash(ip_address)
    return (ip_address, ip_hash)
