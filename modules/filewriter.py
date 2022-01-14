"""
File Writer

For writing URLs to .txt file with with timestamp in filename
"""

from __future__ import annotations
import os
import ipaddress
from datetime import datetime
from typing import List

from modules.utils.log import init_logger
from modules.utils.types import Vendors

BLOCKLISTS_FOLDER: str = "blocklists"

logger = init_logger()


def current_datetime_str() -> str:
    """Current time's datetime string in UTC.

    Returns:
        str: Timestamp in strftime format "%d_%b_%Y_%H_%M_%S-UTC"
    """
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def write_blocklist_txt(urls: List[str], vendor: Vendors) -> None:
    """Split list of urls into hostnames and ip addresses, then write
    hostnames and ip addresses to separate .txt files with timestamp
    in filename and store them in `BLOCKLISTS_FOLDER`.

    `BLOCKLISTS_FOLDER` is created beforehand if it does not exist yet.

    Args:
        urls (List[str]): List of URLs
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)
    """
    if not os.path.exists(BLOCKLISTS_FOLDER):
        os.mkdir(BLOCKLISTS_FOLDER)

    hostnames: List[str] = []
    ip_addresses: List[str] = []
    for url in urls:
        try:
            if isinstance(ipaddress.ip_address(url), ipaddress.IPv4Address):
                ip_addresses.append(url)
            else:
                raise ValueError("Not an IPv4 Address.")
        except ValueError:
            hostnames.append(url)

    hostnames_txt_filename = f"{vendor}_hostnames_{current_datetime_str()}.txt"
    with open(f"{BLOCKLISTS_FOLDER}{os.sep}{hostnames_txt_filename}", "a") as outfile:
        outfile.writelines("\n".join(hostnames))
        logger.info("%d hostname URLs written to file: %s", len(hostnames), hostnames_txt_filename)

    ip_addresses_txt_filename = f"{vendor}_ipv4_{current_datetime_str()}.txt"
    with open(f"{BLOCKLISTS_FOLDER}{os.sep}{ip_addresses_txt_filename}", "a") as outfile:
        outfile.writelines("\n".join(ip_addresses))
        logger.info("%d IPv4 addresses written to file: %s",
        len(ip_addresses), ip_addresses_txt_filename)
