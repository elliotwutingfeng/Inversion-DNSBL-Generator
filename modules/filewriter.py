"""
File Writer

For writing URLs to .txt file with with timestamp in filename
"""

import asyncio
import os
import ipaddress
from datetime import datetime

import aiofiles # type:ignore

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


async def write_blocklist_txt(urls: list[str], vendor: Vendors) -> None:
    """Split list of urls into hostnames and ip addresses, then write
    hostnames and ip addresses in ascending order to separate .txt files
    with timestamp in filename and store them in `BLOCKLISTS_FOLDER`.

    `BLOCKLISTS_FOLDER` is created beforehand if it does not exist yet.

    Args:
        urls (list[str]): List of URLs
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)
    """
    if not os.path.exists(BLOCKLISTS_FOLDER):
        os.mkdir(BLOCKLISTS_FOLDER)

    hostnames: list[str] = []
    ip_addresses: list[str] = []
    for url in urls:
        try:
            if isinstance(ipaddress.ip_address(url), ipaddress.IPv4Address):
                ip_addresses.append(url)
            else:
                raise ValueError("Not an IPv4 Address.")
        except ValueError:
            hostnames.append(url)

    hostnames.sort()
    ip_addresses.sort()

    async def write_hostnames():
        hostnames_txt_filename = f"{vendor}_hostnames_{current_datetime_str()}.txt"
        async with aiofiles.open(f"{BLOCKLISTS_FOLDER}{os.sep}{hostnames_txt_filename}", "a") as outfile:
            await outfile.writelines("\n".join(hostnames))
            logger.info("%d hostname URLs written to file: %s",
            len(hostnames), hostnames_txt_filename)

    async def write_ips():
        ip_addresses_txt_filename = f"{vendor}_ipv4_{current_datetime_str()}.txt"
        async with aiofiles.open(f"{BLOCKLISTS_FOLDER}{os.sep}{ip_addresses_txt_filename}", "a") as outfile:
            await outfile.writelines("\n".join(ip_addresses))
            logger.info("%d IPv4 addresses written to file: %s",
            len(ip_addresses), ip_addresses_txt_filename)
    
    await asyncio.gather(*[asyncio.create_task(write_hostnames()),asyncio.create_task(write_ips())])
