"""
For generating and scanning Google Compute Engine URLs
"""

import ipaddress
import json
from collections.abc import AsyncIterator

from more_itertools import chunked

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger

logger = init_logger()


def _collapse_cidrs(list_of_cidr_nets: list[str]) -> list[str]:
    """Remove overlapping ip ranges

    Args:
        list_of_cidr_nets (list[str]): IP ranges

    Returns:
        list[str]: IP ranges with overlaps removed
    """
    nets = (
        ip
        for _ip in list_of_cidr_nets
        if (ip := ipaddress.ip_network(_ip)) and isinstance(ip, ipaddress.IPv4Network)
    )
    ip_ranges = [str(ip_range) for ip_range in ipaddress.collapse_addresses(nets)]
    return ip_ranges


async def _get_googleusercontent_url_list() -> AsyncIterator[set[str]]:
    """Generate Google Compute Engine URLs and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """

    # Download cloud.json and extract all CIDRs
    endpoint: str = "https://www.gstatic.com/ipranges/cloud.json"
    resp = (await get_async([endpoint]))[endpoint]
    if resp == b"{}":
        logger.warning(
            "Failed to retrieve Google Compute Engine IP ranges; returning empty list"
        )
        yield set()

    resp_json = json.loads(resp)

    prefixes = resp_json.get("prefixes", [])
    ipv4Prefixes_and_scopes = (
        (x["ipv4Prefix"], x["scope"])
        for x in prefixes
        if x.get("service", "") == "Google Cloud"
        and ("ipv4Prefix" in x)
        and ("scope" in x)
    )

    ip_ranges = _collapse_cidrs(
        [x[0] for x in ipv4Prefixes_and_scopes]
    )  # Removes overlapping ip ranges

    def _generate_gce_urls(ip_ranges: list[str]):
        for ip_range in ip_ranges:
            for ip_address in ipaddress.IPv4Network(ip_range.strip()):
                # Google Compute Engine IP addresses are reversed in the subdomain
                yield f"""{".".join(str(ip_address).split(".")[::-1])}.bc.googleusercontent.com"""

    gce_url_generator = _generate_gce_urls(ip_ranges)

    for batch in chunked(gce_url_generator, hostname_expression_batch_size):
        yield generate_hostname_expressions(batch)


class GCE:
    """
    For generating and scanning Google Compute Engine URLs
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []

        if "gce" in parser_args["sources"]:
            self.db_filenames = ["gce_googleusercontent"]

            if parser_args["fetch"]:
                # Generate and Add Google Compute Engine URLs to database
                self.jobs = [
                    (_get_googleusercontent_url_list, update_time, db_filename)
                    for db_filename in self.db_filenames
                ]
