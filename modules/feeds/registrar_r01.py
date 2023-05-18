"""
For fetching and scanning URLs from Registrar R01
"""
import gzip
from collections.abc import AsyncIterator

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger
from more_itertools import chunked

logger = init_logger()


async def _get_r01_domains() -> AsyncIterator[set[str]]:
    """Download domains from Registrar R01 and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """

    endpoints = [
        "https://partner.r01.ru/zones/ru_domains.gz",
        "https://partner.r01.ru/zones/su_domains.gz",
        "https://partner.r01.ru/zones/rf_domains.gz",
    ]

    page_responses = await get_async(endpoints)

    raw_urls: list[str] = []

    for endpoint, resp in page_responses.items():
        if resp != b"{}":
            decompressed_lines = gzip.decompress(resp).decode().split("\n")
            # Ensure that raw_url is always lowercase
            raw_urls += [
                splitted_line[0].lower()
                for line in decompressed_lines
                if (
                    splitted_line := line.split()
                )  # if splitted_line has a length of at least 1
            ]
        else:
            logger.warning("Failed to retrieve Registrar R01 list %s", endpoint)

    for batch in chunked(raw_urls, hostname_expression_batch_size):
        yield generate_hostname_expressions(batch)


class RegistrarR01:
    """
    For fetching and scanning URLs from Registrar R01
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "r01" in parser_args["sources"]:
            self.db_filenames = ["r01_urls"]
            if parser_args["fetch"]:
                # Download and Add Registrar R01 URLs to database
                self.jobs = [(_get_r01_domains, update_time, "r01_urls")]
