"""
For fetching and scanning URLs from Internet.ee
"""

from collections.abc import AsyncIterator

from more_itertools import chunked

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger

logger = init_logger()


async def get_ee_domains() -> AsyncIterator[set[str]]:
    """Download and extract Internet.ee domains
    and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    source: str = (
        "https://raw.githubusercontent.com/elliotwutingfeng/EstonianInternetFoundationDomains/main/domains.txt"
    )
    txt_data: bytes = (
        await get_async([source], max_concurrent_requests=1, max_retries=2)
    )[source]
    if txt_data != b"{}":
        # Extract URLs from TXT file
        raw_urls = [url.strip() for url in txt_data.decode().splitlines()]
        for batch in chunked(raw_urls, hostname_expression_batch_size):
            yield generate_hostname_expressions(batch)


class InternetEE:
    """
    For fetching and scanning URLs from internet.ee
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "internet_ee" in parser_args["sources"]:
            self.db_filenames = ["internet_ee"]
            if parser_args["fetch"]:
                # Download and Add internet.ee URLs to database
                self.jobs = [(get_ee_domains, update_time, self.db_filenames[0])]
