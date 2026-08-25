"""
For fetching and scanning URLs from Internetstiftelsen
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


async def get_internetstiftelsen_domains() -> AsyncIterator[set[str]]:
    """Download and extract domains from Internetstiftelsen
    and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    sources: list[str] = [
        "https://raw.githubusercontent.com/elliotwutingfeng/InternetstiftelsenDomains/main/se_domains.txt",
        "https://raw.githubusercontent.com/elliotwutingfeng/InternetstiftelsenDomains/main/nu_domains.txt",
    ]
    txt_data: dict[str, bytes] = await get_async(
        sources, max_concurrent_requests=1, max_retries=2
    )
    for source in txt_data.keys():
        if txt_data[source] != b"{}":
            # Extract URLs from TXT file
            raw_urls = [url.strip() for url in txt_data[source].decode().splitlines()]
            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)


class Internetstiftelsen:
    """
    For fetching and scanning URLs from Internetstiftelsen
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "internetstiftelsen" in parser_args["sources"]:
            self.db_filenames = ["internetstiftelsen"]
            if parser_args["fetch"]:
                # Download and Add Internetstiftelsen URLs to database
                self.jobs = [
                    (get_internetstiftelsen_domains, update_time, self.db_filenames[0])
                ]
