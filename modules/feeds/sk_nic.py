"""
For fetching and scanning URLs from SK-NIC.sk
"""
from collections.abc import AsyncIterator
from io import BytesIO

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger
from more_itertools import chunked

logger = init_logger()


async def _get_sknic_urls() -> AsyncIterator[set[str]]:
    """Download SK-NIC.sk domains and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """
    with BytesIO() as file:
        endpoint: str = "https://sk-nic.sk/subory/domains.txt"
        resp = (
            await get_async(
                [endpoint],
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
                },
            )
        )[endpoint]
        if resp != b"{}":
            file.write(resp)
            file.seek(0)
            # Ensure that raw_url is always lowercase
            raw_urls = (
                first_item
                for row in file.read().decode().splitlines()
                if (not row.startswith("-")) and (first_item := row.strip().split(";")[0].lower()).endswith(".sk")
            )

            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
        else:
            logger.warning("Failed to retrieve SK-NIC.sk domains; yielding empty list")
            yield set()


class SKNIC:
    """
    For fetching and scanning URLs from SK-NIC.sk
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "sknic" in parser_args["sources"]:
            self.db_filenames = ["sknic"]
            if parser_args["fetch"]:
                # Download and Add SK-NIC.sk URLs to database
                self.jobs = [(_get_sknic_urls, update_time, "sknic")]
