"""
For fetching and scanning URLs from Tranco TOP1M
"""

from collections.abc import AsyncIterator
from io import BytesIO
from zipfile import ZipFile

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger
from more_itertools import chunked

logger = init_logger()


async def _get_top1m_url_list() -> AsyncIterator[set[str]]:
    """Download the Tranco TOP1M dataset and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """
    with BytesIO() as file:
        endpoint: str = "https://tranco-list.eu/top-1m.csv.zip"
        resp = (await get_async([endpoint]))[endpoint]
        if resp != b"{}":
            file.write(resp)
            zfile = ZipFile(file)
            # Ensure that raw_url is always lowercase
            raw_urls = (
                splitted_line[1].lower()
                for line in zfile.open(zfile.namelist()[0]).readlines()
                if len(splitted_line := line.strip().decode().split(",")) >= 2
            )

            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
        else:
            logger.warning("Failed to retrieve TOP1M list; yielding empty list")
            yield set()


class Top1M:
    """
    For fetching and scanning URLs from Tranco TOP1M
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "top1m" in parser_args["sources"]:
            self.db_filenames = ["top1m_urls"]
            if parser_args["fetch"]:
                # Download and Add TOP1M URLs to database
                self.jobs = [(_get_top1m_url_list, update_time, "top1m_urls")]
