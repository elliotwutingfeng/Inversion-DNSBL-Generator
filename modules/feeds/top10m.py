"""
For fetching and scanning URLs from DomCop TOP10M
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


async def _get_top10m_url_list() -> AsyncIterator[set[str]]:
    """Download the DomCop TOP10M dataset and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """
    with BytesIO() as file:
        endpoint: str = "https://www.domcop.com/files/top/top10milliondomains.csv.zip"
        resp = (await get_async([endpoint]))[endpoint]
        if resp != b"{}":
            file.write(resp)
            zfile = ZipFile(file)
            # Ensure that raw_url is always lowercase
            raw_urls = (
                splitted_line[1].replace('"', "").lower()
                for line in zfile.open(zfile.namelist()[0]).readlines()[1:]
                if len(splitted_line := line.strip().decode().split(",")) >= 2
            )

            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
        else:
            logger.warning("Failed to retrieve TOP10M list; yielding empty list")
            yield set()


class Top10M:
    """
    For fetching and scanning URLs from DomCop TOP10M
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "top10m" in parser_args["sources"]:
            self.db_filenames = ["top10m_urls"]
            if parser_args["fetch"]:
                # Download and Add TOP10M URLs to database
                self.jobs = [(_get_top10m_url_list, update_time, "top10m_urls")]
