"""
For fetching and scanning URLs from Tranco TOP1M
"""
from collections.abc import AsyncIterator
from io import BytesIO
from zipfile import ZipFile
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_async
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions


logger = init_logger()

async def _get_top1m_url_list() -> AsyncIterator[list[str]]:
    """Download the Tranco TOP1M dataset and yield all listed URLs in batches.

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list
    """
    logger.info("Downloading TOP1M list...")
    with BytesIO() as file:
        endpoint: str = "https://tranco-list.eu/top-1m.csv.zip"
        resp = (await get_async([endpoint]))[endpoint]
        if resp != b"{}":
            file.write(resp)
            zipfile = ZipFile(file)
            # Ensure that raw_url is always lowercase
            raw_urls = (
                x.strip().decode().split(",")[1].lower()
                for x in zipfile.open(zipfile.namelist()[0]).readlines()
            )
            logger.info("Downloading TOP1M list... [DONE]")

            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
        else:
            logger.warning("Failed to retrieve TOP1M list; yielding empty list")
            yield []



class Top1M:
    """
    For fetching and scanning URLs from Tranco TOP1M
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "top1m" in parser_args["sources"]:
            self.db_filenames = ["top1m_urls"]
            if parser_args["fetch"]:
                # Download and Add TOP1M URLs to database
                self.jobs = [(_get_top1m_url_list, update_time, "top1m_urls")]
