"""
For fetching and scanning URLs from ICANN
"""
from collections.abc import AsyncIterator
import gzip
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_async
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions


logger = init_logger()

async def _get_icann_domains() -> AsyncIterator[list[str]]:
    """Download domains from ICANN and yields all listed URLs in batches.

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list
    """
    logger.info("Downloading ICANN lists...")

    endpoints: list[str] = [] # TODO

    page_responses = await get_async(endpoints)

    raw_urls: list[str] = []
    
    for endpoint,resp in page_responses.items():
        if resp != b"{}":
            decompressed_lines = gzip.decompress(resp).decode().split("\n")
            raw_urls += [line.split('.\t')[0].lower() for line in decompressed_lines]
        else:
            logger.warning("Failed to retrieve ICANN list %s",endpoint)

    logger.info("Downloading ICANN lists... [DONE]")
    for batch in chunked(raw_urls, hostname_expression_batch_size):
        yield generate_hostname_expressions(batch)

class ICANN:
    """
    For fetching and scanning URLs from ICANN
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "icann" in parser_args["sources"]:
            self.db_filenames = ["icann_urls"]
            if parser_args["fetch"]:
                # Download and Add ICANN URLs to database
                self.jobs = [(_get_icann_domains, update_time, "icann_urls")]
