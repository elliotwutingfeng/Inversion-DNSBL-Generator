"""
For fetching and scanning URLs from Internet.ee
"""
import os
import subprocess
from collections.abc import AsyncIterator
import tempfile
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions


logger = init_logger()

async def get_ee_domains() -> AsyncIterator[set[str]]:
    """Download and extract domains from Internet.ee zonefile and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    spooled_tempfile = tempfile.SpooledTemporaryFile(max_size=1 * 1024 ** 3,mode='w+',dir=os.getcwd())
    with spooled_tempfile:
        subprocess.call(["dig", "@zone.internet.ee", "+noall", "+answer", "+noidnout", "+onesoa", "AXFR", "ee."], stdout=spooled_tempfile)
        spooled_tempfile.seek(0)
        raw_urls: list[str] = [line.split()[0].lower().rstrip(".") for line in spooled_tempfile.read().splitlines()]

        for batch in chunked(raw_urls, hostname_expression_batch_size):
            yield generate_hostname_expressions(batch)


class InternetEE:
    """
    For fetching and scanning URLs from internet.ee
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "internet_ee" in parser_args["sources"]:
            self.db_filenames = ["internet_ee"]
            if parser_args["fetch"]:
                # Download and Add internet.ee URLs to database
                self.jobs = [(get_ee_domains, update_time, self.db_filenames[0])]