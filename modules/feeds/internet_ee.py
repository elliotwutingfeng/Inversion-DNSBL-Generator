"""
For fetching and scanning URLs from Internet.ee
"""
import os
import subprocess
import tempfile
from collections.abc import AsyncIterator

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.log import init_logger
from more_itertools import chunked

logger = init_logger()


async def get_ee_domains() -> AsyncIterator[set[str]]:
    """Download and extract domains from Internet.ee zonefile
    and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    successful = False
    raw_urls: list[str] = []
    errors = []
    for _ in range(2):  # 2 attempts
        try:
            temp_file = tempfile.TemporaryFile(mode="w+", dir=os.getcwd())
            with temp_file:
                subprocess.run(
                    [
                        "dig",
                        "@zone.internet.ee",
                        "+noall",
                        "+answer",
                        "+noidnout",
                        "+onesoa",
                        "AXFR",
                        "ee.",
                    ],
                    stdout=temp_file,
                    timeout=9000,  # 2.5 hours
                )
                temp_file.seek(0)
                raw_urls = [
                    splitted_line[0].lower().rstrip(".")
                    for line in temp_file.read().splitlines()
                    if (splitted_line := line.split())  # if splitted_line has a length of at least 1
                ]
        except Exception as error:
            errors.append(error)
        else:
            successful = True
        if successful:
            break

    if not successful:
        logger.error("Internet.ee zone transfer failed. | %s", errors)

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
