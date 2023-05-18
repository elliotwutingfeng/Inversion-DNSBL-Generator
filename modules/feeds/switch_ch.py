"""
For fetching and scanning URLs from Switch.ch
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


async def get_switch_ch_domains(tld: str, key: str) -> AsyncIterator[set[str]]:
    """Download and extract domains from Switch.ch zonefiles
    and yield all listed URLs in batches.

    Args:
        tld (str): Switch.ch Top Level Domain
        (either 'ch' or 'li')
        key (str): TSIG key for doing a DNS zone transfer
        (AXFR) from zonedata.switch.ch

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
                        "-y",
                        key,
                        "@zonedata.switch.ch",
                        "+noall",
                        "+answer",
                        "+noidnout",
                        "+onesoa",
                        "AXFR",
                        f"{tld}.",
                    ],
                    stdout=temp_file,
                    timeout=9000,  # 2.5 hours
                )
                temp_file.seek(0)
                raw_urls = [
                    splitted_line[0].lower().rstrip(".")
                    for line in temp_file.read().splitlines()
                    if (
                        splitted_line := line.split()
                    )  # if splitted_line has a length of at least 1
                ]
        except Exception as error:
            errors.append(error)
        else:
            successful = True
        if successful:
            break

    if not successful:
        logger.error("Switch.ch zone transfer failed for tld: %s | %s", tld, errors)

    for batch in chunked(raw_urls, hostname_expression_batch_size):
        yield generate_hostname_expressions(batch)


class SwitchCH:
    """
    For fetching and scanning URLs from switch.ch
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        # Normally it is unwise to put TSIG keys in source code,
        # but in this case they are already available to the public
        # at https://www.switch.ch/open-data
        tlds = {
            "ch": "hmac-sha512:tsig-zonedata-ch-public-21-01:"
            "stZwEGApYumtXkh73qMLPqfbIDozWKZLkqRvcjKSpRnsor6A"
            "6MxixRL6C2HeSVBQNfMW4wer+qjS0ZSfiWiJ3Q==",
            "li": "hmac-sha512:tsig-zonedata-li-public-21-01:"
            "t8GgeCn+fhPaj+cRy1epox2Vj4hZ45ax6v3rQCkkfIQNg5fs"
            "xuU23QM5mzz+BxJ4kgF/jiQyBDBvL+XWPE6oCQ==",
        }
        if "switch_ch" in parser_args["sources"]:
            self.db_filenames = [f"switch_ch_{tld}" for tld in tlds]
            if parser_args["fetch"]:
                # Download and Add switch.ch URLs to database
                self.jobs = [
                    (
                        get_switch_ch_domains,
                        update_time,
                        db_filename,
                        {"tld": tld, "key": key},
                    )
                    for db_filename, (tld, key) in zip(self.db_filenames, tlds.items())
                ]
