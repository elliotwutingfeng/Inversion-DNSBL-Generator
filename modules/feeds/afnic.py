"""
For fetching and scanning URLs from AFNIC.fr
"""
import csv
from collections.abc import AsyncIterator
from datetime import date
from io import BytesIO, TextIOWrapper
from zipfile import ZipFile

import tldextract
from dateutil.relativedelta import relativedelta
from more_itertools import chunked

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger

# import secrets


logger = init_logger()

YYYYMMDD_STR_FORMAT: str = "{dt:%Y}{dt:%m}{dt:%d}"
YYYYMM_STR_FORMAT: str = "{dt:%Y}{dt:%m}"


def txt_extract(txt_data: bytes) -> list[str]:
    """Extract all valid URLs from a given `txt_data` bytes string

    Args:
        txt_data (bytes): Bytes string of text file

    Returns:
        list[str]: Valid URLs found in `txt_data`
    """
    lines = txt_data.decode().splitlines()
    start = lines.index("#BOF")
    end = lines.index("#EOF")
    if start == -1 or end == -1:
        return []
    return [
        url
        for line in lines[start + 1 : end]
        if tldextract.extract(url := line.strip()).fqdn
    ]


async def get_afnic_daily_updates(
    tld: str, num_days: int | None
) -> AsyncIterator[set[str]]:
    """Download and extract domains from AFNIC.fr daily updates (TXT files) for a given `tld`
    and yield all listed URLs in batches.

    Args:
        tld (str): AFNIC.fr tld
        num_days (int, optional): Counting back from current date,
        the number of days of AFNIC.fr daily updates to fetch and/or analyse. If set to `None`,
        `num days` will be set to 0.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    raw_urls: list[str] = []

    today = date.today()

    if num_days is None:
        num_days = 0
    days = [today + relativedelta(days=-x) for x in range(num_days)]

    links: list[str] = [
        f"https://www.afnic.fr/wp-media/ftp/domaineTLD_Afnic/{YYYYMMDD_STR_FORMAT}_CREA_{tld}.txt".format(
            dt=date
        )
        for date in days
    ]

    for link in links:
        # Download TXT file to memory
        txt_data: bytes = (
            await get_async(links, max_concurrent_requests=1, max_retries=2)
        )[link]
        if txt_data != b"{}":
            # Extract URLs from TXT file
            raw_urls = txt_extract(txt_data)
            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)


async def get_afnic_monthly_archives() -> AsyncIterator[set[str]]:
    """Download and extract domains from AFNIC.fr monthly archives
    and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    raw_urls: list[str] = []

    today = date.today()

    # Archives files are only kept for the past 24 months, we only need the latest version
    months = [today + relativedelta(months=-x) for x in range(24)]

    # AFNIC.fr monthly archive files
    endpoints: list[str] = [
        f"https://www.afnic.fr/wp-media/ftp/documentsOpenData/{YYYYMM_STR_FORMAT}_OPENDATA_A-NomsDeDomaineEnPointFr.zip".format(
            dt=date
        )
        for date in months
    ]

    for endpoint in endpoints:
        with BytesIO() as file:
            resp = (
                await get_async([endpoint], max_concurrent_requests=1, max_retries=2)
            )[endpoint]
            if resp != b"{}":
                file.write(resp)
                file.seek(0)
                zfile = ZipFile(file)
                csv_filename = [
                    filename
                    for filename in zfile.namelist()
                    if filename.endswith(".csv")
                ][0]
                with zfile.open(csv_filename) as csvfile:
                    reader = csv.reader(
                        TextIOWrapper(csvfile, "ISO-8859-1"), delimiter=";"
                    )
                    next(reader, None)  # skip the headers
                    for row in reader:
                        raw_urls.append(row[0])
                for batch in chunked(raw_urls, hostname_expression_batch_size):
                    yield generate_hostname_expressions(batch)
                break  # we only need the first accessible archive


class AFNIC:
    """
    For fetching and scanning URLs from AFNIC.fr
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.num_days: int | None = parser_args["afnic_num_days"]

        if "afnic" in parser_args["sources"]:
            tlds: tuple[str, ...] = ("fr", "re", "pm", "tf", "wf", "yt")
            self.db_filenames = [f"afnic_{tld}" for tld in tlds] + [
                "afnic_monthly_archive"
            ]
            if parser_args["fetch"]:
                # Download and Add AFNIC.fr URLs to database
                # Use list() otherwise mypy will complain about list invariance
                self.jobs = list(
                    [
                        (
                            get_afnic_daily_updates,
                            update_time,
                            db_filename,
                            {"tld": tld, "num_days": self.num_days},
                        )
                        for db_filename, tld in zip(self.db_filenames, tlds)
                    ]
                    + [
                        (
                            get_afnic_monthly_archives,
                            update_time,
                            self.db_filenames[-1],
                        )  # type:ignore
                    ]
                )
