"""
For fetching and scanning URLs from OpenINTEL.nl
"""
import tarfile
from collections.abc import AsyncIterator

from bs4 import BeautifulSoup, SoupStrainer
from modules.utils.feeds import generate_hostname_expressions
from modules.utils.http_requests import get_async, get_async_stream
from modules.utils.log import init_logger
from spavro.datafile import DataFileReader
from spavro.io import FastDatumReader

logger = init_logger()


async def get_latest_tarball_url() -> str:
    """Scrape OpenINTEL.nl for the latest open-tld tarball URL

    Returns:
        str: Latest OpenINTEL.nl open-tld tarball URL
    """
    openintel_url = "https://data.openintel.nl/data/open-tld"
    openintel_url_content = (await get_async([openintel_url]))[openintel_url]

    only_a_tag_with_year = SoupStrainer(
        "a",
        href=lambda x: len(x) == 5 and x[:-1].isnumeric(),
    )
    soup = BeautifulSoup(
        openintel_url_content,
        "lxml",
        parse_only=only_a_tag_with_year,
    )
    res = soup.find_all(lambda tag: tag.string is not None)  # Filter out empty tags

    latest_year: int | None = (
        years[-1]
        if (years := sorted(int(content.string.strip("/")) for content in res))
        else None
    )

    if latest_year is None:
        raise ValueError("No year folders found")

    openintel_year_url = f"{openintel_url}/{latest_year}"
    openintel_year_url_content = (await get_async([openintel_year_url]))[
        openintel_year_url
    ]

    only_a_tag_with_tar = SoupStrainer(
        "a",
        href=lambda x: x.endswith(".tar"),
    )
    soup = BeautifulSoup(
        openintel_year_url_content,
        "lxml",
        parse_only=only_a_tag_with_tar,
    )
    res = soup.find_all(lambda tag: tag.string is not None)  # Filter out empty tags

    latest_tarball: str | None = (
        tarballs[-1]
        if (tarballs := sorted(tag_attrs.get("href") for tag_attrs in res))
        else None
    )

    if latest_tarball is None:
        raise ValueError("No tarballs found")

    endpoint = f"{openintel_year_url}/{latest_tarball}"
    return endpoint


async def _get_openintel_url_list() -> AsyncIterator[set[str]]:
    """Download domains from OpenINTEL.nl endpoint
    and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set

    """
    try:
        endpoint = await get_latest_tarball_url()
        url_generator = extract_openintel_urls(endpoint)
        async for batch in url_generator:
            yield generate_hostname_expressions(batch)
    except Exception as error:
        logger.warning("Failed to retrieve OpenINTEL.nl list %s | %s", endpoint, error)
        yield set()


async def extract_openintel_urls(
    endpoint: str, headers: dict | None = None
) -> AsyncIterator[list[str]]:
    """Extract URLs from GET request stream of OpenINTEL.nl tarball

    Args:
        endpoint (str): HTTP GET request endpoint
        headers (dict, optional): HTTP Headers to send with every request.
        Defaults to None.

    Raises:
        aiohttp.client_exceptions.ClientError: Stream disrupted

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list
    """
    hostnames: set[str] = set()

    fields = (
        "query_name",
        "response_name",
        "soa_mname",
        "soa_rname",
    )

    temp_file = await get_async_stream(endpoint, headers=headers)
    if temp_file:
        with temp_file, tarfile.open(fileobj=temp_file, mode="r") as tar:
            for tarinfo in tar:
                fo = tar.extractfile(tarinfo.name)
                hostnames = set()
                for record in DataFileReader(fo, FastDatumReader()):
                    hostnames.update(
                        record[f][:-1] if f in record and record[f] is not None else ""
                        for f in fields
                    )
                hostnames.discard("")
                yield list(hostnames)


class OpenINTEL:
    """
    For fetching and scanning URLs from OpenINTEL.nl
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "openintel" in parser_args["sources"]:
            self.db_filenames = ["openintel"]
            if parser_args["fetch"]:
                # Download and Add OpenINTEL.nl URLs to database
                self.jobs = [(_get_openintel_url_list, update_time, "openintel")]
