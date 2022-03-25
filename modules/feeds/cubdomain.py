"""
For fetching and scanning URLs from cubdomain.com
"""

import asyncio
from collections import ChainMap
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Optional

import cchardet  # noqa: F401
from bs4 import BeautifulSoup, SoupStrainer
from modules.utils.feeds import generate_hostname_expressions
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from more_itertools import chunked, flatten

logger = init_logger()

YYYY_MM_DD_STR_FORMAT: str = "{dt:%Y}-{dt:%m}-{dt:%d}"


def _generate_dates_and_root_urls(num_days: Optional[int]) -> tuple[list[datetime], list[str]]:
    """Generate list of dates and corresponding root URLs ranging
    from 25th June 2017 to today inclusive

    Args:
        num_days (Optional[int]): Counting back from current date,
        the number of days of CubDomain.com data
        to fetch and/or analyse.
        If set to `None`, all available data
        dating back to 25 June 2017 will be considered.

    Returns:
        tuple[list[datetime], list[str]]: (Dates,Root URLs for each date)
    """
    now = datetime.now()
    if num_days is None:
        num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x) for x in range(num_days)]
    root_urls = [f"https://www.cubdomain.com/domains-registered-by-date/{YYYY_MM_DD_STR_FORMAT}/".format(dt=date) for date in dates]

    return dates, root_urls


async def _create_root_url_map(root_url: str, date: datetime, content: bytes) -> dict:
    """Determine number of available pages for
    `date` YYYY-MM-DD represented by`root_url`.

    Args:
        root_url (str): Root URL representing `date`
        date (datetime): Date for given `root_url`
        content (bytes): first page content for given `root_url`

    Returns:
        dict: Mapping of root URL to its total number of pages and its date
    """
    root_url_to_last_page_and_date = dict()

    if content:
        try:
            # Find all instances of "/domains-registered-by-date/YYYY-MM-DD/{page_number}"
            only_a_tag_with_page_link = SoupStrainer(
                "a",
                class_="page-link",
                href=lambda x: "/domains-registered-by-date/" in x,
            )
            soup = BeautifulSoup(
                content,
                "lxml",
                parse_only=only_a_tag_with_page_link,
            )
            res = soup.find_all(lambda tag: tag.string is not None)  # Filter out empty tags
            # Get the highest possible value of
            # {page_number}; the total number of pages for date YYYY-MM-DD
            last_page = max([1] + [int(x.string.strip()) for x in res if x.string.strip().isnumeric()])
            root_url_to_last_page_and_date[root_url] = {
                "num_pages": last_page,
                "date": date,
            }
        except Exception as error:
            logger.error("%s %s", root_url + "1", error, exc_info=True)
    return root_url_to_last_page_and_date


async def _get_page_urls_by_date_str(num_days: Optional[int]) -> dict:
    """Create list of all domain pages for all dates

    Args:
        num_days (Optional[int]): Counting back from current date,
        the number of days of CubDomain.com data to fetch and/or analyse. If set to `None`,
        all available data dating back to 25 June 2017 will be considered.

    Returns:
        dict: Mapping of date string to its page URLs
    """
    dates, root_urls = _generate_dates_and_root_urls(num_days)
    first_page_url_to_date = dict(zip([root_url + "1" for root_url in root_urls], dates))

    first_page_responses = await get_async([root_url + "1" for root_url in root_urls])

    root_urls_dates_and_contents = [
        (first_page_url[:-1], first_page_url_to_date[first_page_url], content) for first_page_url, content in first_page_responses.items()
    ]

    root_urls_to_last_page_and_date = dict(
        ChainMap(*execute_with_ray(_create_root_url_map, root_urls_dates_and_contents))
    )  # Mapping of each root URL to its total number of pages and its date
    page_urls_by_date_str: dict = dict()
    for root_url, details in root_urls_to_last_page_and_date.items():
        date_str = f"{YYYY_MM_DD_STR_FORMAT}".format(dt=details["date"])
        page_urls_by_date_str[date_str] = []
        for page_number in range(1, details["num_pages"] + 1):
            page_urls_by_date_str[date_str].append(f"{root_url}{page_number}")
    return page_urls_by_date_str


async def _get_cubdomain_page_urls(num_days: Optional[int]) -> list[str]:
    """Create list of all cubdomain page urls

    Args:
        num_days (Optional[int]): Counting back from current date,
        the number of days of CubDomain.com data to fetch and/or analyse.
        If set to `None`, all available data dating back
        to 25 June 2017 will be considered.

    Returns:
        list[str]: List of all cubdomain page urls
    """

    cubdomain_page_urls_by_date_str = await _get_page_urls_by_date_str(num_days)
    cubdomain_page_urls = list(flatten(cubdomain_page_urls_by_date_str.values()))

    return cubdomain_page_urls


async def _download_cubdomain(page_urls: list[str]) -> AsyncIterator[set[str]]:
    """Download cubdomain.com domains and yield
    all listed URLs from each page_url in `page_urls`.

    Each listed domain is encapsulated in this tag
    '<a href="https://www.cubdomain.com/site/ ...'

    Args:
        page_urls (list[str]): Page URLs containing domains

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """

    async def extract_domains(page_url, page_response):
        if page_response != b"{}":
            try:
                only_a_tag_with_cubdomain_site = SoupStrainer("a", href=lambda x: "cubdomain.com/site/" in x)
                soup = BeautifulSoup(
                    page_response,
                    "lxml",
                    parse_only=only_a_tag_with_cubdomain_site,
                )
                res = soup.find_all(lambda tag: tag.string is not None)  # Filter out empty tags
                # Ensure that raw_url is always lowercase
                return generate_hostname_expressions([tag.string.strip().lower() for tag in res])
            except Exception as error:
                logger.error("%s %s", page_url, error, exc_info=True)
                return set()

    for page_urls_ in chunked(page_urls, 1000):  # download in small batches to overcome memory constraints
        page_responses = await get_async(page_urls_)

        domains = set().union(
            *execute_with_ray(
                extract_domains, [(page_url, page_response) for page_url, page_response in page_responses.items()], progress_bar=False
            )
        )
        yield domains


class CubDomain:
    """
    For fetching and scanning URLs from cubdomain.com
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.page_urls = list()
        self.num_days: Optional[int] = parser_args["cubdomain_num_days"]
        if "cubdomain" in parser_args["sources"]:
            self.db_filenames = ["cubdomain"]
            if parser_args["fetch"]:
                # Download and Add CubDomain.com URLs to database
                self.page_urls = asyncio.get_event_loop().run_until_complete(_get_cubdomain_page_urls(self.num_days))
                self.jobs = [
                    (
                        _download_cubdomain,
                        update_time,
                        self.db_filenames[0],
                        {"page_urls": self.page_urls},
                    )
                ]
