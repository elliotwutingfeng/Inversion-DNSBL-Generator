"""
For fetching and scanning URLs from cubdomain.com
"""

import asyncio
from datetime import datetime, timedelta
from collections import ChainMap
from collections.abc import AsyncIterator
from bs4 import BeautifulSoup, SoupStrainer
import cchardet # pylint: disable=unused-import
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.http import get_async
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions
from typing import Union


logger = init_logger()

YYYY_MM_DD_STR_FORMAT: str = "{dt:%Y}-{dt:%m}-{dt:%d}"

def _generate_dates_and_root_urls(num_days: Union[int,None]) -> tuple[list[datetime], list[str]]:
    """Generate list of dates and corresponding root URLs ranging
    from 25th June 2017 to today inclusive

    Args:
        num_days (Union[int,None]): Counting back from current date, 
        the number of days of CubDomain.com data to fetch and/or analyse. If set to `None`,
        all available data dating back to 25 June 2017 will be considered.

    Returns:
        tuple[list[datetime], list[str]]: (Dates,Root URLs for each date)
    """
    now = datetime.now()
    if num_days is None:
        num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x) for x in range(num_days)]
    root_urls = [
        f"https://www.cubdomain.com/domains-registered-by-date/{YYYY_MM_DD_STR_FORMAT}/".format(
            dt=date
        )
        for date in dates
    ]

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
    # pylint: disable=broad-except
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
            res = soup.find_all(
                lambda tag: tag.string is not None
            )  # Filter out empty tags
            # Get the highest possible value of
            # {page_number}; the total number of pages for date YYYY-MM-DD
            last_page = max(
                [1]
                + [int(x.string.strip()) for x in res if x.string.strip().isnumeric()]
            )
            root_url_to_last_page_and_date[root_url] = {
                "num_pages": last_page,
                "date": date,
            }
        except Exception as error:
            logger.error("%s %s", root_url+"1", error, exc_info=True)
    return root_url_to_last_page_and_date


async def _get_page_urls_by_date_str(num_days: Union[int,None]) -> dict:
    """Create list of all domain pages for all dates

    Args:
        num_days (Union[int,None]): Counting back from current date, 
        the number of days of CubDomain.com data to fetch and/or analyse. If set to `None`,
        all available data dating back to 25 June 2017 will be considered.

    Returns:
        dict: Mapping of date string to its page URLs
    """
    dates, root_urls = _generate_dates_and_root_urls(num_days)
    first_page_url_to_date = dict(zip([root_url + "1" for root_url in root_urls],dates))

    first_page_responses = await get_async([root_url + "1" for root_url in root_urls])

    root_urls_dates_and_contents = [(first_page_url[:-1],first_page_url_to_date[first_page_url],content)
    for first_page_url,content in first_page_responses.items()]

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


async def _get_cubdomain_page_urls_by_db_filename(num_days: Union[int,None]) -> dict:
    """Create list of all domain pages for all db_filenames

    Args:
        num_days (Union[int,None]): Counting back from current date, 
        the number of days of CubDomain.com data to fetch and/or analyse. If set to `None`,
        all available data dating back to 25 June 2017 will be considered.

    Returns:
        dict: Mapping of db_filename to page_urls
    """

    cubdomain_page_urls_by_date_str = await _get_page_urls_by_date_str(num_days)
    cubdomain_page_urls_by_db_filename = {
            f"cubdomain_{date_str}": page_urls
            for date_str, page_urls in cubdomain_page_urls_by_date_str.items()
        }

    return cubdomain_page_urls_by_db_filename


async def _download_cubdomain(page_urls: list[str]) -> AsyncIterator[set[str]]:
    """Download cubdomain.com domains and yield
    all listed URLs from each page_url in `page_urls`.

    Each listed domain is encapsulated in this tag
    '<a href="https://www.cubdomain.com/site/ ...'

    Args:
        page_urls (list[str]): Page URLs containing domains registered on date `date_str`

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """
    # pylint: disable=broad-except
    page_responses = await get_async(page_urls)

    only_a_tag_with_cubdomain_site = SoupStrainer(
        "a", href=lambda x: "cubdomain.com/site/" in x
    )
    for page_url,page_response in page_responses.items():
        if page_response != b"{}":
            try:
                soup = BeautifulSoup(
                    page_response,
                    "lxml",
                    parse_only=only_a_tag_with_cubdomain_site,
                )
                res = soup.find_all(
                    lambda tag: tag.string is not None
                )  # Filter out empty tags
                for raw_urls in chunked((tag.string.strip().lower() for tag in res),
                hostname_expression_batch_size): # Ensure that raw_url is always lowercase
                    yield generate_hostname_expressions(raw_urls)
            except Exception as error:
                logger.error("%s %s", page_url, error, exc_info=True)
                yield set()


class CubDomain:
    """
    For fetching and scanning URLs from cubdomain.com
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.page_urls_by_db_filename = dict()
        self.num_days: Union[int,None] = parser_args["cubdomain_num_days"]
        if "cubdomain" in parser_args["sources"]:
            self.db_filenames = [f"cubdomain_{YYYY_MM_DD_STR_FORMAT}".format(dt=date) for date
            in _generate_dates_and_root_urls(self.num_days)[0]]
            if parser_args["fetch"]:
                # Download and Add CubDomain.com URLs to database
                self.page_urls_by_db_filename = asyncio.get_event_loop().run_until_complete(_get_cubdomain_page_urls_by_db_filename(self.num_days))
                self.jobs = [
                (
                    _download_cubdomain,
                    update_time,
                    db_filename,
                    {"page_urls": page_urls},
                )
                for db_filename, page_urls in self.page_urls_by_db_filename.items()
                ]
                