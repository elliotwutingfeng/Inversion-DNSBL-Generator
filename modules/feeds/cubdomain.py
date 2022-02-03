"""
For fetching and scanning URLs from cubdomain.com
"""
import aiohttp
import asyncio
from datetime import datetime, timedelta
from collections import ChainMap
from collections.abc import AsyncIterator,Iterator
from bs4 import BeautifulSoup, SoupStrainer
import cchardet # pylint: disable=unused-import
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.http import curl_req
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions


logger = init_logger()

DATE_STR_FORMAT: str = "{dt:%Y}-{dt:%m}-{dt:%d}"

def _generate_dates_and_root_urls() -> tuple[list[datetime], list[str]]:
    """Generate list of dates ranging
    from 25th June 2017 to today inclusive

    Returns:
        tuple[list[datetime], list[str]]: (Dates,Root URLs for each date)
    """
    #
    now = datetime.now()
    num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x) for x in range(num_days)]
    root_urls = [
        f"https://www.cubdomain.com/domains-registered-by-date/{DATE_STR_FORMAT}/".format(
            dt=date
        )
        for date in dates
    ]

    return dates, root_urls


async def _create_root_url_map(date: datetime, root_url: str) -> dict:
    """Determine number of available pages for
    `date` YYYY-MM-DD represented by`root_url`.

    Args:
        date (datetime): Date for given `root_url`
        root_url (str): Root URL representing `date`

    Returns:
        dict: Mapping of root URL to its total number of pages and its date
    """
    # pylint: disable=broad-except
    root_url_to_last_page_and_date = dict()
    first_page_url = root_url + "1"
    # Go to page 1
    first_page_response: str = curl_req(first_page_url).decode()
    if first_page_response:
        try:
            # Find all instances of "/domains-registered-by-date/YYYY-MM-DD/{page_number}"
            only_a_tag_with_page_link = SoupStrainer(
                "a",
                class_="page-link",
                href=lambda x: "/domains-registered-by-date/" in x,
            )
            soup = BeautifulSoup(
                first_page_response,
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
            logger.error("%s %s", first_page_url, error, exc_info=True)
    return root_url_to_last_page_and_date


def _get_page_urls_by_date_str() -> dict:
    """Create list of all domain pages for all dates

    Returns:
        dict: Mapping of date string to its page URLs
    """
    dates, root_urls = _generate_dates_and_root_urls()
    root_urls_to_last_page_and_date = dict(
        ChainMap(*execute_with_ray(_create_root_url_map, list(zip(dates, root_urls))))
    )  # Mapping of each root URL to its total number of pages and its date
    page_urls_by_date_str: dict = dict()
    for root_url, details in root_urls_to_last_page_and_date.items():
        date_str = f"{DATE_STR_FORMAT}".format(dt=details["date"])
        page_urls_by_date_str[date_str] = []
        for page_number in range(1, details["num_pages"] + 1):
            page_urls_by_date_str[date_str].append(f"{root_url}{page_number}")
    return page_urls_by_date_str


def _get_cubdomain_page_urls_by_db_filename() -> dict:
    """Create list of all domain pages for all db_filenames

    Returns:
        dict: Mapping of db_filename to page_urls
    """
    logger.info("Creating list of all cubdomain.com pages")
    cubdomain_page_urls_by_date_str = _get_page_urls_by_date_str()
    cubdomain_page_urls_by_db_filename = {
            f"cubdomain_{date_str}": page_urls
            for date_str, page_urls in cubdomain_page_urls_by_date_str.items()
        }
    logger.info("Creating list of all cubdomain.com pages...[DONE]")
    return cubdomain_page_urls_by_db_filename


async def _download_cubdomain(page_urls: list[str]) -> AsyncIterator[list[str]]:
    """Download cubdomain.com domains and yields
    all listed URLs from each page_url in `page_urls`.

    Each listed domain is encapsulated in this tag
    '<a href="https://www.cubdomain.com/site/ ...'

    Args:
        page_urls (list[str]): Page URLs containing domains registered on date `date_str`

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list
    """
    # pylint: disable=broad-except
    page_responses = await _download_page_responses(page_urls)

    only_a_tag_with_cubdomain_site = SoupStrainer(
        "a", href=lambda x: "cubdomain.com/site/" in x
    )
    for page_url,page_response in page_responses.items():
        if page_response:
            try:
                soup = BeautifulSoup(
                    page_response,
                    "lxml",
                    parse_only=only_a_tag_with_cubdomain_site,
                )
                res = soup.find_all(
                    lambda tag: tag.string is not None
                )  # Filter out empty tags
                for raw_urls in chunked((tag.string.strip() for tag in res),
                hostname_expression_batch_size):
                    yield generate_hostname_expressions(raw_urls)
            except Exception as error:
                logger.error("%s %s", page_url, error, exc_info=True)
                yield []

async def _download_page_responses(page_urls: list[str]) -> dict[str,str]:
    """Downloads raw text content from a list of `page_urls` asynchronously

    Args:
        page_urls (list[str]): Page URLs to download from

    Returns:
        dict[str,str]: Mapping of page_url to its content
    """
    async def gather_with_concurrency(n: int, *tasks) -> dict[str,str]:
        semaphore = asyncio.Semaphore(n)

        async def sem_task(task):
            async with semaphore:
                return await task

        return dict(await asyncio.gather(*(sem_task(task) for task in tasks)))

    async def get_async(url, session):
        async with session.get(url) as response:
            return (url,await response.text())
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)) as session:
        # Limit number of concurrent connections to 10 to prevent rate-limiting by web server
        return await gather_with_concurrency(10, *[get_async(url, session) for url in page_urls])


class CubDomain:
    """
    For fetching and scanning URLs from cubdomain.com
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.page_urls_by_db_filename = dict()
        if "cubdomain" in parser_args["sources"]:
            self.db_filenames = [f"cubdomain_{DATE_STR_FORMAT}".format(dt=date) for date
            in _generate_dates_and_root_urls()[0]]
            if parser_args["fetch"]:
                # Download and Add CubDomain.com URLs to database
                self.page_urls_by_db_filename = _get_cubdomain_page_urls_by_db_filename()
                self.jobs = [
                (
                    _download_cubdomain,
                    update_time,
                    db_filename,
                    {"page_urls": page_urls},
                )
                for db_filename, page_urls in self.page_urls_by_db_filename.items()
                ]
                