"""
For fetching and scanning URLs from cubdomain.com
"""
from datetime import datetime, timedelta
from collections import ChainMap
from typing import Dict, Iterator, List, Tuple
from bs4 import BeautifulSoup, SoupStrainer
import cchardet  # pylint: disable=unused-import
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.http import curl_get
from modules.feeds.hostname_expressions import generate_hostname_expressions


logger = init_logger()


def _generate_dates_and_root_urls() -> Tuple[List[datetime], List[str]]:
    """Generate list of dates ranging
    from 25th June 2017 to today inclusive

    Returns:
        Tuple[List[datetime], List[str]]: (Dates,Root URLs for each date)
    """
    #
    now = datetime.now()
    num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x) for x in range(num_days)]
    root_urls = [
        "https://www.cubdomain.com/domains-registered-by-date/{dt:%Y}-{dt:%m}-{dt:%d}/".format(
            dt=date
        )
        for date in dates
    ]

    return dates, root_urls


def _create_root_url_map(date: datetime, root_url: str) -> Dict:
    """Determine number of available pages for
    `date` YYYY-MM-DD represented by`root_url`.

    Args:
        date (datetime): Date for given `root_url`
        root_url (str): Root URL representing `date`

    Returns:
        Dict: Mapping of root URL to its total number of pages and its date
    """
    # pylint: disable=broad-except
    root_url_to_last_page_and_date = dict()
    first_page_url = root_url + "1"
    # Go to page 1
    first_page_response: str = curl_get(first_page_url).decode()
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


def _get_page_urls_by_date_str() -> Dict:
    """Create list of all domain pages for all dates

    Returns:
        Dict: Mapping of date string to its page URLs
    """
    dates, root_urls = _generate_dates_and_root_urls()
    root_urls_to_last_page_and_date = dict(
        ChainMap(*execute_with_ray(_create_root_url_map, list(zip(dates, root_urls))))
    )  # Mapping of each root URL to its total number of pages and its date
    page_urls_by_date_str: Dict = dict()
    for root_url, details in root_urls_to_last_page_and_date.items():
        date_str = "{dt:%Y}-{dt:%m}-{dt:%d}".format(  # pylint: disable=invalid-name
            dt=details["date"]
        )
        page_urls_by_date_str[date_str] = []
        for page_number in range(1, details["num_pages"] + 1):
            page_urls_by_date_str[date_str].append(f"{root_url}{page_number}")
    return page_urls_by_date_str


def _get_cubdomain_page_urls_by_db_filename() -> Dict:
    """Create list of all domain pages for all db_filenames

    Returns:
        Dict: Mapping of db_filename to page_urls
    """
    cubdomain_page_urls_by_date_str = _get_page_urls_by_date_str()
    cubdomain_page_urls_by_db_filename = {
            f"cubdomain_{date_str}": page_urls
            for date_str, page_urls in cubdomain_page_urls_by_date_str.items()
        }
    return cubdomain_page_urls_by_db_filename


def _download_cubdomain(page_urls: List[str]) -> Iterator[List[str]]:
    """Download cubdomain.com domains and yields
    all listed URLs from each page_url in `page_urls`.

    Each listed domain is encapsulated in this tag
    '<a href="https://www.cubdomain.com/site/ ...'

    Args:
        page_urls (List[str]): Page URLs containing domains registered on date `date_str`

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    # pylint: disable=broad-except
    only_a_tag_with_cubdomain_site = SoupStrainer(
        "a", href=lambda x: "cubdomain.com/site/" in x
    )
    for page_url in page_urls:
        page_response: str = curl_get(page_url).decode()
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
                yield generate_hostname_expressions([tag.string.strip() for tag in res])
            except Exception as error:
                logger.error("%s %s", page_url, error, exc_info=True)
                yield []

class CubDomain:
    """
    For fetching and scanning URLs from cubdomain.com
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args:Dict,update_time:int):
        self.db_filenames: List[str] = []
        self.jobs: List[Tuple] = []
        self.page_urls_by_db_filename = dict()
        if "cubdomain" in parser_args["sources"]:
            self.page_urls_by_db_filename = _get_cubdomain_page_urls_by_db_filename()
            self.db_filenames = list(self.page_urls_by_db_filename)
            if parser_args["fetch"]:
                # Download and Add CubDomain.com URLs to database
                self.jobs = [
                (
                    _download_cubdomain,
                    update_time,
                    db_filename,
                    {"page_urls": page_urls},
                )
                for db_filename, page_urls in self.page_urls_by_db_filename.items()
                ]
                