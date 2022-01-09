"""Scrapes domains from cubdomain.com
"""
from datetime import datetime, timedelta
import os
from collections import ChainMap
from typing import Dict, List, Tuple
from bs4 import BeautifulSoup
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray
from modules.requests_utils import EnhancedSession


logger = init_logger()


def generate_dates_and_root_urls() -> Tuple[List[datetime], List[str]]:
    """Generate list of dates ranging
    from 25th June 2017 to yesterday inclusive

    Returns:
        Tuple[List[datetime], List[str]]: (Dates,Root URLs for each date)
    """
    #
    now = datetime.now()
    num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x + 1) for x in range(num_days)]
    root_urls = [
        "https://www.cubdomain.com/domains-registered-by-date/{dt:%Y}-{dt:%m}-{dt:%d}/".format(
            dt=date
        )
        for date in dates
    ]
    return dates, root_urls


def create_root_url_map(date: datetime, root_url: str) -> Dict:
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
    try:
        http = EnhancedSession().get_session()
        first_page_response = http.get(first_page_url)

        soup = BeautifulSoup(first_page_response.content, "html.parser")
        # Find all instances of "/domains-registered-by-date/YYYY-MM-DD/{page_number}"
        res = soup.find_all(
            "a",
            class_="page-link",
            href=lambda x: "/domains-registered-by-date/" in x,
        )
        # Get the highest possible value of
        # {page_number}; the total number of pages for date YYYY-MM-DD
        last_page = max(
            [1] + [int(x.string.strip()) for x in res if x.string.strip().isnumeric()]
        )
        root_url_to_last_page_and_date[root_url] = {
            "num_pages": last_page,
            "date": date,
        }
    except Exception as error:
        logger.error("%s %s", first_page_url, error)
    return root_url_to_last_page_and_date


def get_page_urls_by_date_str(root_urls_to_last_page_and_date: Dict) -> Dict:
    """Create list of all domain pages for all dates

    Args:
        root_urls_to_last_page_and_date (Dict): Mapping of root URL
        to its total number of pages and its date

    Returns:
        Dict: Mapping of date string to its page URLs
    """
    page_urls_by_date_str: Dict = dict()
    for root_url, details in root_urls_to_last_page_and_date.items():
        date_str = "{dt:%Y}-{dt:%m}-{dt:%d}".format(  # pylint: disable=invalid-name
            dt=details["date"]
        )
        page_urls_by_date_str[date_str] = []
        for page_number in range(1, details["num_pages"] + 1):
            page_urls_by_date_str[date_str].append(f"{root_url}{page_number}")
    return page_urls_by_date_str


def download_domains(
    date_str: str,
    page_urls: List[str],
    dataset_folder: str = "cubdomain_dataset",
) -> None:
    """Download the domains to .txt files in `dataset_folder`; one .txt file
    for each day.

    Args:
        date_str (str): Date when domains were registered
        page_urls (List[str]): Page URLs containing domains registered on date `date_str`
        dataset_folder (str, optional): Folder to store domain .txt file in.
        Defaults to "cubdomain_dataset".
    """
    # pylint: disable=broad-except
    if not os.path.exists(dataset_folder):
        os.mkdir(dataset_folder)

    with open(f"{dataset_folder}{os.sep}cubdomain_{date_str}.txt", "w") as file:
        urls = set()
        for page_url in page_urls:
            try:
                http = EnhancedSession().get_session()
                page_response = http.get(page_url)
                soup = BeautifulSoup(page_response.content, "html.parser")
                # Each listed domain is encapsulated in this
                # tag '<a href="https://www.cubdomain.com/site/ ...'
                res = soup.find_all("a", href=lambda x: "cubdomain.com/site/" in x)
                urls.update([line.string for line in res])
            except Exception as error:
                logger.error("%s %s", page_url, error)
        file.write("\n".join(urls))


def scrape_cubdomain():
    """Scrapes domains from cubdomain.com"""

    dates, root_urls = generate_dates_and_root_urls()
    root_urls_to_last_page_and_date = dict(
        ChainMap(*execute_with_ray(create_root_url_map, list(zip(dates, root_urls))))
    )

    page_urls_by_date_str = get_page_urls_by_date_str(root_urls_to_last_page_and_date)

    execute_with_ray(
        download_domains,
        [
            (date_str, page_urls, "cubdomain_dataset")
            for date_str, page_urls in page_urls_by_date_str.items()
        ],
    )
