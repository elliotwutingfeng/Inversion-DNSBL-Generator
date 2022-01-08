"""Scrapes domains from cubdomain.com
"""
from datetime import datetime, timedelta
import os
from typing import Dict, List, Tuple
from tqdm import tqdm
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from logger_utils import init_logger

logger = init_logger()

DEFAULT_TIMEOUT = 10  # seconds


class TimeoutHTTPAdapter(HTTPAdapter):
    """HTTP Adapter with connection timeout

    Args:
        HTTPAdapter: The built-in HTTP Adapter for urllib3
    """

    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        # pylint: disable=arguments-differ
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class EnhancedSession:
    # pylint: disable=too-few-public-methods
    """requests.Session() with connection timeout
    + connection retries with backoff"""

    def __init__(self):
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            backoff_factor=1,
        )
        self.http = requests.Session()
        assert_status_hook = (
            lambda response, *args, **kwargs: response.raise_for_status()
        )
        self.http.hooks["response"] = [assert_status_hook]
        self.http.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; "
                "Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
            }
        )
        self.http.mount("", TimeoutHTTPAdapter(max_retries=retry_strategy))

    def get_session(self) -> requests.Session:
        """getter

        Returns:
            requests.Session: requests.Session with
            connection timeout + connection retries with backoff
        """
        return self.http


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


def create_root_url_map(
    http: requests.Session, dates: List[datetime], root_urls: List[str]
) -> Dict:
    """Determine number of available pages for each date YYYY-MM-DD.
    Each date is represented by a root URL.

    Args:
        http (requests.Session): requests.Session with
        connection timeout + connection retries with backoff
        dates (List[datetime]): Dates
        root_urls (List[str]): Root URLs for each date

    Returns:
        Dict: Mapping of root URL to its total number of pages and its date
    """
    root_urls_to_last_page_and_date = dict()
    for date, root_url in tqdm(zip(dates, root_urls), total=len(root_urls)):
        # For each root_url with date YYYY-MM-DD in root_urls, go to page 1
        try:
            first_page_response = http.get(root_url + "1")

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
                [1]
                + [int(x.string.strip()) for x in res if x.string.strip().isnumeric()]
            )
            root_urls_to_last_page_and_date[root_url] = {
                "num_pages": last_page,
                "date": date,
            }
        except requests.exceptions.RequestException as error:
            logger.error(error)
    return root_urls_to_last_page_and_date


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
    http: requests.Session,
    page_urls_by_date_str: Dict,
    dataset_folder: str = "cubdomain_dataset",
) -> None:
    """Download the domains to .txt files in `dataset_folder`; one .txt file
    for each day.

    Args:
        http (requests.Session): requests.Session with
        connection timeout + connection retries with backoff
        page_urls_by_date_str (Dict): Mapping of date string to its page URLs
        dataset_folder (str, optional): Folder to store domain .txt files in.
        Defaults to "cubdomain_dataset".
    """
    if not os.path.exists(dataset_folder):
        os.mkdir(dataset_folder)

    for date_str, pages in tqdm(page_urls_by_date_str.items()):
        with open(f"{dataset_folder}{os.sep}cubdomain_{date_str}.txt", "w") as file:
            urls = set()
            for page in pages:
                try:
                    page_response = http.get(page)
                except requests.exceptions.RequestException as error:
                    logger.error(error)
                soup = BeautifulSoup(page_response.content, "html.parser")
                # Each listed domain is encapsulated in this
                # tag '<a href="https://www.cubdomain.com/site/ ...'
                res = soup.find_all("a", href=lambda x: "cubdomain.com/site/" in x)
                urls.update([line.string for line in res])
            file.write("\n".join(urls))


def scrape_cubdomain():
    """Scrapes domains from cubdomain.com"""

    http = EnhancedSession().get_session()
    dates, root_urls = generate_dates_and_root_urls()
    root_urls_to_last_page_and_date = create_root_url_map(http, dates, root_urls)
    page_urls_by_date_str = get_page_urls_by_date_str(root_urls_to_last_page_and_date)
    download_domains(http, page_urls_by_date_str, dataset_folder="cubdomain_dataset")


if __name__ == "__main__":
    scrape_cubdomain()
