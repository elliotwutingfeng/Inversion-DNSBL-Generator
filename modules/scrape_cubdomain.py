"""[summary]
"""
from datetime import datetime, timedelta
import os
import logging
from typing import Dict
from tqdm import tqdm
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup


DEFAULT_TIMEOUT = 10  # seconds


class TimeoutHTTPAdapter(HTTPAdapter):
    """[summary]

    Args:
        HTTPAdapter ([type]): [description]
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


def main():
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        backoff_factor=1,
    )

    http = requests.Session()
    assert_status_hook = lambda response, *args, **kwargs: response.raise_for_status()
    http.hooks["response"] = [assert_status_hook]
    http.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
        }
    )
    http.mount("", TimeoutHTTPAdapter(max_retries=retry_strategy))

    # Generate list of dates ranging from 25th June 2017 to yesterday inclusive
    now = datetime.now()
    num_days = (now - datetime.strptime("25 June 2017", "%d %B %Y")).days
    dates = [now - timedelta(days=x + 1) for x in range(num_days)]
    root_urls = [
        "https://www.cubdomain.com/domains-registered-by-date/{dt:%Y}-{dt:%m}-{dt:%d}/".format(
            dt=date
        )
        for date in dates
    ]

    # Determine number of available pages for each date YYYY-MM-DD
    root_urls_to_last_page_and_date = dict()
    for date, root_url in tqdm(zip(dates, root_urls), total=len(root_urls)):
        # For each root_url with date YYYY-MM-DD in root_urls, go to page 1
        try:
            first_page_response = http.get(root_url + "1")
        except requests.exceptions.RequestException as error:
            logging.error(error)

        soup = BeautifulSoup(first_page_response.content, "html.parser")
        # Find all instances of "/domains-registered-by-date/YYYY-MM-DD/{page_number}"
        res = soup.find_all(
            "a", class_="page-link", href=lambda x: "/domains-registered-by-date/" in x
        )
        # Get the highest possible value of {page_number}; the total number of pages for date YYYY-MM-DD
        lastPage = max([int(x.string) for x in res if x.string.isnumeric()])
        root_urls_to_last_page_and_date[root_url] = {
            "num_pages": lastPage,
            "date": date,
        }

    # Create list of all domain pages for all dates
    pages_by_date_str: Dict = dict()
    for root_url, details in root_urls_to_last_page_and_date.items():
        date_str = "{dt:%Y}-{dt:%m}-{dt:%d}".format(  # pylint: disable=invalid-name
            dt=details["date"]
        )
        pages_by_date_str[date_str] = []
        for page_number in range(1, details["num_pages"] + 1):
            pages_by_date_str[date_str].append(f"{root_url}{page_number}")

    DATASET_FOLDER = "cubdomain_dataset"
    if not os.path.exists(DATASET_FOLDER):
        os.mkdir(DATASET_FOLDER)

    for date_str, pages in tqdm(pages_by_date_str.items()):
        with open(f"{DATASET_FOLDER}{os.sep}cubdomain_{date_str}.txt", "w") as file:
            urls = set()
            for page in pages:
                try:
                    page_response = http.get(page)
                except requests.exceptions.RequestException as error:
                    logging.error(error)
                soup = BeautifulSoup(page_response.content, "html.parser")
                # Each listed domain is
                # encapsulated in this tag '<a href="https://www.cubdomain.com/site/ ...'
                res = soup.find_all("a", href=lambda x: "cubdomain.com/site/" in x)
                urls.update([line.string for line in res])
            file.write("\n".join(urls))


if __name__ == "__main__":
    main()
