"""
Requests Utilities

Enables unlimited retries for GET and POST requests.

"""
import logging
import time
import json
from typing import Mapping, Text, Union
import requests
from requests.models import Response

from modules.logger_utils import init_logger


headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15",
}

logger = init_logger()


def get_with_retries(url: Union[Text, bytes], stream: bool = False) -> Response:
    """GET request with unlimited retries.

    Args:
        url (Union[Text, bytes]): URL for the new `Request` object
        stream (bool, optional): if False, the response content
        will be immediately downloaded. Defaults to False.

    Raises:
        requests.exceptions.RequestException: There was an
        ambiguous exception that occurred while handling your request

    Returns:
        Response: Contains a server's response to an HTTP request
    """
    attempt = 1
    while True:
        try:
            if stream:
                return requests.get(url, stream=True, headers=headers, timeout=180)
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                raise requests.exceptions.RequestException(
                    f"Status Code not 200. Actual Code is {resp.status_code}"
                )
            return resp
        except requests.exceptions.RequestException as error:
            logging.warning("Attempt %d failed -> %s", attempt, error)
        attempt += 1
        time.sleep(1)


def post_with_retries(url: Union[Text, bytes], payload: Mapping) -> Response:
    """POST request with unlimited retries.

    Args:
        url (Union[Text, bytes]): URL for the new `Request` object
        payload (Mapping): Dictionary to send in the body of the `Request`.

    Raises:
        requests.exceptions.RequestException: There was an
        ambiguous exception that occurred while handling your request

    Returns:
        Response: Contains a server's response to an HTTP request
    """
    attempt = 1
    while True:
        try:
            resp = requests.post(
                url, data=json.dumps(payload), headers=headers, timeout=180
            )
            if resp.status_code != 200:
                raise requests.exceptions.RequestException(
                    f"Status Code not 200. Actual Code is {resp.status_code}"
                )
            return resp
        except requests.exceptions.RequestException as error:
            logging.warning("Attempt %d failed -> %s", attempt, error)
        attempt += 1
        time.sleep(1)
