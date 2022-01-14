"""
Requests Utilities
"""
from io import BytesIO
import time
import json
from typing import Mapping, Text, Union
import requests
import pycurl
from requests.models import Response

from modules.utils.log import init_logger


headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15",
}

DEFAULT_TIMEOUT = 120  # in seconds

logger = init_logger()


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
            logger.warning("Attempt %d failed -> %s", attempt, error)
        attempt += 1
        time.sleep(1)


def backoff_delay(backoff_factor: float,number_of__retries_made: int) -> None:
    """Time delay that exponentially increases with `number_of__retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of__retries_made (int): More retries made -> Longer backoff delay
    """
    time.sleep(backoff_factor * (2 ** (number_of__retries_made - 1)))


def curl_get(url: Union[Text, bytes]) -> bytes:
    """CURL GET request with retry attempts and backoff delay between
    attempts.

    Args:
        url (Union[Text, bytes]): URL endpoint for GET request

    Returns:
        bytes: GET response content
    """
    # pylint: disable=no-member
    max_retries: int = 5
    get_body: bytes = b""
    for number_of__retries_made in range(max_retries):
        try:
            b_obj = BytesIO()
            crl = pycurl.Curl()
            # Set URL value
            crl.setopt(crl.URL, url)  # type: ignore

            # Set HTTP headers
            crl.setopt(pycurl.HTTPHEADER, [f"{key}: {val}" for key,val in headers.items()])

            # Follow redirects (maximum: 5 times)
            crl.setopt(pycurl.FOLLOWLOCATION, 1) # type: ignore
            crl.setopt(pycurl.MAXREDIRS, 5)

            # http://pycurl.io/docs/latest/thread-safety.html
            # https://stackoverflow.com/questions/21887264/why-libcurl-needs-curlopt-nosignal-option-and-what-are-side-effects-when-it-is
            crl.setopt(pycurl.NOSIGNAL, 1)

            # Connection timeout
            crl.setopt(pycurl.CONNECTTIMEOUT, DEFAULT_TIMEOUT)

            # Transfer timeout
            crl.setopt(pycurl.TIMEOUT, 300)

            crl.exception = None  # type: ignore

            # Write bytes that are utf-8 encoded
            crl.setopt(crl.WRITEDATA, b_obj) # type: ignore

            # Perform a file transfer
            crl.perform()

        except pycurl.error as error:
            if error.args[0] == pycurl.E_COULDNT_CONNECT and crl.exception: # type: ignore
                logger.error(crl.exception) # type: ignore
            else:
                logger.error(error)
        else:
            if crl.getinfo(pycurl.RESPONSE_CODE) != 200: # type: ignore
                logger.error("HTTP Status Code: %d", crl.getinfo(pycurl.RESPONSE_CODE))
            else:
                # Get the content stored in the BytesIO object (in byte characters)
                get_body = b_obj.getvalue()
                break
            # End curl session
            crl.close()
        if number_of__retries_made != max_retries - 1: # No delay if final attempt fails
            backoff_delay(1,number_of__retries_made)

    return get_body
