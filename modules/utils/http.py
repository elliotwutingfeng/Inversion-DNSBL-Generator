"""
HTTP Request Utilities
"""
import aiohttp
import asyncio
from io import BytesIO
import time
import json
from typing import Optional,Union
from collections.abc import Mapping
import pycurl

from modules.utils.log import init_logger
from modules.utils.types import RequestTypes


headers = {
    "Content-Type":"application/json",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8,application/json",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15",
}

DEFAULT_TIMEOUT = 120  # in seconds

logger = init_logger()


def backoff_delay(backoff_factor: float,number_of_retries_made: int) -> None:
    """Time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    time.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))

async def backoff_delay_async(backoff_factor: float,number_of_retries_made: int) -> None:
    """Asynchronous time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    await asyncio.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))

def curl_req(url: Union[str, bytes], payload: Optional[Mapping] = None
, request_type: RequestTypes = "GET") -> bytes:
    """Make HTTP GET or POST request with retry attempts and backoff delay between
    attempts, using CURL.

    Args:
        url (Union[Text, bytes]): URL endpoint for HTTP request
        payload (Optional[Mapping], optional): Payload for POST request. Defaults to None.
        request_type (RequestTypes, optional): HTTP request type. Defaults to "GET".

    Returns:
        bytes: HTTP response content
    """
    # pylint: disable=no-member
    max_retries: int = 5
    get_body: bytes = b""
    for number_of_retries_made in range(max_retries):
        try:
            b_obj = BytesIO()
            crl = pycurl.Curl()
            # Set URL value
            crl.setopt(crl.URL, url)  # type: ignore

            # Set HTTP headers
            crl.setopt(pycurl.HTTPHEADER, [f"{key}: {val}" for key,val in headers.items()])

            # Payload if this is a POST request
            if request_type == "POST" and payload is not None:
                crl.setopt(pycurl.POST, 1)
                crl.setopt(crl.POSTFIELDS, json.dumps(payload)) # type: ignore

            # Follow redirects (maximum: 5 times)
            crl.setopt(pycurl.FOLLOWLOCATION, 1) # type: ignore
            crl.setopt(pycurl.MAXREDIRS, 5)

            # http://pycurl.io/docs/latest/thread-safety.html
            # https://stackoverflow.com/questions/21887264/why-libcurl-needs-curlopt-nosignal-option-and-what-are-side-effects-when-it-is
            crl.setopt(pycurl.NOSIGNAL, 1)

            # Connection timeout
            crl.setopt(pycurl.CONNECTTIMEOUT, DEFAULT_TIMEOUT)

            # Transfer timeout
            crl.setopt(pycurl.TIMEOUT, 900)

            crl.exception = None  # type: ignore

            # Write bytes that are utf-8 encoded
            crl.setopt(crl.WRITEDATA, b_obj) # type: ignore

            # Perform a file transfer
            crl.perform()

        except pycurl.error as error:
            if error.args[0] == pycurl.E_COULDNT_CONNECT and crl.exception: # type: ignore
                logger.warning("URL: %s PycURL Exception: %s", url, crl.exception) # type: ignore
            else:
                logger.warning("URL: %s PycURL Error: %s", url, error)
        else:
            if crl.getinfo(pycurl.RESPONSE_CODE) != 200: # type: ignore
                logger.warning("URL: %s HTTP Status Code: %d",
                 url, crl.getinfo(pycurl.RESPONSE_CODE))
            else:
                # Get the content stored in the BytesIO object (in byte characters)
                get_body = b_obj.getvalue()
                break
            # End curl session
            crl.close()
        if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
            backoff_delay(1,number_of_retries_made)
    if not get_body:
        get_body = b"{}" # Allow json.loads to parse body if request fails
        logger.error("URL: %s %s request failed!", url, request_type)
    return get_body


async def get_async(endpoints: list[str]) -> dict[str,bytes]:
    """Given a list of HTTP endpoints, make HTTP GET requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP GET request endpoints

    Returns:
        dict[str,bytes]: Mapping of HTTP GET request endpoint to its HTTP response content
    """
    async def gather_with_concurrency(n: int, *tasks) -> dict[str,bytes]:
        semaphore = asyncio.Semaphore(n)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        return dict(await asyncio.gather(*(sem_task(task) for task in tasks)))

    async def get(url, session):
        max_retries: int = 5
        errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(url) as response:
                    return (url,await response.read())
            except aiohttp.client_exceptions.ClientConnectorError as error:
                errors.append(error)
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s GET request failed! Errors: %s", url, errors)
        return (url,b"{}") # Allow json.loads to parse body if request fails 

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300), raise_for_status=True) as session:
        # Limit number of concurrent connections to 10 to prevent rate-limiting by web server
        # Only one instance of any duplicate endpoint will be used
        return await gather_with_concurrency(10, *[get(url, session) for url in set(endpoints)])


async def post_async(endpoints: list[str], payloads: list[bytes]) -> list[tuple[str,bytes]]:
    """Given a list of HTTP endpoints and a list of payloads, 
    make HTTP POST requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP POST request endpoints
        payloads (list[bytes]): List of HTTP POST request payloads

    Returns:
        list[tuple[str,bytes]]: List of HTTP POST request endpoints 
        and their HTTP response contents
    """
    async def gather_with_concurrency(n: int, *tasks) -> list[tuple[str,bytes]]:
        semaphore = asyncio.Semaphore(n)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        return await asyncio.gather(*(sem_task(task) for task in tasks))

    async def post(url, payload, session):
        max_retries: int = 5
        errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.post(url, data=payload) as response:
                    return (url,await response.read())
            except aiohttp.client_exceptions.ClientConnectorError as error:
                errors.append(error)
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s POST request failed! Errors: %s", url, errors)
        return (url,b"{}") # Allow json.loads to parse body if request fails

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300), raise_for_status=True) as session:
        # Limit number of concurrent connections to 10 to prevent rate-limiting by web server
        return await gather_with_concurrency(10, *[post(url, payload, session) for url,payload in zip(endpoints,payloads)])