"""
HTTP Request Utilities
"""
from typing import AsyncIterator, Optional
import aiohttp
import asyncio
import socket

from modules.utils.log import init_logger

logger = init_logger()

default_headers: dict = {
'Content-Type': 'application/json',
'Connection': 'keep-alive',
'Cache-Control':'no-cache',
'Accept': '*/*'}

class KeepAliveClientRequest(aiohttp.client_reqrep.ClientRequest):
    """Attempt to prevent `Response payload is not completed` error
    
    https://github.com/aio-libs/aiohttp/issues/3904#issuecomment-759205696


    """
    async def send(self, conn):
        """Send keep-alive TCP probes"""
        sock = conn.protocol.transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        return (await super().send(conn))

async def backoff_delay_async(backoff_factor: float,number_of_retries_made: int) -> None:
    """Asynchronous time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    await asyncio.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))

async def get_async(endpoints: list[str], max_concurrent_requests: int = 5, max_retries: int = 5, headers: dict = None) -> dict[str,bytes]:
    """Given a list of HTTP endpoints, make HTTP GET requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP GET request endpoints
        max_concurrent_requests (int, optional): Maximum number of concurrent async HTTP requests. Defaults to 5.
        max_retries (int, optional): Maximum HTTP request retries. Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Returns:
        dict[str,bytes]: Mapping of HTTP GET request endpoint to its HTTP response content. If
        the GET request failed, its HTTP response content will be `b"{}"`
    """
    if headers is None:
        headers = default_headers

    async def gather_with_concurrency(max_concurrent_requests: int, *tasks) -> dict[str,bytes]:
        semaphore = asyncio.Semaphore(max_concurrent_requests)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        tasklist = [sem_task(task) for task in tasks]
        return dict([await f for f in asyncio.as_completed(tasklist)])

    async def get(url, session):
        # errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(url, headers=headers) as response:
                    return (url,await response.read())
            except Exception as error:
                # errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s GET request failed!", url)
        return (url,b"{}") # Allow json.loads to parse body if request fails 

    # GET request timeout of 24 hours (86400 seconds); extended from API default of 5 minutes to handle large filesizes
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
     raise_for_status=True, timeout=aiohttp.ClientTimeout(total=86400), request_class=KeepAliveClientRequest) as session:
        # Only one instance of any duplicate endpoint will be used
        return await gather_with_concurrency(max_concurrent_requests, *[get(url, session) for url in set(endpoints)])


async def post_async(endpoints: list[str], payloads: list[bytes],max_concurrent_requests: int = 5, max_retries:int = 5, headers: dict = None) -> list[tuple[str,bytes]]:
    """Given a list of HTTP endpoints and a list of payloads, 
    make HTTP POST requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP POST request endpoints
        payloads (list[bytes]): List of HTTP POST request payloads
        max_concurrent_requests (int, optional): Maximum number of concurrent async HTTP requests. Defaults to 5.
        max_retries (int, optional): Maximum HTTP request retries. Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Returns:
        list[tuple[str,bytes]]: List of HTTP POST request endpoints 
        and their HTTP response contents. If a POST request failed, its HTTP response content will be `b"{}"`
    """
    if headers is None:
        headers = default_headers

    async def gather_with_concurrency(max_concurrent_requests: int, *tasks) -> list[tuple[str,bytes]]:
        semaphore = asyncio.Semaphore(max_concurrent_requests)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        tasklist = [sem_task(task) for task in tasks]
        return [await f for f in asyncio.as_completed(tasklist)]

    async def post(url, payload, session):
        # errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.post(url, data=payload, headers=headers) as response:
                    return (url,await response.read())
            except Exception as error:
                # errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s POST request failed!", url)
        return (url,b"{}") # Allow json.loads to parse body if request fails

    # POST request timeout of 5 minutes (300 seconds)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
     raise_for_status=True, timeout=aiohttp.ClientTimeout(total=300), request_class=KeepAliveClientRequest) as session:
        return await gather_with_concurrency(max_concurrent_requests, *[post(url, payload, session) for url,payload in zip(endpoints,payloads)])


async def get_async_stream(endpoint: str, max_retries:int = 5, headers: dict = None) -> AsyncIterator[Optional[bytes]]:
    """Given a HTTP endpoint, make a HTTP GET request asynchronously and stream the response chunks

    Args:
        endpoint (str): HTTP GET request endpoint
        max_retries (int, optional): Maximum HTTP request retries. Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Yields:
        AsyncIterator[Optional[bytes]]: HTTP response content as a chunked stream, 
        yield a final None if the GET request fails to complete.
    """
    if headers is None:
        headers = default_headers

    # GET request timeout of 24 hours (86400 seconds); extended from API default of 5 minutes to handle large filesizes
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
     raise_for_status=True, timeout=aiohttp.ClientTimeout(total=86400), request_class=KeepAliveClientRequest) as session:
        # errors: list[str] = []
        connected = False
        completed = False
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(endpoint, headers=headers) as response:
                    async for chunk,_ in response.content.iter_chunks():
                        connected = True # Flag to indicate at least one chunk has been extracted
                        yield chunk
            except Exception as error:
                # errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if connected:
                    logger.error("URL: %s | Stream disrupted", endpoint)
                    break
                if number_of_retries_made != max_retries - 1: # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
            else:
                completed = True # Flag to indicate GET request successful completion
                break
        if not completed:
            logger.error("URL: %s GET request failed!", endpoint)
            yield None
