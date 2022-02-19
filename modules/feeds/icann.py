"""
For fetching and scanning URLs from ICANN CZDS
"""

import asyncio
import gzip
import json
from io import BytesIO
from collections.abc import AsyncIterator
from typing import Iterator
from dotenv import dotenv_values
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_async, post_async
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions


logger = init_logger()

async def _authenticate(username: str,password: str) -> str:
    """Make a POST request for an Access Token from ICANN CZDS. The
    Access Token expires in 24 hours upon receipt.

    Args:
        username (str): ICANN CZDS username
        password (str): ICANN CZDS password

    Returns:
        str: ICANN CZDS Access Token
    """
    authentication_headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    credential = {'username': username,'password': password}
    authentication_url = "https://account-api.icann.org/api/authenticate"
    authentication_payload = json.dumps(credential).encode()

    resp = await post_async([authentication_url], [authentication_payload], headers=authentication_headers)
    body = json.loads(resp[0][1])

    if 'accessToken' not in body:
        logger.error("Failed to authenticate ICANN user")

    return body.get('accessToken',"")

async def _get_approved_endpoints(access_token: str) -> list[str]:
    """Download a list of zone file endpoints from ICANN CZDS. Only
    zone files which current ICANN CZDS user has approved access 
    to will be listed.

    Args:
        access_token (str): ICANN CZDS Access Token

    Returns:
        list[str]: List of zone file endpoints
    """
    links_url = "https://czds-api.icann.org/czds/downloads/links"
    resp = (await get_async([links_url],headers = {'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Bearer {access_token}'}))[links_url]

    body = json.loads(resp)
    if type(body) != list:
        logger.warning("No user-accessible zone files found.")
        return []
    return body

async def _get_icann_domains(endpoint: str, access_token: str) -> AsyncIterator[list[str]]:
    """Download domains from ICANN zone file endpoint and yields all listed URLs in batches.

    Args:
        endpoint (str): ICANN zone file endpoint
        access_token (str): ICANN CZDS Access Token

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list

    """
    logger.info("Downloading ICANN list %s...", endpoint)

    resp: bytes = (await get_async([endpoint], headers = {'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Bearer {access_token}'}))[endpoint]

    raw_urls: Iterator[str] = iter(())
    
    if resp != b"{}":
        with gzip.GzipFile(fileobj=BytesIO(resp),mode='rb') as g:
            # Ensure that raw_url is always lowercase
            raw_urls = (line.decode().split('.\t')[0].lower() for line in g)
            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
    else:
        logger.warning("Failed to retrieve ICANN list %s",endpoint)
        yield []

class ICANN:
    """
    For fetching and scanning URLs from ICANN CZDS
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        username = str(dotenv_values('.env').get('ICANN_ACCOUNT_USERNAME',""))
        password = str(dotenv_values('.env').get('ICANN_ACCOUNT_PASSWORD',""))

        access_token = asyncio.get_event_loop().run_until_complete(_authenticate(username, password))
        endpoints: list[str] = asyncio.get_event_loop().run_until_complete(_get_approved_endpoints(access_token))

        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        
        if "icann" in parser_args["sources"]:
            self.db_filenames = [f"icann_{url.rsplit('/', 1)[-1].rsplit('.')[-2]}" for url in endpoints]
            if parser_args["fetch"]:
                # Download and Add ICANN URLs to database
                self.jobs = [(_get_icann_domains, update_time, db_filename, 
                {'endpoint':endpoint,'access_token':access_token}) 
                for db_filename,endpoint in zip(self.db_filenames,endpoints)]
