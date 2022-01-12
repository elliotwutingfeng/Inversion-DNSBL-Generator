"""
For fetching and scanning URLs from Registrar R01
"""
from __future__ import annotations
from typing import Dict,List,Tuple,Iterator
import gzip
import requests
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_with_retries
from modules.feeds.hostname_expressions import generate_hostname_expressions


logger = init_logger()

def _get_r01_domains() -> Iterator[List[str]]:
    """Downloads domains from Registrar R01 and yields all listed URLs in batches.

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    logger.info("Downloading Registrar R01 lists...")
    endpoints = ["https://partner.r01.ru/zones/ru_domains.gz",
                "https://partner.r01.ru/zones/su_domains.gz",
                "https://partner.r01.ru/zones/rf_domains.gz"]
    raw_urls: List[str] = []
    for endpoint in endpoints:
        try:
            resp = get_with_retries(endpoint)
            decompressed_lines = gzip.decompress(resp.content).decode().split("\n")
            raw_urls += [line.split('\t')[0].lower() for line in decompressed_lines]
        except requests.exceptions.RequestException as error:
            logger.warning("Failed to retrieve Registrar R01 list %s; %s",endpoint, error)

    logger.info("Downloading Registrar R01 lists... [DONE]")
    for batch in chunked(raw_urls, 40_000):
        yield generate_hostname_expressions(batch)

class RegistrarR01:
    """
    For fetching and scanning URLs from Registrar R01
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args:Dict,update_time:int):
        self.db_filenames: List[str] = []
        self.jobs: List[Tuple] = []
        if "r01" in parser_args["sources"]:
            self.db_filenames = ["r01_urls"]
            if parser_args["fetch"]:
                # Download and Add Registrar R01 URLs to database
                self.jobs = [(_get_r01_domains, update_time, "r01_urls")]
