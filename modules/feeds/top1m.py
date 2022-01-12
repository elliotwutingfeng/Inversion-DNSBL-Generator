"""
For fetching and scanning URLs from Tranco TOP1M
"""
from __future__ import annotations
from typing import Dict,List,Tuple,Iterator
from io import BytesIO
from zipfile import ZipFile
import requests
from tqdm import tqdm  # type: ignore
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_with_retries
from modules.feeds.hostname_expressions import generate_hostname_expressions


logger = init_logger()

def _get_top1m_url_list() -> Iterator[List[str]]:
    """Downloads the Tranco TOP1M dataset and yields all listed URLs in batches.

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    logger.info("Downloading TOP1M list...")
    try:
        with BytesIO() as file:
            resp = get_with_retries(
                "https://tranco-list.eu/top-1m.csv.zip", stream=True
            )
            chunk_size = 4096
            for data in tqdm(
                resp.iter_content(chunk_size=chunk_size),
                total=-(-int(resp.headers["Content-Length"]) // chunk_size),
            ):
                file.write(data)
            zipfile = ZipFile(file)
            raw_urls = (
                x.strip().decode().split(",")[1]
                for x in zipfile.open(zipfile.namelist()[0]).readlines()
            )
            logger.info("Downloading TOP1M list... [DONE]")

            for batch in chunked(raw_urls, 40_000):
                yield generate_hostname_expressions(batch)

    except requests.exceptions.RequestException as error:
        logger.warning("Failed to retrieve TOP1M list; yielding empty list: %s", error)
        yield []


class Top1M:
    """
    For fetching and scanning URLs from Tranco TOP1M
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args:Dict,update_time:int):
        self.db_filename: List[str] = []
        self.jobs: List[Tuple] = []
        if "top1m" in parser_args["sources"]:
            self.db_filename = ["top1m_urls"]
            if parser_args["fetch"]:
                # Download and Add TOP1M URLs to database
                self.jobs = [(_get_top1m_url_list, update_time, "top1m_urls")]
