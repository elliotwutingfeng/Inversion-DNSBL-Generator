"""
URL Utilities
"""
from __future__ import annotations
from io import BytesIO
from typing import Iterator, List
from zipfile import ZipFile
import logging
import requests
import tldextract  # type: ignore
from tqdm import tqdm  # type: ignore
from more_itertools import chunked
from modules.logger_utils import init_logger
from modules.requests_utils import get_with_retries

logger = init_logger()


def generate_hostname_expressions(raw_urls: List[str]) -> List[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    See: https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions
    """

    hostname_expressions = set()
    for raw_url in raw_urls:
        ext = tldextract.extract(raw_url)
        if ext.subdomain == "":
            parts = [ext.registered_domain]
        else:
            parts = ext.subdomain.split(".") + [ext.registered_domain]
        hostname_expressions.update(
            [
                f"{'.'.join(parts[-i:])}"
                for i in range(len(parts) if len(parts) < 5 else 5)
            ]
        )
    return list(hostname_expressions)


def get_top1m_url_list() -> Iterator[List[str]]:
    """Downloads the Tranco TOP1M dataset and yields all listed URLs."""
    logging.info("Downloading TOP1M list...")
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
            logging.info("Downloading TOP1M list... [DONE]")

            for batch in chunked(raw_urls, 40_000):
                yield generate_hostname_expressions(batch)

    except requests.exceptions.RequestException as error:
        logging.warning("Failed to retrieve TOP1M list; yielding empty list: %s", error)
        yield []


def get_top10m_url_list() -> Iterator[List[str]]:
    """Downloads the DomCop TOP10M dataset and yields all listed URLs."""
    logging.info("Downloading TOP10M list...")
    try:
        with BytesIO() as file:
            resp = get_with_retries(
                "https://www.domcop.com/files/top/top10milliondomains.csv.zip",
                stream=True,
            )
            chunk_size = 4096
            for data in tqdm(
                resp.iter_content(chunk_size=chunk_size),
                total=-(-int(resp.headers["Content-Length"]) // chunk_size),
            ):
                file.write(data)
            zipfile = ZipFile(file)
            raw_urls = (
                x.strip().decode().split(",")[1].replace('"', "")
                for x in zipfile.open(zipfile.namelist()[0]).readlines()[1:]
            )
            logging.info("Downloading TOP10M list... [DONE]")

            for batch in chunked(raw_urls, 40_000):
                yield generate_hostname_expressions(batch)

    except requests.exceptions.RequestException as error:
        logging.warning(
            "Failed to retrieve TOP10M list; yielding empty list: %s", error
        )
        yield []


def get_local_file_url_list(filename: str) -> Iterator[List[str]]:
    """Yields all listed URLs from local text file"""
    try:
        with open(filename, "r") as file:
            for raw_urls in chunked((_.strip() for _ in file.readlines()), 40_000):
                yield generate_hostname_expressions(raw_urls)
    except OSError as error:

        logging.warning(
            "Failed to retrieve local list (%s); yielding empty list: %s",
            filename,
            error,
        )
        yield []
