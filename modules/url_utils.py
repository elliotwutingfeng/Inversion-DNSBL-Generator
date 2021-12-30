from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
import requests
import logging
import tldextract
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray
from modules.requests_utils import get_with_retries
from tqdm import tqdm

from more_itertools import chunked

logger = init_logger()


def generate_hostname_expressions(raw_urls: list[str]) -> list[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    See: https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions
    """

    raw_url_chunks: list[list[str]] = chunked(raw_urls, 50_000)

    def aux(raw_url_chunk):
        hostname_expressions = set()
        for raw_url in raw_url_chunk:
            ext = tldextract.extract(raw_url)
            if ext.subdomain == "":
                parts = [ext.registered_domain]
            else:
                parts = ext.subdomain.split(".") + [ext.registered_domain]
            hostname_expressions.update(
                [f"{'.'.join(parts[-i:])}" for i in range(min(5, len(parts)))]
            )
        return hostname_expressions

    hostname_expressions = execute_with_ray(
        [(raw_url_chunk,) for raw_url_chunk in raw_url_chunks],
        aux,
        progress_bar=False,
    )

    return list(set().union(*hostname_expressions))


def get_top1m_url_list() -> list[str]:
    """Downloads the Tranco TOP1M dataset and returns all listed URLs."""
    logging.info("Downloading TOP1M list...")
    try:
        with BytesIO() as f:
            resp = get_with_retries(
                "https://tranco-list.eu/top-1m.csv.zip", stream=True
            )
            chunk_size = 4096
            for data in tqdm(
                resp.iter_content(chunk_size=chunk_size),
                total=-(-int(resp.headers["Content-Length"]) // chunk_size),
            ):
                f.write(data)
            zipfile = ZipFile(f)
            raw_urls = [
                x.strip().decode().split(",")[1]
                for x in zipfile.open(zipfile.namelist()[0]).readlines()
            ]
            logging.info("Downloading TOP1M list... [DONE]")
            top1m_urls = (
                generate_hostname_expressions(raw_urls)
                for raw_urls in chunked(raw_urls, 400_000)
            )

            return top1m_urls
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to retrieve TOP1M list; returning empty list: {e}")
        return []


def get_top10m_url_list() -> list[str]:
    """Downloads the DomCop TOP10M dataset and returns all listed URLs."""
    logging.info("Downloading TOP10M list...")
    try:
        with BytesIO() as f:
            resp = get_with_retries(
                "https://www.domcop.com/files/top/top10milliondomains.csv.zip",
                stream=True,
            )
            chunk_size = 4096
            for data in tqdm(
                resp.iter_content(chunk_size=chunk_size),
                total=-(-int(resp.headers["Content-Length"]) // chunk_size),
            ):
                f.write(data)
            zipfile = ZipFile(f)
            raw_urls = [
                x.strip().decode().split(",")[1].replace('"', "")
                for x in zipfile.open(zipfile.namelist()[0]).readlines()[1:]
            ]
            logging.info("Downloading TOP10M list... [DONE]")
            top10m_urls = (
                generate_hostname_expressions(raw_urls)
                for raw_urls in chunked(raw_urls, 400_000)
            )

            return top10m_urls
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to retrieve TOP10M list; returning empty list: {e}")
        return []


def get_local_file_url_list(file: str) -> list[str]:
    """Returns all listed URLs from local text file"""
    try:
        with open(file, "r") as f:
            urls = (
                generate_hostname_expressions(raw_urls)
                for raw_urls in chunked((_.strip() for _ in f.readlines()), 400_000)
            )

            return urls
    except OSError as e:
        logging.warning(
            f"Failed to retrieve local list ({file}); returning empty list: {e}"
        )
        return []