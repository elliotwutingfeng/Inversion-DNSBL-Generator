from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
import requests
import logging
import tldextract
from logger_utils import init_logger
from requests_utils import get_with_retries
from tqdm import tqdm
import math
import ray

logger = init_logger()


def generate_hostname_expressions(raw_urls: list[str]) -> list[str]:
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
            [f"{'.'.join(parts[-i:])}" for i in range(min(5, len(parts)))]
        )
    return list(hostname_expressions)


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
                total=math.ceil(int(resp.headers["Content-Length"]) / chunk_size),
            ):
                f.write(data)
            zipfile = ZipFile(f)
            top1m_raw_urls = [
                x.strip().decode().split(",")[1]
                for x in zipfile.open(zipfile.namelist()[0]).readlines()
            ]
            top1m_urls = generate_hostname_expressions(top1m_raw_urls)
            logging.info("Downloading TOP1M list... [DONE]")
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
                total=math.ceil(int(resp.headers["Content-Length"]) / chunk_size),
            ):
                f.write(data)
            zipfile = ZipFile(f)
            top10m_raw_urls = [
                x.strip().decode().split(",")[1].replace('"', "")
                for x in zipfile.open(zipfile.namelist()[0]).readlines()[1:]
            ]
            top10m_urls = generate_hostname_expressions(top10m_raw_urls)
            logging.info("Downloading TOP10M list... [DONE]")
            return top10m_urls
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to retrieve TOP10M list; returning empty list: {e}")
        return []


def get_local_file_url_list(file: str) -> list[str]:
    """Returns all listed URLs from local text file"""
    logging.info(f"Extracting local list ({file}) ...")
    try:
        with open(file, "r") as f:
            raw_urls = [_.strip() for _ in f.readlines()]
            urls = generate_hostname_expressions(raw_urls)
            logging.info(f"Extracting local list ({file}) ... [DONE]")
        return urls
    except OSError as e:
        logging.warning(
            f"Failed to retrieve local list ({file}); returning empty list: {e}"
        )
        return []


if __name__ == "__main__":
    top1m_urls, top10m_urls = get_top1m_url_list(), get_top10m_url_list()

    logging.info(len(top1m_urls))
    logging.info(len(top10m_urls))