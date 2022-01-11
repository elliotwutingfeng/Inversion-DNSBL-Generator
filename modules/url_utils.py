"""
Utilities for gathering URLs from various sources
"""
from __future__ import annotations
from io import BytesIO
import os
import pathlib
from typing import Iterator, List, Tuple
from zipfile import ZipFile
import logging
import requests
import tldextract  # type: ignore
from tqdm import tqdm  # type: ignore
from more_itertools import chunked
from more_itertools.more import sort_together
from modules.logger_utils import init_logger
from modules.requests_utils import get_with_retries

logger = init_logger()


def generate_hostname_expressions(raw_urls: List[str]) -> List[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    See: https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

    Args:
        raw_urls (List[str]): URLs to generate Safe Browsing API-compliant
        hostname expressions from.

    Returns:
        List[str]: `raw_urls` + Safe Browsing API-compliant hostname expressions of `raw_urls`
    """
    # pylint: disable=broad-except

    hostname_expressions = set()
    for raw_url in raw_urls:
        try:
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
        except Exception as error:
            logger.error("%s %s", raw_url, error, exc_info=True)
    return list(hostname_expressions)


def get_top1m_url_list() -> Iterator[List[str]]:
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


def get_top10m_url_list() -> Iterator[List[str]]:
    """Downloads the DomCop TOP10M dataset and yields all listed URLs in batches.

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    logger.info("Downloading TOP10M list...")
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
            logger.info("Downloading TOP10M list... [DONE]")

            for batch in chunked(raw_urls, 40_000):
                yield generate_hostname_expressions(batch)

    except requests.exceptions.RequestException as error:
        logger.warning("Failed to retrieve TOP10M list; yielding empty list: %s", error)
        yield []


def get_local_file_url_list(txt_filepath: str) -> Iterator[List[str]]:
    """Yields all listed URLs in batches from local text file.

    Args:
        txt_filepath (str): Filepath of local text file containing URLs

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    try:
        with open(txt_filepath, "r") as file:
            for raw_urls in chunked((_.strip() for _ in file.readlines()), 40_000):
                yield generate_hostname_expressions(raw_urls)
    except OSError as error:

        logger.warning(
            "Failed to retrieve local list (%s); yielding empty list: %s",
            txt_filepath,
            error,
        )
        yield []


def retrieve_domainsproject_txt_filepaths_and_db_filenames() -> Tuple[
    List[str], List[str]
]:
    """Scans for Domains Project .txt source files and generates filepaths
    to .txt source files, and database filenames for each .txt source file.

    Returns:
        Tuple[List[str], List[str]]: (Filepaths to .txt source files,
        Database filenames for each .txt source file)
    """
    # Scan Domains Project's "domains" directory for domainsproject_urls_db_filenames
    domainsproject_dir = pathlib.Path.cwd().parents[0] / "domains" / "data"
    domainsproject_txt_filepaths: List[str] = []
    domainsproject_urls_db_filenames: List[str] = []
    for root, _, files in os.walk(domainsproject_dir):
        for file in files:
            if file.lower().endswith(".txt"):
                domainsproject_urls_db_filenames.append(f"{file[:-4]}")
                domainsproject_txt_filepaths.append(os.path.join(root, file))

    # Sort domainsproject_txt_filepaths and domainsproject_urls_db_filenames by ascending filesize
    domainsproject_filesizes: List[int] = [
        os.path.getsize(path) for path in domainsproject_txt_filepaths
    ]
    [
        domainsproject_filesizes,
        domainsproject_txt_filepaths,
        domainsproject_urls_db_filenames,
    ] = [
        list(_)
        for _ in sort_together(
            (
                domainsproject_filesizes,
                domainsproject_txt_filepaths,
                domainsproject_urls_db_filenames,
            )
        )
    ]
    return domainsproject_txt_filepaths, domainsproject_urls_db_filenames
