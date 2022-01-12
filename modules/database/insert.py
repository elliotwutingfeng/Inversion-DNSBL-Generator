"""
SQLite utilities for making INSERT queries
"""
from __future__ import annotations
from typing import Callable, List, Mapping, Optional, Set, Iterator

from apsw import Error
from modules.utils.log import init_logger
from modules.database.connect import create_connection
from modules.database.hash import compute_url_hash,int_addr_to_ip_and_hash

logger = init_logger()

def add_urls(
    url_list_fetcher: Callable[..., Iterator[List[str]]],
    update_time: int,
    db_filename: str,
    url_list_fetcher_args: Optional[Mapping] = None,
) -> None:
    """Retrieves a list of URLs and UPSERT URLs into
    urls table of SQLite database at `db_filename`.db.
    If any given URL already exists in urls table,
    update its lastListed timestamp field to `update_time`.

    Args:
        url_list_fetcher (Callable[..., Iterator[List[str]]]): Fetches URL list
        from local or remote sources
        update_time (int): Time when URLs are added to database in UNIX Epoch seconds
        db_filename (str): SQLite database filename
        url_list_fetcher_args (Optional[Mapping], optional): Arguments for `url_list_fetcher`.
        Defaults to None.
    """
    urls = url_list_fetcher(
        **(url_list_fetcher_args if url_list_fetcher_args is not None else {})
    )

    last_listed = update_time
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                logger.info(
                    "Performing INSERT-UPDATE URLs to urls table of %s...", db_filename
                )

                for url_batch in urls:
                    cur.executemany(
                        """
                    INSERT INTO urls (url, lastListed, hash)
                    VALUES (?,?,?)
                    ON CONFLICT(url)
                    DO UPDATE SET lastListed=excluded.lastListed
                    """,
                        (
                            (url, last_listed, compute_url_hash(url))
                            for url in url_batch
                        ),
                    )

                logger.info(
                    "Performing INSERT-UPDATE URLs to urls table of %s...[DONE]",
                    db_filename,
                )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


def add_ip_addresses(db_filename: str, first_octet: int) -> None:
    """For a given `first_octet`, INSERT all 2 ** 24 ipv4 addresses and their sha256 hashes
    into urls table of SQLite database at `db_filename`.db.

    Example: if `first_octet` == 42,
    INSERT ipv4 addresses from 42.0.0.0 to 42.255.255.255

    Args:
        db_filename (str): SQLite database filename
        first_octet (int): First octet of ipv4 address
    """
    conn = create_connection(db_filename)
    if conn is not None:
        ips_to_generate = 2 ** 24
        try:
            # Check if there are 2 ** 24 ips in database
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT MAX(_rowid_) FROM urls")
                number_of_ipv4_addresses = cur.fetchall()[0][0]
            if number_of_ipv4_addresses != ips_to_generate:
                # If database does not have 2 ** 24 IPs,
                # delete all rows from ipv4_ urls table and regenerate IPs
                logger.info(
                    "INSERT %d ipv4 addresses to urls table of %s...",
                    ips_to_generate,
                    db_filename,
                )
                with conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM urls")
                with conn:
                    cur = conn.cursor()
                    cur.executemany(
                        """
                    INSERT INTO urls (url,hash)
                    VALUES (?,?)
                    """,
                        (
                            int_addr_to_ip_and_hash(int_addr + (2 ** 24) * first_octet)
                            for int_addr in range(ips_to_generate)
                        ),
                    )

                    logger.info(
                        "INSERT %d ipv4 addresses to urls table of %s...[DONE]",
                        ips_to_generate,
                        db_filename,
                    )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


def replace_malicious_url_hash_prefixes(hash_prefixes: Set[bytes], vendor: str) -> None:
    """Replace maliciousHashPrefixes table contents with latest malicious URL
    hash prefixes from Safe Browsing API

    Args:
        hash_prefixes (Set[bytes]): Malicious URL hash prefixes from Safe Browsing API
        vendor (str): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)
    """
    logger.info("Updating database with %s malicious URL hashes", vendor)
    conn = create_connection("malicious")
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    "DELETE FROM maliciousHashPrefixes WHERE vendor = ?", (vendor,)
                )
                cur.executemany(
                    """
                    INSERT INTO maliciousHashPrefixes (hashPrefix,prefixSize,vendor)
                    VALUES (?, ?, ?)
                    """,
                    (
                        (hashPrefix, len(hashPrefix), vendor)
                        for hashPrefix in hash_prefixes
                    ),
                )
            logger.info(
                "Updating database with %s malicious URL hashes...[DONE]", vendor
            )
        except Error as error:
            logger.error("vendor:%s %s", vendor, error, exc_info=True)
        conn.close()
