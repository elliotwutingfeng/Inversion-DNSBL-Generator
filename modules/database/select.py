"""
Database Utilities
"""
from __future__ import annotations
from typing import  List, Set
import os
from apsw import Error
from modules.database.connect import create_connection
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray

logger = init_logger()


def retrieve_matching_hash_prefix_urls(
    db_filename: str, prefix_sizes: List[int], vendor: str
) -> List[str]:
    """Identify URLs from `db_filename`.db database with sha256 hashes beginning with
    any of the malicious URL hash prefixes in `malicious`.db database.

    Args:
        db_filename (str): SQLite database filename
        prefix_sizes (List[int]): Hash prefix sizes for a given `vendor`
        vendor (str): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

    Returns:
        List[str]: URLs with sha256 hashes beginning with
        any of the malicious URL hash prefixes in `malicious`.db database
    """
    conn = create_connection(db_filename)
    urls = []
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur = cur.execute(
                    f"ATTACH database 'databases{os.sep}malicious.db' as malicious"
                )
                cur = cur.execute(
                    """
                    CREATE TEMPORARY TABLE IF NOT EXISTS vendorHashPrefixes
                    AS SELECT hashPrefix FROM malicious.maliciousHashPrefixes
                    WHERE vendor = ?
                    """,
                    (vendor,),
                )
                for prefix_size in prefix_sizes:
                    cur = cur.execute(
                        """
                        SELECT url FROM urls
                        WHERE substring(urls.hash,1,?)
                        IN vendorHashPrefixes
                        """,
                        (prefix_size,),
                    )
                    urls += [x[0] for x in cur.fetchall()]
                cur.execute("DROP TABLE vendorHashPrefixes")
        except Error as error:
            logger.error(
                "filename:%s prefix_sizes:%s vendor:%s %s",
                db_filename,
                prefix_sizes,
                vendor,
                error,
                exc_info=True,
            )
        conn.close()

    return urls


def retrieve_vendor_hash_prefix_sizes(vendor: str) -> List[int]:
    """Retrieve from database hash prefix sizes for a given `vendor`.

    Args:
        vendor (str): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

    Returns:
        List[int]: Hash prefix sizes for a given `vendor`
    """
    prefix_sizes = []

    conn = create_connection("malicious")
    if conn is not None:
        try:
            with conn:
                # Find all prefix_sizes
                cur = conn.cursor()
                cur = cur.execute(
                    "SELECT DISTINCT prefixSize FROM maliciousHashPrefixes WHERE vendor = ?",
                    (vendor,),
                )
                prefix_sizes = [x[0] for x in cur.fetchall()]
        except Error as error:
            logger.error("vendor:%s %s", vendor, error, exc_info=True)
        conn.close()
    return prefix_sizes


def retrieve_malicious_urls(urls_db_filenames: List[str]) -> List[str]:
    """Retrieves URLs from database most recently marked as malicious by Safe Browsing API.

    Args:
        urls_db_filenames (List[str]): Filenames of SQLite databases
        containing URLs and their malicious statuses

    Returns:
        List[str]: URLs deemed by Safe Browsing API to be malicious
    """
    logger.info(
        "Retrieving URLs from database most recently marked as malicious by Safe Browsing API"
    )

    def retrieve_malicious_urls_(urls_db_filename: str) -> Set[str]:
        malicious_urls: Set[str] = set()
        conn = create_connection(urls_db_filename)
        if conn is not None:
            try:
                with conn:
                    cur = conn.cursor()
                    # Most recent lastGoogleMalicious timestamp
                    cur.execute("SELECT MAX(lastGoogleMalicious) FROM urls")
                    last_google_malicious = [x[0] for x in cur.fetchall()][0]
                    # Most recent lastYandexMalicious timestamp
                    cur.execute("SELECT MAX(lastYandexMalicious) FROM urls")
                    last_yandex_malicious = [x[0] for x in cur.fetchall()][0]
                    cur.execute(
                        """
            SELECT url FROM urls
            WHERE lastGoogleMalicious = ? OR lastYandexMalicious = ?
            """,
                        (last_google_malicious, last_yandex_malicious),
                    )
                    malicious_urls.update((x[0] for x in cur.fetchall()))
            except Error as error:
                logger.error("filename:%s %s", urls_db_filename, error, exc_info=True)
            conn.close()

        return malicious_urls

    malicious_urls = set().union(
        *execute_with_ray(
            retrieve_malicious_urls_, [(filename,) for filename in urls_db_filenames]
        )
    )
    logger.info(
        "Retrieving URLs from database most recently"
        " marked as malicious by Safe Browsing API...[DONE]"
    )
    return list(malicious_urls)
