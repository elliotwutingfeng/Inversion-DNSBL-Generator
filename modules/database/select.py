"""
SQLite utilities for making SELECT queries
"""
import os
from apsw import Error
from modules.database.connect import create_connection
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.types import Vendors

logger = init_logger()


async def retrieve_matching_hash_prefix_urls(
    db_filename: str, prefix_sizes: list[int], vendor: Vendors
) -> list[str]:
    """Identify URLs from `db_filename`.db database with sha256 hashes beginning with
    any of the malicious URL hash prefixes in `malicious`.db database.

    Args:
        db_filename (str): SQLite database filename
        prefix_sizes (list[int]): Hash prefix sizes for a given `vendor`
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

    Returns:
        list[str]: URLs with sha256 hashes beginning with
        any of the malicious URL hash prefixes in `malicious`.db database
    """
    conn = create_connection(db_filename)
    urls = []
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
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


def retrieve_vendor_hash_prefix_sizes(vendor: Vendors) -> list[int]:
    """Retrieve from database hash prefix sizes for a given `vendor`.

    Args:
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

    Returns:
        list[int]: Hash prefix sizes for a given `vendor`
    """
    prefix_sizes = []

    conn = create_connection("malicious")
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                # Find all prefix_sizes
                cur = cur.execute(
                    "SELECT DISTINCT prefixSize FROM maliciousHashPrefixes WHERE vendor = ?",
                    (vendor,),
                )
                prefix_sizes = [x[0] for x in cur.fetchall()]
        except Error as error:
            logger.error("vendor:%s %s", vendor, error, exc_info=True)
        conn.close()
    return prefix_sizes


def retrieve_malicious_urls(urls_db_filenames: list[str], vendor: Vendors) -> list[str]:
    """Retrieves URLs from database most recently marked as malicious by Safe Browsing API
    of `vendor`.

    Args:
        urls_db_filenames (list[str]): Filenames of SQLite databases
        containing URLs and their malicious statuses
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

    Returns:
        list[str]: URLs deemed by Safe Browsing API of `vendor` to be malicious
    """
    logger.info(
        "Retrieving URLs from database most recently "
        "marked as malicious by %s Safe Browsing API",vendor
    )

    async def retrieve_malicious_urls_(urls_db_filename: str, vendor: Vendors) -> set[str]:
        malicious_urls: set[str] = set()
        conn = create_connection(urls_db_filename)
        if conn is not None:
            try:
                cur = conn.cursor()
                with conn:
                    if vendor == "Google":
                        # Most recent lastGoogleMalicious timestamp
                        cur.execute("SELECT MAX(lastGoogleMalicious) FROM urls")
                        last_google_malicious = [x[0] for x in cur.fetchall()][0]
                        cur.execute(
                            """
                        SELECT url FROM urls
                        WHERE lastGoogleMalicious = ?
                        """,
                            (last_google_malicious,),
                        )
                    elif vendor == "Yandex":
                        # Most recent lastYandexMalicious timestamp
                        cur.execute("SELECT MAX(lastYandexMalicious) FROM urls")
                        last_yandex_malicious = [x[0] for x in cur.fetchall()][0]
                        cur.execute(
                        """
                        SELECT url FROM urls
                        WHERE lastYandexMalicious = ?
                        """,
                            ( last_yandex_malicious,),
                        )
                    else:
                        raise ValueError('vendor must be "Google" or "Yandex"')
                    malicious_urls.update((x[0] for x in cur.fetchall()))
            except Error as error:
                logger.error("filename:%s %s", urls_db_filename, error, exc_info=True)
            conn.close()

        return malicious_urls

    malicious_urls = set().union(
        *execute_with_ray(
            retrieve_malicious_urls_, [(filename,vendor) for filename in urls_db_filenames]
        )
    )
    logger.info(
        "Retrieving URLs from database most recently"
        " marked as malicious by %s Safe Browsing API...[DONE]",vendor
    )
    return list(malicious_urls)
