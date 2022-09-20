"""
SQLite utilities for making INSERT queries
"""
from collections.abc import AsyncIterator, Callable, Iterator, Mapping

from apsw import Error
from modules.database.common import vacuum_and_close
from modules.database.connect import create_connection
from modules.database.hash import compute_url_hash, int_addr_to_ip_and_hash
from modules.utils.log import init_logger
from modules.utils.types import Vendors

logger = init_logger()


async def add_urls(
    url_set_fetcher: Callable[..., AsyncIterator[set[str]]],
    update_time: int,
    db_filename: str,
    url_set_fetcher_args: Mapping | None = None,
) -> None:
    """Retrieve a set of URLs and UPSERT URLs into
    urls table of SQLite database at `db_filename`.db.
    If any given URL already exists in urls table,
    update its lastListed timestamp field to `update_time`.

    Args:
        url_set_fetcher (Callable[..., AsyncIterator[set[str]]]):
        Fetches URL set from local or remote sources
        update_time (int): Time when URLs are added to database in
        UNIX Epoch seconds
        db_filename (str): SQLite database filename
        url_set_fetcher_args (Mapping, optional): Arguments
        for `url_set_fetcher`.
        Defaults to None.
    """
    urls = url_set_fetcher(**(url_set_fetcher_args if url_set_fetcher_args is not None else {}))

    last_listed = update_time
    conn = create_connection(db_filename)
    if conn is not None:
        logger.info(
            "Performing INSERT-UPDATE URLs to urls table of %s...",
            db_filename,
        )
        try:
            async for url_batch in urls:
                cur = conn.cursor()
                with conn:
                    cur.executemany(
                        """
                    INSERT INTO urls (url, lastListed, hash)
                    VALUES (?,?,?)
                    ON CONFLICT(url)
                    DO UPDATE SET lastListed=excluded.lastListed
                    """,
                        ((url, last_listed, compute_url_hash(url)) for url in url_batch),
                    )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        else:
            logger.info(
                "Performing INSERT-UPDATE URLs to " "urls table of %s...[DONE]",
                db_filename,
            )
        conn.close()
    else:
        logger.error("filename:%s %s", db_filename, "Unable to connect to database")


async def add_ip_addresses(db_filename: str, first_octet: int) -> None:
    """For a given `first_octet`, INSERT all 2 ** 24 ipv4 addresses
    and their sha256 hashes
    into urls table of SQLite database at `db_filename`.db.

    Example: if `first_octet` == 42,
    INSERT ipv4 addresses from 42.0.0.0 to 42.255.255.255

    Args:
        db_filename (str): SQLite database filename
        first_octet (int): First octet of ipv4 address
    """
    conn = create_connection(db_filename)
    if conn is not None:
        ips_to_generate = 2**24
        try:
            # Check if there are 2 ** 24 ips in database
            cur = conn.cursor()
            with conn:
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
                    cur.execute("DELETE FROM urls")
                with conn:
                    cur.executemany(
                        """
                    INSERT INTO urls (url,hash)
                    VALUES (?,?)
                    """,
                        (int_addr_to_ip_and_hash(int_addr + (2**24) * first_octet) for int_addr in range(ips_to_generate)),
                    )

                    logger.info(
                        "INSERT %d ipv4 addresses to " "urls table of %s...[DONE]",
                        ips_to_generate,
                        db_filename,
                    )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        vacuum_and_close(conn)


def replace_malicious_url_hash_prefixes(hash_prefixes: set[str], vendor: Vendors) -> None:
    """Replace maliciousHashPrefixes table contents with latest malicious URL
    hash prefixes from Safe Browsing API

    Args:
        hash_prefixes (set[str]): Malicious URL hash prefixes
        from Safe Browsing API
        vendor (Vendors): Safe Browsing API vendor name
        (e.g. "Google", "Yandex" etc.)
    """
    logger.info("Updating database with %s malicious URL hash prefixes", vendor)
    conn = create_connection("malicious")
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                cur.execute(
                    "DELETE FROM maliciousHashPrefixes WHERE vendor = ?",
                    (vendor,),
                )
                cur.executemany(
                    """
                    INSERT INTO
                    maliciousHashPrefixes (hashPrefix,prefixSize,vendor)
                    VALUES (?, ?, ?)
                    """,
                    ((hashPrefix, len(hashPrefix), vendor) for hashPrefix in hash_prefixes),
                )
            logger.info(
                "Updating database with %s " "malicious URL hash prefixes...[DONE]",
                vendor,
            )
        except Error as error:
            logger.error("vendor:%s %s", vendor, error, exc_info=True)
        vacuum_and_close(conn)


def replace_malicious_url_full_hashes(full_hashes: Iterator[str], vendor: Vendors) -> None:
    """Replace maliciousFullHashes table contents with latest malicious URL
    full hashes from Safe Browsing API

    Args:
        full_hashes (Iterator[str]): Malicious URL full hashes
        from Safe Browsing API
        vendor (Vendors): Safe Browsing API vendor name
        (e.g. "Google", "Yandex" etc.)
    """
    logger.info("Updating database with %s malicious URL full hashes", vendor)
    conn = create_connection("malicious")
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                cur.execute("savepoint pt")
                cur.execute(
                    "DELETE FROM maliciousFullHashes WHERE vendor = ?",
                    (vendor,),
                )
                cur.executemany(
                    """
                    INSERT OR IGNORE INTO maliciousFullHashes (fullHash,vendor)
                    VALUES (?, ?)
                    """,
                    ((fullHash, vendor) for fullHash in full_hashes),
                )
                # ROLLBACK transaction if no full hashes were added
                cur = cur.execute("SELECT COUNT(fullHash) from maliciousFullHashes where vendor = ?", (vendor,))
                fullHash_count: int = cur.fetchall()[0][0]
                if not fullHash_count:
                    cur.execute("ROLLBACK to savepoint pt")
                    logger.info(
                        "Updating database with %s malicious URL full hashes...[DONE:NO FULL HASHES FOUND, ROLLING BACK]",
                        vendor,
                    )
                else:
                    logger.info(
                        "Updating database with %s malicious URL full hashes...[DONE]",
                        vendor,
                    )
        except Error as error:
            logger.error("vendor:%s %s", vendor, error, exc_info=True)
        vacuum_and_close(conn)
