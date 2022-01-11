"""
Database Utilities
"""
from __future__ import annotations
from typing import Callable, List, Mapping, Optional, Set, Tuple, Type, Iterator
import logging
from hashlib import sha256
import socket
import os
import struct
import apsw  # type: ignore
from apsw import Error
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray


logger = init_logger()


def create_connection(db_filename: str) -> Optional[Type[apsw.Connection]]:
    """Create a database connection to the SQLite database at `db_filename`,
     if `db_filename` is None, connect to a new in-memory database.

    Args:
        db_filename (str): SQLite database filename

    Returns:
        Optional[Type[apsw.Connection]]: SQLite database connection
    """
    databases_folder = "databases"
    conn = None

    try:
        if not os.path.exists(databases_folder):
            os.mkdir(databases_folder)
        conn = apsw.Connection(
            ":memory:"
            if db_filename is None
            else f"{databases_folder}{os.sep}{db_filename}.db"
        )
        cur = conn.cursor()
        cur.execute(
            "PRAGMA auto_vacuum = FULL"
        )  # https://www.sqlite.org/pragma.html#pragma_auto_vacuum
        cur.execute(
            "PRAGMA temp_store = MEMORY"
        )  # https://www.sqlite.org/pragma.html#pragma_temp_store
        cur.execute("PRAGMA journal_mode = WAL")  # https://www.sqlite.org/wal.html
    except Error as error:
        logger.error("filename:%s %s", db_filename, error)
    return conn


def create_ips_table(db_filename: str) -> None:
    """Create SQLite table for storing ipv4 addresses
    at `db_filename`.db database.

    Args:
        db_filename (str): SQLite database filename
    """
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS urls (
                            url text,
                            lastGoogleMalicious integer,
                            lastYandexMalicious integer,
                            hash blob
                            )"""
                )
                # To avoid writing redundant SQL queries,
                # we shall refer to ipv4 addresses as urls in SQL
        except Error as error:
            logger.error("filename:%s %s", db_filename, error)
        conn.close()


def create_urls_table(db_filename: str) -> None:
    """Create SQLite table for storing URLs (that are not ipv4 addresses)
    at `db_filename`.db database.

    Args:
        db_filename (str): SQLite database filename
    """
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS urls (
                            url text UNIQUE,
                            lastListed integer,
                            lastGoogleMalicious integer,
                            lastYandexMalicious integer,
                            hash blob
                            )"""
                )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error)
        conn.close()


def compute_url_hash(url: str) -> bytes:
    """Computes sha256 hash of `url` as specified by Safe Browsing API.

    Args:
        url (str): URL to be hashed

    Returns:
        bytes: sha256 hash of `url` as specified by Safe Browsing API.
    """
    return sha256(f"{url}/".encode()).digest()


def int_addr_to_ip_and_hash(int_addr: int) -> Tuple[str, bytes]:
    """Convert integer representation of ipv4 address
    to `ip_address` string and its Safe Browsing API sha256 `ip_hash`

    Args:
        int_addr (int): integer representation of ipv4 address

    Returns:
        Tuple[str, bytes]: `ip_address` string and its Safe Browsing API sha256 `ip_hash`
    """
    ip_address = socket.inet_ntoa(struct.pack("!I", int_addr))
    ip_hash = compute_url_hash(ip_address)
    return (ip_address, ip_hash)


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
            logger.error("filename:%s %s", db_filename, error)
        conn.close()


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
            logger.error("filename:%s %s", db_filename, error)
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
            logger.error("vendor:%s %s", vendor, error)
        conn.close()


def get_matching_hash_prefix_urls(
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
            logger.error("vendor:%s %s", vendor, error)
        conn.close()
    return prefix_sizes


def create_malicious_url_hash_prefixes_table() -> None:
    """Create SQLite table for storing malicious URL hash prefixes
    at `malicious`.db database.
    """
    conn = create_connection("malicious")
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS maliciousHashPrefixes (
                                                hashPrefix blob,
                                                prefixSize integer,
                                                vendor text
                                                )"""
                )
        except Error as error:
            logger.error("%s", error)
        conn.close()


def initialise_databases(db_filenames: List[str], mode: str) -> None:
    """Create database for each db_filename in `db_filenames` list, and
    database `malicious`.db for storing malicious URL hash prefixes
    if any of them do not exist yet.

    Args:
        db_filenames (List[str]): SQLite database filenames
        mode (str): If "domains", create databases for non-ipv4 URLs,
        if "ips", create databases for ipv4 addresses

    Raises:
        ValueError: `mode` must be "domains" or "ips"
    """
    logger.info(
        "Creating .db files if they do not exist yet for %d %s .txt files",
        len(db_filenames),
        mode,
    )
    if mode == "domains":
        execute_with_ray(
            create_urls_table,
            [(filename,) for filename in db_filenames],
        )
    elif mode == "ips":
        execute_with_ray(
            create_ips_table,
            [(filename,) for filename in db_filenames],
        )
    else:
        raise ValueError('mode must be "domains" or "ips"')
    create_malicious_url_hash_prefixes_table()


def update_malicious_urls(
    update_time: int, vendor: str, db_filename: str, malicious_urls: List[str]
) -> None:
    """Updates malicious status of all URLs currently in database
    i.e. for URLs found in `malicious_urls`,
    set lastGoogleMalicious or lastYandexMalicious value to `update_time`.

    Args:
        update_time (int): Time when malicious URL statuses in database
        are updated in UNIX Epoch seconds
        vendor (str): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)
        db_filename (str): SQLite database filename
        malicious_urls (List[str]): URLs deemed by Safe Browsing API to be malicious

    Raises:
        ValueError: `vendor` must be "Google" or "Yandex"
    """
    logger.info(
        "Updating %s database with verified %s malicious URLs", db_filename, vendor
    )
    vendor_to_update_query = {
        "Google": """
                    UPDATE urls
                    SET lastGoogleMalicious = ?
                    WHERE url IN malicious_urls
                    """,
        "Yandex": """
                    UPDATE urls
                    SET lastYandexMalicious = ?
                    WHERE url IN malicious_urls
                    """,
    }
    if vendor not in vendor_to_update_query:
        raise ValueError('vendor must be "Google" or "Yandex"')
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TEMPORARY TABLE
                    IF NOT EXISTS malicious_urls(url text)
                    """
                )
                cur.executemany(
                    """
                    INSERT INTO malicious_urls
                    VALUES (?)
                    """,
                    ((url,) for url in malicious_urls),
                )
                cur.execute(vendor_to_update_query[vendor], (update_time,))
                cur.execute("DROP TABLE malicious_urls")
            logger.info(
                "Updating %s database with verified %s malicious URLs...[DONE]",
                db_filename,
                vendor,
            )
        except Error as error:
            logger.error("vendor:%s filename:%s %s", vendor, db_filename, error)
        conn.close()


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
                logger.error("filename:%s %s", urls_db_filename, error)
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
