"""
Database Utilities
"""
from __future__ import annotations
from typing import Callable, List, Optional, Set, Tuple, Type
import logging
from hashlib import sha256
import socket
import os
import struct
import apsw  # type: ignore
from apsw import Error
from more_itertools import chunked
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray


logger = init_logger()


def create_connection(db_filename: str) -> Optional[Type[apsw.Connection]]:
    """Create a database connection to the SQLite database specified by db_filename,
     if db_filename is None, connect to a new in-memory database.

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
        cur.execute("PRAGMA journal_mode = WAL")  # https://www.sqlite.org/wal.html
        cur.execute(
            "PRAGMA auto_vacuum = 1"
        )  # https://www.sqlite.org/pragma.html#pragma_auto_vacuum
    except Error as error:
        logging.error("filename:%s %s", db_filename, error)
    return conn


def create_ips_table(db_filename: str) -> None:
    """Create SQLite table for storing ipv4 addresses.

    Args:
        db_filename (str): [description]
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
        except Error as error:
            logging.error("filename:%s %s", db_filename, error)
        conn.close()


def create_urls_table(db_filename: str) -> None:
    """Create SQLite table for storing URLs.

    Args:
        db_filename (str): [description]
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
            logging.error("filename:%s %s", db_filename, error)
        conn.close()


def compute_url_hash(url: str) -> bytes:
    """Returns sha256 hash of url as specified by Safe Browsing API.

    Args:
        url (str): [description]

    Returns:
        bytes: [description]
    """
    return sha256(f"{url}/".encode()).digest()


def int_addr_to_ip_and_hash(int_addr: int) -> Tuple[str, bytes]:
    """Convert integer representation of ipv4 address
    to ip_address string and its Safe Browsing API hash

    Args:
        int_addr (int): [description]

    Returns:
        Tuple[str, bytes]: [description]
    """
    ip_address = socket.inet_ntoa(struct.pack("!I", int_addr))
    ip_hash = compute_url_hash(ip_address)
    return (ip_address, ip_hash)


def add_ip_addresses(filename: str, first_octet: int) -> None:
    """Add all 2 ** 32 ips and their hashes into urls table of 255 .db files.
    1 file for each bit in first octet.

    Args:
        filename (str): [description]
        first_octet (int): [description]
    """
    conn = create_connection(filename)
    if conn is not None:
        ips_to_generate = 2 ** 24
        try:
            # Check if there are 2 ** 24 ips in DB
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT MAX(_rowid_) FROM urls")
                number_of_ipv4_addresses = cur.fetchall()[0][0]
            if number_of_ipv4_addresses != ips_to_generate:
                # If DB does not have 2 ** 24 IPs,
                # delete all rows from ipv4_ urls table and regenerate IPs
                logging.info(
                    "INSERT %d ipv4 addresses to urls table of %s...",
                    ips_to_generate,
                    filename,
                )
                with conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM urls")
                with conn:
                    cur = conn.cursor()
                    for int_addr in range(ips_to_generate):
                        cur.execute(
                            """
                        INSERT INTO urls (url,hash)
                        VALUES (?,?)
                        """,
                            int_addr_to_ip_and_hash(int_addr + (2 ** 24) * first_octet),
                        )

                    logging.info(
                        "INSERT %d ipv4 addresses to urls table of %s...[DONE]",
                        ips_to_generate,
                        filename,
                    )
        except Error as error:
            logging.error("filename:%s %s", filename, error)
        conn.close()


def add_urls(
    url_list_fetcher: Callable[..., List[str]],
    update_time: int,
    filename: str,
    filepath: Optional[str] = None,
) -> None:
    """Add a list of urls into filename's urls table
    If any given url already exists, update its lastListed field

    Args:
        url_list_fetcher (Callable[..., List[str]]): [description]
        update_time (int): [description]
        filename (str): [description]
        filepath (Optional[str], optional): [description]. Defaults to None.
    """

    urls = url_list_fetcher() if filepath is None else url_list_fetcher(filepath)
    last_listed = update_time
    conn = create_connection(filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                logging.info(
                    "Performing INSERT-UPDATE URLs to urls table of %s...", filename
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

                logging.info(
                    "Performing INSERT-UPDATE URLs to urls table of %s...[DONE]",
                    filename,
                )
        except Error as error:
            logging.error("filename:%s %s", filename, error)
        conn.close()


def add_malicious_hash_prefixes(hash_prefixes: Set[bytes], vendor: str) -> None:
    """Replace maliciousHashPrefixes table contents with list of hash prefixes

    Args:
        hash_prefixes (Set[bytes]): [description]
        vendor (str): [description]
    """
    logging.info("Updating DB with %s malicious URL hashes", vendor)
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
        except Error as error:
            logging.error("vendor:%s %s", vendor, error)
        conn.close()


def get_matching_hash_prefix_urls(
    filename: str, prefix_sizes: List[int], vendor: str
) -> List[str]:
    """Identify urls with hashes beginning with
    any of the malicious hash prefixes in database

    Args:
        filename (str): [description]
        prefix_sizes (List[int]): [description]
        vendor (str): [description]

    Returns:
        List[str]: [description]
    """
    conn = create_connection(filename)
    urls = []
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur = cur.execute(
                    f"ATTACH database 'databases{os.sep}malicious.db' as malicious"
                )
                for prefix_size in prefix_sizes:
                    cur = cur.execute(
                        """
                        SELECT url FROM urls
                        WHERE substring(urls.hash,1,?)
                        IN (SELECT hashPrefix FROM malicious.maliciousHashPrefixes
                        WHERE vendor = ?)
                        """,
                        (prefix_size, vendor),
                    )
                    urls += [x[0] for x in cur.fetchall()]
            with conn:
                cur = conn.cursor()
                cur = cur.execute("DETACH database malicious")
        except Error as error:
            logging.error(
                "filename:%s prefix_size:%s vendor:%s %s",
                filename,
                prefix_sizes,
                vendor,
                error,
            )
        conn.close()

    return urls


def retrieve_vendor_prefix_sizes(vendor: str) -> List[int]:
    """Retrieve vendor prefix sizes from database.

    Args:
        vendor (str): [description]

    Returns:
        List[int]: [description]
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
            logging.error("vendor:%s %s", vendor, error)
        conn.close()
    return prefix_sizes


def create_malicious_hash_prefixes_table() -> None:
    """Create maliciousHashPrefixes table"""
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
            logging.error("%s", error)
        conn.close()


def initialise_database(filenames: List[str], mode: str) -> None:
    """Initialise database tables.

    Args:
        filenames (List[str]): [description]
        mode (str): [description]

    Raises:
        ValueError: [description]
    """
    logging.info(
        "Creating .db files if they do not exist yet for %d .txt files", len(filenames)
    )
    if mode == "domains":
        execute_with_ray(
            create_urls_table,
            [(filename,) for filename in filenames],
        )
    elif mode == "ips":
        execute_with_ray(
            create_ips_table,
            [(filename,) for filename in filenames],
        )
    else:
        raise ValueError('mode must be "domains" or "ips"')
    create_malicious_hash_prefixes_table()


def update_malicious_urls(
    update_time: int, vendor: str, filename: str, malicious_urls: List[str]
) -> None:
    """Updates malicious status of all urls currently in DB
    i.e. for urls found in malicious_urls,
    set lastGoogleMalicious or lastYandexMalicious value to update_time.

    Args:
        update_time (int): [description]
        vendor (str): [description]
        filename (str): [description]
        malicious_urls (List[str]): [description]

    Raises:
        ValueError: [description]
    """
    logging.info("Updating %s DB with verified %s malicious URLs", filename, vendor)
    vendor_to_column = {
        "Google": "lastGoogleMalicious",
        "Yandex": "lastYandexMalicious",
    }
    if vendor not in vendor_to_column:
        raise ValueError('vendor must be "Google" or "Yandex"')
    conn = create_connection(filename)
    if conn is not None:
        try:
            batch_size = 30_000
            malicious_url_batches = chunked(malicious_urls, batch_size)
            for malicious_url_batch in malicious_url_batches:
                malicious_url_batch_length = len(malicious_url_batch)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        f"""
                        UPDATE urls
                        SET {vendor_to_column[vendor]} = ?
                        WHERE url IN ({','.join('?'*malicious_url_batch_length)})
                        """,
                        (update_time, *malicious_url_batch),
                    )
            # TODO: Create temporary in memory database,
            # dump malicious URLs inside and use it to update malicious url statuses
            # e.g. where url in (select url from memory db)
            logging.info(
                "Updating %s DB with verified %s malicious URLs...[DONE]",
                filename,
                vendor,
            )
        except Error as error:
            logging.error("vendor:%s filename:%s %s", vendor, filename, error)
        conn.close()


def retrieve_malicious_urls(urls_filenames: List[str]) -> List[str]:
    """Retrieves all urls from DB most recently marked as malicious by Safe Browsing API.

    Args:
        urls_filenames (List[str]): [description]

    Returns:
        List[str]: [description]
    """

    def retrieve_malicious_urls_(filename: str) -> Set[str]:
        malicious_urls: Set[str] = set()
        conn = create_connection(filename)
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
                logging.error("filename:%s %s", filename, error)
            conn.close()

        return malicious_urls

    malicious_urls = set().union(
        *execute_with_ray(
            retrieve_malicious_urls_, [(filename,) for filename in urls_filenames]
        )
    )

    return list(malicious_urls)
