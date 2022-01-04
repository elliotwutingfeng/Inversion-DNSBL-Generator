from __future__ import annotations
from typing import Callable, List, Optional, Set, Tuple
import apsw
from apsw import Error
import logging
from hashlib import sha256
import os
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray
import socket
import struct
from more_itertools import chunked


# sqlite> .header on
# sqlite> .mode column

logger = init_logger()


def create_connection(filename: str) -> Optional[apsw.Connection]:
    """create a database connection to the SQLite database
        specified by db_file, if db_file is None, connect to a new in-memory database
    :param db_file: database file
    :return: Connection object or None
    """
    databases_folder = "databases"
    conn = None

    try:
        if not os.path.exists(databases_folder):
            os.mkdir(databases_folder)
        conn = apsw.Connection(
            ":memory:"
            if filename == None
            else f"{databases_folder}{os.sep}{filename}.db"
        )
        cur = conn.cursor()
        cur.execute(
            "PRAGMA journal_mode = WAL"
        )  # Enable Write-Ahead Log option; https://www.sqlite.org/wal.html
        cur.execute("PRAGMA auto_vacuum = 1")  # Enable auto_vacuum
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    return conn


def create_ips_table(filename: str) -> None:
    conn = create_connection(filename)
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS urls (
                           url text,
                           lastGoogleMalicious integer,
                           lastYandexMalicious integer,
                           hash blob
                           )"""
            )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def create_urls_table(filename: str) -> None:
    conn = create_connection(filename)
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS urls (
                           url text UNIQUE,
                           lastListed integer,
                           lastGoogleMalicious integer,
                           lastYandexMalicious integer,
                           hash blob
                           )"""
            )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def compute_url_hash(url: str) -> bytes:
    """Returns sha256 hash of url as specified by Safe Browsing API"""
    return sha256(f"{url}/".encode()).digest()


def int_addr_to_ip_and_hash(int_addr: int) -> Tuple[str, bytes]:
    ip = socket.inet_ntoa(struct.pack("!I", int_addr))
    hash = compute_url_hash(ip)
    return (ip, hash)


def add_IPs(filename: str, first_octet: int) -> None:
    """
    Add all 2 ** 32 ips and their hashes into urls table of 255 .db files.
    1 file for each bit in first octet.
    """
    conn = create_connection(filename)
    ips_to_generate = 2 ** 24
    try:
        # Check if there are 2 ** 24 ips in DB
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT MAX(_rowid_) FROM urls")
            number_of_ipv4_addresses = cur.fetchall()[0][0]
        if number_of_ipv4_addresses != ips_to_generate:
            # If DB does not have 2 ** 24 IPs, delete all rows from ipv4_ urls table and regenerate IPs
            logging.info(
                f"INSERT {ips_to_generate} ipv4 addresses to urls table of {filename}..."
            )
            with conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM urls")
            with conn:
                cur = conn.cursor()
                for int_addr in range(ips_to_generate):
                    cur.execute(
                        f"""
                    INSERT INTO urls (url,hash)
                    VALUES (?,?)
                    """,
                        int_addr_to_ip_and_hash(int_addr + (2 ** 24) * first_octet),
                    )

                logging.info(
                    f"INSERT {ips_to_generate} ipv4 addresses to urls table of {filename}...[DONE]"
                )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def add_URLs(
    url_list_fetcher: Callable[[Optional[str]], List[str]],
    updateTime: int,
    filename: str,
    filepath: Optional[str] = None,
) -> None:
    """
    Add a list of urls into filename's urls table
    If any given url already exists, update its lastListed field
    """
    urls = url_list_fetcher() if filepath == None else url_list_fetcher(filepath)
    lastListed = updateTime
    conn = create_connection(filename)
    try:
        with conn:
            cur = conn.cursor()
            logging.info(
                f"Performing INSERT-UPDATE URLs to urls table of {filename}..."
            )

            for url_batch in urls:
                cur.executemany(
                    f"""
                INSERT INTO urls (url, lastListed, hash)
                VALUES (?,?,?)
                ON CONFLICT(url)
                DO UPDATE SET lastListed=excluded.lastListed
                """,
                    ((url, lastListed, compute_url_hash(url)) for url in url_batch),
                )

            logging.info(
                f"Performing INSERT-UPDATE URLs to urls table of {filename}...[DONE]"
            )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def add_maliciousHashPrefixes(hash_prefixes: Set[bytes], vendor: str) -> None:
    """
    Replace maliciousHashPrefixes table contents with list of hash prefixes
    """
    logging.info(f"Updating DB with {vendor} malicious URL hashes")
    conn = create_connection("malicious")
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM maliciousHashPrefixes WHERE vendor = ?", (vendor,))
            cur.executemany(
                """
                INSERT INTO maliciousHashPrefixes (hashPrefix,prefixSize,vendor)
                VALUES (?, ?, ?)
                """,
                ((hashPrefix, len(hashPrefix), vendor) for hashPrefix in hash_prefixes),
            )
    except Error as e:
        logging.error(f"vendor:{vendor} {e}")
    conn.close()


def get_matching_hashPrefix_urls(
    filename: str, prefixSize: int, vendor: str
) -> List[str]:
    conn = create_connection(filename)
    urls = []
    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute(
                f"ATTACH database 'databases{os.sep}malicious.db' as malicious"
            )
            cur = cur.execute(
                f"""SELECT url FROM urls 
                WHERE substring(urls.hash,1,?) IN (SELECT hashPrefix FROM malicious.maliciousHashPrefixes
                WHERE vendor = ?)""",
                (prefixSize, vendor),
            )
            urls = [x[0] for x in cur.fetchall()]
        with conn:
            cur = conn.cursor()
            cur = cur.execute("DETACH database malicious")
    except Error as e:
        logging.error(
            f"filename:{filename} prefixSize:{prefixSize} vendor:{vendor} {e}"
        )
    conn.close()

    return urls


def retrieve_vendor_prefixSizes(vendor: str) -> List[int]:
    conn = create_connection("malicious")
    prefixSizes = []
    try:
        with conn:
            # Find all prefixSizes
            cur = conn.cursor()
            cur = cur.execute(
                "SELECT DISTINCT prefixSize FROM maliciousHashPrefixes WHERE vendor = ?",
                (vendor,),
            )
            prefixSizes = [x[0] for x in cur.fetchall()]
    except Error as e:
        logging.error(f"vendor: {vendor} {e}")
    conn.close()
    return prefixSizes


def create_maliciousHashPrefixes_table() -> None:
    """create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    conn = create_connection("malicious")
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
    except Error as e:
        logging.error(f"{e}")
    conn.close()


def initialise_database(filenames: List[str], mode: str) -> None:
    # initialise tables
    logging.info(
        f"Creating .db files if they do not exist yet for {len(filenames)} .txt files"
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
    create_maliciousHashPrefixes_table()


def update_malicious_URLs(
    updateTime: int, vendor: str, filename: str, malicious_urls: List[str]
) -> None:
    """
    Updates malicious status of all urls currently in DB
    i.e. for urls found in malicious_urls, set lastGoogleMalicious or lastYandexMalicious value to updateTime
    """
    logging.info(f"Updating {filename} DB with verified {vendor} malicious URLs")
    vendorToColumn = {
        "Google": "lastGoogleMalicious",
        "Yandex": "lastYandexMalicious",
    }
    if vendor not in vendorToColumn:
        raise ValueError('vendor must be "Google" or "Yandex"')
    conn = create_connection(filename)
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
                    SET {vendorToColumn[vendor]} = ?
                    WHERE url IN ({','.join('?'*malicious_url_batch_length)})
                    """,
                    (updateTime, *malicious_url_batch),
                )
        logging.info(
            f"Updating {filename} DB with verified {vendor} malicious URLs...[DONE]"
        )
    except Error as e:
        logging.error(f"vendor:{vendor} filename:{filename} {e}")
    conn.close()


def retrieve_malicious_URLs(urls_filenames: List[str]) -> List[str]:
    """
    Retrieves all urls from DB most recently marked as malicious by Safe Browsing API
    """

    def retrieve_malicious_URLs_(filename: str) -> Set[str]:
        malicious_urls = set()
        conn = create_connection(filename)
        try:
            with conn:
                cur = conn.cursor()
                # Most recent lastGoogleMalicious timestamp
                cur.execute(f"SELECT MAX(lastGoogleMalicious) FROM urls")
                lastGoogleMalicious = [x[0] for x in cur.fetchall()][0]
                # Most recent lastYandexMalicious timestamp
                cur.execute(f"SELECT MAX(lastYandexMalicious) FROM urls")
                lastYandexMalicious = [x[0] for x in cur.fetchall()][0]
                cur.execute(
                    f"""
        SELECT url FROM urls
        WHERE lastGoogleMalicious = ? OR lastYandexMalicious = ?
        """,
                    (lastGoogleMalicious, lastYandexMalicious),
                )
                malicious_urls.update((x[0] for x in cur.fetchall()))
        except Error as e:
            logging.error(f"filename:{filename} {e}")
        conn.close()

        return malicious_urls

    malicious_urls = set().union(
        *execute_with_ray(
            retrieve_malicious_URLs_, [(filename,) for filename in urls_filenames]
        )
    )

    return list(malicious_urls)