from __future__ import annotations
import apsw
from apsw import Error
import logging
from hashlib import sha256
from tqdm import tqdm
import os
from modules.list_utils import flatten
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray
import socket
import struct
from more_itertools import chunked


# sqlite> .header on
# sqlite> .mode column

logger = init_logger()


def create_connection(filename):
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
    except Error as e:
        logging.error(f"filename:{filename} {e}")

    return conn


def create_ips_table(filename="ipv4"):
    conn = create_connection(filename)
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS ips (
                           lastGoogleMalicious integer,
                           lastYandexMalicious integer,
                           hash blob
                           );"""
            )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def create_urls_table(filename):
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
                           );"""
            )
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def compute_url_hash(url):
    """Returns sha256 hash of url as specified by Safe Browsing API"""
    return sha256(f"{url}/".encode()).digest()


# select hash from ips where rowid = 1;
# Note that rowid begins with 1, not 0.


def int_addr_to_ip(int_addr):
    return socket.inet_ntoa(struct.pack("!I", int_addr))


def int_addr_to_hash(int_addr):
    return compute_url_hash(socket.inet_ntoa(struct.pack("!I", int_addr)))


def add_IPs(filename="ipv4"):
    """
    Add all 2**32 ips and their hashes into ips table
    """
    conn = create_connection(filename)
    try:
        with conn:
            cur = conn.cursor()
            logging.info(f"INSERT ipv4 addresses to ips table of {filename}...")
            for int_addr in tqdm(range(2 ** 32)):
                cur.execute(
                    f"""
                INSERT INTO ips (hash)
                VALUES (?)
                """,
                    (int_addr_to_hash(int_addr),),
                )

            logging.info(f"INSERT ipv4 addresses to ips table of {filename}...[DONE]")
    except Error as e:
        logging.error(f"filename:{filename} {e}")
    conn.close()


def add_URLs(url_list_fetcher, updateTime, filename, filepath=None):
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


def add_maliciousHashPrefixes(hash_prefixes, vendor):
    """
    Replace maliciousHashPrefixes table contents with list of hash prefixes
    """
    logging.info(f"Updating DB with {vendor} malicious URL hashes")
    conn = create_connection("malicious")
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM maliciousHashPrefixes WHERE vendor = ?;", (vendor,)
            )
            cur.executemany(
                """
                INSERT INTO maliciousHashPrefixes (hashPrefix,prefixSize,vendor)
                VALUES (?, ?, ?);
                """,
                ((hashPrefix, len(hashPrefix), vendor) for hashPrefix in hash_prefixes),
            )
    except Error as e:
        logging.error(f"vendor:{vendor} {e}")
    conn.close()


def get_matching_hashPrefix_urls(filename, prefixSize, vendor):
    conn = create_connection(filename)
    urls = []
    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute(
                f"ATTACH database 'databases{os.sep}malicious.db' as malicious"
            )
            cur = cur.execute(
                f"""SELECT url from urls 
                WHERE substring(urls.hash,1,?) in (select hashPrefix from malicious.maliciousHashPrefixes
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


def retrieve_vendor_prefixSizes(vendor) -> list[int]:
    conn = create_connection("malicious")
    prefixSizes = []
    try:
        with conn:
            # Find all prefixSizes
            cur = conn.cursor()
            cur = cur.execute(
                "SELECT DISTINCT prefixSize from maliciousHashPrefixes WHERE vendor = ?;",
                (vendor,),
            )
            prefixSizes = [x[0] for x in cur.fetchall()]
    except Error as e:
        logging.error(f"vendor: {vendor} {e}")
    conn.close()
    return prefixSizes


def identify_suspected_urls(vendor, filename, prefixSizes):
    # logging.info(f"Identifying suspected {vendor} malicious URLs for {filename}")
    conn = create_connection(filename)
    suspected_urls = []
    try:
        # Find all urls with matching hash_prefixes
        suspected_urls = flatten(
            execute_with_ray(
                [(filename, prefixSize, vendor) for prefixSize in prefixSizes],
                get_matching_hashPrefix_urls,
                progress_bar=False,
            )
        )

        logging.info(
            f"{len(suspected_urls)} URLs from {filename} potentially marked malicious by {vendor} Safe Browsing API."
        )
    except Error as e:
        logging.error(
            f"vendor:{vendor} filename:{filename} prefixSizes:{prefixSizes} {e}"
        )
    conn.close()

    return suspected_urls


def create_maliciousHashPrefixes_table():
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
                                            );"""
            )
    except Error as e:
        logging.error(f"{e}")
    conn.close()


def initialise_database(urls_filenames):
    # initialise tables
    logging.info(
        f"Creating .db files if they do not exist yet for {len(urls_filenames)} .txt files"
    )
    execute_with_ray([(filename,) for filename in urls_filenames], create_urls_table)
    create_ips_table()
    create_maliciousHashPrefixes_table()


def update_malicious_URLs(malicious_urls, updateTime, vendor, filename):
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
    except Error as e:
        logging.error(f"vendor:{vendor} filename:{filename} {e}")
    conn.close()


def retrieve_malicious_URLs(urls_filenames) -> list[str]:
    """
    Retrieves all urls from DB most recently marked as malicious by Safe Browsing API
    """

    def retrieve_malicious_URLs_(filename):
        malicious_urls = set()
        conn = create_connection(filename)
        try:
            with conn:
                cur = conn.cursor()
                # Most recent lastGoogleMalicious timestamp
                cur.execute(f"SELECT MAX(lastGoogleMalicious) from urls")
                lastGoogleMalicious = [x[0] for x in cur.fetchall()][0]
                # Most recent lastYandexMalicious timestamp
                cur.execute(f"SELECT MAX(lastYandexMalicious) from urls")
                lastYandexMalicious = [x[0] for x in cur.fetchall()][0]
                cur.execute(
                    f"""
        SELECT url from urls
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
            [(filename,) for filename in urls_filenames], retrieve_malicious_URLs_
        )
    )

    return list(malicious_urls)