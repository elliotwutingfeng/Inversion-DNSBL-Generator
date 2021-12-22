import apsw
from apsw import Error
import logging
from hashlib import sha256
from tqdm import tqdm
import ray
from list_utils import chunks, flatten
import os
from logger_utils import init_logger
from ray_utils import execute_with_ray


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
        logging.error(e)

    return conn


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
                           lastReachable integer,
                           hash blob
                           );"""
            )
    except Error as e:
        logging.error(e)
    conn.close()


def compute_url_hash(url):
    """Returns sha256 hash of url as specified by Safe Browsing API"""
    return sha256(f"{url}/".encode()).digest()


def add_URLs(url_list_fetcher, updateTime, filename, filepath=None):
    """
    Add a list of urls into filename's urls_{id} table
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
            batch_size = 50
            url_batches = list(chunks(urls, batch_size))

            for url_batch in url_batches:
                cur.execute(
                    f"""
                INSERT INTO urls (url, lastListed, hash)
                VALUES {",".join(("(?,?,?)" for _ in range(len(url_batch))))}
                ON CONFLICT(url)
                DO UPDATE SET lastListed=excluded.lastListed
                """,
                    flatten(
                        ((url, lastListed, compute_url_hash(url)) for url in url_batch)
                    ),
                )

            logging.info(
                f"Performing INSERT-UPDATE URLs to urls table of {filename}...[DONE]"
            )
    except Error as e:
        logging.error(e)
    conn.close()


def add_maliciousHashPrefixes(hash_prefixes, vendor):
    """
    Replace maliciousHashPrefixes table contents with list of hash prefixes
    """
    logging.info(f"Updating DB with {vendor} malicious URL hashes")
    conn = create_connection("maliciousHashPrefixes")
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
                (
                    (hashPrefix, len(hashPrefix), vendor)
                    for hashPrefix in list(hash_prefixes)
                ),
            )
    except Error as e:
        logging.error(e)
    conn.close()


def get_matching_hashPrefix_urls(filename, prefixSize, vendor):
    conn = create_connection(filename)
    urls = []

    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute(
                "ATTACH database 'databases/maliciousHashPrefixes.db' as maliciousHashPrefixes"
            )
            cur = cur.execute(
                f"""SELECT url from urls INNER JOIN maliciousHashPrefixes.maliciousHashPrefixes 
                WHERE substring(urls.hash,1,?) = maliciousHashPrefixes.maliciousHashPrefixes.hashPrefix 
                AND maliciousHashPrefixes.maliciousHashPrefixes.vendor = ?;""",
                (prefixSize, vendor),
            )
            urls = [x[0] for x in cur.fetchall()]
    except Error as e:
        logging.error(e)
    conn.close()

    return urls


def identify_suspected_urls(vendor, filename):
    logging.info(f"Identifying suspected {vendor} malicious URLs for {filename}")
    conn = create_connection(filename)
    try:
        with conn:
            # Find all prefixSizes
            cur = conn.cursor()
            cur = cur.execute(
                "ATTACH database 'databases/maliciousHashPrefixes.db' as maliciousHashPrefixes"
            )
            cur = cur.execute(
                "SELECT DISTINCT prefixSize from maliciousHashPrefixes.maliciousHashPrefixes WHERE vendor = ?;",
                (vendor,),
            )
            prefixSizes = [x[0] for x in cur.fetchall()]

        # Find all urls with matching hash_prefixes
        suspected_urls = flatten(
            execute_with_ray(
                [(filename, prefixSize, vendor) for prefixSize in prefixSizes],
                get_matching_hashPrefix_urls,
            )
        )

        logging.info(
            f"{len(suspected_urls)} URLs from {filename} potentially marked malicious by {vendor} Safe Browsing API."
        )
    except Error as e:
        logging.error(e)
    conn.close()

    return suspected_urls


def create_maliciousHashPrefixes_table():
    """create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    conn = create_connection("maliciousHashPrefixes")
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
        logging.error(e)
    conn.close()


def initialise_database(urls_filenames):
    # initialise tables
    logging.info(f"Creating .db files for {len(urls_filenames)} .txt files")
    execute_with_ray([(filename,) for filename in urls_filenames], create_urls_table)
    create_maliciousHashPrefixes_table()


def update_malicious_URLs(malicious_urls, updateTime, vendor, filename):
    """
    Updates malicious status of all urls currently in DB
    i.e. for urls found in malicious_urls, set lastGoogleMalicious or lastYandexMalicious value to updateTime
    """
    logging.info(f"Updating {filename} DB with verified {vendor} malicious URLs")
    vendorToColumn = {"Google": "lastGoogleMalicious", "Yandex": "lastYandexMalicious"}
    if vendor not in vendorToColumn:
        raise ValueError('vendor must be "Google" or "Yandex"')
    conn = create_connection(filename)
    try:
        batch_size = 30_000
        malicious_url_batches = list(chunks(malicious_urls, batch_size))
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
        logging.error(e)
    conn.close()


def retrieve_malicious_URLs(urls_filenames):
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
                malicious_urls.update([x[0] for x in cur.fetchall()])
        except Error as e:
            logging.error(e)
        conn.close()

        return malicious_urls

    malicious_urls = set().union(
        *execute_with_ray(
            [(filename,) for filename in urls_filenames], retrieve_malicious_URLs_
        )
    )

    return list(malicious_urls)


def update_activity_URLs(alive_urls, updateTime, filenames):
    """
    Updates alive status of all urls currently in DB
    i.e. urls found alive, set lastReachable value to updateTime
    """
    logging.info("Updating DB with URL host statuses")
    for filename in tqdm(filenames):
        conn = create_connection(filename)
        try:
            batch_size = 30_000
            alive_url_batches = list(chunks(alive_urls, batch_size))
            for alive_url_batch in alive_url_batches:
                alive_url_batch_length = len(alive_url_batch)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        f"""
                    UPDATE urls
                    SET lastReachable = ?
                    WHERE url IN ({','.join('?'*alive_url_batch_length)})
                    """,
                        (updateTime, *alive_url_batch),
                    )
        except Error as e:
            logging.error(e)
        conn.close()