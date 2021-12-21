import apsw
from apsw import Error
import logging
from hashlib import sha256
from tqdm import tqdm
import ray
from list_utils import chunks, flatten

from logger_utils import init_logger
from ray_utils import execute_tasks


# sqlite> .header on
# sqlite> .mode column

logger = init_logger()
database = "urls.db"


def create_connection(db_file=database):
    """create a database connection to the SQLite database
        specified by db_file, if db_file is None, connect to a new in-memory database
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = apsw.Connection(":memory:" if db_file == None else db_file)
        cur = conn.cursor()
        cur.execute(
            "PRAGMA journal_mode = WAL"
        )  # Enable Write-Ahead Log option; https://www.sqlite.org/wal.html
    except Error as e:
        logging.error(e)

    return conn


def create_urls_table(table_name):
    conn = create_connection()
    logging.info(f"Creating table {table_name} if it does not exist...")
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS {table_name} (
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


def add_URLs(urls, updateTime, filename):
    """
    Add a list of urls into filename's urls_{id} table
    If any given url already exists, update its lastListed field
    """
    lastListed = updateTime
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            # Obtain id from lookup table to use as part of generated table_name
            cur.execute(
                "SELECT id from urls_filenames where urls_filename=? LIMIT 1",
                (filename,),
            )
            id = [int(x[0]) for x in cur.fetchall()][0]
            table_name = f"urls_{id}"
            logging.info(
                f"Generated table_name: {table_name} from lookup table for filename: {filename}"
            )
        create_urls_table(table_name)
        with conn:
            cur = conn.cursor()
            logging.info(
                f"Performing INSERT-UPDATE URLs to table {table_name} representing filename {filename}..."
            )
            batch_size = 50
            url_batches = list(chunks(urls, batch_size))

            for url_batch in tqdm(url_batches):
                cur.execute(
                    f"""
                INSERT INTO {table_name} (url, lastListed, hash)
                VALUES {",".join(("(?,?,?)" for _ in range(len(url_batch))))}
                ON CONFLICT(url)
                DO UPDATE SET lastListed=excluded.lastListed
                """,
                    flatten(
                        ((url, lastListed, compute_url_hash(url)) for url in url_batch)
                    ),
                )

            logging.info(
                f"Performing INSERT-UPDATE URLs to table {table_name} representing filename {filename}... [DONE]"
            )
    except Error as e:
        logging.error(e)
    conn.close()


def add_maliciousHashPrefixes(hash_prefixes, vendor):
    """
    Replace maliciousHashPrefixes table contents with list of hash prefixes
    """
    logging.info(f"Updating DB with {vendor} malicious URL hashes")
    conn = create_connection()
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


def get_urls_tables():
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute("SELECT id FROM urls_filenames")
            ids = [int(x[0]) for x in cur.fetchall()]
            urls_tables = [f"urls_{id}" for id in ids]
    except Error as e:
        logging.error(e)
    conn.close()

    return urls_tables


def get_matching_hashPrefix_urls(task):
    urls_table, prefixSize, vendor = task
    conn = create_connection()
    urls = []
    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute(
                f"""SELECT url from {urls_table} INNER JOIN maliciousHashPrefixes 
                WHERE substring({urls_table}.hash,1,?) = maliciousHashPrefixes.hashPrefix 
                AND maliciousHashPrefixes.vendor = ?;""",
                (prefixSize, vendor),
            )
            urls = [x[0] for x in cur.fetchall()]
    except Error as e:
        logging.error(e)
    conn.close()

    return urls


def identify_suspected_urls(vendor):
    logging.info(f"Identifying suspected {vendor} malicious URLs")
    conn = create_connection()
    try:
        with conn:
            # Find all prefixSizes
            cur = conn.cursor()
            cur = cur.execute(
                "SELECT DISTINCT prefixSize from maliciousHashPrefixes WHERE vendor = ?;",
                (vendor,),
            )
            prefixSizes = [x[0] for x in cur.fetchall()]

            suspected_urls = []

            urls_tables = get_urls_tables()

            combinations = [
                (urls_table, prefixSize)
                for prefixSize in prefixSizes
                for urls_table in urls_tables
            ]

            # Find all urls with matching hash_prefixes
            suspected_urls = flatten(
                execute_tasks(
                    [
                        (urls_table, prefixSize, vendor)
                        for urls_table, prefixSize in combinations
                    ],
                    get_matching_hashPrefix_urls,
                )
            )

            logging.info(
                f"{len(suspected_urls)} URLs potentially marked malicious by {vendor} Safe Browsing API."
            )
    except Error as e:
        logging.error(e)
    conn.close()

    return suspected_urls


def create_filenames_table(urls_filenames):
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                """CREATE TABLE IF NOT EXISTS urls_filenames (
            id integer PRIMARY KEY,
            urls_filename text UNIQUE
                )
                """
            )
            cur.executemany(
                "INSERT OR IGNORE into urls_filenames (id,urls_filename) VALUES (?, ?)",
                ((None, name) for name in urls_filenames),
            )
    except Error as e:
        logging.error(e)
    conn.close()


def create_maliciousHashPrefixes_table():
    """create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    conn = create_connection()
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
    conn = create_connection()
    if conn is None:
        raise Exception("Failed to initialise database")
    conn.close()
    # initialise tables
    create_filenames_table(urls_filenames)
    create_maliciousHashPrefixes_table()


def update_malicious_URLs(malicious_urls, updateTime, vendor):
    """
    Updates malicious status of all urls currently in DB
    i.e. for urls found in malicious_urls, set lastGoogleMalicious or lastYandexMalicious value to updateTime
    """
    logging.info(f"Updating DB with verified {vendor} malicious URLs")
    urls_tables = get_urls_tables()
    vendorToColumn = {"Google": "lastGoogleMalicious", "Yandex": "lastYandexMalicious"}
    if vendor not in vendorToColumn:
        raise ValueError('vendor must be "Google" or "Yandex"')
    for urls_table in tqdm(urls_tables):
        conn = create_connection()
        try:
            batch_size = 30_000
            malicious_url_batches = list(chunks(malicious_urls, batch_size))
            for malicious_url_batch in malicious_url_batches:
                malicious_url_batch_length = len(malicious_url_batch)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        f"""
                        UPDATE {urls_table}
                        SET {vendorToColumn[vendor]} = ?
                        WHERE url IN ({','.join('?'*malicious_url_batch_length)})
                        """,
                        (updateTime, *malicious_url_batch),
                    )
        except Error as e:
            logging.error(e)
        conn.close()


def retrieve_malicious_URLs():
    """
    Retrieves all urls from DB most recently marked as malicious by Safe Browsing API
    """

    def retrieve_malicious_URLs_(urls_table):
        malicious_urls = set()
        conn = create_connection()
        try:
            with conn:
                cur = conn.cursor()
                # Most recent lastGoogleMalicious timestamp
                cur.execute(f"SELECT MAX(lastGoogleMalicious) from {urls_table}")
                lastGoogleMalicious = [x[0] for x in cur.fetchall()][0]
                # Most recent lastYandexMalicious timestamp
                cur.execute(f"SELECT MAX(lastYandexMalicious) from {urls_table}")
                lastYandexMalicious = [x[0] for x in cur.fetchall()][0]
                cur.execute(
                    f"""
        SELECT url from {urls_table}
        WHERE lastGoogleMalicious = ? OR lastYandexMalicious = ?
        """,
                    (lastGoogleMalicious, lastYandexMalicious),
                )
                malicious_urls.update([x[0] for x in cur.fetchall()])
        except Error as e:
            logging.error(e)
        conn.close()

        return malicious_urls

    urls_tables = get_urls_tables()
    malicious_urls = set().union(*execute_tasks(urls_tables, retrieve_malicious_URLs_))

    return list(malicious_urls)


def update_activity_URLs(alive_urls, updateTime):
    """
    Updates alive status of all urls currently in DB
    i.e. urls found alive, set lastReachable value to updateTime
    """
    logging.info("Updating DB with URL host statuses")
    urls_tables = get_urls_tables()
    for urls_table in tqdm(urls_tables):
        conn = create_connection()
        try:
            batch_size = 30_000
            alive_url_batches = list(chunks(alive_urls, batch_size))
            for alive_url_batch in alive_url_batches:
                alive_url_batch_length = len(alive_url_batch)
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        f"""
                    UPDATE {urls_table}
                    SET lastReachable = ?
                    WHERE url IN ({','.join('?'*alive_url_batch_length)})
                    """,
                        (updateTime, *alive_url_batch),
                    )
        except Error as e:
            logging.error(e)
        conn.close()