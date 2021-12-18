import apsw
from apsw import Error
import logging
from hashlib import sha256

from logger_utils import init_logger

# sqlite> .header on
# sqlite> .mode column

logger = init_logger()

def compute_url_hash(url):
    return sha256(f"{url}/".encode()).digest()

database = "urls.db"
sql_create_urls_table = """CREATE TABLE IF NOT EXISTS urls (
                           url text UNIQUE,
                           lastListed integer,
                           lastGoogleMalicious integer,
                           lastYandexMalicious integer,
                           lastReachable integer,
                           hash blob
                           );"""

sql_create_maliciousHashPrefixes_table = """CREATE TABLE IF NOT EXISTS maliciousHashPrefixes (
                                            hashPrefix blob,
                                            prefixSize integer,
                                            vendor text
                                            );"""

def add_maliciousHashPrefixes(hash_prefixes, vendor):
    """
    Replace maliciousHashPrefixes table contents with list of hash prefixes
    """
    sql = '''
    INSERT INTO maliciousHashPrefixes (hashPrefix,prefixSize,vendor)
    VALUES (?, ?, ?);
    '''
    logging.info(f"Updating DB with {vendor} malicious URL hashes")
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM maliciousHashPrefixes WHERE vendor = ?;",(vendor,))
            cur.executemany(sql,((hashPrefix,len(hashPrefix),vendor) for hashPrefix in list(hash_prefixes)))
    except Error as e:
        logging.error(e)
    conn.close()

def identify_suspected_urls(vendor):
    logging.info(f"Identifying suspected {vendor} malicious URLs")
    conn = create_connection()
    try:
        with conn:
            # Find all prefixSizes
            cur = conn.cursor()
            cur = cur.execute("SELECT DISTINCT prefixSize from maliciousHashPrefixes WHERE vendor = ?;",(vendor,))
            prefixSizes = [x[0] for x in cur.fetchall()]

            suspected_urls = []
            for prefixSize in prefixSizes:
            # Find all urls with matching hash_prefixes
                cur = cur.execute('''SELECT url from urls INNER JOIN maliciousHashPrefixes 
                WHERE substring(urls.hash,1,?) = maliciousHashPrefixes.hashPrefix 
                AND maliciousHashPrefixes.vendor = ?;''',(prefixSize,vendor))
                suspected_urls += [x[0] for x in cur.fetchall()]
            logging.info(f"{len(suspected_urls)} URLs potentially marked malicious by {vendor} Safe Browsing API.")
    except Error as e:
        logging.error(e)
    conn.close()

    return suspected_urls

def create_connection(db_file=database):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = apsw.Connection(':memory:' if db_file==None else db_file)
        cur = conn.cursor()
        cur.execute('PRAGMA journal_mode = WAL') # Enable Write-Ahead Log option; https://www.sqlite.org/wal.html
    except Error as e:
        logging.error(e)

    return conn

def create_table(create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(create_table_sql)
    except Error as e:
        logging.error(e)
    conn.close()

def initialise_database():
    # Create database with 2 tables
    conn = create_connection(database)
    # initialise tables
    if conn is not None:
        create_table(sql_create_urls_table)
        create_table(sql_create_maliciousHashPrefixes_table)
    else:
        logging.error("Error! cannot create the database connection.")

    return conn

def add_URLs(urls, updateTime):
    """
    Add a list of urls into the urls table
    If any given url already exists, update its lastListed field
    """
    sql = '''
    INSERT INTO urls (url, lastListed, hash)
    VALUES (?, ?, ?)
    ON CONFLICT(url)
    DO UPDATE SET lastListed=excluded.lastListed
    '''
    lastListed = updateTime
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            logging.info("Performing INSERT-UPDATE URLs to DB...")
            cur.executemany(sql,((url,lastListed, compute_url_hash(url)) for url in urls))
            logging.info("Performing INSERT-UPDATE to DB... [DONE]")
    except Error as e:
        logging.error(e)
    conn.close()

def get_all_URLs():
    """
    Returns list of all urls currently in DB
    """
    sql = '''
    SELECT url FROM urls;
    '''
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur = cur.execute(sql)
            urls = [row[0] for row in cur.fetchall()]
    except Error as e:
        logging.error(e)
    conn.close()

    return urls

def update_malicious_URLs(malicious_urls, updateTime, vendor):
    """
    Updates malicious status of all urls currently in DB
    i.e. urls found in malicious_urls, set lastGoogleMalicious or lastYandexMalicious value to updateTime
    """
    logging.info(f"Updating DB with verified {vendor} malicious URLs")
    number_of_malicious_urls = len(malicious_urls)

    if vendor == "Google":
        sql = f'''
        UPDATE urls
        SET lastGoogleMalicious = ?
        WHERE url IN ({','.join('?'*number_of_malicious_urls)})
        '''
    elif vendor == "Yandex":
        sql = f'''
        UPDATE urls
        SET lastYandexMalicious = ?
        WHERE url IN ({','.join('?'*number_of_malicious_urls)})
        '''
    else:
        raise ValueError('vendor must be "Google" or "Yandex"')
    
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(sql,(updateTime,*malicious_urls))
    except Error as e:
        logging.error(e)
    conn.close()

def update_activity_URLs(alive_urls, updateTime):
    """
    Updates alive status of all urls currently in DB
    i.e. urls found alive, set lastReachable value to updateTime
    """
    logging.info("Updating DB with URL host statuses")
    number_of_alive_urls = len(alive_urls)
    sql = f'''
    UPDATE urls
    SET lastReachable = ?
    WHERE url IN ({','.join('?'*number_of_alive_urls)})
    '''
    conn = create_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(sql,(updateTime,*alive_urls))
    except Error as e:
        logging.error(e)
    conn.close()