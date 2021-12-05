import sqlite3
from sqlite3 import Error
import logging
from hashlib import sha256

# sqlite> .header on
# sqlite> .mode column

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def compute_url_hash(url):
    return sha256(f"{url}/".encode()).digest()

database = "urls.db"
sql_create_urls_table = """CREATE TABLE IF NOT EXISTS urls (
                                    url text PRIMARY KEY,
                                    lastListed integer,
                                    lastMalicious integer,
                                    lastReachable integer,
                                    hash blob
                                );"""

sql_create_updatelog_table = """CREATE TABLE IF NOT EXISTS updatelog (
                                id integer PRIMARY KEY,
                                updated integer NOT NULL
                            );"""

sql_create_hashPrefixes_table = """CREATE TABLE IF NOT EXISTS hashPrefixes (
                                id integer PRIMARY KEY,
                                hashPrefix blob,
                                prefixSize integer
                            );"""

def add_hash_prefixes(conn, hash_prefixes):
    """
    Replace hashPrefixes table contents with list of hash prefixes
    """
    sql = '''
    INSERT INTO hashPrefixes (id,hashPrefix,prefixSize)
    VALUES (?, ?, ?);
    '''
    
    cur = conn.cursor()
    cur.execute("DELETE FROM hashPrefixes;")
    cur.executemany(sql,((None,hashPrefix,len(hashPrefix)) for hashPrefix in list(hash_prefixes)))
    conn.commit()
    return cur.lastrowid

def identify_suspected_urls(conn):
    # Find all prefixSizes
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT prefixSize from hashPrefixes;")
    prefixSizes = [x[0] for x in cur.fetchall()]

    suspected_urls = []
    for prefixSize in prefixSizes:
    # Find all urls with matching hash_prefixes
        cur = conn.cursor()
        cur.execute(f"SELECT url from urls INNER JOIN hashPrefixes WHERE substring(urls.hash,1,{prefixSize}) = hashPrefixes.hashPrefix;")
        suspected_urls += [x[0] for x in cur.fetchall()]
    return suspected_urls

def create_connection(db_file=None):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(':memory:' if db_file==None else db_file)
    except Error as e:
        logging.error(e)

    return conn

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        logging.error(e)

def initialise_database():
    # Create database with 2 tables
    conn = create_connection(database)
    # initialise tables
    if conn is not None:
        # create urls table
        create_table(conn, sql_create_urls_table)

        # create updatelog table
        create_table(conn, sql_create_updatelog_table)

        # create hashPrefixes table
        create_table(conn, sql_create_hashPrefixes_table)

    else:
        logging.error("Error! cannot create the database connection.")

    return conn

def add_URLs(conn, urls, updateTime):
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
    
    cur = conn.cursor()
    cur.executemany(sql,((url,lastListed, compute_url_hash(url)) for url in urls))
    conn.commit()
    return cur.lastrowid

def get_all_URLs(conn):
    """
    Returns list of all urls currently in DB
    """
    sql = '''
    SELECT url FROM urls;
    '''
    
    cur = conn.cursor()
    cur.execute(sql)
    urls = [row[0] for row in cur.fetchall()]
    return urls

def update_malicious_URLs(conn, unsafe_urls, updateTime):
    """
    Updates malicious status of all urls currently in DB
    i.e. urls found in unsafe_urls, set lastMalicious value to updateTime
    """
    number_of_unsafe_urls = len(unsafe_urls)
    sql = f'''
    UPDATE urls
    SET lastMalicious = ?
    WHERE url IN ({','.join('?'*number_of_unsafe_urls)})
    '''

    cur = conn.cursor()
    cur.execute(sql,(updateTime,*unsafe_urls))
    conn.commit()
    return cur.lastrowid

def update_activity_URLs(conn, alive_urls, updateTime):
    """
    Updates alive status of all urls currently in DB
    i.e. urls found alive, set lastReachable value to updateTime
    """
    number_of_alive_urls = len(alive_urls)
    sql = f'''
    UPDATE urls
    SET lastReachable = ?
    WHERE url IN ({','.join('?'*number_of_alive_urls)})
    '''

    cur = conn.cursor()
    cur.execute(sql,(updateTime,*alive_urls))
    conn.commit()
    return cur.lastrowid    