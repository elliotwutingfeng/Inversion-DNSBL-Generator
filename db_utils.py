import sqlite3
from sqlite3 import Error

database = "urls.db"
sql_create_urls_table = """CREATE TABLE IF NOT EXISTS urls (
                                    url text PRIMARY KEY,
                                    lastListed integer,
                                    lastMalicious integer,
                                    lastReachable integer
                                );"""

sql_create_updatelog_table = """CREATE TABLE IF NOT EXISTS updatelog (
                                id integer PRIMARY KEY,
                                updated integer NOT NULL
                            );"""

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
        print(e)

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
        print(e)

def add_urls(conn, urls, updateTime):
    """
    Add a list of urls into the urls table
    If any given url already exists, update its lastListed field
    """
    sql = '''
    INSERT INTO urls (url, lastListed)
  VALUES (?, ?)
  ON CONFLICT(url)
  DO UPDATE SET lastListed=excluded.lastListed
    '''
    lastListed = updateTime
    
    cur = conn.cursor()
    cur.executemany(sql,((url,lastListed) for url in urls))
    conn.commit()
    return cur.lastrowid

def get_all_urls(conn):
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