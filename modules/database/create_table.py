"""[summary]
"""
from __future__ import annotations
from typing import List
from apsw import Error

from modules.logger_utils import init_logger
from modules.database.connect import create_connection
from modules.ray_utils import execute_with_ray

logger = init_logger()

def _create_ips_table(db_filename: str) -> None:
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
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


def _create_urls_table(db_filename: str) -> None:
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
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


def _create_malicious_url_hash_prefixes_table() -> None:
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
            logger.error("%s", error, exc_info=True)
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
            _create_urls_table,
            [(filename,) for filename in db_filenames],
        )
    elif mode == "ips":
        execute_with_ray(
            _create_ips_table,
            [(filename,) for filename in db_filenames],
        )
    else:
        raise ValueError('mode must be "domains" or "ips"')
    _create_malicious_url_hash_prefixes_table()
