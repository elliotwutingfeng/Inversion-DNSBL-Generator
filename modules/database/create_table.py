"""
SQLite utilities for making CREATE TABLE queries
"""

from apsw import Error

from modules.database.connect import create_connection
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.types import DatabaseTableModes

logger = init_logger()


async def _create_ips_table(db_filename: str) -> None:
    """Create SQLite table for storing ipv4 addresses
    at `db_filename`.db database.

    Args:
        db_filename (str): SQLite database filename
    """
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS urls (
                            url text,
                            lastGoogleMalicious integer,
                            lastYandexMalicious integer,
                            hash text
                            )"""
                )
                # To avoid writing redundant SQL queries,
                # we shall refer to ipv4 addresses as urls in SQL
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


async def _create_urls_table(db_filename: str) -> None:
    """Create SQLite table for storing URLs (that are not ipv4 addresses)
    at `db_filename`.db database.

    Args:
        db_filename (str): SQLite database filename
    """
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS urls (
                            url text UNIQUE,
                            lastListed integer,
                            lastGoogleMalicious integer,
                            lastYandexMalicious integer,
                            hash text
                            )"""
                )
        except Error as error:
            logger.error("filename:%s %s", db_filename, error, exc_info=True)
        conn.close()


def _create_malicious_url_hashes_tables(
    db_filename: str = "malicious",
) -> None:
    """Create SQLite tables for storing malicious URL hash prefixes and full hashes
    at `malicious`.db database.

    Args:
        db_filename (str): SQLite database filename. Defaults to "malicious".
    """
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            cur = conn.cursor()
            with conn:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS maliciousHashPrefixes (
                                                hashPrefix text,
                                                prefixSize integer,
                                                vendor text
                                                )"""
                )
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS maliciousFullHashes (
                                                fullHash text,
                                                vendor text,
                                                UNIQUE (fullHash,vendor)
                                                )"""
                )
        except Error as error:
            logger.error("%s", error, exc_info=True)
        conn.close()


def initialise_databases(
    db_filenames: list[str] | None = None,
    mode: DatabaseTableModes = "hashes",
) -> None:
    """If `mode` is set to "domains" or "ips", create database for
    each db_filename in `db_filenames`
    list if any of them do not exist yet.
    If `mode` is set to "hashes", create database for storing malicious
    URL hash prefixes and full hashes.

    Args:
        db_filenames (list[str], optional): SQLite database filenames.
        Defaults to None.
        mode (DatabaseTableModes): If "hashes", create databases for
        malicious URL hash prefixes and full hashes,
        if "domains", create databases for non-ipv4 URLs,
        if "ips", create databases for ipv4 addresses.
        Defaults to "hashes".

    Raises:
        ValueError: `mode` must be "hashes" or "domains" or "ips"
    """
    if mode not in ("hashes", "domains", "ips"):
        raise ValueError('mode must be "hashes" or "domains" or "ips"')

    if mode == "hashes":
        db_filenames = ["malicious"]
    elif db_filenames is None or not len(db_filenames):
        return

    logger.info(
        "Initialising %d %s .db %s",
        len(db_filenames),
        mode,
        "files" if len(db_filenames) > 1 else "file",
    )
    if mode == "hashes":
        _create_malicious_url_hashes_tables(db_filenames[0])
    elif mode == "domains":
        execute_with_ray(
            _create_urls_table,
            [(filename,) for filename in db_filenames],
        )
    elif mode == "ips":
        execute_with_ray(
            _create_ips_table,
            [(filename,) for filename in db_filenames],
        )
