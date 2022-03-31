"""
SQLite utilities for connecting to databases
"""
import os
from typing import Optional

import apsw  # type: ignore
from apsw import Error
from modules.utils.log import init_logger

logger = init_logger()


def create_connection(db_filename: str) -> Optional[type[apsw.Connection]]:
    """Create a database connection to the SQLite database at `db_filename`,
     if `db_filename` is None, connect to a new in-memory database.

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
        conn = apsw.Connection(":memory:" if db_filename is None else f"{databases_folder}{os.sep}{db_filename}.db")
        # Retry connection to locked database for maximum of 15000 ms
        conn.setbusytimeout(15000)
        cur = conn.cursor()
        cur.execute("PRAGMA auto_vacuum = FULL")  # https://www.sqlite.org/pragma.html#pragma_auto_vacuum
        cur.execute("PRAGMA temp_store = MEMORY")  # https://www.sqlite.org/pragma.html#pragma_temp_store
        cur.execute("PRAGMA journal_mode = WAL")  # https://www.sqlite.org/wal.html
    except Error as error:
        logger.error("filename:%s %s", db_filename, error, exc_info=True)
    return conn
