"""
SQLite utilities for making UPDATE queries
"""
from apsw import Error
from modules.utils.log import init_logger
from modules.database.connect import create_connection
from modules.utils.types import Vendors

logger = init_logger()

async def update_malicious_urls(
    update_time: int, vendor: Vendors, db_filename: str, malicious_urls: list[str]
) -> None:
    """Updates malicious status of all URLs currently in database
    i.e. for URLs found in `malicious_urls`,
    set lastGoogleMalicious or lastYandexMalicious value to `update_time`.

    Args:
        update_time (int): Time when malicious URL statuses in database
        are updated in UNIX Epoch seconds
        vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)
        db_filename (str): SQLite database filename
        malicious_urls (list[str]): URLs deemed by Safe Browsing API to be malicious

    Raises:
        ValueError: `vendor` must be "Google" or "Yandex"
    """
    logger.info(
        "Updating %s database with verified %s malicious URLs", db_filename, vendor
    )
    vendor_to_update_query = {
        "Google": """
                    UPDATE urls
                    SET lastGoogleMalicious = ?
                    WHERE url IN malicious_urls
                    """,
        "Yandex": """
                    UPDATE urls
                    SET lastYandexMalicious = ?
                    WHERE url IN malicious_urls
                    """,
    }
    if vendor not in vendor_to_update_query:
        raise ValueError('vendor must be "Google" or "Yandex"')
    conn = create_connection(db_filename)
    if conn is not None:
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TEMPORARY TABLE
                    IF NOT EXISTS malicious_urls(url text)
                    """
                )
                cur.executemany(
                    """
                    INSERT INTO malicious_urls
                    VALUES (?)
                    """,
                    ((url,) for url in malicious_urls),
                )
                cur.execute(vendor_to_update_query[vendor], (update_time,))
                cur.execute("DROP TABLE malicious_urls")
            logger.info(
                "Updating %s database with verified %s malicious URLs...[DONE]",
                db_filename,
                vendor,
            )
        except Error as error:
            logger.error(
                "vendor:%s filename:%s %s", vendor, db_filename, error, exc_info=True
            )
        conn.close()
