"""
File Writer

For writing URLs to .txt file with timestamping
"""

from __future__ import annotations
import logging
import os
from datetime import datetime
from typing import List

from modules.logger_utils import init_logger

BLOCKLISTS_FOLDER: str = "blocklists"
BLOCKLIST_FILENAME: str = "URLs_marked_malicious_by_Safe_Browsing"

logger: logging.Logger = init_logger()


def current_datetime_str() -> str:
    """Current time's datetime string in UTC.

    Returns:
        str: Timestamp in format "%d_%b_%Y_%H_%M_%S-UTC"
    """
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def write_urls_to_txt_file(urls: List[str]) -> None:
    """Writes list of URLs to .txt file with timestamping and stores it in BLOCKLISTS_FOLDER.

    BLOCKLISTS_FOLDER is created beforehand if it does not exist yet.

    Args:
        urls (List[str]): List of URLs
    """
    if not os.path.exists(BLOCKLISTS_FOLDER):
        os.mkdir(BLOCKLISTS_FOLDER)

    txt_filename = f"{BLOCKLIST_FILENAME}_{current_datetime_str()}.txt"
    with open(f"{BLOCKLISTS_FOLDER}{os.sep}{txt_filename}", "a") as outfile:
        outfile.writelines("\n".join(urls))
        logging.info("%d URLs written to file: %s", len(urls), txt_filename)
