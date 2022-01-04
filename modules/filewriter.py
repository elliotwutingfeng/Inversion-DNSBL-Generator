"""
For writing text files
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


def current_timestamp_str() -> str:
    """
    Gets current time and returns timestamp string
    """
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def write_db_malicious_urls_to_file(malicious_urls: List[str]) -> None:
    """
    Writes all database URLs marked malicious by Safe Browsing API to TXT file.
    """
    logging.info(
        "%d URLs confirmed to be marked malicious by all Safe Browsing APIs.",
        len(malicious_urls),
    )

    if not os.path.exists(BLOCKLISTS_FOLDER):
        os.mkdir(BLOCKLISTS_FOLDER)

    txt_filename = f"{BLOCKLIST_FILENAME}_{current_timestamp_str()}.txt"
    with open(f"{BLOCKLISTS_FOLDER}{os.sep}{txt_filename}", "a") as outfile:
        outfile.writelines("\n".join(malicious_urls))
        logging.info("File written: %s", txt_filename)
