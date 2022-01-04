from __future__ import annotations
import logging
import os
from datetime import datetime
from typing import List

from modules.logger_utils import init_logger

blocklists_folder: str = "blocklists"
blocklist_filename: str = "URLs_marked_malicious_by_Safe_Browsing"

logger: logging.Logger = init_logger()


def current_timestamp_str() -> str:
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def write_db_malicious_urls_to_file(malicious_urls: List[str]) -> None:
    """
    Writes all database URLs marked malicious by Safe Browsing API to TXT file.
    """
    logging.info(
        f"{len(malicious_urls)} URLs confirmed to be marked malicious by all Safe Browsing APIs."
    )

    if not os.path.exists(blocklists_folder):
        os.mkdir(blocklists_folder)

    txt_filename = f"{blocklist_filename}_{current_timestamp_str()}.txt"
    with open(f"{blocklists_folder}{os.sep}{txt_filename}", "a") as outfile:
        outfile.writelines("\n".join(malicious_urls))
        logging.info(f"File written: {txt_filename}")