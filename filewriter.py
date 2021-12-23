from __future__ import annotations
import logging
import json
import os
from datetime import datetime

from logger_utils import init_logger

blocklists_folder = "blocklists"
blocklist_filename = "URLs_marked_malicious_by_Safe_Browsing"

logger = init_logger()


def current_timestamp_str():
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def write_top1m_malicious_urls_to_file(
    malicious_urls: list[str], top1m_urls: list[str]
) -> None:
    """
    Writes current TOP1M URLs marked malicious by all Safe Browsing APIs, and current TOP1M URLs to JSON file.
    Also writes current TOP1M URLs marked malicious by all Safe Browsing APIs to TXT file.
    """
    logging.info(
        f"{len(malicious_urls)} URLs marked malicious by all Safe Browsing APIs."
    )
    logging.info(
        f"{len(malicious_urls)/len(top1m_urls)*100.0}% of TOP1M URLs marked malicious by all Safe Browsing APIs."
    )

    if not os.path.exists(blocklists_folder):
        os.mkdir(blocklists_folder)

    json_filename = f"{blocklist_filename}_{current_timestamp_str()}.json"
    with open(f"{blocklists_folder}{os.sep}{json_filename}", "w") as outfile:
        json.dump({"malicious": malicious_urls, "original": top1m_urls}, outfile)
        logging.info(f"File written: {json_filename}")

    txt_filename = f"{blocklist_filename}_{current_timestamp_str()}.txt"
    with open(f"{blocklists_folder}{os.sep}{txt_filename}", "w") as outfile:
        outfile.writelines("\n".join(malicious_urls))
        logging.info(f"File written: {txt_filename}")


def write_all_malicious_urls_to_file(malicious_urls: list[str]) -> None:
    """
    Writes all database URLs marked malicious by Safe Browsing API to TXT file.
    """
    logging.info(
        f"{len(malicious_urls)} URLs confirmed to be marked malicious by all Safe Browsing APIs."
    )

    if not os.path.exists(blocklists_folder):
        os.mkdir(blocklists_folder)

    txt_filename = f"{blocklist_filename}_{current_timestamp_str()}.txt"
    with open(f"{blocklists_folder}{os.sep}{txt_filename}", "w") as outfile:
        outfile.writelines("\n".join(malicious_urls))
        logging.info(f"File written: {txt_filename}")