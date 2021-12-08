from __future__ import annotations
import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def write_top1m_malicious_urls_to_file(malicious_urls: list[str],top1m_urls: list[str]) -> None:
    """
    Writes current TOP1M URLs marked malicious by Safe Browsing API, and current TOP1M URLs to JSON file.
    Also writes current TOP1M URLs marked malicious by Safe Browsing API to TXT file.
    """
    logging.info(f'{len(malicious_urls)} URLs marked malicious by Safe Browsing API.')
    logging.info(f'{len(malicious_urls)/len(top1m_urls)*100.0}% of TOP1M URLs marked malicious by Safe Browsing API.')    
    with open('URLs_marked_malicious_by_Safe_Browsing.json', 'w') as outfile:
        json.dump({"malicious":malicious_urls, "original": top1m_urls}, outfile)
    with open('URLs_marked_malicious_by_Safe_Browsing.txt', 'w') as outfile:
        outfile.writelines("\n".join(malicious_urls))

def write_all_malicious_urls_to_file(malicious_urls: list[str]) -> None:
    """
    Writes all database URLs marked malicious by Safe Browsing API to TXT file.
    """
    logging.info(f'{len(malicious_urls)} URLs confirmed to be marked malicious by Safe Browsing API.')
    with open('URLs_marked_malicious_by_Safe_Browsing.txt', 'w') as outfile:
        outfile.writelines("\n".join(malicious_urls))