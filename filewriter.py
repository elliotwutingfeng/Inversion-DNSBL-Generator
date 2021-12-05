from __future__ import annotations
import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def write_top1m_unsafe_urls_to_file(unsafe_urls: list[str],top1m_urls: list[str]) -> None:
    """
    Writes current TOP1M URLs marked unsafe by Google, and current TOP1M URLs to JSON file.
    Also writes current TOP1M URLs marked unsafe by Google to TXT file.
    """
    logging.info(f'{len(unsafe_urls)} URLs marked unsafe by Google Safe Browsing API.')
    logging.info(f'{len(unsafe_urls)/len(top1m_urls)*100.0}% of TOP1M URLs marked unsafe by Google Safe Browsing API.')    
    with open('URLs_marked_unsafe_by_Google.json', 'w') as outfile:
        json.dump({"unsafe":unsafe_urls, "original": top1m_urls}, outfile)
    with open('URLs_marked_unsafe_by_Google.txt', 'w') as outfile:
        outfile.writelines("\n".join(unsafe_urls))

def write_all_unsafe_urls_to_file(unsafe_urls: list[str]) -> None:
    """
    Writes all database URLs marked unsafe by Google to TXT file.
    """
    logging.info(f'{len(unsafe_urls)} URLs confirmed to be marked unsafe by Google Safe Browsing API.')
    with open('blocklist.txt', 'w') as outfile:
        outfile.writelines("\n".join(unsafe_urls))