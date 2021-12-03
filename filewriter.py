from __future__ import annotations
import logging
import json

def write_unsafe_urls_to_file(unsafe_urls: list[str],top1m_urls: list[str]) -> None:
    """
    Writes list of URLs marked unsafe by Google, and original list of TOP1M URLs to JSON file.
    Also writes list of URLs marked unsafe by Google to TXT file.
    """
    logging.info(f'{len(unsafe_urls)} URLs marked unsafe by Google Safe Browsing API.')
    logging.info(f'{len(unsafe_urls)/len(top1m_urls)*100.0}% of TOP1M URLs marked unsafe by Google Safe Browsing API.')    
    with open('URLs_marked_unsafe_by_Google.json', 'a') as outfile:
        json.dump({"unsafe":unsafe_urls, "original": top1m_urls}, outfile)
    with open('URLs_marked_unsafe_by_Google.txt', 'a') as outfile:
        outfile.writelines(s + '\n' for s in unsafe_urls)
