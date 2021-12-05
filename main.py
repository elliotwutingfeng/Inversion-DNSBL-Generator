import logging
import argparse
import ray
from update_database import update_database

from url_utils import get_top1m_whitelist
from safebrowsing import get_malicious_URLs
from filewriter import write_top1m_malicious_urls_to_file

logger = logging.getLogger()
logger.setLevel(logging.INFO)

if __name__=='__main__':

    testing_quantity = 4000
    parser = argparse.ArgumentParser(description='''Python script to periodically update a local SQLite database with popular URLs 
    sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API to generate a 
    malicious URL blocklist for applications like pfBlockerNG/Pi-hole etc. Uses [Ray](http://www.ray.io/) to make 
    parallel requests with pipelining to the Google Safe Browsing API.''')
    parser.add_argument('--mode', required=True, choices=['testing', 'full'], 
    help=f"""
    testing: Generate URLs_marked_malicious_by_Google.txt based on last {testing_quantity} URLs from Tranco TOP1M list 
    | full: Update local database with latest TOP1M+TOP10M URLs and generate URLs_marked_malicious_by_Google.txt from local database""")
    args = parser.parse_args()

    if args.mode == 'full':
        update_database()
    else:
        ray.shutdown()
        ray.init(include_dashboard=False)
        top1m_urls = get_top1m_whitelist()[-testing_quantity:]
        malicious_urls = get_malicious_URLs(top1m_urls)
        write_top1m_malicious_urls_to_file(malicious_urls,top1m_urls)
        ray.shutdown()