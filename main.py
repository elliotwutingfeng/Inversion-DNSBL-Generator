import logging
import argparse
import ray
from update_database import update_database

from url_utils import get_top1m_whitelist
from safebrowsing import get_unsafe_URLs
from filewriter import write_top1m_unsafe_urls_to_file

logger = logging.getLogger()
logger.setLevel(logging.INFO)

if __name__=='__main__':

    testing_quantity = 4000
    parser = argparse.ArgumentParser(description='Find all URLs in Tranco TOP1M/DomCop Top10M deemed by Google Safe Browsing API to be unsafe.')
    parser.add_argument('--mode', required=True, choices=['testing', 'full'], 
    help=f"""
    testing: Generate blocklist.txt based on last {testing_quantity} URLs from Tranco TOP1M list 
    | full: Update local database with latest TOP1M+TOP10M URLs and generate blocklist.txt from local database""")
    args = parser.parse_args()

    if args.mode == 'full':
        update_database()
    else:
        ray.shutdown()
        ray.init(include_dashboard=False)
        top1m_urls = get_top1m_whitelist()[-testing_quantity:]
        unsafe_urls = get_unsafe_URLs(top1m_urls)
        write_top1m_unsafe_urls_to_file(unsafe_urls,top1m_urls)
        ray.shutdown()