import logging
import argparse
import ray

from top1m_utils import get_top1m_whitelist
from safebrowsing import get_unsafe_URLs
from filewriter import write_unsafe_urls_to_file

if __name__=='__main__':
    ray.shutdown()
    ray.init(include_dashboard=False,num_cpus=4)

    logging.basicConfig(level=logging.INFO)

    testing_quantity = 4000

    parser = argparse.ArgumentParser(description='Find all URLs in Tranco TOP1M deemed by Google Safe Browsing API to be unsafe.')
    parser.add_argument('--mode', required=True, choices=['testing', 'full'], 
    help=f"testing: Lookup last {testing_quantity} URLs from Tranco TOP1M list on Google Safe Browsing API | full: Lookup all 1000,000 URLs on Google Safe Browsing API")
    args = parser.parse_args()

    top1m_urls = get_top1m_whitelist()[-testing_quantity if args.mode == 'testing' else 0:]
    unsafe_urls = get_unsafe_URLs(top1m_urls)
    write_unsafe_urls_to_file(unsafe_urls,top1m_urls)
    ray.shutdown()