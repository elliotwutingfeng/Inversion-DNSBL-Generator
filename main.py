import logging
import argparse
import ray
from logger_utils import init_logger
from update_database import update_database

from url_utils import get_top1m_url_list
from safebrowsing import SafeBrowsing
from filewriter import write_top1m_malicious_urls_to_file

logger = init_logger()

if __name__ == "__main__":

    testing_quantity = 1500
    parser = argparse.ArgumentParser(
        description="""Python script to periodically update a local SQLite database with popular URLs 
    sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API and Yandex Safe Browsing API to generate a 
    malicious URL blocklist for applications like pfBlockerNG/Pi-hole etc. Uses [Ray](http://www.ray.io/) to make 
    parallel requests with pipelining to the Google Safe Browsing API and Yandex Safe Browsing API."""
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["testing", "full"],
        help=f"""
    testing: Generate URLs_marked_malicious_by_Safe_Browsing.txt based on last {testing_quantity} URLs from Tranco TOP1M list 
    | full: Update local database with latest TOP1M+TOP10M URLs and generate URLs_marked_malicious_by_Safe_Browsing.txt from local database""",
    )
    args = parser.parse_args()

    if args.mode == "full":
        update_database()
    else:
        ray.shutdown()
        ray.init(include_dashboard=False)
        test_urls = get_top1m_url_list()[-testing_quantity:]

        gsb = SafeBrowsing("Google")
        google_malicious_urls = gsb.get_malicious_URLs(test_urls)

        ysb = SafeBrowsing("Yandex")
        yandex_malicious_urls = ysb.get_malicious_URLs(test_urls)

        malicious_urls = list(set(google_malicious_urls + yandex_malicious_urls))

        write_top1m_malicious_urls_to_file(malicious_urls, test_urls)
        ray.shutdown()