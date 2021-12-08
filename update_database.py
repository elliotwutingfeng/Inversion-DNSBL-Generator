## This script demonstrates the basic features of the database
import ray
import time
import logging

from db_utils import (
add_maliciousHashPrefixes,
identify_suspected_urls,
initialise_database,
add_URLs,
update_malicious_URLs,
update_activity_URLs
)
from alivecheck import check_activity_URLs
from filewriter import write_all_malicious_urls_to_file
from safebrowsing import SafeBrowsing
from url_utils import get_top10m_whitelist, get_top1m_whitelist

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def update_database():
    ray.shutdown()
    ray.init(include_dashboard=False)
    conn = initialise_database()
    
    logging.info("Adding whitelisted URLs to DB")
    updateTime = time.time() 
    top1m_urls = get_top1m_whitelist()
    add_URLs(conn, top1m_urls, updateTime)
    del top1m_urls
    top10m_urls = get_top10m_whitelist()
    add_URLs(conn, top10m_urls, updateTime)
    del top10m_urls

    malicious_urls = []
    for vendor in ["Google","Yandex"]:
        sb = SafeBrowsing(vendor)
        
        logging.info(f"Downloading {vendor} malicious URL hashes")
        hash_prefixes = sb.get_malicious_hash_prefixes()
        logging.info(f"Updating DB with {vendor} malicious URL hashes")
        add_maliciousHashPrefixes(conn, hash_prefixes, vendor)
        del hash_prefixes

        logging.info(f"Identifying suspected {vendor} malicious URLs")
        suspected_urls = identify_suspected_urls(conn, vendor)
        logging.info(f"Verifying suspected {vendor} malicious URLs")
        vendor_malicious_urls = sb.get_malicious_URLs(suspected_urls)
        malicious_urls += vendor_malicious_urls
        del suspected_urls
        
        logging.info(f"Updating DB with verified {vendor} malicious URLs")
        update_malicious_URLs(conn, vendor_malicious_urls, updateTime, vendor)

    logging.info("Writing malicious URLs to blocklist URLs_marked_malicious_by_Safe_Browsing.txt")
    malicious_urls = list(set(malicious_urls))
    write_all_malicious_urls_to_file(malicious_urls)

    #logging.info("Checking host statuses of malicious URLs with fping")
    #alive_and_not_dns_blocked_urls,alive_and_dns_blocked_urls,_,_,_ = check_activity_URLs(malicious_urls)
    #logging.info("Updating DB with malicious URL host statuses")
    #update_activity_URLs(conn, alive_and_not_dns_blocked_urls+alive_and_dns_blocked_urls, updateTime)

    # push to GitHub
    # TODO
    
    ray.shutdown()

if __name__=='__main__':
    update_database()