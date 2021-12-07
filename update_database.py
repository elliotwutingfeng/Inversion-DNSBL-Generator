## This script demonstrates the basic features of the database
import ray
import time
import logging

from db_utils import (
add_hash_prefixes,
identify_suspected_urls,
initialise_database,
add_URLs,get_all_URLs,
update_malicious_URLs,
update_activity_URLs
)
from alivecheck import check_activity_URLs
from filewriter import write_all_malicious_urls_to_file
from safebrowsing import get_malicious_hash_prefixes, get_malicious_URLs
from url_utils import get_top10m_whitelist, get_top1m_whitelist

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def update_database():
    ray.shutdown()
    ray.init(include_dashboard=False)
    conn = initialise_database()
    # Fetch and UPSERT database with whitelisted URLs
    logging.info("Adding whitelisted URLs to DB")
    updateTime = time.time() 
    top1m_urls = get_top1m_whitelist()
    add_URLs(conn, top1m_urls, updateTime)
    del top1m_urls
    top10m_urls = get_top10m_whitelist()
    add_URLs(conn, top10m_urls, updateTime)
    del top10m_urls
    
    # Update malicious URL hash DB
    logging.info("Downloading malicious URL hashes")
    hash_prefixes = get_malicious_hash_prefixes()
    add_hash_prefixes(conn, hash_prefixes)
    del hash_prefixes

    # Identify malicious URLs, UPDATE them in the DB
    logging.info("Identifying suspected malicious URLs")
    suspected_urls = identify_suspected_urls(conn)
    logging.info("Verifying suspected malicious URLs")
    malicious_urls = get_malicious_URLs(suspected_urls)
    del suspected_urls
    logging.info("Updating malicious URLs")
    update_malicious_URLs(conn, malicious_urls, updateTime)

    # Generate TXT blocklist
    logging.info("Writing malicious URLs to URLs_marked_malicious_by_Google.txt")
    write_all_malicious_urls_to_file(malicious_urls)

    # Fping malicious_urls URLs, UPDATE them in the DB
    logging.info("Checking host statuses of malicious URLs")
    # all_urls = get_all_URLs(conn)
    alive_and_not_dns_blocked_urls,alive_and_dns_blocked_urls,_,_,_ = check_activity_URLs(malicious_urls)
    update_activity_URLs(conn, alive_and_not_dns_blocked_urls+alive_and_dns_blocked_urls, updateTime)

    # push to GitHub
    # TODO
    
    ray.shutdown()

if __name__=='__main__':
    update_database()