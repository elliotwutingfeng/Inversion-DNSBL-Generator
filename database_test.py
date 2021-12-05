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
from filewriter import write_all_unsafe_urls_to_file
from safebrowsing import get_malicious_hash_prefixes, get_unsafe_URLs
from top1m_utils import get_top1m_whitelist

logger = logging.getLogger()
logger.setLevel(logging.INFO)

if __name__=='__main__':
    ray.shutdown()
    ray.init(include_dashboard=False)
    conn = initialise_database()
    # Fetch today's TOP1M
    logging.info("Fetching TOP1M")
    top1m_urls = get_top1m_whitelist()
    #top1m_urls = ["google.com","yahoo.com","halo.com","daolulianghua.com"] # daolulianghua.com is unsafe

    updateTime = time.time()

    # UPSERT database with today's TOP1M
    logging.info("Adding URLs to DB")
    project_id = add_URLs(conn, top1m_urls, updateTime)
    all_urls = get_all_URLs(conn)
    
    # Update malicious URL hash DB
    hash_prefixes = get_malicious_hash_prefixes()
    add_hash_prefixes(conn, hash_prefixes)

    # Identify malicious URLs, UPDATE them in the DB
    logging.info("Identify suspected malicious URLs")
    suspected_urls = identify_suspected_urls(conn)
    logging.info("Verify suspected malicious URLs")
    unsafe_urls = get_unsafe_URLs(suspected_urls)
    logging.info("Updating malicious URLs")
    update_malicious_URLs(conn, unsafe_urls, updateTime)

    # Fping all URLs, UPDATE them in the DB (TODO: Too slow!)
    # alive_urls,_ = check_activity_URLs(all_urls)
    # update_activity_URLs(conn, alive_urls, updateTime)

    # Generate TXT blocklist
    write_all_unsafe_urls_to_file(unsafe_urls)

    # push to GitHub
    # TODO
    
    ray.shutdown()