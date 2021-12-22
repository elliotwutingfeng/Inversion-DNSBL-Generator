## This script demonstrates the basic features of the database
import ray
import time
import os
from tqdm import tqdm
import pathlib

from db_utils import (
    add_maliciousHashPrefixes,
    identify_suspected_urls,
    initialise_database,
    add_URLs,
    retrieve_malicious_URLs,
    update_malicious_URLs,
    update_activity_URLs,
)
from alivecheck import check_activity_URLs
from filewriter import write_all_malicious_urls_to_file
from ray_utils import execute_with_ray
from safebrowsing import SafeBrowsing
from url_utils import get_local_file_url_list, get_top10m_url_list, get_top1m_url_list
from list_utils import flatten


def update_database():
    ray.shutdown()
    ray.init(include_dashboard=False)
    updateTime = int(time.time())  # seconds since UNIX Epoch

    urls_filenames = []

    # Get local urls_filenames
    local_domains_dir = (
        pathlib.Path.cwd().parents[0] / "Domains Project" / "domains" / "data"
    )
    local_domains_filepaths = []
    for root, _, files in tqdm(list(os.walk(local_domains_dir))):
        for file in files:
            # Look for dotcom URLs only
            # domain2multi-com1d domain2multi-af00 domain2multi-com0d domain2multi-ax00
            if file.lower().endswith(".txt"):
                urls_filenames.append(f"{file[:-4]}")
                local_domains_filepaths.append(os.path.join(root, file))

    # urls_filenames.append("top1m_urls")
    # urls_filenames.append("top10m_urls")
    # Create DB files
    initialise_database(urls_filenames)
    """
    # Extract and Add local URLs to DB
    execute_with_ray(
        [
            (get_local_file_url_list, updateTime, filename, filepath)
            for filepath, filename in zip(local_domains_filepaths, urls_filenames)
        ],
        add_URLs,
    )

    # Download and Add TOP1M and TOP10M URLs to DB
    execute_with_ray(
        [
            (get_top1m_url_list, updateTime, "top1m_urls"),
            (get_top10m_url_list, updateTime, "top10m_urls"),
        ],
        add_URLs,
    )
    
    for vendor in ["Google", "Yandex"]:
        sb = SafeBrowsing(vendor)

        # Download and Update Safe Browsing API Malicious Hash Prefixes to DB
        hash_prefixes = sb.get_malicious_hash_prefixes()
        add_maliciousHashPrefixes(hash_prefixes, vendor)
        del hash_prefixes  # "frees" memory
    """
    for vendor in ["Google", "Yandex"]:
        sb = SafeBrowsing(vendor)

        # Identify URLs in DB whose full Hashes match with Malicious Hash Prefixes
        suspected_urls = flatten(
            execute_with_ray(
                [(vendor, filename) for filename in urls_filenames],
                identify_suspected_urls,
            )
        )

        # To Improve: If suspected_urls ever gets too large to fit in RAM we may need to store it in a temporary SQLITE file (or levelDB?)

        # Among these URLs, identify those with full Hashes are found on Safe Browsing API Server
        vendor_malicious_urls = sb.get_malicious_URLs(suspected_urls)
        del suspected_urls  # "frees" memory

        # To parallelise
        # Update vendor_malicious_urls to DB
        for filename in tqdm(urls_filenames):
            update_malicious_URLs(vendor_malicious_urls, updateTime, vendor, filename)

    # Write malicious_urls to TXT file (overwrites existing TXT file)
    malicious_urls = retrieve_malicious_URLs(urls_filenames)
    write_all_malicious_urls_to_file(malicious_urls)

    """
    # Check host statuses of URLs with fping and update host statuses to DB
    alive_and_not_dns_blocked_urls,alive_and_dns_blocked_urls,_,_,_ = check_activity_URLs(malicious_urls)
    update_activity_URLs(alive_and_not_dns_blocked_urls+alive_and_dns_blocked_urls, updateTime, filenames)
    """

    # push to GitHub
    # TODO

    ray.shutdown()


if __name__ == "__main__":
    update_database()