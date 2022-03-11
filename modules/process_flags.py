"""
Process flags
"""
import asyncio
import time
import sys
import inspect
from more_itertools import flatten
import ray

from modules.database.select import (
    check_for_hashes,
    retrieve_matching_full_hash_urls,
    retrieve_matching_hash_prefix_urls,
    retrieve_malicious_urls,
    retrieve_vendor_hash_prefix_sizes,
)
from modules.database.create_table import initialise_databases
from modules.database.insert import (
    add_urls,
    add_ip_addresses,
    replace_malicious_url_full_hashes,
    replace_malicious_url_hash_prefixes,
)
from modules.database.update import update_malicious_urls
from modules.filewriter import write_blocklist_txt
from modules.utils.github import upload_blocklists
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.safebrowsing import SafeBrowsing
from modules import feeds

logger = init_logger()

def process_flags(parser_args: dict) -> None:
    # pylint: disable=too-many-locals
    """Run DNSBL generator tasks in sequence based on `parser_args` flags set by user.

    Args:
        parser_args (dict): Flags set by user; see `main.py` for more details
    """
    ray.shutdown()
    ray.init(include_dashboard=parser_args["include_dashboard"], num_cpus=parser_args["num_cpus"])
    update_time = int(time.time())  # seconds since UNIX Epoch

    domains_feeds = [cls(parser_args,update_time) 
    for clsname,cls in inspect.getmembers(sys.modules["modules.feeds"], inspect.isclass) 
    if clsname != 'Ipv4']

    domains_db_filenames: list[str] = list(flatten(_.db_filenames for _ in domains_feeds))

    ipv4 = feeds.Ipv4(parser_args)

    # Create database files
    initialise_databases(mode="hashes")
    initialise_databases(domains_db_filenames, mode="domains")
    initialise_databases(ipv4.db_filenames, mode="ips")

    domains_jobs = tuple(flatten(_.jobs for _ in domains_feeds))

    # UPSERT URLs to database
    execute_with_ray(add_urls, domains_jobs)
    execute_with_ray(add_ip_addresses, ipv4.jobs)

    # If `update_hashes` is enabled, download Safe Browsing API Malicious URL hash prefixes 
    # and update database with hash prefixes
    if parser_args["update_hashes"]:
        for vendor in parser_args["vendors"]:
            safebrowsing = SafeBrowsing(vendor)

            url_threatlist_combinations: list[dict] = safebrowsing.retrieve_url_threatlist_combinations()
            threat_list_updates: dict = safebrowsing.retrieve_threat_list_updates(url_threatlist_combinations)
            hash_prefixes: set[bytes] = safebrowsing.get_malicious_url_hash_prefixes(threat_list_updates)
            replace_malicious_url_hash_prefixes(hash_prefixes, vendor)

            if vendor == "Google":
                # Download Safe Browsing API Malicious URL full hashes 
                # and update database with full hashes
                replace_malicious_url_full_hashes(
                        safebrowsing.get_malicious_url_full_hashes(hash_prefixes, url_threatlist_combinations), 
                        vendor
                        )

    if parser_args["identify"]:
        malicious_urls = dict()
        hashes_in_database: dict = dict()
        for vendor in parser_args["vendors"]:
            safebrowsing = SafeBrowsing(vendor)
            vendor_malicious_urls: list[str] = []

            # Skip blocklist generation for this vendor 
            # if hash prefixes table or full hashes table are empty
            hashes_in_database[vendor] = check_for_hashes(vendor)
            if not hashes_in_database[vendor]:
                logger.warning("No hashes found in database for vendor: %s. "
                "Skipping blocklist generation for this vendor. "
                "You will need to run this program again with the `-u` flag to download hashes, "
                "look up `--help` or `README.md` for instructions",vendor)
                continue
            elif vendor == "Google":
                # Identify URLs in database whose full Hashes match with Malicious URL full hashes
                logger.info("Identifying %s malicious URLs",vendor)
                vendor_malicious_urls = list(set(
                    flatten(
                        execute_with_ray(
                            retrieve_matching_full_hash_urls,
                            [
                                (update_time, filename, vendor)
                                for filename in domains_db_filenames + ipv4.db_filenames
                            ],
                        ),
                    )
                ))
            elif vendor == "Yandex":
                prefix_sizes = retrieve_vendor_hash_prefix_sizes(vendor)

                # Identify URLs in database whose full Hashes match with Malicious URL hash prefixes
                logger.info("Identifying suspected %s malicious URLs",vendor)
                suspected_urls = set(
                    flatten(
                        execute_with_ray(
                            retrieve_matching_hash_prefix_urls,
                            [
                                (filename, prefix_sizes, vendor)
                                for filename in domains_db_filenames + ipv4.db_filenames
                            ],
                        ),
                    )
                )

                # Among these URLs, identify those with full Hashes
                # found on Safe Browsing API Server
                vendor_malicious_urls = safebrowsing.lookup_malicious_urls(suspected_urls)
                del suspected_urls  # "frees" memory
            else:
                raise ValueError('vendor must be "Google" or "Yandex"')
            
            malicious_urls[vendor] = vendor_malicious_urls
            blocklist_filenames: tuple[str,...] = asyncio.get_event_loop().run_until_complete(write_blocklist_txt(malicious_urls[vendor],vendor))

            # Push blocklists to GitHub
            upload_blocklists(vendor,blocklist_filenames)

        # Update malicious URL statuses in database (only for Lookup+Update API method)
        for vendor in parser_args["vendors"]:
            if not hashes_in_database[vendor]:
                continue
            if vendor == "Yandex":
                logger.info("Updating %s malicious URL statuses in database",vendor)
                execute_with_ray(
                    update_malicious_urls,
                    [
                        (update_time, vendor, filename)
                        for filename in domains_db_filenames + ipv4.db_filenames
                    ],
                    object_store={"malicious_urls": malicious_urls[vendor]},
                )

    # Retrieve malicious URLs from database and write to blocklists
    if parser_args["retrieve"]:
        for vendor in parser_args["vendors"]:
            asyncio.get_event_loop().run_until_complete(write_blocklist_txt(retrieve_malicious_urls(domains_db_filenames, vendor), vendor))
    ray.shutdown()
