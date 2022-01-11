"""
Process flags
"""
import time
from typing import Any, Dict, List, Tuple
from more_itertools import flatten
import ray

from modules.db_utils import (
    add_ip_addresses,
    replace_malicious_url_hash_prefixes,
    get_matching_hash_prefix_urls,
    initialise_databases,
    add_urls,
    retrieve_malicious_urls,
    retrieve_vendor_hash_prefix_sizes,
    update_malicious_urls,
)
from modules.filewriter import write_urls_to_txt_file
from modules.ray_utils import execute_with_ray
from modules.safebrowsing import SafeBrowsing
from modules.cubdomain_url_utils import get_page_urls_by_date_str, download_cubdomain
from modules.url_utils import (
    get_local_file_url_list,
    get_top10m_url_list,
    get_top1m_url_list,
    retrieve_domainsproject_txt_filepaths_and_db_filenames,
)


def process_flags(parser_args: Dict) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Run assorted DNSBL generator tasks in sequence based on `parser_args` flags set by user.

    Args:
        parser_args (Dict): Flags set by user; see `main.py` for more details
    """
    ray.shutdown()
    ray.init(include_dashboard=False, num_cpus=parser_args["num_cpus"])
    update_time = int(time.time())  # seconds since UNIX Epoch

    top1m_urls_db_filename = ["top1m_urls"] if "top1m" in parser_args["sources"] else []
    top10m_urls_db_filename = (
        ["top10m_urls"] if "top1m" in parser_args["sources"] else []
    )
    if "cubdomain" in parser_args["sources"]:
        cubdomain_page_urls_by_date_str = get_page_urls_by_date_str()
        cubdomain_page_urls_by_db_filename = {
            f"cubdomain_{date_str}": page_urls
            for date_str, page_urls in cubdomain_page_urls_by_date_str.items()
        }
        cubdomain_urls_db_filenames = list(cubdomain_page_urls_by_db_filename)
    else:
        cubdomain_urls_db_filenames = []
    if "domainsproject" in parser_args["sources"]:
        (
            domainsproject_txt_filepaths,
            domainsproject_urls_db_filenames,
        ) = retrieve_domainsproject_txt_filepaths_and_db_filenames()
    else:
        domainsproject_urls_db_filenames = []

    domains_db_filenames = (
        top1m_urls_db_filename
        + top10m_urls_db_filename
        + cubdomain_urls_db_filenames
        + domainsproject_urls_db_filenames
    )

    if "ipv4" in parser_args["sources"]:
        add_ip_addresses_jobs: List[Tuple] = [
            (f"ipv4_{first_octet}", first_octet) for first_octet in range(2 ** 8)
        ]
        ips_db_filenames = [_[0] for _ in add_ip_addresses_jobs]
    else:
        ips_db_filenames = []

    # Create database files
    initialise_databases(domains_db_filenames, mode="domains")
    initialise_databases(ips_db_filenames, mode="ips")

    if parser_args["fetch"]:
        add_urls_jobs: List[Tuple[Any, ...]] = []
        if "top1m" in parser_args["sources"]:
            # Download and Add TOP1M URLs to database
            add_urls_jobs.append((get_top1m_url_list, update_time, "top1m_urls"))
        if "top10m" in parser_args["sources"]:
            # Download and Add TOP10M URLs to database
            add_urls_jobs.append((get_top10m_url_list, update_time, "top10m_urls"))
        if "domainsproject" in parser_args["sources"]:
            # Extract and Add Domains Project URLs to database
            add_urls_jobs += [
                (
                    get_local_file_url_list,
                    update_time,
                    db_filename,
                    {"txt_filepath": txt_filepath},
                )
                for txt_filepath, db_filename in zip(
                    domainsproject_txt_filepaths, domainsproject_urls_db_filenames
                )
            ]
        if "cubdomain" in parser_args["sources"]:
            # Download and Add CubDomain.com URLs to database
            add_urls_jobs += [
                (
                    download_cubdomain,
                    update_time,
                    db_filename,
                    {"page_urls": page_urls},
                )
                for db_filename, page_urls in cubdomain_page_urls_by_db_filename.items()
            ]
        execute_with_ray(add_urls, add_urls_jobs)

        if "ipv4" in parser_args["sources"]:
            # Generate and Add ipv4 addresses to database
            execute_with_ray(add_ip_addresses, add_ip_addresses_jobs)

    if parser_args["identify"]:
        malicious_urls = dict()
        for vendor in parser_args["vendors"]:
            safebrowsing = SafeBrowsing(vendor)

            if not parser_args["use_existing_hashes"]:
                # Download and Update Safe Browsing API Malicious URL hash prefixes to database
                hash_prefixes = safebrowsing.get_malicious_url_hash_prefixes()
                replace_malicious_url_hash_prefixes(hash_prefixes, vendor)
                del hash_prefixes  # "frees" memory

            prefix_sizes = retrieve_vendor_hash_prefix_sizes(vendor)

            # Identify URLs in database whose full Hashes match with Malicious URL hash prefixes
            suspected_urls = set(
                flatten(
                    execute_with_ray(
                        get_matching_hash_prefix_urls,
                        [
                            (filename, prefix_sizes, vendor)
                            for filename in domains_db_filenames + ips_db_filenames
                        ],
                    ),
                )
            )

            # To Improve: Store suspected_urls into malicious.db under
            # suspected_urls table columns: [url,Google,Yandex]

            # Among these URLs, identify those with full Hashes
            # found on Safe Browsing API Server
            vendor_malicious_urls = safebrowsing.get_malicious_urls(suspected_urls)
            del suspected_urls  # "frees" memory
            malicious_urls[vendor] = vendor_malicious_urls

        write_urls_to_txt_file(list(set(flatten(malicious_urls.values()))))

        # TODO push blocklist to GitHub

        # Update malicious URL statuses in database
        for vendor in parser_args["vendors"]:
            execute_with_ray(
                update_malicious_urls,
                [
                    (update_time, vendor, filename)
                    for filename in domains_db_filenames + ips_db_filenames
                ],
                task_obj_store_args={"malicious_urls": malicious_urls[vendor]},
            )

    if parser_args["retrieve"]:
        write_urls_to_txt_file(retrieve_malicious_urls(domains_db_filenames))
    ray.shutdown()
