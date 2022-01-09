"""
Process flags
"""
import time
import os
import pathlib
from typing import Any, Dict, List, Tuple
from more_itertools import flatten
from more_itertools.more import sort_together
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
from modules.scrape_cubdomain import get_page_urls_by_date_str
from modules.url_utils import (
    get_local_file_url_list,
    get_top10m_url_list,
    get_top1m_url_list,
)


def retrieve_domainsproject_filepaths_and_db_filenames():
    """[summary]

    Returns:
        [type]: [description]
    """
    # Scan Domains Project's "domains" directory for local urls_filenames
    domainsproject_dir = pathlib.Path.cwd().parents[0] / "domains" / "data"
    domainsproject_filepaths: List[str] = []
    domainsproject_urls_db_filenames: List[str] = []
    for root, _, files in os.walk(domainsproject_dir):
        for file in files:
            if file.lower().endswith(".txt"):
                domainsproject_urls_db_filenames.append(f"{file[:-4]}")
                domainsproject_filepaths.append(os.path.join(root, file))

    # Sort domainsproject_filepaths and domainsproject_urls_db_filenames by ascending filesize
    domainsproject_filesizes: List[int] = [
        os.path.getsize(path) for path in domainsproject_filepaths
    ]
    [
        domainsproject_filesizes,
        domainsproject_filepaths,
        domainsproject_urls_db_filenames,
    ] = [
        list(_)
        for _ in sort_together(
            (
                domainsproject_filesizes,
                domainsproject_filepaths,
                domainsproject_urls_db_filenames,
            )
        )
    ]
    return domainsproject_filepaths, domainsproject_urls_db_filenames


def process_flags(
    fetch: bool,
    identify: bool,
    use_existing_hashes: bool,
    retrieve: bool,
    sources: List[str],
    vendors: List[str],
) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-arguments,too-many-statements

    """Run assorted DNSBL generator tasks in sequence based on flags set by user.

    Args:
        fetch (bool): If True, fetch URL datasets from local and/or remote sources,
        and update them to database
        identify (bool): If True, use Safe Browsing API to identify malicious URLs in database,
        write the URLs to a .txt file blocklist, and update database with these malicious URLs
        use_existing_hashes (bool): If True, use existing malicious URL hashes when
        identifying malicious URLs in database
        retrieve (bool): If True, retrieve URLs in database that have been flagged
        as malicious from past scans, then create a .txt file blocklist
        sources (List[str]): URL sources (e.g. top1m, top10m etc.)
        vendors (List[str]): Safe Browsing API vendors (e.g. Google, Yandex etc.)
    """
    ray.shutdown()
    ray.init(include_dashboard=True)
    update_time = int(time.time())  # seconds since UNIX Epoch

    top1m_urls_db_filename = ["top1m_urls"] if "top1m" in sources else []
    top10m_urls_db_filename = ["top10m_urls"] if "top1m" in sources else []
    if "cubdomain" in sources:
        cubdomain_page_urls_by_date_str = get_page_urls_by_date_str()
        cubdomain_urls_db_filenames = [
            f"cubdomain_{date_str}" for date_str in cubdomain_page_urls_by_date_str
        ]
    else:
        cubdomain_urls_db_filenames = []
    if "domainsproject" in sources:
        (
            domainsproject_filepaths,
            domainsproject_urls_db_filenames,
        ) = retrieve_domainsproject_filepaths_and_db_filenames()
    else:
        domainsproject_urls_db_filenames = []

    if "ipv4" in sources:
        add_ip_addresses_jobs: List[Tuple] = [
            (f"ipv4_{first_octet}", first_octet) for first_octet in range(2 ** 8)
        ]
        ips_filenames = [_[0] for _ in add_ip_addresses_jobs]
    else:
        ips_filenames = []

    urls_filenames = (
        top1m_urls_db_filename
        + top10m_urls_db_filename
        + cubdomain_urls_db_filenames
        + domainsproject_urls_db_filenames
    )

    # Create database files
    initialise_databases(urls_filenames, mode="domains")
    initialise_databases(ips_filenames, mode="ips")

    if fetch:
        add_urls_jobs: List[Tuple[Any, ...]] = []
        if "top1m" in sources:
            # Download and Add TOP1M URLs to database
            add_urls_jobs.append((get_top1m_url_list, update_time, "top1m_urls"))
        if "top10m" in sources:
            # Download and Add TOP10M URLs to database
            add_urls_jobs.append((get_top10m_url_list, update_time, "top10m_urls"))
        if "domainsproject" in sources:
            # Extract and Add local URLs to database
            add_urls_jobs += [
                (get_local_file_url_list, update_time, filename, filepath)
                for filepath, filename in zip(domainsproject_filepaths, urls_filenames)
            ]
        execute_with_ray(add_urls, add_urls_jobs)

        if "ipv4" in sources:
            # Generate and Add ipv4 addresses to database
            execute_with_ray(add_ip_addresses, add_ip_addresses_jobs)

    if identify:
        malicious_urls = dict()
        for vendor in vendors:
            safebrowsing = SafeBrowsing(vendor)

            if not use_existing_hashes:
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
                            for filename in urls_filenames + ips_filenames
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
        for vendor in vendors:
            execute_with_ray(
                update_malicious_urls,
                [
                    (update_time, vendor, filename)
                    for filename in urls_filenames + ips_filenames
                ],
                task_obj_store_args={"malicious_urls": malicious_urls[vendor]},
            )

    if retrieve:
        write_urls_to_txt_file(retrieve_malicious_urls(urls_filenames))
    ray.shutdown()
