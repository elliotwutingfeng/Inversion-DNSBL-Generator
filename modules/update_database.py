from typing import Any, Iterable, List, Tuple
from more_itertools.more import sort_together
import ray
import time
import os
import pathlib

from modules.db_utils import (
    add_IPs,
    add_maliciousHashPrefixes,
    get_matching_hashPrefix_urls,
    initialise_database,
    add_URLs,
    retrieve_malicious_URLs,
    retrieve_vendor_prefixSizes,
    update_malicious_URLs,
)

from modules.filewriter import write_db_malicious_urls_to_file
from modules.ray_utils import execute_with_ray
from modules.safebrowsing import SafeBrowsing
from modules.url_utils import (
    get_local_file_url_list,
    get_top10m_url_list,
    get_top1m_url_list,
)
from more_itertools import flatten


def update_database(
    fetch: bool, identify: bool, retrieve: bool, sources: List[str], vendors: List[str]
) -> None:
    ray.shutdown()
    ray.init(include_dashboard=True)
    updateTime = int(time.time())  # seconds since UNIX Epoch

    urls_filenames: List[str] = []
    ips_filenames: List[str] = []

    if "domainsproject" in sources:
        # Scan Domains Project's "domains" directory for local urls_filenames
        local_domains_dir = pathlib.Path.cwd().parents[0] / "domains" / "data"
        local_domains_filepaths: List[str] = []
        for root, _, files in os.walk(local_domains_dir):
            for file in files:
                if file.lower().endswith(".txt"):
                    urls_filenames.append(f"{file[:-4]}")
                    local_domains_filepaths.append(os.path.join(root, file))
        # Sort local_domains_filepaths and urls_filenames by ascending filesize

        local_domains_filesizes: List[int] = [
            os.path.getsize(path) for path in local_domains_filepaths
        ]

        [local_domains_filesizes, local_domains_filepaths, urls_filenames] = [
            list(_)
            for _ in sort_together(
                (local_domains_filesizes, local_domains_filepaths, urls_filenames)
            )
        ]

    if "top1m" in sources:
        urls_filenames.append("top1m_urls")
    if "top10m" in sources:
        urls_filenames.append("top10m_urls")
    if "ipv4" in sources:
        add_IPs_jobs = [
            (f"ipv4_{first_octet}", first_octet) for first_octet in range(2 ** 8)
        ]
        ips_filenames = [_[0] for _ in add_IPs_jobs]

    # Create DB files
    initialise_database(urls_filenames, mode="domains")
    initialise_database(ips_filenames, mode="ips")

    if fetch:
        add_URLs_jobs: List[Tuple[Any, ...]] = []
        if "domainsproject" in sources:
            # Extract and Add local URLs to DB
            add_URLs_jobs += [
                (get_local_file_url_list, updateTime, filename, filepath)
                for filepath, filename in zip(local_domains_filepaths, urls_filenames)
            ]
        if "top1m" in sources:
            # Download and Add TOP1M URLs to DB
            add_URLs_jobs.append((get_top1m_url_list, updateTime, "top1m_urls"))
        if "top10m" in sources:
            # Download and Add TOP10M URLs to DB
            add_URLs_jobs.append((get_top10m_url_list, updateTime, "top10m_urls"))
        execute_with_ray(add_URLs, add_URLs_jobs)

        if "ipv4" in sources:
            # Generate and Add ipv4 addresses to DB
            execute_with_ray(add_IPs, add_IPs_jobs)

    if identify:
        for vendor in vendors:
            sb = SafeBrowsing(vendor)

            # Download and Update Safe Browsing API Malicious Hash Prefixes to DB
            hash_prefixes = sb.get_malicious_hash_prefixes()
            add_maliciousHashPrefixes(hash_prefixes, vendor)
            del hash_prefixes  # "frees" memory

        malicious_urls = dict()
        for vendor in vendors:
            sb = SafeBrowsing(vendor)

            prefixSizes = retrieve_vendor_prefixSizes(vendor)
            suspected_urls = set()
            for prefixSize in prefixSizes:
                # Identify URLs in DB whose full Hashes match with Malicious Hash Prefixes
                suspected_urls.update(
                    set(
                        flatten(
                            execute_with_ray(
                                get_matching_hashPrefix_urls,
                                [
                                    (filename, prefixSize, vendor)
                                    for filename in urls_filenames + ips_filenames
                                ],
                            ),
                        )
                    )
                )

                # To Improve: Store suspected_urls into malicious.db under suspected_urls table columns: [url,Google,Yandex]

            # Among these URLs, identify those with full Hashes are found on Safe Browsing API Server
            vendor_malicious_urls = sb.get_malicious_URLs(suspected_urls)
            del suspected_urls  # "frees" memory
            malicious_urls[vendor] = vendor_malicious_urls

        # Write malicious_urls to TXT file
        write_db_malicious_urls_to_file(list(set(flatten(malicious_urls.values()))))

        # TODO push blocklist to GitHub

        # Update malicious URL statuses in DB
        for vendor in vendors:
            execute_with_ray(
                update_malicious_URLs,
                [
                    (updateTime, vendor, filename)
                    for filename in urls_filenames + ips_filenames
                ],
                store={"malicious_urls": malicious_urls[vendor]},
            )

    if retrieve:
        # Write malicious_urls to TXT file
        write_db_malicious_urls_to_file(retrieve_malicious_URLs(urls_filenames))
    ray.shutdown()