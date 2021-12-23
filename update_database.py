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
    retrieve_provider_prefixSizes,
    update_malicious_URLs,
)

from filewriter import write_db_malicious_urls_to_file
from ray_utils import execute_with_ray
from safebrowsing import SafeBrowsing
from url_utils import get_local_file_url_list, get_top10m_url_list, get_top1m_url_list
from list_utils import flatten


def update_database(tasks, lists, providers):
    ray.shutdown()
    ray.init(include_dashboard=False)
    updateTime = int(time.time())  # seconds since UNIX Epoch

    urls_filenames = []

    if "domainsproject" in lists:
        # Scan "Domains Project" directory for local urls_filenames
        local_domains_dir = (
            pathlib.Path.cwd().parents[0] / "Domains Project" / "domains" / "data"
        )
        local_domains_filepaths = []
        for root, _, files in tqdm(list(os.walk(local_domains_dir))):
            for file in files:
                if file.lower().endswith(".txt"):
                    urls_filenames.append(f"{file[:-4]}")
                    local_domains_filepaths.append(os.path.join(root, file))

    if "top1m" in lists:
        urls_filenames.append("top1m_urls")
    if "top10m" in lists:
        urls_filenames.append("top10m_urls")

    # Create DB files
    initialise_database(urls_filenames)

    if "fetch" in tasks:
        add_URLs_jobs = []
        if "domainsproject" in lists:
            # Extract and Add local URLs to DB
            add_URLs_jobs += [
                (get_local_file_url_list, updateTime, filename, filepath)
                for filepath, filename in zip(local_domains_filepaths, urls_filenames)
            ]
        if "top1m" in lists:
            # Download and Add TOP1M URLs to DB
            add_URLs_jobs.append((get_top1m_url_list, updateTime, "top1m_urls"))
        if "top10m" in lists:
            # Download and Add TOP10M URLs to DB
            add_URLs_jobs.append((get_top10m_url_list, updateTime, "top10m_urls"))
        execute_with_ray(add_URLs_jobs, add_URLs)

    if "generate" in tasks:
        for provider in providers:
            sb = SafeBrowsing(provider)

            # Download and Update Safe Browsing API Malicious Hash Prefixes to DB
            hash_prefixes = sb.get_malicious_hash_prefixes()
            add_maliciousHashPrefixes(hash_prefixes, provider)
            del hash_prefixes  # "frees" memory

        malicious_urls = dict()
        for provider in providers:
            sb = SafeBrowsing(provider)

            prefixSizes = retrieve_provider_prefixSizes(provider)
            # Identify URLs in DB whose full Hashes match with Malicious Hash Prefixes
            suspected_urls = flatten(
                execute_with_ray(
                    [(provider, filename, prefixSizes) for filename in urls_filenames],
                    identify_suspected_urls,
                )
            )

            # To Improve: Store suspected_urls into malicious.db under suspected_urls table columns: [url,Google,Yandex]

            # Among these URLs, identify those with full Hashes are found on Safe Browsing API Server
            provider_malicious_urls = sb.get_malicious_URLs(suspected_urls)
            del suspected_urls  # "frees" memory
            malicious_urls[provider] = provider_malicious_urls

        # Write malicious_urls to TXT file
        write_db_malicious_urls_to_file(flatten(list(malicious_urls.values())))

        # TODO push blocklist to GitHub

        # TODO parallelise this section
        # Update malicious URL statuses in DB
        for filename in tqdm(urls_filenames):
            for provider in providers:
                update_malicious_URLs(
                    malicious_urls[provider], updateTime, provider, filename
                )

    ray.shutdown()