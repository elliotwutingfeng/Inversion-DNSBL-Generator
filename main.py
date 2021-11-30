from __future__ import annotations
import requests
from requests.models import Response
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
from urllib.error import HTTPError
import itertools
import json
import logging
from dotenv import dotenv_values
import argparse
import ray

from progressbar_utils import execute_tasks

API_KEY = dotenv_values(".env")['API_KEY']

def chunks(lst: list, n: int) -> list:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def get_top1m_whitelist() -> list[str]:
    """Downloads the Tranco TOP1M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP1M list...")
    try:
      resp = urlopen("https://tranco-list.eu/top-1m.csv.zip")
      zipfile = ZipFile(BytesIO(resp.read()))
      top1m_urls = [x.strip().decode().split(',')[1] for x in zipfile.open(zipfile.namelist()[0]).readlines()]
      logging.info("Downloading TOP1M list... [DONE]")
      return top1m_urls
    except HTTPError as e:
      raise SystemExit(e)

def google_lookup_api_payload(url_list: list[str]) -> dict:
    """
    For a given list of URLs, generate a POST request payload for Google Safe Browsing Lookup API endpoint.
    API Reference: https://developers.google.com/safe-browsing/v4/lookup-api
    """
    data = {
        "client": {
          "clientId":      "yourcompanyname",
          "clientVersion": "1.5.2"
        },
        "threatInfo": {
          "threatTypes":      ["THREAT_TYPE_UNSPECIFIED",
                               "MALWARE",
                               "SOCIAL_ENGINEERING",
                               "UNWANTED_SOFTWARE",
                              "POTENTIALLY_HARMFUL_APPLICATION"],
          "platformTypes":    ["PLATFORM_TYPE_UNSPECIFIED",
                               "WINDOWS",
                               "LINUX",
                               "OSX",
                               "IOS",
                               "ANY_PLATFORM",
                               "ALL_PLATFORMS",
                               "CHROME"],
          "threatEntryTypes": ["THREAT_ENTRY_TYPE_UNSPECIFIED",
                               "URL","EXECUTABLE"],
          "threatEntries": [
            {"url": f"http://{url}"} for url in url_list
          ]
        }
      }
    return data

@ray.remote
def google_api_lookup(url_batch: list[str], actor_id: ray._raylet.ObjectRef) -> Response:
    """Returns Google Safe Browsing API threatMatches for a given list of URLs
    
    """
    data = google_lookup_api_payload(url_batch)
    try:
        # Make POST request for each sublist of URLs
        res = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}',json=data)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    if res.status_code != 200:
        raise SystemExit(Exception("Error: Google API Response Code is not 200, Actual: " + str(res.status_code) ))
    actor_id.update.remote(1) # Update progressbar
    return res

def get_unsafe_URLs(urls: list[str]) -> list[Response]:
    """Find all URLs in Tranco TOP1M deemed by Google Safe Browsing API to be unsafe."""
    # Split list of URLs into sublists of maximum size 500 (to adhere to API limit)
    url_batches = list(chunks(urls,500))
    logging.info(f'{len(url_batches)} batches')
    results = execute_tasks(url_batches,google_api_lookup)

    return results

def write_unsafe_urls_to_file(unsafe_urls: list[Response],top1m_urls: list[str]) -> None:
    """
    Writes list of URLs marked unsafe by Google, and original list of TOP1M URLs to JSON file.
    Also writes list of URLs marked unsafe by Google to TXT file.
    """
    unsafe = list(itertools.chain(*[res.json()['matches'] for res in unsafe_urls if len(list(res.json().keys())) != 0 ]))
    unsafe = list(set([x['threat']['url'] for x in unsafe]))
    logging.info(f'{len(unsafe)} URLs marked unsafe by Google Safe Browsing API.')
    logging.info(f'{len(unsafe)/len(top1m_urls)*100.0}% of TOP1M URLs marked unsafe by Google Safe Browsing API.')    
    with open('URLs_marked_unsafe_by_Google.json', 'a') as outfile:
        json.dump({"unsafe":unsafe, "original": top1m_urls}, outfile)
    with open('URLs_marked_unsafe_by_Google.txt', 'a') as outfile:
        outfile.writelines(s + '\n' for s in unsafe)

if __name__=='__main__':
    ray.shutdown()
    ray.init(include_dashboard=False,num_cpus=4)

    logging.basicConfig(level=logging.INFO)

    testing_quantity = 4000

    parser = argparse.ArgumentParser(description='Find all URLs in Tranco TOP1M deemed by Google Safe Browsing API to be unsafe.')
    parser.add_argument('--mode', required=True, choices=['testing', 'full'], 
    help=f"testing: Lookup last {testing_quantity} URLs from Tranco TOP1M list on Google Safe Browsing API | full: Lookup all 1000,000 URLs on Google Safe Browsing API")
    args = parser.parse_args()

    top1m_urls = get_top1m_whitelist()[-testing_quantity if args.mode == 'testing' else 0:]
    unsafe_urls = get_unsafe_URLs(top1m_urls)
    write_unsafe_urls_to_file(unsafe_urls,top1m_urls)
    ray.shutdown()