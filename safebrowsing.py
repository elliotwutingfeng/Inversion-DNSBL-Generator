from __future__ import annotations
import time
from dotenv import dotenv_values
from ray_utils import execute_tasks
import requests
from requests.models import Response
import itertools
import logging
import ray


API_KEY = dotenv_values(".env")['API_KEY']

def chunks(lst: list, n: int) -> list:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

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
    time.sleep(2) # To prevent rate limiting
    actor_id.update.remote(1) # Update progressbar
    return res

def get_unsafe_URLs(urls: list[str]) -> list[str]:
    """Find all URLs in Tranco TOP1M deemed by Google Safe Browsing API to be unsafe."""
    # Split list of URLs into sublists of maximum size 500 (to adhere to API limit)
    url_batches = list(chunks(urls,500))
    logging.info(f'{len(url_batches)} batches')
    results = execute_tasks(url_batches,google_api_lookup)
    unsafe = list(itertools.chain(*[res.json()['matches'] for res in results if len(list(res.json().keys())) != 0 ]))
    unsafe_urls = list(set([x['threat']['url'].replace("https://","").replace("http://","") for x in unsafe]))
    return unsafe_urls
