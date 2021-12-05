from __future__ import annotations
import time
from dotenv import dotenv_values
from ray_utils import execute_tasks
import requests
from requests.models import Response
import itertools
import logging
import ray
from tqdm import tqdm
import base64

logger = logging.getLogger()
logger.setLevel(logging.INFO)

API_KEY = dotenv_values(".env")['API_KEY']

######## Safe Browsing Lookup API ########
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
    """Find all URLs in a given list of URLs deemed by Google Safe Browsing API to be unsafe."""
    # Split list of URLs into sublists of maximum size 500 (to adhere to API limit)
    url_batches = list(chunks(urls,500))
    logging.info(f'{len(url_batches)} batches')
    results = execute_tasks(url_batches,google_api_lookup)
    unsafe = list(itertools.chain(*[res.json()['matches'] for res in results if len(list(res.json().keys())) != 0 ]))
    unsafe_urls = list(set([x['threat']['url'].replace("https://","").replace("http://","") for x in unsafe]))
    return unsafe_urls

######## Safe Browsing Update API ########
def retrieve_combinations():
    '''Before sending a request to the Safe Browsing servers, 
    the client should retrieve the names of the currently available Safe Browsing lists.
    This will help ensure that the parameters or type combinations specified in the request are valid.
    '''
    threatlist_combinations = requests.get(f"https://safebrowsing.googleapis.com/v4/threatLists?key={API_KEY}").json()['threatLists']
    url_threatlist_combinations = [x for x in threatlist_combinations if x['threatEntryType']=='URL']    
    return url_threatlist_combinations

def post_threatListUpdates(url_threatlist_combinations):
    req_body = {
      "client": {
              "clientId":      "yourcompanyname",
              "clientVersion": "1.5.2"
            },
      "listUpdateRequests": url_threatlist_combinations
    }
    res = requests.post(f"https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={API_KEY}",json=req_body)
    assert(res.status_code == 200)
    res_json = res.json() # dict_keys(['listUpdateResponses', 'minimumWaitDuration'])
    logging.info(f"Minimum wait duration: {res_json['minimumWaitDuration']}")
    return res_json

def get_malicious_hashes(listUpdateResponses):
    hashes = set()
    prefixSizes = []
    for x in tqdm(listUpdateResponses):

        y = x['additions'][0]['rawHashes']
        prefixSize = y['prefixSize']
        rawHashes = base64.b64decode(y['rawHashes'].encode('ascii'))
        
        hashes_list = sorted([rawHashes[i:i+prefixSize] for i in range(0, len(rawHashes), prefixSize)])
        hashes.update(hashes_list)
        prefixSizes += [prefixSize]
    
    # The uncompressed threat entries in hash format of a particular prefix length. 
    # Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes, 
    # but some hashes are lengthened if they collide with the hash of a popular URL.
    assert(set([len(x) for x in hashes]) == set(prefixSizes))
    return hashes

def get_malicious_hash_prefixes():
    """Download latest malicious hash prefixes from Google Safe Browsing API"""
    url_threatlist_combinations = retrieve_combinations()
    res_json = post_threatListUpdates(url_threatlist_combinations)
    listUpdateResponses = res_json['listUpdateResponses']
    hashes = get_malicious_hashes(listUpdateResponses)
    return hashes