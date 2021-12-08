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

GOOGLE_API_KEY = dotenv_values(".env")['GOOGLE_API_KEY']
YANDEX_API_KEY = dotenv_values(".env")['YANDEX_API_KEY']

def chunks(lst: list, n: int) -> list:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class SafeBrowsing:
    def __init__(self,vendor):
        self.vendor = vendor
        if vendor == "Google":
            self.threatMatchesEndpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
            self.threatListsEndpoint = f"https://safebrowsing.googleapis.com/v4/threatLists?key={GOOGLE_API_KEY}"
            self.threatListUpdatesEndpoint = f"https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={GOOGLE_API_KEY}"
            self.maximum_url_batch_size = 500
        elif vendor == "Yandex":
            self.threatMatchesEndpoint = f"https://sba.yandex.net/v4/threatMatches:find?key={YANDEX_API_KEY}"
            self.threatListsEndpoint = f"https://sba.yandex.net/v4/threatLists?key={YANDEX_API_KEY}"
            self.threatListUpdatesEndpoint = f"https://sba.yandex.net/v4/threatListUpdates:fetch?key={YANDEX_API_KEY}"
            self.maximum_url_batch_size = 300 # Tested to be 300 URLs even though API docs states it as 500 ¯\_(ツ)_/¯
        else:
          raise ValueError('vendor must be "Google" or "Yandex"')

    ######## Safe Browsing Lookup API ########
    @staticmethod
    def threatMatches_payload(url_list: list[str]) -> dict:
        """
        For a given list of URLs, generate a POST request payload for Safe Browsing Lookup API endpoint.
        Google API Reference: https://developers.google.com/safe-browsing/v4/lookup-api
        Yandex API Reference: https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/lookup.html
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
                                  "ANDROID",
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


    def threatMatches_lookup(self):
      @ray.remote
      def threatMatches_lookup_(url_batch: list[str], actor_id: ray._raylet.ObjectRef) -> Response:
          """Returns Safe Browsing API threatMatches for a given list of URLs
          """

          data = SafeBrowsing.threatMatches_payload(url_batch)
          try:
              # Make POST request for each sublist of URLs
              res = requests.post(self.threatMatchesEndpoint,json=data)
          except requests.exceptions.RequestException as e:
              raise SystemExit(e)
          if res.status_code != 200:
              raise SystemExit(Exception("Error: threatMatches API Response Code is not 200, Actual: " + str(res.status_code) ))
          time.sleep(2) # To prevent rate limiting
          actor_id.update.remote(1) # Update progressbar
          return res
      return threatMatches_lookup_

    def get_malicious_URLs(self,urls: list[str]) -> list[str]:
        """Find all URLs in a given list of URLs deemed by Safe Browsing API to be malicious."""
        # Split list of URLs into sublists of length == maximum_url_batch_size
        url_batches = list(chunks(urls,self.maximum_url_batch_size))
        logging.info(f'{len(url_batches)} batches')
        results = execute_tasks(url_batches,self.threatMatches_lookup())
        malicious = list(itertools.chain(*[res.json()['matches'] for res in results if len(list(res.json().keys())) != 0 ]))
        malicious_urls = list(set([x['threat']['url'].replace("https://","").replace("http://","") for x in malicious]))

        logging.info(f'{len(malicious_urls)} URLs confirmed to be marked malicious by {self.vendor} Safe Browsing API.')

        return malicious_urls

    ######## Safe Browsing Update API ########
    def retrieve_threatListUpdates(self):
        '''Before sending a request to the Safe Browsing servers, 
        the client should retrieve the names of the currently available Safe Browsing lists.
        This will help ensure that the parameters or type combinations specified in the request are valid.
        
        Google API Reference: https://developers.google.com/safe-browsing/v4/update-api
        Yandex API Reference: https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/update-threatlist.html
        '''
        threatlist_combinations = requests.get(self.threatListsEndpoint).json()['threatLists']

        url_threatlist_combinations = [x for x in threatlist_combinations
        if x['threatEntryType']=='URL']
        
        req_body = {
          "client": {
                  "clientId":      "yourcompanyname",
                  "clientVersion": "1.5.2"
                },
          "listUpdateRequests": url_threatlist_combinations
        }
        res = requests.post(self.threatListUpdatesEndpoint,json=req_body)
        if res.status_code != 200:
          return {}
        res_json = res.json() # dict_keys(['listUpdateResponses', 'minimumWaitDuration'])
        if 'listUpdateResponses' not in res_json:
          return {}
        logging.info(f"Minimum wait duration: {res_json['minimumWaitDuration']}")
        return res_json

    @staticmethod
    def get_malicious_hashes(listUpdateResponses):
        hashes = set()
        prefixSizes = []
        for x in tqdm(listUpdateResponses):
            for addition in x['additions']:
                y = addition['rawHashes']
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

    def get_malicious_hash_prefixes(self):
        """Download latest malicious hash prefixes from Safe Browsing API"""
        res_json = self.retrieve_threatListUpdates()
        if res_json == {}:
          return set()
        listUpdateResponses = res_json['listUpdateResponses']
        hashes = SafeBrowsing.get_malicious_hashes(listUpdateResponses)
        return hashes