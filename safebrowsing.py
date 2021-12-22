from __future__ import annotations
import time
from dotenv import dotenv_values
from list_utils import chunks
from logger_utils import init_logger
from ray_utils import execute_tasks
import requests
from requests.models import Response
import itertools
import logging
import ray
from tqdm import tqdm
import base64

from requests_utils import get_with_retries, post_with_retries

logger = init_logger()

GOOGLE_API_KEY = dotenv_values(".env")["GOOGLE_API_KEY"]
YANDEX_API_KEY = dotenv_values(".env")["YANDEX_API_KEY"]


class SafeBrowsing:
    def __init__(self, vendor):
        self.vendor = vendor
        if vendor == "Google":
            self.threatMatchesEndpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
            self.threatListsEndpoint = f"https://safebrowsing.googleapis.com/v4/threatLists?key={GOOGLE_API_KEY}"
            self.threatListUpdatesEndpoint = f"https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={GOOGLE_API_KEY}"
            self.maximum_url_batch_size = 500
        elif vendor == "Yandex":
            self.threatMatchesEndpoint = (
                f"https://sba.yandex.net/v4/threatMatches:find?key={YANDEX_API_KEY}"
            )
            self.threatListsEndpoint = (
                f"https://sba.yandex.net/v4/threatLists?key={YANDEX_API_KEY}"
            )
            self.threatListUpdatesEndpoint = f"https://sba.yandex.net/v4/threatListUpdates:fetch?key={YANDEX_API_KEY}"
            # Even though API docs states maximum batch size limit as 500
            # Tested absolute maximum is batch size 300 (but fails often)
            # Somewhat stable: batch size 200
            # ¯\_(ツ)_/¯
            self.maximum_url_batch_size = 200
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
            "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
            "threatInfo": {
                "threatTypes": [
                    "THREAT_TYPE_UNSPECIFIED",
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": [
                    "PLATFORM_TYPE_UNSPECIFIED",
                    "WINDOWS",
                    "LINUX",
                    "ANDROID",
                    "OSX",
                    "IOS",
                    "ANY_PLATFORM",
                    "ALL_PLATFORMS",
                    "CHROME",
                ],
                "threatEntryTypes": [
                    "THREAT_ENTRY_TYPE_UNSPECIFIED",
                    "URL",
                    "EXECUTABLE",
                ],
                "threatEntries": [{"url": f"http://{url}"} for url in url_list],
            },
        }
        return data

    def threatMatches_lookup(self, url_batch: list[str]) -> Response:
        """Returns Safe Browsing API threatMatches for a given list of URLs"""

        data = SafeBrowsing.threatMatches_payload(url_batch)
        try:
            # Make POST request for each sublist of URLs
            res = post_with_retries(self.threatMatchesEndpoint, data)
        except requests.exceptions.RequestException as e:
            res = requests.Response()

        time.sleep(2)  # To prevent rate limiting
        return res

    def get_malicious_URLs(self, urls: list[str]) -> list[str]:
        """Find all URLs in a given list of URLs deemed by Safe Browsing API to be malicious."""
        logging.info(f"Verifying suspected {self.vendor} malicious URLs")
        # Split list of URLs into sublists of length == maximum_url_batch_size
        url_batches = list(chunks(urls, self.maximum_url_batch_size))
        logging.info(f"{len(url_batches)} batches")
        results = execute_tasks(
            [(url_batch,) for url_batch in url_batches], self.threatMatches_lookup
        )

        malicious = list(
            itertools.chain(
                *[
                    res.json()["matches"]
                    for res in results
                    if len(list(res.json().keys())) != 0
                ]
            )
        )
        # Remove http, https prefixes
        malicious_urls = list(
            set(
                [
                    x["threat"]["url"].replace("https://", "").replace("http://", "")
                    for x in malicious
                ]
            )
        )

        logging.info(
            f"{len(malicious_urls)} URLs confirmed to be marked malicious by {self.vendor} Safe Browsing API."
        )

        return malicious_urls

    ######## Safe Browsing Update API ########
    def retrieve_threatListUpdates(self):
        """Before sending a request to the Safe Browsing servers,
        the client should retrieve the names of the currently available Safe Browsing lists.
        This will help ensure that the parameters or type combinations specified in the request are valid.

        Google API Reference: https://developers.google.com/safe-browsing/v4/update-api
        Yandex API Reference: https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/update-threatlist.html
        """
        threatlist_combinations = get_with_retries(self.threatListsEndpoint).json()[
            "threatLists"
        ]

        if self.vendor == "Google":
            url_threatlist_combinations = [
                x for x in threatlist_combinations if x["threatEntryType"] == "URL"
            ]
        else:
            # Yandex API returns status code 204 with no content if url_threatlist_combinations is too large
            url_threatlist_combinations = [
                {
                    "threatType": "ANY",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "state": "",
                },
                {
                    "threatType": "UNWANTED_SOFTWARE",
                    "threatEntryType": "URL",
                    "platformType": "PLATFORM_TYPE_UNSPECIFIED",
                    "state": "",
                },
                {
                    "threatType": "MALWARE",
                    "threatEntryType": "URL",
                    "platformType": "PLATFORM_TYPE_UNSPECIFIED",
                    "state": "",
                },
                {
                    "threatType": "SOCIAL_ENGINEERING",
                    "threatEntryType": "URL",
                    "platformType": "PLATFORM_TYPE_UNSPECIFIED",
                    "state": "",
                },
            ]

        req_body = {
            "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
            "listUpdateRequests": url_threatlist_combinations,
        }
        res = post_with_retries(self.threatListUpdatesEndpoint, req_body)

        res_json = (
            res.json()
        )  # dict_keys(['listUpdateResponses', 'minimumWaitDuration'])
        if "listUpdateResponses" not in res_json:
            return {}
        logging.info(f"Minimum wait duration: {res_json['minimumWaitDuration']}")
        return res_json

    @staticmethod
    def get_malicious_hashes(listUpdateResponses):
        hashes = set()
        prefixSizes = set()
        for x in tqdm(listUpdateResponses):
            for addition in x["additions"]:
                y = addition["rawHashes"]
                prefixSize = y["prefixSize"]
                rawHashes = base64.b64decode(y["rawHashes"].encode("ascii"))

                hashes_list = sorted(
                    [
                        rawHashes[i : i + prefixSize]
                        for i in range(0, len(rawHashes), prefixSize)
                    ]
                )
                hashes.update(hashes_list)
                prefixSizes.add(prefixSize)

        # The uncompressed threat entries in hash format of a particular prefix length.
        # Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes,
        # but some hashes are lengthened if they collide with the hash of a popular URL.
        assert set([len(x) for x in hashes]) == prefixSizes
        return hashes

    def get_malicious_hash_prefixes(self):
        """Download latest malicious hash prefixes from Safe Browsing API"""
        logging.info(f"Downloading {self.vendor} malicious URL hashes")
        res_json = self.retrieve_threatListUpdates()
        if res_json == {}:
            return set()
        listUpdateResponses = res_json["listUpdateResponses"]
        hashes = SafeBrowsing.get_malicious_hashes(listUpdateResponses)
        return hashes