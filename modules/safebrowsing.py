"""
Safe Browsing API helper class
"""
from __future__ import annotations
import time
from typing import Dict, List, Mapping, Set
import itertools
import logging
import base64
from dotenv import dotenv_values
from more_itertools.more import chunked
import requests
from requests.models import Response
from tqdm import tqdm  # type: ignore
from modules.logger_utils import init_logger
from modules.ray_utils import execute_with_ray
from modules.requests_utils import get_with_retries, post_with_retries

GOOGLE_API_KEY = dotenv_values(".env")["GOOGLE_API_KEY"]
YANDEX_API_KEY = dotenv_values(".env")["YANDEX_API_KEY"]

logger = init_logger()


class SafeBrowsing:
    """
    Safe Browsing API helper class
    """

    def __init__(self, vendor: str) -> None:
        self.vendor = vendor
        if vendor == "Google":
            endpoint_prefix = "https://safebrowsing.googleapis.com/v4/"
            self.threatMatchesEndpoint = (  # pylint: disable=invalid-name
                f"{endpoint_prefix}threatMatches:find?key={GOOGLE_API_KEY}"
            )
            self.threatListsEndpoint = (  # pylint: disable=invalid-name
                f"{endpoint_prefix}threatLists?key={GOOGLE_API_KEY}"
            )
            self.threatListUpdatesEndpoint = (  # pylint: disable=invalid-name
                f"{endpoint_prefix}threatListUpdates:fetch?key={GOOGLE_API_KEY}"
            )
            self.maximum_url_batch_size = 500
        elif vendor == "Yandex":
            endpoint_prefix = "https://sba.yandex.net/v4/"
            self.threatMatchesEndpoint = (
                f"{endpoint_prefix}threatMatches:find?key={YANDEX_API_KEY}"
            )
            self.threatListsEndpoint = (
                f"{endpoint_prefix}threatLists?key={YANDEX_API_KEY}"
            )
            self.threatListUpdatesEndpoint = (
                f"{endpoint_prefix}threatListUpdates:fetch?key={YANDEX_API_KEY}"
            )
            # Even though API docs states maximum batch size limit as 500
            # Tested absolute maximum is batch size 300 (but fails often)
            # Somewhat stable: batch size 200
            # ¯\_(ツ)_/¯
            self.maximum_url_batch_size = 200
        else:
            raise ValueError('vendor must be "Google" or "Yandex"')

    ######## Safe Browsing Lookup API ########
    @staticmethod
    def threat_matches_payload(
        url_list: List[str],
    ) -> Dict:  # pylint: disable=invalid-name
        """
        For a given list of URLs,
        generate a POST request payload for Safe Browsing Lookup API endpoint.

        Google API Reference
        https://developers.google.com/safe-browsing/v4/lookup-api

        Yandex API Reference
        https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/lookup.html
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

    def threat_matches_lookup(self, url_batch: List[str]) -> Response:
        """
        Returns Safe Browsing API threatMatches for a given list of URLs.
        """

        data = SafeBrowsing.threat_matches_payload(url_batch)
        try:
            # Make POST request for each sublist of URLs
            res = post_with_retries(self.threatMatchesEndpoint, data)
        except requests.exceptions.RequestException:
            res = requests.Response()

        time.sleep(2)  # To prevent rate limiting
        return res

    def get_malicious_urls(self, urls: Set[str]) -> List[str]:
        """
        Find all URLs in a given list of URLs deemed by Safe Browsing API to be malicious.
        """
        logging.info("Verifying suspected %s malicious URLs", self.vendor)
        # Split list of URLs into sublists of length == maximum_url_batch_size
        url_batches = chunked(urls, self.maximum_url_batch_size)
        logging.info("%d batches", -(-len(urls) // self.maximum_url_batch_size))
        results = execute_with_ray(
            self.threat_matches_lookup,
            [(url_batch,) for url_batch in url_batches],
            progress_bar=False,
        )

        malicious = list(
            itertools.chain(
                *(res.json()["matches"] for res in results if "matches" in res.json())
            )
        )
        # Remove http, https prefixes
        malicious_urls = list(
            set(
                (
                    x["threat"]["url"].replace("https://", "").replace("http://", "")
                    for x in malicious
                )
            )
        )

        logging.info(
            "%d URLs confirmed to be marked malicious by %s Safe Browsing API.",
            len(malicious_urls),
            self.vendor,
        )

        return malicious_urls

    ######## Safe Browsing Update API ########
    def retrieve_threat_list_updates(self) -> Dict:
        """
        Before sending a request to the Safe Browsing servers,
        the client should retrieve the names of the
        currently available Safe Browsing lists.
        This will help ensure that the parameters
        or type combinations specified in the request are valid.

        Google API Reference
        https://developers.google.com/safe-browsing/v4/update-api
        Yandex API Reference
        https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/update-threatlist.html
        """
        threatlist_combinations = get_with_retries(self.threatListsEndpoint).json()[
            "threatLists"
        ]
        # TODO: Check if "IP_RANGE" is useful, currently Google has only one hashPrefix entry.
        if self.vendor == "Google":
            url_threatlist_combinations = [
                x
                for x in threatlist_combinations
                if "threatEntryType" in x
                and x["threatEntryType"]
                in (
                    "URL",
                    "IP_RANGE",
                )
            ]
        else:
            # Yandex API returns status code 204 with no content
            # if url_threatlist_combinations is too large
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
        logging.info("Minimum wait duration: %s", res_json["minimumWaitDuration"])
        return res_json

    @staticmethod
    def get_malicious_hashes(list_update_responses: Mapping) -> Set[bytes]:
        """
        Obtain malicious hashes from Safe Browsing API
        """
        hashes = set()
        prefix_sizes = set()
        for list_update_response in tqdm(list_update_responses):
            for addition in list_update_response["additions"]:
                raw_hashes_ = addition["rawHashes"]
                prefix_size = raw_hashes_["prefixSize"]
                raw_hashes = base64.b64decode(raw_hashes_["rawHashes"].encode("ascii"))

                hashes_list = sorted(
                    [
                        raw_hashes[i : i + prefix_size]
                        for i in range(0, len(raw_hashes), prefix_size)
                    ]
                )
                hashes.update(hashes_list)
                prefix_sizes.add(prefix_size)

        # The uncompressed threat entries in hash format of a particular prefix length.
        # Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes,
        # but some hashes are lengthened if they collide with the hash of a popular URL.
        # assert set((len(x) for x in hashes)) == prefix_sizes

        return hashes

    def get_malicious_hash_prefixes(self) -> Set[bytes]:
        """Download latest malicious hash prefixes from Safe Browsing API"""
        logging.info("Downloading %s malicious URL hashes", self.vendor)
        res_json = self.retrieve_threat_list_updates()
        if res_json == {}:
            return set()
        list_update_responses = res_json["listUpdateResponses"]
        hashes = SafeBrowsing.get_malicious_hashes(list_update_responses)
        return hashes
