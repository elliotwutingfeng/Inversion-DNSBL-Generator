"""
Safe Browsing API helper class
"""
import asyncio
import itertools
import base64
import json
from dotenv import dotenv_values
from more_itertools.more import chunked
from tqdm import tqdm  # type: ignore
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from modules.utils.http import curl_req
from modules.utils.types import Vendors

GOOGLE_API_KEY = dotenv_values(".env")["GOOGLE_API_KEY"]
YANDEX_API_KEY = dotenv_values(".env")["YANDEX_API_KEY"]

logger = init_logger()


class SafeBrowsing:
    """
    Safe Browsing API helper class
    """

    def __init__(self, vendor: Vendors) -> None:
        """Initializes Safe Browsing API helper class
        for a given `vendor` (e.g. "Google", "Yandex" etc.)

        Args:
            vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

        Raises:
            ValueError: `vendor` must be "Google" or "Yandex"
        """
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
    def _threat_matches_payload(
        url_list: list[str],
    ) -> dict:  # pylint: disable=invalid-name
        """For a given list of URLs,
        generate a POST request payload for Safe Browsing API threatMatches endpoint.

        Google API Reference
        https://developers.google.com/safe-browsing/v4/lookup-api

        Yandex API Reference
        https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/lookup.html

        Args:
            url_list (list[str]): URLs to add to Safe Browsing API threatMatches payload

        Returns:
            dict: Safe Browsing API threatMatches payload
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

    async def _threat_matches_lookup(self, url_batch: list[str]) -> dict:
        """Submits list of URLs to Safe Browsing API threatMatches endpoint
        and returns the API response.

        Args:
            url_batch (list[str]): URLs to submit to Safe Browsing API
            threatMatches endpoint for inspection

        Returns:
            dict: Safe Browsing API threatMatches response
        """

        data = SafeBrowsing._threat_matches_payload(url_batch)

        # Make POST request for each sublist of URLs
        res = json.loads(curl_req(self.threatMatchesEndpoint, payload=data, request_type="POST"))

        await asyncio.sleep(2)  # To prevent rate limiting
        return res

    def get_malicious_urls(self, urls: set[str]) -> list[str]:
        """Identify all URLs in a given set of `urls` deemed by Safe Browsing API to be malicious.

        Args:
            urls (set[str]): URLs to be submitted to Safe Browsing API

        Returns:
            list[str]: URLs deemed by Safe Browsing API to be malicious
        """
        logger.info("Verifying suspected %s malicious URLs", self.vendor)
        # Split list of URLs into sublists of length == maximum_url_batch_size
        url_batches = chunked(urls, self.maximum_url_batch_size)
        logger.info("%d batches", -(-len(urls) // self.maximum_url_batch_size))
        results = execute_with_ray(
            self._threat_matches_lookup,
            [(url_batch,) for url_batch in url_batches],
            progress_bar=True,
        )

        malicious = list(
            itertools.chain(
                *(res["matches"] for res in results if "matches" in res)
            )
        )
        # Removes http, https prefixes
        malicious_urls = list(
            set(
                (
                    x["threat"]["url"].replace("https://", "").replace("http://", "")
                    for x in malicious
                )
            )
        )

        logger.info(
            "%d URLs confirmed to be marked malicious by %s Safe Browsing API.",
            len(malicious_urls),
            self.vendor,
        )

        return malicious_urls

    ######## Safe Browsing Update API ########
    def _retrieve_threat_list_updates(self) -> dict:
        """GET names of currently available Safe Browsing lists from threatLists endpoint,
        and returns threatListUpdates endpoint JSON response
        in Dictionary-form for all available lists.

        Google API Reference
        https://developers.google.com/safe-browsing/v4/update-api
        Yandex API Reference
        https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/update-threatlist.html

        Returns:
            dict: Dictionary-form of Safe Browsing API threatListUpdates.fetch JSON response
            https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatListUpdates/fetch
        """
        threat_lists_endpoint_resp = curl_req(self.threatListsEndpoint)
        if threat_lists_endpoint_resp:
            threatlist_combinations = json.loads(threat_lists_endpoint_resp)[
                "threatLists"
            ]
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
            res = curl_req(self.threatListUpdatesEndpoint, payload=req_body, request_type="POST")

            res_json = (
                json.loads(res)
            )  # dict_keys(['listUpdateResponses', 'minimumWaitDuration'])
            if "listUpdateResponses" not in res_json:
                return {}
            logger.info("Minimum wait duration: %s", res_json["minimumWaitDuration"])
            return res_json

        return {} # Empty dict() if self.threatListsEndpoint is unreachable

    def get_malicious_url_hash_prefixes(self) -> set[bytes]:
        """Download latest malicious URL hash prefixes from Safe Browsing API.

        The uncompressed threat entries in hash format of a particular prefix length.
        Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes,
        but some hashes are lengthened if they collide with the hash of a popular URL.

        Returns:
            set[bytes]: Malicious URL hash prefixes from Safe Browsing API
        """
        logger.info("Downloading %s malicious URL hashes", self.vendor)
        res_json = self._retrieve_threat_list_updates()
        if res_json == {}:
            return set()
        list_update_responses = res_json["listUpdateResponses"]

        hash_prefixes = set()

        for list_update_response in tqdm(list_update_responses):
            for addition in list_update_response["additions"]:
                raw_hash_prefixes_ = addition["rawHashes"]
                prefix_size = raw_hash_prefixes_["prefixSize"]
                raw_hash_prefixes = base64.b64decode(
                    raw_hash_prefixes_["rawHashes"].encode()
                )

                hashes_list = sorted(
                    [
                        raw_hash_prefixes[i : i + prefix_size]
                        for i in range(0, len(raw_hash_prefixes), prefix_size)
                    ]
                )
                hash_prefixes.update(hashes_list)
        logger.info("Downloading %s malicious URL hashes...[DONE]", self.vendor)
        return hash_prefixes
