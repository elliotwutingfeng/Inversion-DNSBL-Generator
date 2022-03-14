"""
Safe Browsing API helper class
"""
import asyncio
import base64
import itertools
import json
from typing import Iterator

from dotenv import dotenv_values
from more_itertools import flatten
from more_itertools.more import chunked
from tqdm import tqdm  # type: ignore

from modules.utils.http_requests import get_async, post_async
from modules.utils.log import init_logger
from modules.utils.types import Vendors

SAFEBROWSING_API_KEYS = {
    "Google": dotenv_values(".env")["GOOGLE_API_KEY"],
    "Yandex": dotenv_values(".env")["YANDEX_API_KEY"],
}

logger = init_logger()


class SafeBrowsing:
    """
    Safe Browsing API helper class
    """

    def __init__(self, vendor: Vendors) -> None:
        """Initialize Safe Browsing API helper class
        for a given `vendor` (e.g. "Google", "Yandex" etc.)

        Args:
            vendor (Vendors): Safe Browsing API vendor name (e.g. "Google", "Yandex" etc.)

        Raises:
            ValueError: `vendor` must be "Google" or "Yandex"
        """
        self.vendor = vendor

        if vendor not in ("Google", "Yandex"):
            raise ValueError('vendor must be "Google" or "Yandex"')

        endpoint_prefixes = {
            "Google": "https://safebrowsing.googleapis.com/v4/",
            "Yandex": "https://sba.yandex.net/v4/",
        }

        self.threatMatchesEndpoint = (
            f"{endpoint_prefixes[vendor]}threatMatches:find?key={SAFEBROWSING_API_KEYS[vendor]}"
        )
        self.threatListsEndpoint = (
            f"{endpoint_prefixes[vendor]}threatLists?key={SAFEBROWSING_API_KEYS[vendor]}"
        )
        self.threatListUpdatesEndpoint = f"{endpoint_prefixes[vendor]}threatListUpdates:fetch?key={SAFEBROWSING_API_KEYS[vendor]}"
        self.fullHashesEndpoint = (
            f"{endpoint_prefixes[vendor]}fullHashes:find?key={SAFEBROWSING_API_KEYS[vendor]}"
        )
        self.maximum_url_batch_size = {"Google": 500, "Yandex": 200}[vendor]
        # Even though Yandex API docs states maximum batch size limit as 500
        # Tested absolute maximum is batch size 300 (but fails often)
        # Somewhat stable: batch size 200
        # ¯\_(ツ)_/¯

    # Safe Browsing Lookup API
    def _threat_matches_payload(
        self,
        url_list: list[str],
    ) -> dict:
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
        return {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.5.2",
            },
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

    async def _threat_matches_lookup(self, url_batches: Iterator[list[str]]) -> list[dict]:
        """Submit list of URLs to Safe Browsing API threatMatches endpoint
        and return the API response.

        Args:
            url_batches (Iterator[list[str]]): Batches of URLs to submit
            to Safe Browsing API threatMatches endpoint for inspection

        Returns:
            list[dict]: List of each URL batch's
            Safe Browsing API threatMatches response
        """
        endpoints: list[str] = []
        payloads: list[bytes] = []
        for url_batch in url_batches:
            # Make POST request for each sublist of URLs
            endpoints.append(self.threatMatchesEndpoint)
            payloads.append(json.dumps(self._threat_matches_payload(url_batch)).encode())
        responses = await post_async(endpoints, payloads, max_concurrent_requests=10)

        return [json.loads(body) for _, body in responses]

    def lookup_malicious_urls(self, urls: set[str]) -> list[str]:
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

        results = asyncio.get_event_loop().run_until_complete(
            self._threat_matches_lookup(url_batches)
        )

        malicious = itertools.chain(*(res["matches"] for res in results if "matches" in res))

        # Removes `https` and `http` prefixes
        malicious_urls = list(
            set(
                (
                    x.get("threat", {})
                    .get("url", "")
                    .replace("https://", "")
                    .replace("http://", "")
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

    # Safe Browsing Update API
    def retrieve_url_threatlist_combinations(self) -> list[dict]:
        """GET names of currently available Safe Browsing lists from threatLists endpoint

        Returns:
            list[dict]: Names of currently available Safe Browsing lists from threatLists endpoint
        """
        threat_lists_endpoint_resp = asyncio.get_event_loop().run_until_complete(
            get_async([self.threatListsEndpoint])
        )[self.threatListsEndpoint]
        url_threatlist_combinations = []  # Empty list if self.threatListsEndpoint is unreachable
        if threat_lists_endpoint_resp != b"{}":
            threatlist_combinations = json.loads(threat_lists_endpoint_resp)["threatLists"]
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
                # Yandex API will return status code 204 with no content
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
        return url_threatlist_combinations

    def retrieve_threat_list_updates(self, url_threatlist_combinations: list[dict]) -> dict:
        """Return threatListUpdates endpoint JSON response
        in Dictionary-form for all available lists.

        Google API Reference
        https://developers.google.com/safe-browsing/v4/update-api
        Yandex API Reference
        https://yandex.com/dev/safebrowsing/doc/quickstart/concepts/update-threatlist.html

        Args:
            url_threatlist_combinations (list[dict]): Names of currently available
            Safe Browsing lists from threatLists endpoint

        Returns:
            dict: Dictionary-form of Safe Browsing API threatListUpdates.fetch JSON response
            https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatListUpdates/fetch
        """

        if url_threatlist_combinations:
            req_body = {
                "client": {
                    "clientId": "yourcompanyname",
                    "clientVersion": "1.5.2",
                },
                "listUpdateRequests": url_threatlist_combinations,
            }
            payload: bytes = json.dumps(req_body).encode()
            res = asyncio.get_event_loop().run_until_complete(
                post_async([self.threatListUpdatesEndpoint], [payload])
            )[0][1]

            res_json = json.loads(res)  # dict_keys(['listUpdateResponses', 'minimumWaitDuration'])
            if "listUpdateResponses" not in res_json:
                return {}
            logger.info("Minimum wait duration: %s", res_json["minimumWaitDuration"])
            return res_json

        return {}  # Empty dict() if url_threatlist_combinations is empty

    def get_malicious_url_hash_prefixes(self, threat_list_updates: dict) -> set[bytes]:
        """Download latest malicious URL hash prefixes from Safe Browsing API.

        The uncompressed threat entries in hash format of a particular prefix length.
        Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes,
        but some hashes are lengthened if they collide with the hash of a popular URL.

        Args:
            threat_list_updates (dict): Dictionary-form of Safe Browsing API
            threatListUpdates.fetch JSON response

        Returns:
            set[bytes]: Malicious URL hash prefixes from Safe Browsing API
        """
        logger.info("Downloading %s malicious URL hash prefixes", self.vendor)
        if threat_list_updates == {}:
            logger.info(
                "Downloading %s malicious URL hash prefixes...[DONE:NO THREAT LISTS FOUND]",
                self.vendor,
            )
            return set()
        list_update_responses = threat_list_updates["listUpdateResponses"]

        hash_prefixes = set()

        for list_update_response in tqdm(list_update_responses):
            for addition in list_update_response.get("additions", []):
                raw_hash_prefixes_ = addition.get("rawHashes", dict())
                prefix_size: int = raw_hash_prefixes_.get("prefixSize", 0)
                if (not isinstance(prefix_size, int)) or prefix_size <= 0:
                    continue
                raw_hash_prefixes = base64.b64decode(
                    raw_hash_prefixes_.get("rawHashes", "").encode()
                )

                hashes_list = [
                    raw_hash_prefixes[i : i + prefix_size]  # noqa: E203
                    for i in range(0, len(raw_hash_prefixes), prefix_size)
                ]

                hash_prefixes.update(hashes_list)
        logger.info("Downloading %s malicious URL hash prefixes...[DONE]", self.vendor)
        return hash_prefixes

    def get_malicious_url_full_hashes(
        self,
        hash_prefixes: set[bytes],
        url_threatlist_combinations: list[dict],
    ) -> Iterator[bytes]:
        """Download latest malicious URL full hashes from Safe Browsing API.

        Args:
            hash_prefixes (set[bytes]): Malicious URL hash prefixes from Safe Browsing API
            url_threatlist_combinations (list[dict]): Names of currently available
            Safe Browsing lists from threatLists endpoint

        Returns:
            set[bytes]: Malicious URL full hashes from Safe Browsing API
        """
        logger.info("Downloading %s malicious URL full hashes", self.vendor)
        b64_encoded_hash_prefixes: list[str] = [
            base64.b64encode(hash_prefix).decode() for hash_prefix in hash_prefixes
        ]

        payloads: list[bytes] = [
            json.dumps(
                {
                    "client": {
                        "clientId": "yourcompanyname",
                        "clientVersion": "1.5.2",
                    },
                    "clientStates": [""],
                    "threatInfo": {
                        "threatTypes": list(
                            set(x["threatType"] for x in url_threatlist_combinations)
                        ),
                        "platformTypes": list(
                            set(x["platformType"] for x in url_threatlist_combinations)
                        ),
                        "threatEntryTypes": list(
                            set(x["threatEntryType"] for x in url_threatlist_combinations)
                        ),
                        "threatEntries": [{"hash": hashPrefix} for hashPrefix in hashPrefixesBatch],
                    },
                }
            ).encode()
            for hashPrefixesBatch in chunked(b64_encoded_hash_prefixes, self.maximum_url_batch_size)
        ]

        endpoints: list[str] = [self.fullHashesEndpoint] * len(payloads)
        responses: list[tuple] = asyncio.get_event_loop().run_until_complete(
            post_async(endpoints, payloads, max_concurrent_requests=10)  # type:ignore
        )
        logger.info("Downloading %s malicious URL full hashes...[DONE]", self.vendor)

        threat_matches: Iterator[dict] = flatten(
            json.loads(x[1]).get("matches", dict()) for x in responses
        )
        fullHashes: Iterator[bytes] = (
            base64.b64decode(x.get("threat", {}).get("hash", "").encode())
            for x in threat_matches
            if x.get("threat", {}).get("hash", "") != ""
        )

        return fullHashes
