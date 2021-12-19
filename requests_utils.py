import logging
import requests
import time
import json

from logger_utils import init_logger

logger = init_logger()

headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15",
}


def get_with_retries(endpoint, stream=False):
    attempt = 1
    while True:
        try:
            if stream:
                return requests.get(endpoint, stream=True, headers=headers, timeout=15)
            else:
                resp = requests.get(endpoint, headers=headers, timeout=15)
                if resp.status_code != 200:
                    raise requests.exceptions.RequestException(
                        f"Status Code not 200. Actual Code is {resp.status_code}"
                    )
                return resp
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt} failed -> {e}")
        attempt += 1
        time.sleep(1)


def post_with_retries(endpoint, payload):
    attempt = 1
    while True:
        try:
            resp = requests.post(
                endpoint, data=json.dumps(payload), headers=headers, timeout=15
            )
            if resp.status_code != 200:
                raise requests.exceptions.RequestException(
                    f"Status Code not 200. Actual Code is {resp.status_code}"
                )
            return resp
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt} failed -> {e}")
        attempt += 1
        time.sleep(1)