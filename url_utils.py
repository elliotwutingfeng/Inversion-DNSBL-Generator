from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
import requests
import logging
import tldextract
from tqdm import tqdm
import math
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

headers = { "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15" }

def get_with_retries(endpoint,stream=False):
    return requests.get(endpoint,stream,headers=headers)
    for attempt in range(1,21):
        try:
            resp = requests.get(endpoint,stream,headers=headers)
            return resp
        except requests.exceptions.RequestException as e:
            logging.warning(f"{attempt} {e}")
            if attempt == 20:
                raise requests.exceptions.RequestException(e)


def post_with_retries(endpoint,payload):
    for attempt in range(1,21):
        try:
            resp = requests.post(endpoint,data=json.dumps(payload),headers=headers)
            if resp.status_code != 200:
                continue
            return resp
        except requests.exceptions.RequestException as e:
            logging.warning(f"{attempt} {e}")
            if attempt == 20:
                raise requests.exceptions.RequestException(e)

def get_top1m_whitelist() -> list[str]:
    """Downloads the Tranco TOP1M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP1M list...")
    try:
        with BytesIO() as f:
            resp = requests.get("https://tranco-list.eu/top-1m.csv.zip", stream=True)
            chunk_size = 4096
            for data in tqdm(resp.iter_content(chunk_size=chunk_size),
                             total=math.ceil(int(resp.headers['Content-Length'])/chunk_size)):
                f.write(data)
            zipfile = ZipFile(f)
            top1m_urls = [x.strip().decode().split(',')[1] for x in zipfile.open(zipfile.namelist()[0]).readlines()]
            logging.info("Downloading TOP1M list... [DONE]")
            return top1m_urls
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

def get_top10m_whitelist() -> list[str]:
    """Downloads the DomCop TOP10M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP10M list...")
    try:
        with BytesIO() as f:
            resp = requests.get("https://www.domcop.com/files/top/top10milliondomains.csv.zip", stream=True)
            chunk_size = 4096
            for data in tqdm(resp.iter_content(chunk_size=chunk_size),
                             total=math.ceil(int(resp.headers['Content-Length'])/chunk_size)):
                f.write(data)
            zipfile = ZipFile(f)
            top10m_urls = [tldextract.extract(x.strip().decode().split(',')[1].replace('"',"")).registered_domain 
                       for x in zipfile.open(zipfile.namelist()[0]).readlines()[1:]]
            logging.info("Downloading TOP10M list... [DONE]")
            return top10m_urls
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

if __name__=='__main__':
    top1m_urls = get_top1m_whitelist()
    logging.info(len(top1m_urls))
    top10m_urls = get_top10m_whitelist()
    logging.info(len(top10m_urls))