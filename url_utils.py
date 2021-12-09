from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
import requests
import logging
import tldextract
from requests_utils import get_with_retries
from tqdm import tqdm
import math


def get_top1m_whitelist() -> list[str]:
    """Downloads the Tranco TOP1M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP1M list...")
    try:
        with BytesIO() as f:
            resp = get_with_retries("https://tranco-list.eu/top-1m.csv.zip", stream=True)
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
            resp = get_with_retries("https://www.domcop.com/files/top/top10milliondomains.csv.zip", stream=True)
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