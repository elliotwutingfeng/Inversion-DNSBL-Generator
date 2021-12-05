from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_top1m_whitelist() -> list[str]:
    """Downloads the Tranco TOP1M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP1M list...")
    try:
        resp = requests.get("https://tranco-list.eu/top-1m.csv.zip")
        zipfile = ZipFile(BytesIO(resp.content))
        top1m_urls = [x.strip().decode().split(',')[1] for x in zipfile.open(zipfile.namelist()[0]).readlines()]
        logging.info("Downloading TOP1M list... [DONE]")
        return top1m_urls
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)