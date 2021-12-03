from __future__ import annotations
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
from urllib.error import HTTPError
import logging

def get_top1m_whitelist() -> list[str]:
    """Downloads the Tranco TOP1M Whitelist and returns all whitelisted URLs."""
    logging.info("Downloading TOP1M list...")
    try:
      resp = urlopen("https://tranco-list.eu/top-1m.csv.zip")
      zipfile = ZipFile(BytesIO(resp.read()))
      top1m_urls = [x.strip().decode().split(',')[1] for x in zipfile.open(zipfile.namelist()[0]).readlines()]
      logging.info("Downloading TOP1M list... [DONE]")
      return top1m_urls
    except HTTPError as e:
      raise SystemExit(e)