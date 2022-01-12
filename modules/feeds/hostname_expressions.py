"""
Utilities for gathering URLs from various sources
"""
from __future__ import annotations
from typing import List
import tldextract  # type: ignore
from modules.utils.log import init_logger

logger = init_logger()


def generate_hostname_expressions(raw_urls: List[str]) -> List[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    See: https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

    Args:
        raw_urls (List[str]): URLs to generate Safe Browsing API-compliant
        hostname expressions from.

    Returns:
        List[str]: `raw_urls` + Safe Browsing API-compliant hostname expressions of `raw_urls`
    """
    # pylint: disable=broad-except

    hostname_expressions = set()
    for raw_url in raw_urls:
        try:
            ext = tldextract.extract(raw_url)
            if ext.subdomain == "":
                parts = [ext.registered_domain]
            else:
                parts = ext.subdomain.split(".") + [ext.registered_domain]
            hostname_expressions.update(
                [
                    f"{'.'.join(parts[-i:])}"
                    for i in range(len(parts) if len(parts) < 5 else 5)
                ]
            )
        except Exception as error:
            logger.error("%s %s", raw_url, error, exc_info=True)
    return list(hostname_expressions)
