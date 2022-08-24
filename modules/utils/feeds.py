"""
For generating Safe Browsing API-compliant hostname expressions
"""
import re

import tldextract
from modules.utils.log import init_logger

logger = init_logger()

# UPSERT hostname expressions into database
# in small batches to reduce RAM usage
hostname_expression_batch_size: int = 40_000


def generate_hostname_expressions_(raw_url: str) -> list[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    for a given `raw_url`

    Args:
        raw_url (str): URL, without prefixes
        (e.g. http:// https:// etc.),
        to generate Safe Browsing API-compliant
        hostname expression from.

    Returns:
        list[str]: Safe Browsing API-compliant
        hostname expressions for `raw_url`.
    """
    # Remove zero width spaces from raw_url
    url = re.sub(r"[\u200B-\u200D\uFEFF]", "", raw_url)

    try:
        tldresult = tldextract.extract(url)
        subdomain, domain_name = tldresult.subdomain, tldresult.registered_domain
        if domain_name == "":
            # No registered_domain recognised -> do not
            # split url into parts
            return [url] if url.strip() else []
        elif subdomain == "":
            # No subdomains found
            return [f"www.{domain_name}", domain_name, f"www.{url}", url]
        else:
            # Subdomains and registered_domain found -> extract them all
            parts = subdomain.split(".") + [domain_name]

        # Safe Browsing API-compliant hostname expressions
        # Include [url] for cases where url has a subdirectory
        # (e.g. google.com/<subdirectory>)
        return (
            [f"{'.'.join(parts[-i:])}" for i in range(min(len(parts), 5))]
            + [url]
            + [url.split(".", maxsplit=1)[1] if subdomain == "www" else f"www.{domain_name}"]
        )
    except Exception as error:
        logger.error("%s %s", url, error, exc_info=True)
        # if tldextract fails, return url as-is.
        return [url]


def generate_hostname_expressions(raw_urls: list[str]) -> set[str]:
    """Generate Safe Browsing API-compliant hostname expressions
    for a given batch of `raw_urls`

    See
    https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

    Args:
        raw_urls (list[str]): URLs, without prefixes
        (e.g. http:// https:// etc.),
        to generate Safe Browsing API-compliant
        hostname expressions from.

    Returns:
        set[str]: Safe Browsing API-compliant
        hostname expressions for each url in `raw_urls`
    """

    hostname_expressions = set()
    for raw_url in raw_urls:
        hostname_expressions.update(generate_hostname_expressions_(raw_url))

    return hostname_expressions
