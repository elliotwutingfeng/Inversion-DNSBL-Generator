"""
For generating Safe Browsing API-compliant hostname expressions
"""
import re

import tldextract  # type: ignore
from modules.utils.log import init_logger

logger = init_logger()

# UPSERT hostname expressions into database
# in small batches to reduce RAM usage
hostname_expression_batch_size: int = 40_000


def generate_hostname_expressions(raw_urls: list[str]) -> set[str]:
    """Generate Safe Browsing API-compliant hostname expressions

    See
    https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

    Args:
        raw_urls (list[str]): URLs, without prefixes
        (e.g. http:// https:// etc.),
        to generate Safe Browsing API-compliant
        hostname expressions from.

    Returns:
        set[str]: `raw_urls` + Safe Browsing API-compliant
        hostname expressions of `raw_urls`
    """

    hostname_expressions = set()
    for raw_url in raw_urls:
        # Remove zero width spaces from raw_url
        url = re.sub(r"[\u200B-\u200D\uFEFF]", "", raw_url)
        try:
            ext = tldextract.extract(url)
            if ext.registered_domain == "":
                # No registered_domain recognised -> do not
                # split url into parts
                parts = []
            elif ext.subdomain == "":
                # No subdomains found -> extract registered_domain
                parts = [ext.registered_domain]
            else:
                # Subdomains and registered_domain found -> extract them all
                parts = ext.subdomain.split(".") + [ext.registered_domain]

            # Safe Browsing API-compliant hostname expressions
            # Include [url] for cases where url has a subdirectory
            # (e.g. google.com/<subdirectory>)
            hostname_expressions.update(
                [
                    f"{'.'.join(parts[-i:])}"
                    for i in range(len(parts) if len(parts) < 5 else 5)
                ]
                + [url]
            )
        except Exception as error:
            logger.error("%s %s", url, error, exc_info=True)
    return hostname_expressions
