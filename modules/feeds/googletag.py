"""
For fetching and scanning URLs from Google Threat Analysis Group
"""

import re
from collections.abc import AsyncIterator

import feedparser
from bs4 import BeautifulSoup
from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.log import init_logger
from more_itertools import chunked, flatten
from urlextract import URLExtract

logger = init_logger()


async def _get_googletag_urls() -> AsyncIterator[set[str]]:
    """Download Google Threat Analysis Group domains and yield all listed URLs in batches.

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """

    # Parse RSS feed (limited to latest 20 entries)
    feed_url = "https://blog.google/threat-analysis-group/rss/"
    feed = feedparser.parse(feed_url)
    ioc_urls: list[str] = []
    extractor = URLExtract()
    for entry in feed.entries:
        # IOCs are almost always found within <li> tags; if not, kindly open an issue on the GitHub repo.
        soup = BeautifulSoup(entry["summary"], "lxml")
        # extract only tag contents with defangs (i.e. content with "[:]" or "[.]")
        tag_text: list[str] = [
            tag.text
            for tag in soup.find_all("li")
            if "[.]" in tag.text or "[:]" in tag.text
        ]
        # fang all tag text
        fanged_tag_text: list[str] = [
            re.sub(r"\[:\]", ":", re.sub(r"\[\.\]", ".", text)).strip().split(" ")[0]
            for text in tag_text
        ]
        # remove all url schemes (i.e. http://, https:// etc.)
        ioc_urls += [
            re.sub(r"(?:[a-zA-Z]+:\/\/)?", "", url, 1)
            for url in flatten(
                [
                    extractor.find_urls(may_contain_urls)
                    for may_contain_urls in fanged_tag_text
                ]
            )
        ]
    if feed.entries:
        for batch in chunked(ioc_urls, hostname_expression_batch_size):
            yield generate_hostname_expressions(batch)
    else:
        logger.warning(
            "Failed to retrieve Google Threat Analysis Group domains; yielding empty list"
        )
        yield set()


class GoogleTag:
    """
    For fetching and scanning URLs from Google Threat Analysis Group
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "googletag" in parser_args["sources"]:
            self.db_filenames = ["googletag"]
            if parser_args["fetch"]:
                # Download and Add Google Threat Analysis Group URLs to database
                self.jobs = [(_get_googletag_urls, update_time, "googletag")]
