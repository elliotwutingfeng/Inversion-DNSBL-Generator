"""
For fetching and scanning URLs from DomCop TOP10M
"""
from collections.abc import Iterator
from io import BytesIO
from zipfile import ZipFile
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import curl_req
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions

logger = init_logger()

def _get_top10m_url_list() -> Iterator[list[str]]:
    """Downloads the DomCop TOP10M dataset and yields all listed URLs in batches.

    Yields:
        Iterator[list[str]]: Batch of URLs as a list
    """
    logger.info("Downloading TOP10M list...")
    with BytesIO() as file:
        resp = curl_req("https://www.domcop.com/files/top/top10milliondomains.csv.zip")
        if resp:
            file.write(resp)
            zipfile = ZipFile(file)
            raw_urls = (
                x.strip().decode().split(",")[1].replace('"', "")
                for x in zipfile.open(zipfile.namelist()[0]).readlines()[1:]
            )
            logger.info("Downloading TOP10M list... [DONE]")

            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)
        else:
            logger.warning("Failed to retrieve TOP10M list; yielding empty list")
            yield []

class Top10M:
    """
    For fetching and scanning URLs from DomCop TOP10M
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "top10m" in parser_args["sources"]:
            self.db_filenames = ["top10m_urls"]
            if parser_args["fetch"]:
                # Download and Add TOP10M URLs to database
                self.jobs = [(_get_top10m_url_list, update_time, "top10m_urls")]
