"""
For generating and scanning Amazon Web Services EC2 URLs
"""
from __future__ import annotations
from typing import Dict,List,Tuple,Iterator
import ipaddress
import requests
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import get_with_retries
from modules.feeds.hostname_expressions import generate_hostname_expressions


logger = init_logger()

def _get_ec2_url_list() -> Iterator[List[str]]:
    """Generates Amazon Web Services EC2 URLs and yields all listed URLs in batches.

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    def _generate_ec2_urls(ip_prefixes_and_regions):
        for ip_prefix,region in ip_prefixes_and_regions:
            for ip_address in ipaddress.IPv4Network(ip_prefix.strip()):
                yield f'''ec2-{'-'.join(str(ip_address).split('.'))}.{'compute-1' if
                region == 'us-east-1' else region+'.compute'}.amazonaws.com'''
    try:
        resp_json = get_with_retries("https://ip-ranges.amazonaws.com/ip-ranges.json").json()
        ip_prefixes_and_regions = [(x['ip_prefix'],x['region'])
        for x in resp_json["prefixes"] if x['service'].upper() == 'EC2']
        ec2_url_generator = _generate_ec2_urls(ip_prefixes_and_regions)

        for batch in chunked(ec2_url_generator, 40_000):
            yield generate_hostname_expressions(batch)

    except requests.exceptions.RequestException as error:
        logger.warning("Failed to generate Amazon Web "
        "Services EC2 URLs; yielding empty list: %s", error)
        yield []


class AmazonWebServicesEC2:
    """
    For generating and scanning Amazon Web Services EC2 URLs
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args:Dict,update_time:int):
        self.db_filenames: List[str] = []
        self.jobs: List[Tuple] = []
        if "ec2" in parser_args["sources"]:
            self.db_filenames = ["ec2_urls"]
            if parser_args["fetch"]:
                # Generate and Add Amazon Web Services EC2 URLs to database
                self.jobs = [(_get_ec2_url_list, update_time, "ec2_urls")]
