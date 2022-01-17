"""
For generating and scanning Amazon Web Services EC2 URLs
"""
from __future__ import annotations
from typing import Dict,List,Iterator, Tuple
import ipaddress
import json
from collections import defaultdict
from more_itertools import chunked
from modules.utils.log import init_logger
from modules.utils.http import curl_req
from modules.feeds.hostname_expressions import generate_hostname_expressions


logger = init_logger()

def _collapse_cidrs(list_of_cidr_nets: List[str]) -> List[str]:
    """Remove overlapping ip ranges

    Args:
        list_of_cidr_nets (List[str]): IP ranges

    Returns:
        List[str]: IP ranges with overlaps removed
    """
    nets = (ipaddress.ip_network(_ip) for _ip in list_of_cidr_nets)
    ip_ranges = [str(ip_range) for ip_range in ipaddress.collapse_addresses(nets)]
    return ip_ranges

def _get_region_to_ip_ranges_per_region_map() -> Dict:
    """Downloads Amazon's official IP ranges and generates list of Amazon Web Services
    EC2 IPv4 ranges for each AWS region.

    Returns:
        Dict: Map each AWS region to a list of EC2 IPv4 ranges associated with that region
    """
    resp = curl_req("https://ip-ranges.amazonaws.com/ip-ranges.json")
    if resp == b'':
        logger.warning("Failed to retrieve Amazon Web "
        "Services IP ranges; returning empty list")
        return defaultdict(list)

    resp_json = json.loads(resp)
    ip_prefixes_and_regions = [(x['ip_prefix'],x['region'])
    for x in resp_json["prefixes"] if x['service'].upper() == 'EC2']
    region_to_ip_ranges_map = defaultdict(list)
    for ip_prefix,region in ip_prefixes_and_regions:
        region_to_ip_ranges_map[region].append(ip_prefix)
    return region_to_ip_ranges_map

def _get_ec2_url_list(region: str, ip_ranges: List[str]) -> Iterator[List[str]]:
    """Generates Amazon Web Services EC2 URLs located at
    AWS `region` and yields all listed URLs in batches.

    Args:
        region (str): AWS region
        ip_ranges (List[str]): IP Ranges for aws `region`

    Yields:
        Iterator[List[str]]: Batch of URLs as a list
    """
    def _generate_ec2_urls(region: str,ip_ranges: List[str]):
        suffix = f'''.{'compute-1' if region == 'us-east-1'
        else region+'.compute'}.amazonaws.com'''
        collapsed_ip_ranges = _collapse_cidrs(ip_ranges) # Removes overlapping ip ranges
        for ip_range in collapsed_ip_ranges:
            for ip_address in ipaddress.IPv4Network(ip_range.strip()):
                yield f'''ec2-{'-'.join(str(ip_address).split('.'))}{suffix}'''

    ec2_url_generator = _generate_ec2_urls(region,ip_ranges)

    for batch in chunked(ec2_url_generator, 40_000):
        yield generate_hostname_expressions(batch)


class AmazonWebServicesEC2:
    """
    For generating and scanning Amazon Web Services EC2 URLs
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, parser_args:Dict, update_time:int):
        self.db_filenames: List[str] = []
        self.jobs: List[Tuple] = []

        if "ec2" in parser_args["sources"]:
            map_region_to_ip_ranges_per_region = _get_region_to_ip_ranges_per_region_map()

            if map_region_to_ip_ranges_per_region:
                regions,ip_ranges_per_region = zip(*map_region_to_ip_ranges_per_region.items())
            else:
                regions,ip_ranges_per_region = tuple(),tuple()


            self.db_filenames = [f"ec2_{region}_urls" for region in regions]

            if parser_args["fetch"]:
                # Generate and Add Amazon Web Services EC2 URLs to database
                self.jobs = [(_get_ec2_url_list, update_time, db_filename,
                {"region":region,"ip_ranges":ip_ranges})
                for db_filename,region,ip_ranges
                in zip(self.db_filenames,regions,ip_ranges_per_region)]