"""
For generating and scanning IPv4 addresses
"""
from typing import Dict, List, Tuple

from modules.utils.log import init_logger


logger = init_logger()

class Ipv4:
    """
    For generating and scanning IPv4 addresses
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args:Dict):
        self.db_filenames: List[str] = []
        self.jobs: List[Tuple] = []
        if "ipv4" in parser_args["sources"]:
            self.db_filenames = [_[0] for _ in self.jobs]
            if parser_args["fetch"]:
                # Generate and Add ipv4 addresses to database
                self.jobs = [
                (f"ipv4_{first_octet}", first_octet) for first_octet in range(2 ** 8)
            ]
        