"""Tests for logger_utils.py
"""


import logging
import os
from typing import Any
from modules.logger_utils import init_logger


class MockMkdir:
    """Mocks os.mkdir for testing"""

    def __init__(self) -> None:
        self.received_args: Any = None

    def __call__(self, *args: Any) -> None:
        self.received_args = args

    def get_received_args(self) -> Any:
        """Returns received arguments

        Returns:
            Any: received arguments
        """
        return self.received_args


def test_init_logger():
    """[summary]"""

    orig_mkdir = os.mkdir
    orig_os_path_exists = os.path.exists

    os.mkdir = MockMkdir()
    os.path.exists = lambda _: False

    logger = init_logger("logs")

    assert (
        os.mkdir.received_args[0] == "logs"
    ), "Attempt to create 'logs' folder should be made"

    assert (
        logging.getLevelName(logger.getEffectiveLevel()) == "WARNING"
    ), "Logging level should be 'WARNING'"

    os.mkdir = orig_mkdir
    os.path.exists = orig_os_path_exists
