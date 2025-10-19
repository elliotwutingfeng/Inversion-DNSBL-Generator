"""Tests for log.py"""

import logging
import os
from typing import Any

from modules.utils.log import init_logger


class MockMkdir:
    """Mock os.mkdir for testing"""

    def __init__(self) -> None:
        self.received_args: Any = None

    def __call__(self, *args: Any) -> None:
        self.received_args = args

    def get_received_args(self) -> Any:
        """Return received arguments

        Returns:
            Any: received arguments
        """
        return self.received_args


def test_init_logger():
    """Test `init_logger`"""

    orig_mkdir = os.mkdir
    orig_os_path_exists = os.path.exists

    os.mkdir = MockMkdir()
    os.path.exists = lambda _: False

    logger = init_logger("logs")

    assert os.mkdir.received_args[0] == "logs", (
        "Attempt to create 'logs' folder should be made"
    )

    assert logging.getLevelName(logger.getEffectiveLevel()) == "INFO", (
        "Logging level should be 'INFO'"
    )

    os.mkdir = orig_mkdir
    os.path.exists = orig_os_path_exists
