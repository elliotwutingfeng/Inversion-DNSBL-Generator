"""
Logger Utilities
"""
import os
import logging


LOGS_FOLDER: str = "logs"


def init_logger() -> logging.Logger:
    """
    Initialise a logging.Logger instance with custom format settings
    """
    if not os.path.exists(LOGS_FOLDER):
        os.mkdir(LOGS_FOLDER)
    # Add date and timestamp to logging messages
    logging.basicConfig(
        handlers=[
            logging.FileHandler(f"{LOGS_FOLDER}{os.sep}progress.log", mode="a"),
            logging.StreamHandler(),
        ],
        format="""
        %(asctime)s %(levelname)-4s [%(filename)s:%(lineno)s - %(funcName)2s() ] %(message)s
        """,
        level=logging.INFO,
        datefmt="%d-%m-%Y %H:%M:%S",
    )

    # Disables filelock logging clutter from tldextract library
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger = logging.getLogger()

    return logger
