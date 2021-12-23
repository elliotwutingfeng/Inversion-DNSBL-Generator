import logging
from datetime import datetime
import os

logs_folder = "logs"


def current_timestamp_str():
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def init_logger():
    if not os.path.exists(logs_folder):
        os.mkdir(logs_folder)
    # Add date and timestamp to logging messages
    logging.basicConfig(
        filename=f"{logs_folder}{os.sep}progress_{current_timestamp_str()}.log",
        filemode="a",
        format="%(asctime)s %(levelname)-4s [%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s",
        level=logging.INFO,
        datefmt="%d-%m-%Y %H:%M:%S",
    )

    # Disables filelock logging clutter from tldextract library
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger = logging.getLogger()

    return logger