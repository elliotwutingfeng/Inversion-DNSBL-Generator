import logging
import os

logs_folder = "logs"


def init_logger():
    if not os.path.exists(logs_folder):
        os.mkdir(logs_folder)
    # Add date and timestamp to logging messages
    logging.basicConfig(
        handlers=[
            logging.FileHandler(f"{logs_folder}{os.sep}progress.log", mode="a"),
            logging.StreamHandler(),
        ],
        format="%(asctime)s %(levelname)-4s [%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s",
        level=logging.INFO,
        datefmt="%d-%m-%Y %H:%M:%S",
    )

    # Disables filelock logging clutter from tldextract library
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger = logging.getLogger()

    return logger