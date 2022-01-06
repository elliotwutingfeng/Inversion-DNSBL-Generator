"""
Logger Utilities
"""
import os
import logging


LOGS_FOLDER: str = "logs"


def init_logger() -> logging.Logger:
    """Returns a logger with custom format settings.

    `LOGS_FOLDER` is created beforehand if it does not exist yet.

    Returns:
        logging.Logger: logger that logs to `progress.log` in `LOGS_FOLDER`
    """
    if not os.path.exists(LOGS_FOLDER):
        os.mkdir(LOGS_FOLDER)

    # Add information like timestamp, filename, and line number to logging messages
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

    # Prevents tldextract library's filelock-related messages from cluttering the logs
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger = logging.getLogger()

    return logger
