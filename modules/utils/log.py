"""
Logger Utilities
"""
import os
import logging


def init_logger(logs_folder: str = "logs") -> logging.Logger:
    """Return a logger with custom format settings.

    `logs_folder` is created beforehand if it does not exist yet.

    Args:
        logs_folder (str, optional): Logs folder location. Defaults to "logs".

    Returns:
        logging.Logger: logger that logs to `progress.log` in `logs_folder`
    """
    if not os.path.exists(logs_folder):
        os.mkdir(logs_folder)

    # Add information like timestamp, filename, and line number to logging messages
    logging.basicConfig(
        handlers=[
            logging.FileHandler(f"{logs_folder}{os.sep}progress.log", mode="a"),
            logging.StreamHandler(),
        ],
        format="""
        %(asctime)s %(levelname)-4s [%(filename)s:%(lineno)s - %(funcName)2s() ] %(message)s
        """,
        level=logging.INFO,
        datefmt="%d-%m-%Y %H:%M:%S",
    )

    # (Temporarily disabled) Prevents tldextract library's filelock-related messages from cluttering the logs
    # logging.getLogger("filelock").setLevel(logging.WARNING)

    logger = logging.getLogger()
    logger.setLevel("INFO")

    return logger
