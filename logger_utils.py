import logging

def init_logger():
    # Add date and timestamp to logging messages
    logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')

    # Disables filelock logging clutter from tldextract library
    logging.getLogger("filelock").setLevel(logging.WARNING)
    
    logger = logging.getLogger()
    #logger.setLevel(logging.INFO)

    return logger