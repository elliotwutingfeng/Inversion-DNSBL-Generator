import logging

def init_logger():
    # Disables filelock logging clutter from tldextract library
    logging.getLogger("filelock").setLevel(logging.WARNING)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    return logger