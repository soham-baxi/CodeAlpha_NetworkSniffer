import logging
from datetime import datetime

def setup_logger(name="sniffer_logger", log_file=None):
    if not log_file:
        log_file = f"sniffer_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger
