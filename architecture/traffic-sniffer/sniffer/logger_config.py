"""
Configuration module for the network sniffer.
It creates logs both on the file and the console.
"""

import logging
import os
from datetime import datetime


def setup_logger(name='PacketSniffer', log_dir='logs'):
    """
    Logger set up
    
    Args:
        name: logger name
        log_dir: output dir
    
    Returns:
        Configured Logger
    """

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    log_filename = os.path.join(
        log_dir, 
        f'sniffer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )

    # logger configuration
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # file handler
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger