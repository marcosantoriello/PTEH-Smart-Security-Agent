"""
Centralized logging configuration module.
Creates logs both on file and console with consistent formatting.
"""

import logging
import os
from datetime import datetime


def get_logger(name, log_dir='logs', level=logging.INFO):
    """
    Get or create a configured logger instance.
    
    Args:
        name: Logger name (typically the module name)
        log_dir: Directory where log files will be stored
        level: Logging level (default: INFO)
    
    Returns:
        Configured Logger instance
    """
    
    # Check if logger already exists to avoid duplicate handlers
    logger = logging.getLogger(name)
    
    # If logger already has handlers, return it as is
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create log filename with timestamp
    log_filename = os.path.join(
        log_dir,
        f'{name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    
    # Log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
