"""Logging configuration for MicroPKI."""

import logging
import sys
from datetime import datetime
from typing import Optional


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up the logger with the specified configuration.
    
    Args:
        log_file: Optional path to log file. If None, logs to stderr.
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create formatter with ISO 8601 timestamp
    class ISO8601Formatter(logging.Formatter):
        def formatTime(self, record, datefmt=None):
            dt = datetime.fromtimestamp(record.created)
            return dt.isoformat(timespec='milliseconds')
    
    formatter = ISO8601Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Add handler for stderr or file
    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stderr)
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger
