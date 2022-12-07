"""
This module instantiates a logger object for the Semm Codebase
"""

import logging
import sys
import os

def create_debug_handler():

    """
    This helper function creates a debug_handler which outputs log to the console
    to be added to a logger instance.

    Returns:
        debug_handler(StreamHandler): Logging Handler for Processing Debug logs and outputting to terminal
    """

    debug_handler = logging.StreamHandler(sys.stdout)
    debug_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    debug_handler.setFormatter(formatter)

    return debug_handler


# create logger
logger = logging.getLogger('logs-semm')
logger.setLevel(logging.DEBUG)
debug_handler = create_debug_handler()

# Add console handler to logger
logger.addHandler(debug_handler)
