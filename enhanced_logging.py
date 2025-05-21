"""
Enhanced logging system for AI-IDS
---------------------------------
This module provides logging utilities for the AI-IDS system.
"""

import os
import sys
import time
import logging
import functools
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

# Configure logging
def configure_logging(name, level=logging.INFO):
    """Configure logging for a module"""
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    # Create file handler
    log_file = os.path.join(logs_dir, f"{name}.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger





# Get logger for a module
def get_logger(name, level=logging.INFO):
    """Get logger for a module"""
    return configure_logging(name, level)

# Performance tracking decorator
def track_performance(operation_name):
    """Decorator for tracking performance of operations"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get logger
            logger = logging.getLogger('performance')
            
            # Start timer
            start_time = time.time()
            
            # Log start
            logger.info(f"[START] {operation_name}")
            
            try:
                # Call function
                result = func(*args, **kwargs)
                
                # Log success
                logger.info(f"[SUCCESS] {operation_name}")
                
                return result
            
            except Exception as e:
                # Log error
                logger.error(f"[ERROR] {operation_name}: {e}")
                
                # Re-raise exception
                raise
            
            finally:
                # Log end
                end_time = time.time()
                duration = end_time - start_time
                logger.info(f"[END] {operation_name} - Duration: {duration:.2f}s")
        
        return wrapper
    
    return decorator

# Performance tracking context manager
@contextmanager
def track_performance_context(operation_name):
    """Context manager for tracking performance of operations"""
    # Get logger
    logger = logging.getLogger('performance')
    
    # Start timer
    start_time = time.time()
    
    # Log start
    logger.info(f"[START] {operation_name}")
    
    try:
        # Yield control
        yield
        
        # Log success
        logger.info(f"[SUCCESS] {operation_name}")
    
    except Exception as e:
        # Log error
        logger.error(f"[ERROR] {operation_name}: {e}")
        
        # Re-raise exception
        raise
    
    finally:
        # Log end
        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"[END] {operation_name} - Duration: {duration:.2f}s")
