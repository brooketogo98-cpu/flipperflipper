#!/usr/bin/env python3
"""
Centralized logging system for Stitch RAT
Provides structured logging with rotation and multiple handlers
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime

class StitchLogger:
    """Centralized logger for Stitch RAT"""
    
    def __init__(self, name='stitch', log_dir='logs', level=logging.INFO):
        self.name = name
        self.log_dir = log_dir
        self.level = level
        self.logger = None
        self._setup()
        
    def _setup(self):
        """Setup logger with handlers"""
        # Create logs directory
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(self.level)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
            
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler (INFO and above)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation (DEBUG and above)
        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f'{self.name}.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Error file handler (ERROR and above)
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, f'{self.name}_errors.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
    def debug(self, msg, *args, **kwargs):
        """Log debug message"""
        self.logger.debug(msg, *args, **kwargs)
        
    def info(self, msg, *args, **kwargs):
        """Log info message"""
        self.logger.info(msg, *args, **kwargs)
        
    def warning(self, msg, *args, **kwargs):
        """Log warning message"""
        self.logger.warning(msg, *args, **kwargs)
        
    def error(self, msg, *args, **kwargs):
        """Log error message"""
        self.logger.error(msg, *args, **kwargs)
        
    def critical(self, msg, *args, **kwargs):
        """Log critical message"""
        self.logger.critical(msg, *args, **kwargs)
        
    def exception(self, msg, *args, **kwargs):
        """Log exception with traceback"""
        self.logger.exception(msg, *args, **kwargs)


# Global logger instance
_global_logger = None

def get_logger(name='stitch', log_dir='logs'):
    """Get or create global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = StitchLogger(name, log_dir)
    return _global_logger


# Convenience module-level functions
def debug(msg, *args, **kwargs):
    """Log debug message"""
    get_logger().debug(msg, *args, **kwargs)

def info(msg, *args, **kwargs):
    """Log info message"""
    get_logger().info(msg, *args, **kwargs)

def warning(msg, *args, **kwargs):
    """Log warning message"""
    get_logger().warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    """Log error message"""
    get_logger().error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):
    """Log critical message"""
    get_logger().critical(msg, *args, **kwargs)

def exception(msg, *args, **kwargs):
    """Log exception with traceback"""
    get_logger().exception(msg, *args, **kwargs)


if __name__ == '__main__':
    # Test the logger
    logger = get_logger()
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    try:
        1 / 0
    except Exception:
        logger.exception("This is an exception with traceback")
    
    print(f"\nLogs written to: {os.path.abspath('logs/')}")
