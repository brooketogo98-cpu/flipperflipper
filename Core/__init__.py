#!/usr/bin/env python3
"""
Core Elite Implementation Package
Advanced security research tools for educational purposes
"""

# Import only what's actually needed and working
try:
    from .elite_executor import EliteCommandExecutor, create_elite_executor
    ELITE_EXECUTOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Elite executor not available: {e}")
    ELITE_EXECUTOR_AVAILABLE = False

try:
    from .security_bypass import SecurityBypass
    SECURITY_BYPASS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Security bypass not available: {e}")
    SECURITY_BYPASS_AVAILABLE = False

try:
    from .direct_syscalls import DirectSyscalls
    DIRECT_SYSCALLS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Direct syscalls not available: {e}")
    DIRECT_SYSCALLS_AVAILABLE = False

__version__ = "1.0.0"
__author__ = "Security Research Team"

__all__ = [
    'EliteCommandExecutor',
    'create_elite_executor',
    'SecurityBypass',
    'DirectSyscalls'
]