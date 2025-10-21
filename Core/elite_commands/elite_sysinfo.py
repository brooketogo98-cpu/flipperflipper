#!/usr/bin/env python3
"""
Elite System Information
Comprehensive system information gathering (alias for systeminfo)
"""

from .elite_systeminfo import elite_systeminfo

def elite_sysinfo(detailed: bool = True) -> dict:
    """
    Comprehensive system information gathering (alias for systeminfo)
    
    Args:
        detailed: Include detailed system information
    
    Returns:
        Dict containing comprehensive system information
    """
    
    # This is an alias for elite_systeminfo (ignores detailed parameter for compatibility)
    return elite_systeminfo()

if __name__ == "__main__":
    result = elite_sysinfo()
    print(f"System Info Result: {result}")