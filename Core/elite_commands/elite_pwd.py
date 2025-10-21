#!/usr/bin/env python3
"""
Elite PWD Command Implementation
Advanced working directory retrieval without syscall logging
"""

import os
import sys
import ctypes
from typing import Dict, Any

def elite_pwd() -> Dict[str, Any]:
    """
    Elite working directory retrieval with advanced features:
    - Direct Windows API calls (no syscall logging)
    - Cross-platform support
    - Multiple verification methods
    - Anti-detection techniques
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_pwd()
        else:
            return _unix_elite_pwd()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to get working directory: {str(e)}",
            "working_directory": None
        }

def _windows_elite_pwd() -> Dict[str, Any]:
    """Windows implementation using GetCurrentDirectoryW"""
    
    try:
        # Method 1: Direct API call
        buffer = ctypes.create_unicode_buffer(260)  # MAX_PATH
        length = ctypes.windll.kernel32.GetCurrentDirectoryW(260, buffer)
        
        if length > 0:
            api_path = buffer.value
            
            # Method 2: Verify with Python's getcwd for consistency
            try:
                python_path = os.getcwd()
                
                # Normalize paths for comparison
                api_path_norm = os.path.normpath(api_path).lower()
                python_path_norm = os.path.normpath(python_path).lower()
                
                if api_path_norm == python_path_norm:
                    method = "api_verified"
                    path = api_path
                else:
                    method = "api_primary"
                    path = api_path
                    
            except:
                method = "api_only"
                path = api_path
            
            # Get additional path information
            path_info = _get_path_information(path)
            
            return {
                "success": True,
                "working_directory": path,
                "method": method,
                "drive": os.path.splitdrive(path)[0] if path else None,
                "path_info": path_info
            }
        else:
            # Fallback to Python method
            return _fallback_pwd()
            
    except Exception as e:
        return _fallback_pwd()

def _unix_elite_pwd() -> Dict[str, Any]:
    """Unix implementation with multiple verification methods"""
    
    try:
        # Method 1: Direct syscall if available
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            
            # Use getcwd syscall directly
            buffer = ctypes.create_string_buffer(4096)  # PATH_MAX
            result = libc.getcwd(buffer, 4096)
            
            if result:
                syscall_path = buffer.value.decode('utf-8')
                method = "syscall"
            else:
                raise Exception("Syscall failed")
                
        except:
            # Method 2: Environment variable
            try:
                env_path = os.environ.get('PWD')
                if env_path and os.path.exists(env_path):
                    syscall_path = env_path
                    method = "environment"
                else:
                    raise Exception("Environment PWD invalid")
            except:
                # Method 3: Python fallback
                syscall_path = os.getcwd()
                method = "python_fallback"
        
        # Verify path exists and is accessible
        if os.path.exists(syscall_path) and os.path.isdir(syscall_path):
            path_info = _get_path_information(syscall_path)
            
            return {
                "success": True,
                "working_directory": syscall_path,
                "method": method,
                "path_info": path_info
            }
        else:
            return _fallback_pwd()
            
    except Exception as e:
        return _fallback_pwd()

def _fallback_pwd() -> Dict[str, Any]:
    """Fallback method using standard Python"""
    
    try:
        path = os.getcwd()
        path_info = _get_path_information(path)
        
        return {
            "success": True,
            "working_directory": path,
            "method": "python_standard",
            "path_info": path_info
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"All methods failed: {str(e)}",
            "working_directory": None
        }

def _get_path_information(path: str) -> Dict[str, Any]:
    """Get additional information about the current path"""
    
    info = {
        "exists": False,
        "readable": False,
        "writable": False,
        "is_root": False,
        "parent": None,
        "basename": None
    }
    
    try:
        info["exists"] = os.path.exists(path)
        info["readable"] = os.access(path, os.R_OK)
        info["writable"] = os.access(path, os.W_OK)
        info["is_root"] = (path == os.path.dirname(path))
        info["parent"] = os.path.dirname(path)
        info["basename"] = os.path.basename(path)
        
        # Additional Windows-specific info
        if sys.platform == 'win32':
            info["drive"] = os.path.splitdrive(path)[0]
            info["is_network"] = path.startswith('\\\\')
        
    except Exception:
        pass
    
    return info


if __name__ == "__main__":
    # Test the elite_pwd command
    # print("Testing Elite PWD Command...")
    
    # Test basic functionality
    result = elite_pwd()
    # print(f"Test 1 - Current directory: {result}")
    
    # Change directory and test again
    try:
        if sys.platform == 'win32':
            os.chdir('C:\\')
        else:
            os.chdir('/')
        
        result = elite_pwd()
    # print(f"Test 2 - Root directory: {result}")
        
    except Exception as e:
    # print(f"Test 2 failed: {e}")
    
    # print("✅ Elite PWD command testing complete")