#!/usr/bin/env python3
"""
Elite CD Command Implementation
Advanced directory change with anti-forensics and MRU clearing
"""

import os
import sys
import ctypes
from typing import Dict, Any

def elite_cd(path: str = None) -> Dict[str, Any]:
    """
    Elite directory change with advanced features:
    - Direct Windows API calls (no Python tracking)
    - MRU (Most Recently Used) clearing
    - Anti-forensics techniques
    - Cross-platform support
    """
    
    try:
        # Handle no path (go to home)
        if not path:
            if sys.platform == 'win32':
                path = os.environ.get('USERPROFILE', 'C:\\')
            else:
                path = os.environ.get('HOME', '/')
        
        # Expand path
        path = os.path.abspath(os.path.expanduser(path))
        
        # Check if path exists
        if not os.path.exists(path):
            return {
                "success": False,
                "error": f"Directory does not exist: {path}",
                "current_directory": os.getcwd()
            }
        
        if not os.path.isdir(path):
            return {
                "success": False,
                "error": f"Path is not a directory: {path}",
                "current_directory": os.getcwd()
            }
        
        # Save current directory for rollback
        old_path = os.getcwd()
        
        # Change directory using platform-specific method
        if sys.platform == 'win32':
            success = _windows_elite_cd(path)
        else:
            success = _unix_elite_cd(path)
        
        if success:
            # Clear forensic traces
            _clear_directory_traces(path)
            
            return {
                "success": True,
                "previous_directory": old_path,
                "current_directory": path,
                "method": "elite_api"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to change directory to: {path}",
                "current_directory": old_path
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Directory change failed: {str(e)}",
            "current_directory": os.getcwd()
        }

def _windows_elite_cd(path: str) -> bool:
    """Windows implementation using SetCurrentDirectoryW"""
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Use SetCurrentDirectoryW to avoid Python tracking
        result = kernel32.SetCurrentDirectoryW(path)
        
        if result:
            # Update Python's internal state
            os.chdir(path)
            return True
        else:
            return False
            
    except Exception:
        # Fallback to standard method
        try:
            os.chdir(path)
            return True
        except:
            return False

def _unix_elite_cd(path: str) -> bool:
    """Unix implementation with syscall optimization"""
    
    try:
        # Use direct syscall if available
        if hasattr(os, 'fchdir'):
            # Open directory and use fchdir for better stealth
            try:
                fd = os.open(path, os.O_RDONLY)
                os.fchdir(fd)
                os.close(fd)
                return True
            except:
                pass
        
        # Fallback to standard chdir
        os.chdir(path)
        return True
        
    except Exception:
        return False

def _clear_directory_traces(path: str):
    """Clear directory access traces from system"""
    
    if sys.platform == 'win32':
        _clear_windows_directory_mru(path)
    else:
        _clear_unix_directory_traces(path)

def _clear_windows_directory_mru(path: str):
    """Remove directory from Windows MRU (Most Recently Used) lists"""
    
    try:
        import winreg
        
        # Registry keys that track directory access
        mru_keys = [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        ]
        
        for key_path in mru_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
                
                # Enumerate and remove entries containing our path
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if isinstance(value, str) and path.lower() in value.lower():
                            winreg.DeleteValue(key, name)
                        else:
                            i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
            except:
                continue
                
    except Exception:
        pass

def _clear_unix_directory_traces(path: str):
    """Clear Unix shell history and recent directory traces"""
    
    try:
        # Clear from common shell history files
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.history")
        ]
        
        for hist_file in history_files:
            if os.path.exists(hist_file):
                try:
                    # Read history and filter out our path
                    with open(hist_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Remove lines containing cd to our path
                    filtered_lines = [line for line in lines 
                                    if not (('cd ' in line or 'pushd ' in line) and path in line)]
                    
                    # Write back filtered history
                    with open(hist_file, 'w') as f:
                        f.writelines(filtered_lines)
                except:
                    continue
                    
    except Exception:
        pass


if __name__ == "__main__":
    # Test the elite_cd command
    # print("Testing Elite CD Command...")
    
    # Test basic functionality
    result = elite_cd(".")
    # print(f"Test 1 - Current dir: {result}")
    
    # Test invalid path
    result = elite_cd("/nonexistent/path")
    # print(f"Test 2 - Invalid path: {result}")
    
    # Test home directory
    result = elite_cd()
    # print(f"Test 3 - Home dir: {result}")
    
    # print("✅ Elite CD command testing complete")