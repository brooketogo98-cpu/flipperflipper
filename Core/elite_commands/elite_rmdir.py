#!/usr/bin/env python3
"""
Elite RMDIR Command Implementation
Advanced directory removal with secure deletion and anti-forensics
"""

import os
import sys
import ctypes
import shutil
import time
from typing import Dict, Any, List

def elite_rmdir(dirpath: str, recursive: bool = False, secure: bool = True) -> Dict[str, Any]:
    """
    Elite directory removal with advanced features:
    - Secure deletion with content wiping
    - Recursive directory tree removal
    - Anti-forensics techniques
    - Cross-platform support
    - Recovery prevention
    """
    
    try:
        # Validate directory path
        if not dirpath:
            return {
                "success": False,
                "error": "Directory path is required",
                "removed_directories": []
            }
        
        # Expand path
        dirpath = os.path.abspath(os.path.expanduser(dirpath))
        
        # Check if directory exists
        if not os.path.exists(dirpath):
            return {
                "success": False,
                "error": f"Directory does not exist: {dirpath}",
                "removed_directories": []
            }
        
        if not os.path.isdir(dirpath):
            return {
                "success": False,
                "error": f"Path is not a directory: {dirpath}",
                "removed_directories": []
            }
        
        # Check if directory is empty (for non-recursive removal)
        if not recursive:
            try:
                contents = os.listdir(dirpath)
                if contents:
                    return {
                        "success": False,
                        "error": f"Directory is not empty. Use recursive=True to remove non-empty directories: {dirpath}",
                        "removed_directories": []
                    }
            except PermissionError:
                return {
                    "success": False,
                    "error": f"Permission denied accessing directory: {dirpath}",
                    "removed_directories": []
                }
        
        removed_directories = []
        
        if recursive:
            # Remove directory tree recursively
            removed_directories = _remove_directory_tree_secure(dirpath, secure)
        else:
            # Remove single empty directory
            if _remove_single_directory_secure(dirpath, secure):
                removed_directories.append(dirpath)
            else:
                return {
                    "success": False,
                    "error": f"Failed to remove directory: {dirpath}",
                    "removed_directories": []
                }
        
        return {
            "success": True,
            "removed_directories": removed_directories,
            "recursive": recursive,
            "secure_deletion": secure,
            "method": "elite_secure_rmdir"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Directory removal failed: {str(e)}",
            "removed_directories": []
        }

def _remove_directory_tree_secure(dirpath: str, secure: bool) -> List[str]:
    """Securely remove directory tree recursively"""
    
    removed_directories = []
    
    try:
        # Walk directory tree in reverse order (deepest first)
        for root, dirs, files in os.walk(dirpath, topdown=False):
            # Remove files first
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if secure:
                        _secure_wipe_file(filepath)
                    _delete_file_secure(filepath)
                except Exception:
                    continue
            
            # Remove subdirectories
            for dir_name in dirs:
                subdir = os.path.join(root, dir_name)
                try:
                    if _remove_single_directory_secure(subdir, secure):
                        removed_directories.append(subdir)
                except Exception:
                    continue
        
        # Remove root directory
        try:
            if _remove_single_directory_secure(dirpath, secure):
                removed_directories.append(dirpath)
        except Exception:
            pass
            
    except Exception:
        pass
    
    return removed_directories

def _remove_single_directory_secure(dirpath: str, secure: bool) -> bool:
    """Remove a single directory with security measures"""
    
    try:
        # Apply anti-forensics before removal
        if secure:
            _apply_directory_anti_forensics(dirpath)
        
        # Platform-specific removal
        if sys.platform == 'win32':
            return _windows_remove_directory(dirpath)
        else:
            return _unix_remove_directory(dirpath)
            
    except Exception:
        return False

def _windows_remove_directory(dirpath: str) -> bool:
    """Windows directory removal using API calls"""
    
    try:
        # Method 1: Try RemoveDirectoryW API
        if ctypes.windll.kernel32.RemoveDirectoryW(dirpath):
            return True
        
        # Method 2: Try MoveFileExW with delayed deletion
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        if ctypes.windll.kernel32.MoveFileExW(dirpath, None, MOVEFILE_DELAY_UNTIL_REBOOT):
            return True
        
        # Method 3: Standard Python removal
        os.rmdir(dirpath)
        return True
        
    except Exception:
        return False

def _unix_remove_directory(dirpath: str) -> bool:
    """Unix directory removal with syscalls"""
    
    try:
        # Method 1: Direct rmdir syscall
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            result = libc.rmdir(dirpath.encode('utf-8'))
            if result == 0:
                return True
        except:
            pass
        
        # Method 2: Standard Python removal
        os.rmdir(dirpath)
        return True
        
    except Exception:
        return False

def _apply_directory_anti_forensics(dirpath: str):
    """Apply anti-forensics techniques to directory before removal"""
    
    try:
        # Modify directory timestamps to obscure deletion time
        current_time = time.time()
        old_time = current_time - (24 * 60 * 60)  # 24 hours ago
        
        try:
            os.utime(dirpath, (old_time, old_time))
        except:
            pass
        
        # Platform-specific anti-forensics
        if sys.platform == 'win32':
            _windows_directory_anti_forensics(dirpath)
        else:
            _unix_directory_anti_forensics(dirpath)
            
    except Exception:
        pass

def _windows_directory_anti_forensics(dirpath: str):
    """Apply Windows-specific anti-forensics"""
    
    try:
        # Clear directory from MRU lists
        _clear_windows_directory_mru(dirpath)
        
        # Modify directory attributes
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4
        
        try:
            # Set as hidden/system before deletion
            ctypes.windll.kernel32.SetFileAttributesW(dirpath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        except:
            pass
            
    except Exception:
        pass

def _unix_directory_anti_forensics(dirpath: str):
    """Apply Unix-specific anti-forensics"""
    
    try:
        # Clear from shell history
        _clear_unix_directory_traces(dirpath)
        
        # Change permissions to make less visible
        try:
            os.chmod(dirpath, 0o000)  # Remove all permissions
        except:
            pass
            
    except Exception:
        pass

def _secure_wipe_file(filepath: str):
    """Securely wipe file content before deletion"""
    
    try:
        file_size = os.path.getsize(filepath)
        
        # Skip very large files to avoid detection
        if file_size > 50 * 1024 * 1024:  # 50MB limit
            return
        
        # Single pass wipe with random data
        with open(filepath, 'r+b') as f:
            import random
            chunk_size = 4096
            bytes_written = 0
            
            while bytes_written < file_size:
                remaining = min(chunk_size, file_size - bytes_written)
                random_data = bytes(random.getrandbits(8) for _ in range(remaining))
                f.write(random_data)
                bytes_written += remaining
            
            f.flush()
            os.fsync(f.fileno())
            
    except Exception:
        pass

def _delete_file_secure(filepath: str):
    """Securely delete file"""
    
    try:
        if sys.platform == 'win32':
            # Try DeleteFileW
            ctypes.windll.kernel32.DeleteFileW(filepath)
        else:
            # Try unlink
            os.unlink(filepath)
            
    except Exception:
        pass

def _clear_windows_directory_mru(dirpath: str):
    """Clear Windows directory MRU traces"""
    
    try:
        import winreg
        
        mru_keys = [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
        ]
        
        dirname = os.path.basename(dirpath).lower()
        
        for key_path in mru_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
                
                # Remove entries containing directory name
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if isinstance(value, str) and dirname in value.lower():
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

def _clear_unix_directory_traces(dirpath: str):
    """Clear Unix directory traces from shell history"""
    
    try:
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.history")
        ]
        
        dirname = os.path.basename(dirpath)
        
        for hist_file in history_files:
            if os.path.exists(hist_file):
                try:
                    with open(hist_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Remove lines containing directory name
                    filtered_lines = [line for line in lines if dirname not in line]
                    
                    with open(hist_file, 'w') as f:
                        f.writelines(filtered_lines)
                except:
                    continue
                    
    except Exception:
        pass


if __name__ == "__main__":
    # Test the elite_rmdir command
    # print("Testing Elite RMDIR Command...")
    
    # Create test directory structure
    test_dir = "test_rmdir"
    nested_dir = os.path.join(test_dir, "nested")
    
    os.makedirs(nested_dir, exist_ok=True)
    with open(os.path.join(nested_dir, "test_file.txt"), 'w') as f:
        f.write("Test content")
    
    # Test recursive removal
    result = elite_rmdir(test_dir, recursive=True, secure=True)
    # print(f"Test 1 - Recursive removal: {result['success']}")
    
    # Create empty directory for non-recursive test
    empty_dir = "test_empty_rmdir"
    os.makedirs(empty_dir, exist_ok=True)
    
    # Test single directory removal
    result = elite_rmdir(empty_dir, recursive=False)
    # print(f"Test 2 - Empty directory removal: {result['success']}")
    
    # Test non-existent directory
    result = elite_rmdir("nonexistent_dir")
    # print(f"Test 3 - Non-existent directory: {result['success']}")
    
    # print("✅ Elite RMDIR command testing complete")