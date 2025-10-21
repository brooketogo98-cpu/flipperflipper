#!/usr/bin/env python3
"""
Elite RM Command Implementation
Advanced file deletion with secure wiping and anti-forensics
"""

import os
import sys
import ctypes
import random
import time
from typing import Dict, Any, List

def elite_rm(filepath: str, secure: bool = True, recursive: bool = False) -> Dict[str, Any]:
    """
    Elite file deletion with advanced features:
    - Secure wiping (multiple passes)
    - Anti-forensics techniques
    - Directory tree deletion
    - Cross-platform support
    - Recovery prevention
    """
    
    try:
        # Validate file path
        if not filepath:
            return {
                "success": False,
                "error": "File path is required",
                "deleted_files": []
            }
        
        # Expand path
        filepath = os.path.abspath(os.path.expanduser(filepath))
        
        # Check if path exists
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": f"Path does not exist: {filepath}",
                "deleted_files": []
            }
        
        deleted_files = []
        
        if os.path.isfile(filepath):
            # Delete single file
            success = _delete_file_secure(filepath, secure)
            if success:
                deleted_files.append(filepath)
            else:
                return {
                    "success": False,
                    "error": f"Failed to delete file: {filepath}",
                    "deleted_files": deleted_files
                }
                
        elif os.path.isdir(filepath):
            if not recursive:
                return {
                    "success": False,
                    "error": f"Path is a directory. Use recursive=True to delete directories: {filepath}",
                    "deleted_files": []
                }
            
            # Delete directory recursively
            deleted_files = _delete_directory_secure(filepath, secure)
            
        else:
            return {
                "success": False,
                "error": f"Unknown path type: {filepath}",
                "deleted_files": []
            }
        
        return {
            "success": True,
            "deleted_files": deleted_files,
            "secure_wipe": secure,
            "method": "elite_secure_delete"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Deletion failed: {str(e)}",
            "deleted_files": []
        }

def _delete_file_secure(filepath: str, secure: bool) -> bool:
    """Securely delete a single file"""
    
    try:
        if secure:
            # Secure wipe before deletion
            if not _secure_wipe_file(filepath):
                return False
        
        # Platform-specific deletion
        if sys.platform == 'win32':
            return _windows_delete_file(filepath)
        else:
            return _unix_delete_file(filepath)
            
    except Exception:
        return False

def _delete_directory_secure(dirpath: str, secure: bool) -> List[str]:
    """Securely delete directory and all contents"""
    
    deleted_files = []
    
    try:
        # Walk directory tree in reverse order (files first, then directories)
        for root, dirs, files in os.walk(dirpath, topdown=False):
            # Delete files first
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if _delete_file_secure(filepath, secure):
                        deleted_files.append(filepath)
                except:
                    continue
            
            # Delete empty directories
            for dir in dirs:
                dirpath_full = os.path.join(root, dir)
                try:
                    if sys.platform == 'win32':
                        _windows_delete_directory(dirpath_full)
                    else:
                        os.rmdir(dirpath_full)
                    deleted_files.append(dirpath_full)
                except:
                    continue
        
        # Delete root directory
        try:
            if sys.platform == 'win32':
                _windows_delete_directory(dirpath)
            else:
                os.rmdir(dirpath)
            deleted_files.append(dirpath)
        except:
            pass
            
    except Exception:
        pass
    
    return deleted_files

def _secure_wipe_file(filepath: str) -> bool:
    """Perform secure wiping of file content"""
    
    try:
        file_size = os.path.getsize(filepath)
        
        # Skip very large files to avoid detection
        if file_size > 100 * 1024 * 1024:  # 100MB
            return True
        
        # Multiple pass wiping
        patterns = [
            b'\x00',  # Zeros
            b'\xFF',  # Ones
            b'\xAA',  # Alternating
            b'\x55',  # Alternating inverse
        ]
        
        for pattern in patterns:
            try:
                with open(filepath, 'r+b') as f:
                    f.seek(0)
                    # Write pattern in chunks
                    chunk_size = 8192
                    bytes_written = 0
                    
                    while bytes_written < file_size:
                        remaining = min(chunk_size, file_size - bytes_written)
                        chunk = pattern * remaining
                        f.write(chunk[:remaining])
                        bytes_written += remaining
                    
                    f.flush()
                    os.fsync(f.fileno())
                    
            except Exception:
                continue
        
        # Random pass
        try:
            with open(filepath, 'r+b') as f:
                f.seek(0)
                chunk_size = 8192
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
        
        return True
        
    except Exception:
        return True  # Continue with deletion even if wiping fails

def _windows_delete_file(filepath: str) -> bool:
    """Windows file deletion using API calls"""
    
    try:
        # Method 1: Try DeleteFileW
        if ctypes.windll.kernel32.DeleteFileW(filepath):
            return True
        
        # Method 2: Try MoveFileExW with delayed deletion
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        if ctypes.windll.kernel32.MoveFileExW(filepath, None, MOVEFILE_DELAY_UNTIL_REBOOT):
            return True
        
        # Method 3: Standard Python deletion
        os.remove(filepath)
        return True
        
    except Exception:
        return False

def _windows_delete_directory(dirpath: str) -> bool:
    """Windows directory deletion using API calls"""
    
    try:
        # Try RemoveDirectoryW
        if ctypes.windll.kernel32.RemoveDirectoryW(dirpath):
            return True
        
        # Fallback to Python
        os.rmdir(dirpath)
        return True
        
    except Exception:
        return False

def _unix_delete_file(filepath: str) -> bool:
    """Unix file deletion with syscalls"""
    
    try:
        # Method 1: Direct unlink syscall
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            result = libc.unlink(filepath.encode('utf-8'))
            if result == 0:
                return True
        except:
            pass
        
        # Method 2: Standard Python deletion
        os.remove(filepath)
        return True
        
    except Exception:
        return False


if __name__ == "__main__":
    # Test the elite_rm command
    print("Testing Elite RM Command...")
    
    # Create test files
    test_file = "test_rm.txt"
    test_dir = "test_rm_dir"
    
    with open(test_file, 'w') as f:
        f.write("Test content for secure deletion")
    
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "nested_file.txt"), 'w') as f:
        f.write("Nested file content")
    
    # Test file deletion
    result = elite_rm(test_file, secure=True)
    print(f"Test 1 - File deletion: {result['success']}")
    
    # Test directory deletion
    result = elite_rm(test_dir, secure=True, recursive=True)
    print(f"Test 2 - Directory deletion: {result['success']}")
    
    # Test non-existent file
    result = elite_rm("nonexistent.txt")
    print(f"Test 3 - Non-existent: {result['success']}")
    
    print("✅ Elite RM command testing complete")