#!/usr/bin/env python3
"""
Elite CP Command Implementation
Advanced file copying with integrity verification and stealth
"""

import os
import sys
import shutil
import hashlib
import ctypes
from typing import Dict, Any, List

def elite_cp(source: str, destination: str, recursive: bool = False, 
             preserve_timestamps: bool = True, verify_integrity: bool = True) -> Dict[str, Any]:
    """
    Elite file copying with advanced features:
    - Integrity verification (SHA256 checksums)
    - Timestamp preservation options
    - Recursive directory copying
    - Cross-platform support
    - Memory-efficient streaming for large files
    """
    
    try:
        # Validate paths
        if not source or not destination:
            return {
                "success": False,
                "error": "Source and destination paths are required",
                "copied_files": []
            }
        
        # Expand paths
        source = os.path.abspath(os.path.expanduser(source))
        destination = os.path.abspath(os.path.expanduser(destination))
        
        # Check if source exists
        if not os.path.exists(source):
            return {
                "success": False,
                "error": f"Source does not exist: {source}",
                "copied_files": []
            }
        
        copied_files = []
        
        if os.path.isfile(source):
            # Copy single file
            success, dest_path = _copy_file_elite(source, destination, preserve_timestamps, verify_integrity)
            if success:
                copied_files.append({"source": source, "destination": dest_path})
            else:
                return {
                    "success": False,
                    "error": f"Failed to copy file: {source} -> {destination}",
                    "copied_files": []
                }
                
        elif os.path.isdir(source):
            if not recursive:
                return {
                    "success": False,
                    "error": f"Source is a directory. Use recursive=True to copy directories: {source}",
                    "copied_files": []
                }
            
            # Copy directory recursively
            copied_files = _copy_directory_elite(source, destination, preserve_timestamps, verify_integrity)
            
        else:
            return {
                "success": False,
                "error": f"Unknown source type: {source}",
                "copied_files": []
            }
        
        return {
            "success": True,
            "copied_files": copied_files,
            "total_files": len(copied_files),
            "preserve_timestamps": preserve_timestamps,
            "verify_integrity": verify_integrity,
            "method": "elite_copy"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Copy operation failed: {str(e)}",
            "copied_files": []
        }

def _copy_file_elite(source: str, destination: str, preserve_timestamps: bool, verify_integrity: bool) -> tuple:
    """Copy a single file with elite techniques"""
    
    try:
        # Determine actual destination path
        if os.path.isdir(destination):
            dest_path = os.path.join(destination, os.path.basename(source))
        else:
            dest_path = destination
        
        # Create destination directory if needed
        dest_dir = os.path.dirname(dest_path)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        
        # Get source file info
        source_stat = os.stat(source)
        source_size = source_stat.st_size
        
        # Use platform-specific copying method
        if sys.platform == 'win32':
            success = _windows_copy_file(source, dest_path, preserve_timestamps)
        else:
            success = _unix_copy_file(source, dest_path, preserve_timestamps)
        
        if not success:
            return False, None
        
        # Verify integrity if requested
        if verify_integrity:
            if not _verify_file_integrity(source, dest_path):
                try:
                    os.remove(dest_path)
                except:
                    pass
                return False, None
        
        # Preserve file attributes
        if preserve_timestamps:
            try:
                os.utime(dest_path, (source_stat.st_atime, source_stat.st_mtime))
                if hasattr(os, 'chmod'):
                    os.chmod(dest_path, source_stat.st_mode)
            except:
                pass
        
        return True, dest_path
        
    except Exception:
        return False, None

def _copy_directory_elite(source: str, destination: str, preserve_timestamps: bool, verify_integrity: bool) -> List[Dict]:
    """Copy directory recursively with elite techniques"""
    
    copied_files = []
    
    try:
        # Create destination directory
        if not os.path.exists(destination):
            os.makedirs(destination, exist_ok=True)
        
        # Walk source directory
        for root, dirs, files in os.walk(source):
            # Calculate relative path
            rel_path = os.path.relpath(root, source)
            if rel_path == '.':
                dest_root = destination
            else:
                dest_root = os.path.join(destination, rel_path)
            
            # Create subdirectories
            for dir_name in dirs:
                src_dir = os.path.join(root, dir_name)
                dest_dir = os.path.join(dest_root, dir_name)
                
                try:
                    if not os.path.exists(dest_dir):
                        os.makedirs(dest_dir, exist_ok=True)
                    
                    # Preserve directory timestamps
                    if preserve_timestamps:
                        src_stat = os.stat(src_dir)
                        os.utime(dest_dir, (src_stat.st_atime, src_stat.st_mtime))
                        
                except Exception:
                    continue
            
            # Copy files
            for file_name in files:
                src_file = os.path.join(root, file_name)
                dest_file = os.path.join(dest_root, file_name)
                
                try:
                    success, final_dest = _copy_file_elite(src_file, dest_file, preserve_timestamps, verify_integrity)
                    if success:
                        copied_files.append({"source": src_file, "destination": final_dest})
                except Exception:
                    continue
                    
    except Exception:
        pass
    
    return copied_files

def _windows_copy_file(source: str, destination: str, preserve_timestamps: bool) -> bool:
    """Windows file copying using CopyFileExW"""
    
    try:
        # Try CopyFileExW for better performance
        COPY_FILE_FAIL_IF_EXISTS = 0x1
        
        result = ctypes.windll.kernel32.CopyFileExW(
            source, destination, None, None, None, 0
        )
        
        if result:
            return True
        
        # Fallback to Python shutil
        shutil.copy2(source, destination)
        return True
        
    except Exception:
        # Final fallback to basic copy
        try:
            shutil.copy(source, destination)
            return True
        except:
            return False

def _unix_copy_file(source: str, destination: str, preserve_timestamps: bool) -> bool:
    """Unix file copying with sendfile optimization"""
    
    try:
        # Method 1: Try sendfile for efficiency (Linux)
        if hasattr(os, 'sendfile'):
            try:
                with open(source, 'rb') as src_fd:
                    with open(destination, 'wb') as dst_fd:
                        # Use sendfile for zero-copy transfer
                        src_stat = os.fstat(src_fd.fileno())
                        os.sendfile(dst_fd.fileno(), src_fd.fileno(), 0, src_stat.st_size)
                return True
            except:
                pass
        
        # Method 2: Chunked copy for large files
        try:
            with open(source, 'rb') as src_fd:
                with open(destination, 'wb') as dst_fd:
                    chunk_size = 64 * 1024  # 64KB chunks
                    while True:
                        chunk = src_fd.read(chunk_size)
                        if not chunk:
                            break
                        dst_fd.write(chunk)
            return True
        except:
            pass
        
        # Method 3: Python shutil fallback
        if preserve_timestamps:
            shutil.copy2(source, destination)
        else:
            shutil.copy(source, destination)
        return True
        
    except Exception:
        return False

def _verify_file_integrity(source: str, destination: str) -> bool:
    """Verify file integrity using SHA256 checksums"""
    
    try:
        def get_file_hash(filepath):
            hash_sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        
        source_hash = get_file_hash(source)
        dest_hash = get_file_hash(destination)
        
        return source_hash == dest_hash
        
    except Exception:
        return False


if __name__ == "__main__":
    # Test the elite_cp command
    print("Testing Elite CP Command...")
    
    # Create test source file
    source_file = "test_cp_source.txt"
    with open(source_file, 'w') as f:
        f.write("Test content for copying")
    
    # Test file copy
    result = elite_cp(source_file, "test_cp_dest.txt")
    print(f"Test 1 - File copy: {result['success']}")
    
    # Create test directory
    test_dir = "test_cp_dir"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "nested.txt"), 'w') as f:
        f.write("Nested file content")
    
    # Test directory copy
    result = elite_cp(test_dir, "test_cp_dir_dest", recursive=True)
    print(f"Test 2 - Directory copy: {result['success']}")
    
    # Clean up
    try:
        os.remove(source_file)
        os.remove("test_cp_dest.txt")
        shutil.rmtree(test_dir)
        shutil.rmtree("test_cp_dir_dest")
    except:
        pass
    
    print("✅ Elite CP command testing complete")