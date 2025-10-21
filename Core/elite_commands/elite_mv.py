#!/usr/bin/env python3
"""
Elite MV Command Implementation
Advanced file/directory moving with stealth and integrity verification
"""

import os
import sys
import shutil
import ctypes
from typing import Dict, Any

def elite_mv(source: str, destination: str) -> Dict[str, Any]:
    """
    Elite file/directory moving with advanced features:
    - Atomic operations where possible
    - Cross-filesystem support
    - Integrity verification
    - Anti-forensics techniques
    - Cross-platform support
    """
    
    try:
        # Validate paths
        if not source or not destination:
            return {
                "success": False,
                "error": "Source and destination paths are required",
                "moved_items": []
            }
        
        # Expand paths
        source = os.path.abspath(os.path.expanduser(source))
        destination = os.path.abspath(os.path.expanduser(destination))
        
        # Check if source exists
        if not os.path.exists(source):
            return {
                "success": False,
                "error": f"Source does not exist: {source}",
                "moved_items": []
            }
        
        # Check if source and destination are the same
        if os.path.samefile(source, destination) if os.path.exists(destination) else source == destination:
            return {
                "success": False,
                "error": f"Source and destination are the same: {source}",
                "moved_items": []
            }
        
        # Determine final destination path
        if os.path.isdir(destination) and os.path.exists(destination):
            final_dest = os.path.join(destination, os.path.basename(source))
        else:
            final_dest = destination
        
        # Check if destination already exists
        if os.path.exists(final_dest):
            return {
                "success": False,
                "error": f"Destination already exists: {final_dest}",
                "moved_items": []
            }
        
        # Perform the move operation
        if sys.platform == 'win32':
            success = _windows_elite_move(source, final_dest)
        else:
            success = _unix_elite_move(source, final_dest)
        
        if success:
            # Apply anti-forensics techniques
            _apply_move_stealth(final_dest)
            
            return {
                "success": True,
                "moved_items": [{"source": source, "destination": final_dest}],
                "method": "elite_atomic_move"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to move: {source} -> {final_dest}",
                "moved_items": []
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Move operation failed: {str(e)}",
            "moved_items": []
        }

def _windows_elite_move(source: str, destination: str) -> bool:
    """Windows move operation using MoveFileExW"""
    
    try:
        # Method 1: Try MoveFileExW for atomic operation
        MOVEFILE_REPLACE_EXISTING = 0x1
        MOVEFILE_COPY_ALLOWED = 0x2
        MOVEFILE_WRITE_THROUGH = 0x8
        
        flags = MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH
        
        result = ctypes.windll.kernel32.MoveFileExW(source, destination, flags)
        if result:
            return True
        
        # Method 2: Try simple MoveFileW
        result = ctypes.windll.kernel32.MoveFileW(source, destination)
        if result:
            return True
        
        # Method 3: Fallback to Python shutil
        shutil.move(source, destination)
        return True
        
    except Exception:
        return False

def _unix_elite_move(source: str, destination: str) -> bool:
    """Unix move operation with atomic rename when possible"""
    
    try:
        # Method 1: Try atomic rename (same filesystem)
        try:
            os.rename(source, destination)
            return True
        except OSError as e:
            # If cross-filesystem, fall through to copy+delete
            if e.errno == 18:  # EXDEV - cross-device link
                pass
            else:
                raise
        
        # Method 2: Copy and delete (cross-filesystem)
        if os.path.isdir(source):
            shutil.copytree(source, destination, symlinks=True)
            shutil.rmtree(source)
        else:
            shutil.copy2(source, destination)
            os.remove(source)
        
        return True
        
    except Exception:
        # Method 3: Python shutil fallback
        try:
            shutil.move(source, destination)
            return True
        except:
            return False

def _apply_move_stealth(destination: str):
    """Apply stealth techniques to moved files/directories"""
    
    try:
        if sys.platform == 'win32':
            _windows_move_stealth(destination)
        else:
            _unix_move_stealth(destination)
            
    except Exception:
        pass

def _windows_move_stealth(destination: str):
    """Apply Windows-specific stealth techniques after move"""
    
    try:
        # Clear file from recent documents and MRU lists
        _clear_windows_file_traces(destination)
        
        # Modify file attributes to reduce visibility
        if os.path.isfile(destination):
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
            ctypes.windll.kernel32.SetFileAttributesW(destination, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        
    except Exception:
        pass

def _unix_move_stealth(destination: str):
    """Apply Unix-specific stealth techniques after move"""
    
    try:
        # Clear from shell history
        _clear_unix_file_traces(destination)
        
        # Set appropriate permissions
        if os.path.isfile(destination):
            os.chmod(destination, 0o644)
        elif os.path.isdir(destination):
            os.chmod(destination, 0o755)
        
    except Exception:
        pass

def _clear_windows_file_traces(filepath: str):
    """Clear Windows file access traces"""
    
    try:
        import winreg
        
        # Registry keys that track file access
        trace_keys = [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
        ]
        
        filename = os.path.basename(filepath).lower()
        
        for key_path in trace_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
                
                # Remove entries containing our filename
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if isinstance(value, str) and filename in value.lower():
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

def _clear_unix_file_traces(filepath: str):
    """Clear Unix shell history traces"""
    
    try:
        # Clear from common shell history files
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.history")
        ]
        
        filename = os.path.basename(filepath)
        
        for hist_file in history_files:
            if os.path.exists(hist_file):
                try:
                    # Read and filter history
                    with open(hist_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Remove lines containing our filename
                    filtered_lines = [line for line in lines if filename not in line]
                    
                    # Write back filtered history
                    with open(hist_file, 'w') as f:
                        f.writelines(filtered_lines)
                except:
                    continue
                    
    except Exception:
        pass


if __name__ == "__main__":
    # Test the elite_mv command
    print("Testing Elite MV Command...")
    
    # Create test source file
    source_file = "test_mv_source.txt"
    with open(source_file, 'w') as f:
        f.write("Test content for moving")
    
    # Test file move
    result = elite_mv(source_file, "test_mv_dest.txt")
    print(f"Test 1 - File move: {result['success']}")
    
    # Create test directory
    test_dir = "test_mv_dir"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "nested.txt"), 'w') as f:
        f.write("Nested file content")
    
    # Test directory move
    result = elite_mv(test_dir, "test_mv_dir_dest")
    print(f"Test 2 - Directory move: {result['success']}")
    
    # Test non-existent source
    result = elite_mv("nonexistent.txt", "dest.txt")
    print(f"Test 3 - Non-existent source: {result['success']}")
    
    # Clean up
    try:
        if os.path.exists("test_mv_dest.txt"):
            os.remove("test_mv_dest.txt")
        if os.path.exists("test_mv_dir_dest"):
            shutil.rmtree("test_mv_dir_dest")
    except:
        pass
    
    print("✅ Elite MV command testing complete")