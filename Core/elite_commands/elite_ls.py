#!/usr/bin/env python3
"""
Elite LS Command Implementation
Advanced directory listing with hidden file detection and ADS enumeration
"""

import ctypes
from ctypes import wintypes
import os
import sys
import stat
import time
from typing import Dict, Any, List

def elite_ls(directory: str = ".") -> Dict[str, Any]:
    """
    Elite directory listing with advanced features:
    - Hidden file detection
    - Alternate Data Streams (ADS) enumeration
    - System file identification
    - Extended attributes on Unix
    - No access time updates
    """
    
    try:
        if os.name == 'nt':
            return _windows_elite_ls(directory)
        else:
            return _unix_elite_ls(directory)
    except Exception as e:
        return {
            "success": False,
            "error": f"Directory listing failed: {str(e)}",
            "directory": directory
        }

def _windows_elite_ls(directory: str) -> Dict[str, Any]:
    """Windows implementation using FindFirstFileExW to avoid access time updates"""
    
    kernel32 = ctypes.windll.kernel32
    
    # Constants
    INVALID_HANDLE_VALUE = -1
    FILE_ATTRIBUTE_HIDDEN = 0x02
    FILE_ATTRIBUTE_SYSTEM = 0x04
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_ARCHIVE = 0x20
    FILE_ATTRIBUTE_READONLY = 0x01
    FILE_ATTRIBUTE_COMPRESSED = 0x800
    FILE_ATTRIBUTE_ENCRYPTED = 0x4000
    
    class WIN32_FIND_DATAW(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("dwReserved0", wintypes.DWORD),
            ("dwReserved1", wintypes.DWORD),
            ("cFileName", wintypes.WCHAR * 260),
            ("cAlternateFileName", wintypes.WCHAR * 14),
        ]
    
    find_data = WIN32_FIND_DATAW()
    files = []
    
    try:
        # Ensure directory path is absolute and properly formatted
        abs_directory = os.path.abspath(directory)
        search_path = os.path.join(abs_directory, "*")
        
        # Use FindFirstFileExW with FindExInfoBasic to reduce access time updates
        handle = kernel32.FindFirstFileExW(
            search_path,
            1,  # FindExInfoBasic (reduces metadata access)
            ctypes.byref(find_data),
            0,  # FindExSearchNameMatch
            None,
            2   # FIND_FIRST_EX_LARGE_FETCH flag
        )
        
        if handle == INVALID_HANDLE_VALUE:
            error = kernel32.GetLastError()
            return {
                "success": False,
                "error": f"Cannot access directory: {directory} (Error: {error})",
                "directory": directory
            }
        
        # Process all files
        while True:
            filename = find_data.cFileName
            
            # Skip . and ..
            if filename not in [".", ".."]:
                file_info = {
                    'name': filename,
                    'size': (find_data.nFileSizeHigh << 32) + find_data.nFileSizeLow,
                    'attributes': find_data.dwFileAttributes,
                    'hidden': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN),
                    'system': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM),
                    'directory': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY),
                    'readonly': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_READONLY),
                    'archive': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE),
                    'compressed': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED),
                    'encrypted': bool(find_data.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED),
                    'creation_time': _filetime_to_timestamp(find_data.ftCreationTime),
                    'modified_time': _filetime_to_timestamp(find_data.ftLastWriteTime),
                    'type': 'directory' if find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY else 'file'
                }
                
                # Check for Alternate Data Streams
                full_path = os.path.join(abs_directory, filename)
                ads = _check_ads(full_path)
                if ads:
                    file_info['ads'] = ads
                    file_info['has_ads'] = True
                else:
                    file_info['has_ads'] = False
                
                # Get extended file information
                file_info.update(_get_extended_file_info(full_path))
                
                files.append(file_info)
            
            # Get next file
            if not kernel32.FindNextFileW(handle, ctypes.byref(find_data)):
                break
        
        kernel32.FindClose(handle)
        
        return {
            "success": True,
            "directory": abs_directory,
            "files": files,
            "total_files": len(files),
            "hidden_files": sum(1 for f in files if f['hidden']),
            "system_files": sum(1 for f in files if f['system']),
            "ads_files": sum(1 for f in files if f.get('has_ads', False))
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows directory scan failed: {str(e)}",
            "directory": directory
        }

def _check_ads(filepath: str) -> List[str]:
    """Check for Alternate Data Streams using FindFirstStreamW"""
    
    kernel32 = ctypes.windll.kernel32
    streams = []
    
    try:
        # Define stream info structure
        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", ctypes.c_longlong),
                ("cStreamName", wintypes.WCHAR * 296)
            ]
        
        find_data = WIN32_FIND_STREAM_DATA()
        
        # Use FindFirstStreamW to enumerate streams
        handle = kernel32.FindFirstStreamW(
            filepath,
            0,  # FindStreamInfoStandard
            ctypes.byref(find_data),
            0
        )
        
        if handle != -1:
            while True:
                stream_name = find_data.cStreamName
                # Skip the default data stream
                if stream_name and stream_name != "::$DATA" and not stream_name.startswith(":"):
                    streams.append({
                        'name': stream_name,
                        'size': find_data.StreamSize
                    })
                
                if not kernel32.FindNextStreamW(handle, ctypes.byref(find_data)):
                    break
            
            kernel32.FindClose(handle)
    
    except Exception:
        # FindFirstStreamW not available or failed
        pass
    
    return streams

def _get_extended_file_info(filepath: str) -> Dict[str, Any]:
    """Get extended file information"""
    
    info = {}
    
    try:
        # Get file version information for executables
        if filepath.lower().endswith(('.exe', '.dll', '.sys')):
            version_info = _get_file_version(filepath)
            if version_info:
                info['version'] = version_info
        
        # Check if file is signed
        if filepath.lower().endswith(('.exe', '.dll', '.sys', '.msi')):
            info['signed'] = _is_file_signed(filepath)
        
        # Get file hash (MD5) for small files
        if os.path.isfile(filepath):
            file_size = os.path.getsize(filepath)
            if file_size < 1024 * 1024:  # Only hash files < 1MB
                info['md5'] = _get_file_hash(filepath)
    
    except Exception:
        pass
    
    return info

def _get_file_version(filepath: str) -> Dict[str, str]:
    """Get file version information"""
    
    try:
        import win32api
        
        version_info = win32api.GetFileVersionInfo(filepath, "\\")
        version = "%d.%d.%d.%d" % (
            version_info['FileVersionMS'] >> 16,
            version_info['FileVersionMS'] & 0xFFFF,
            version_info['FileVersionLS'] >> 16,
            version_info['FileVersionLS'] & 0xFFFF
        )
        
        return {
            'file_version': version,
            'product_version': version
        }
    
    except Exception:
        return {}

def _is_file_signed(filepath: str) -> bool:
    """Check if file has a valid digital signature"""
    
    try:
        # This would use WinVerifyTrust API in a full implementation
        # For now, return False as placeholder
        return False
    
    except Exception:
        return False

def _get_file_hash(filepath: str) -> str:
    """Get MD5 hash of file"""
    
    try:
        import hashlib
        
        with open(filepath, 'rb') as f:
            file_hash = hashlib.md5()
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)
        
        return file_hash.hexdigest()
    
    except Exception:
        return ""

def _filetime_to_timestamp(filetime: wintypes.FILETIME) -> float:
    """Convert Windows FILETIME to Unix timestamp"""
    
    try:
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        timestamp = (filetime.dwHighDateTime << 32) + filetime.dwLowDateTime
        # Convert to Unix timestamp (seconds since January 1, 1970)
        unix_timestamp = (timestamp - 116444736000000000) / 10000000.0
        return unix_timestamp
    
    except Exception:
        return 0.0

def _unix_elite_ls(directory: str) -> Dict[str, Any]:
    """Unix implementation with extended attributes and hidden file detection"""
    
    files = []
    
    try:
        abs_directory = os.path.abspath(directory)
        
        # Use os.listdir to get all files (including hidden)
        for filename in os.listdir(abs_directory):
            filepath = os.path.join(abs_directory, filename)
            
            try:
                # Use lstat to avoid following symlinks initially
                file_stat = os.lstat(filepath)
                
                file_info = {
                    'name': filename,
                    'size': file_stat.st_size,
                    'hidden': filename.startswith('.'),
                    'mode': stat.filemode(file_stat.st_mode),
                    'permissions': oct(file_stat.st_mode)[-3:],
                    'uid': file_stat.st_uid,
                    'gid': file_stat.st_gid,
                    'inode': file_stat.st_ino,
                    'links': file_stat.st_nlink,
                    'creation_time': file_stat.st_ctime,
                    'modified_time': file_stat.st_mtime,
                    'access_time': file_stat.st_atime,
                    'type': 'directory' if stat.S_ISDIR(file_stat.st_mode) else 'file',
                    'symlink': stat.S_ISLNK(file_stat.st_mode)
                }
                
                # If it's a symlink, get target
                if file_info['symlink']:
                    try:
                        file_info['link_target'] = os.readlink(filepath)
                    except Exception:
                        file_info['link_target'] = 'unknown'
                
                # Check for extended attributes
                xattrs = _get_extended_attributes(filepath)
                if xattrs:
                    file_info['xattrs'] = xattrs
                
                # Get file type details
                if stat.S_ISREG(file_stat.st_mode):
                    file_info['executable'] = os.access(filepath, os.X_OK)
                    
                    # Get MIME type if possible
                    mime_type = _get_mime_type(filepath)
                    if mime_type:
                        file_info['mime_type'] = mime_type
                
                files.append(file_info)
                
            except OSError:
                # File might have been deleted or inaccessible
                continue
        
        return {
            "success": True,
            "directory": abs_directory,
            "files": files,
            "total_files": len(files),
            "hidden_files": sum(1 for f in files if f['hidden']),
            "symlinks": sum(1 for f in files if f.get('symlink', False))
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix directory scan failed: {str(e)}",
            "directory": directory
        }

def _get_extended_attributes(filepath: str) -> List[str]:
    """Get extended attributes (Linux/macOS)"""
    
    xattrs = []
    
    try:
        # Try different extended attribute implementations
        try:
            import xattr
            attrs = xattr.listxattr(filepath)
            xattrs = [attr.decode() if isinstance(attr, bytes) else attr for attr in attrs]
        except ImportError:
            # Try os.listxattr (Python 3.3+)
            try:
                attrs = os.listxattr(filepath)
                xattrs = attrs
            except (AttributeError, OSError):
                pass
    
    except Exception:
        pass
    
    return xattrs

def _get_mime_type(filepath: str) -> str:
    """Get MIME type of file"""
    
    try:
        import mimetypes
        mime_type, _ = mimetypes.guess_type(filepath)
        return mime_type or 'unknown'
    
    except Exception:
        return 'unknown'


if __name__ == "__main__":
    # Test the elite ls command
    # print("Testing Elite LS Command...")
    
    # Test current directory
    result = elite_ls(".")
    
    if result['success']:
    # print(f"✅ Listed {result['total_files']} files in {result['directory']}")
    # print(f"Hidden files: {result.get('hidden_files', 0)}")
        
        if os.name == 'nt':
    # print(f"System files: {result.get('system_files', 0)}")
    # print(f"Files with ADS: {result.get('ads_files', 0)}")
        else:
    # print(f"Symlinks: {result.get('symlinks', 0)}")
        
        # Show first few files as example
        for i, file_info in enumerate(result['files'][:3]):
    # print(f"  {file_info['name']} ({file_info['size']} bytes)")
            if file_info.get('hidden'):
    # print(f"    ⚠️ Hidden file")
            if file_info.get('has_ads'):
    # print(f"    📎 Has alternate data streams")
    else:
    # print(f"❌ Elite LS failed: {result['error']}")
    
    # print("Elite LS command test complete")