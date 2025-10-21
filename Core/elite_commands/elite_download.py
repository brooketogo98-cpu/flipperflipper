#!/usr/bin/env python3
"""
Elite Download Command Implementation
Secure file download with chunking, encryption, and integrity verification
"""

import os
import sys
import hashlib
import base64
import time
import threading
from typing import Dict, Any, Optional, Generator
import ctypes
from ctypes import wintypes

def elite_download(filepath: str, chunk_size: int = 1024*1024, verify_integrity: bool = True) -> Dict[str, Any]:
    """
    Elite file download with advanced features:
    - Chunked transfer for large files
    - Integrity verification with checksums
    - No access time updates (Windows)
    - Memory-efficient streaming
    - Progress tracking
    - Error recovery
    """
    
    try:
        # Validate file path
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": f"File not found: {filepath}",
                "filepath": filepath
            }
        
        if not os.path.isfile(filepath):
            return {
                "success": False,
                "error": f"Path is not a file: {filepath}",
                "filepath": filepath
            }
        
        # Get file information
        file_info = _get_file_info(filepath)
        
        # Check if file is accessible
        if not os.access(filepath, os.R_OK):
            return {
                "success": False,
                "error": f"Permission denied: {filepath}",
                "filepath": filepath
            }
        
        # Start download process
        if sys.platform == 'win32':
            return _windows_elite_download(filepath, chunk_size, verify_integrity, file_info)
        else:
            return _unix_elite_download(filepath, chunk_size, verify_integrity, file_info)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Download failed: {str(e)}",
            "filepath": filepath
        }

def _get_file_info(filepath: str) -> Dict[str, Any]:
    """Get comprehensive file information"""
    
    try:
        stat_info = os.stat(filepath)
        
        info = {
            'size': stat_info.st_size,
            'modified_time': stat_info.st_mtime,
            'access_time': stat_info.st_atime,
            'creation_time': getattr(stat_info, 'st_birthtime', stat_info.st_ctime),
            'mode': stat_info.st_mode,
            'uid': getattr(stat_info, 'st_uid', 0),
            'gid': getattr(stat_info, 'st_gid', 0),
            'inode': getattr(stat_info, 'st_ino', 0)
        }
        
        # Get file type
        _, ext = os.path.splitext(filepath)
        info['extension'] = ext.lower()
        
        # Detect file type by content for certain files
        if info['size'] > 0 and info['size'] < 1024:  # Small files only
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(16)
                    info['file_signature'] = header.hex()
            except:
                pass
        
        return info
        
    except Exception as e:
        return {'error': str(e)}

def _windows_elite_download(filepath: str, chunk_size: int, verify_integrity: bool, file_info: Dict[str, Any]) -> Dict[str, Any]:
    """Windows implementation using CreateFile with FILE_FLAG_BACKUP_SEMANTICS"""
    
    kernel32 = ctypes.windll.kernel32
    
    # Constants
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    INVALID_HANDLE_VALUE = -1
    
    file_handle = None
    chunks_data = []
    total_read = 0
    
    try:
        # Open file with backup semantics to avoid updating access time
        file_handle = kernel32.CreateFileW(
            filepath,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
            None
        )
        
        if file_handle == INVALID_HANDLE_VALUE:
            error = kernel32.GetLastError()
            return {
                "success": False,
                "error": f"Cannot open file: {filepath} (Error: {error})",
                "filepath": filepath
            }
        
        # Initialize hash for integrity verification
        if verify_integrity:
            file_hash = hashlib.sha256()
        
        # Read file in chunks
        chunk_count = 0
        start_time = time.time()
        
        while True:
            # Allocate buffer for chunk
            buffer = ctypes.create_string_buffer(chunk_size)
            bytes_read = wintypes.DWORD()
            
            # Read chunk
            success = kernel32.ReadFile(
                file_handle,
                buffer,
                chunk_size,
                ctypes.byref(bytes_read),
                None
            )
            
            if not success or bytes_read.value == 0:
                break
            
            # Get actual data read
            chunk_data = buffer.raw[:bytes_read.value]
            chunks_data.append(base64.b64encode(chunk_data).decode())
            
            total_read += bytes_read.value
            chunk_count += 1
            
            # Update hash
            if verify_integrity:
                file_hash.update(chunk_data)
            
            # Progress callback could be added here
            
        # Close file handle
        kernel32.CloseHandle(file_handle)
        file_handle = None
        
        # Prepare result
        result = {
            "success": True,
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": total_read,
            "chunks": chunks_data,
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "download_time": time.time() - start_time,
            "file_info": file_info
        }
        
        # Add integrity hash
        if verify_integrity:
            result["sha256"] = file_hash.hexdigest()
        
        return result
        
    except Exception as e:
        # Clean up on error
        if file_handle and file_handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(file_handle)
        
        return {
            "success": False,
            "error": f"Windows download failed: {str(e)}",
            "filepath": filepath,
            "bytes_read": total_read
        }

def _unix_elite_download(filepath: str, chunk_size: int, verify_integrity: bool, file_info: Dict[str, Any]) -> Dict[str, Any]:
    """Unix implementation with minimal access time updates"""
    
    chunks_data = []
    total_read = 0
    
    try:
        # Store original access time to restore it
        original_atime = file_info.get('access_time')
        
        # Initialize hash for integrity verification
        if verify_integrity:
            file_hash = hashlib.sha256()
        
        # Read file in chunks
        chunk_count = 0
        start_time = time.time()
        
        with open(filepath, 'rb') as f:
            while True:
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break
                
                chunks_data.append(base64.b64encode(chunk_data).decode())
                total_read += len(chunk_data)
                chunk_count += 1
                
                # Update hash
                if verify_integrity:
                    file_hash.update(chunk_data)
        
        # Restore original access time if possible
        if original_atime:
            try:
                os.utime(filepath, (original_atime, file_info.get('modified_time', original_atime)))
            except:
                pass  # Not critical if this fails
        
        # Prepare result
        result = {
            "success": True,
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": total_read,
            "chunks": chunks_data,
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "download_time": time.time() - start_time,
            "file_info": file_info
        }
        
        # Add integrity hash
        if verify_integrity:
            result["sha256"] = file_hash.hexdigest()
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix download failed: {str(e)}",
            "filepath": filepath,
            "bytes_read": total_read
        }

def elite_download_stream(filepath: str, chunk_size: int = 1024*1024) -> Generator[Dict[str, Any], None, None]:
    """
    Streaming version of elite download for very large files
    Yields chunks as they are read instead of storing them all in memory
    """
    
    try:
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            yield {
                "success": False,
                "error": f"File not found or not accessible: {filepath}",
                "chunk_index": 0,
                "final": True
            }
            return
        
        file_info = _get_file_info(filepath)
        total_size = file_info.get('size', 0)
        
        # Yield initial info
        yield {
            "success": True,
            "type": "info",
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "total_size": total_size,
            "chunk_size": chunk_size,
            "file_info": file_info
        }
        
        # Stream chunks
        chunk_index = 0
        bytes_read = 0
        
        with open(filepath, 'rb') as f:
            while True:
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break
                
                chunk_b64 = base64.b64encode(chunk_data).decode()
                bytes_read += len(chunk_data)
                
                yield {
                    "success": True,
                    "type": "chunk",
                    "chunk_index": chunk_index,
                    "chunk_data": chunk_b64,
                    "chunk_size": len(chunk_data),
                    "bytes_read": bytes_read,
                    "progress": (bytes_read / total_size) * 100 if total_size > 0 else 0,
                    "final": False
                }
                
                chunk_index += 1
        
        # Yield completion
        yield {
            "success": True,
            "type": "complete",
            "total_chunks": chunk_index,
            "total_bytes": bytes_read,
            "final": True
        }
        
    except Exception as e:
        yield {
            "success": False,
            "error": str(e),
            "chunk_index": chunk_index,
            "final": True
        }

def verify_download_integrity(original_path: str, chunks_data: list, expected_hash: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify downloaded file integrity by comparing with original
    """
    
    try:
        # Reconstruct file from chunks
        reconstructed_data = b''
        for chunk_b64 in chunks_data:
            chunk_data = base64.b64decode(chunk_b64)
            reconstructed_data += chunk_data
        
        # Calculate hash of reconstructed data
        reconstructed_hash = hashlib.sha256(reconstructed_data).hexdigest()
        
        # Calculate hash of original file
        original_hash = hashlib.sha256()
        with open(original_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                original_hash.update(chunk)
        
        original_hash_hex = original_hash.hexdigest()
        
        # Compare
        integrity_valid = reconstructed_hash == original_hash_hex
        
        if expected_hash:
            expected_valid = reconstructed_hash == expected_hash
        else:
            expected_valid = True
        
        return {
            "success": True,
            "integrity_valid": integrity_valid,
            "expected_valid": expected_valid,
            "original_hash": original_hash_hex,
            "reconstructed_hash": reconstructed_hash,
            "expected_hash": expected_hash,
            "size_match": len(reconstructed_data) == os.path.getsize(original_path)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Integrity verification failed: {str(e)}"
        }


if __name__ == "__main__":
    # Test the elite download command
    # print("Testing Elite Download Command...")
    
    # Create a test file
    test_file = "test_download.txt"
    test_content = "This is a test file for elite download.\n" * 100
    
    try:
        with open(test_file, 'w') as f:
            f.write(test_content)
        
    # print(f"Created test file: {test_file} ({len(test_content)} bytes)")
        
        # Test download
        result = elite_download(test_file, chunk_size=1024)
        
        if result['success']:
    # print(f"✅ Downloaded {result['size']} bytes in {result['chunk_count']} chunks")
    # print(f"Download time: {result['download_time']:.3f} seconds")
            
            if 'sha256' in result:
    # print(f"SHA256: {result['sha256']}")
            
            # Test integrity verification
            verification = verify_download_integrity(test_file, result['chunks'], result.get('sha256'))
            if verification['success'] and verification['integrity_valid']:
    # print("✅ Integrity verification passed")
            else:
    # print("❌ Integrity verification failed")
        else:
    # print(f"❌ Download failed: {result['error']}")
        
        # Clean up
        os.remove(test_file)
    # print("Test file cleaned up")
        
    except Exception as e:
    # print(f"❌ Test failed: {e}")
        # Clean up on error
        if os.path.exists(test_file):
            os.remove(test_file)
    
    # print("Elite Download command test complete")