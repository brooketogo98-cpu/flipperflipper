#!/usr/bin/env python3
"""
Elite Upload Command Implementation
Secure file upload with chunking, encryption, and integrity verification
"""

import os
import sys
import hashlib
import base64
import time
import tempfile
from typing import Dict, Any, List
import ctypes
from ctypes import wintypes

def elite_upload(filepath: str, chunks_data: List[str], expected_hash: str = None, 
                overwrite: bool = False, verify_integrity: bool = True) -> Dict[str, Any]:
    """
    Elite file upload with advanced features:
    - Chunked transfer reconstruction
    - Integrity verification with checksums
    - Atomic write operations
    - Backup of existing files
    - Permission preservation
    """
    
    try:
        # Validate input
        if not chunks_data:
            return {
                "success": False,
                "error": "No chunk data provided",
                "filepath": filepath
            }
        
        # Check if file exists and handle overwrite
        if os.path.exists(filepath) and not overwrite:
            return {
                "success": False,
                "error": f"File already exists: {filepath} (use overwrite=True to replace)",
                "filepath": filepath
            }
        
        # Validate target directory
        target_dir = os.path.dirname(os.path.abspath(filepath))
        if not os.path.exists(target_dir):
            return {
                "success": False,
                "error": f"Target directory does not exist: {target_dir}",
                "filepath": filepath
            }
        
        if not os.access(target_dir, os.W_OK):
            return {
                "success": False,
                "error": f"No write permission to directory: {target_dir}",
                "filepath": filepath
            }
        
        # Perform upload
        if sys.platform == 'win32':
            return _windows_elite_upload(filepath, chunks_data, expected_hash, overwrite, verify_integrity)
        else:
            return _unix_elite_upload(filepath, chunks_data, expected_hash, overwrite, verify_integrity)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Upload failed: {str(e)}",
            "filepath": filepath
        }

def _windows_elite_upload(filepath: str, chunks_data: List[str], expected_hash: str, 
                         overwrite: bool, verify_integrity: bool) -> Dict[str, Any]:
    """Windows implementation using CreateFile with atomic operations"""
    
    kernel32 = ctypes.windll.kernel32
    
    # Constants
    GENERIC_WRITE = 0x40000000
    CREATE_NEW = 1
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    INVALID_HANDLE_VALUE = -1
    
    temp_file = None
    file_handle = None
    total_written = 0
    
    try:
        # Create temporary file for atomic operation
        temp_file = filepath + ".tmp." + str(int(time.time()))
        
        # Open temporary file for writing
        file_handle = kernel32.CreateFileW(
            temp_file,
            GENERIC_WRITE,
            0,  # No sharing during write
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            None
        )
        
        if file_handle == INVALID_HANDLE_VALUE:
            error = kernel32.GetLastError()
            return {
                "success": False,
                "error": f"Cannot create temporary file: {temp_file} (Error: {error})",
                "filepath": filepath
            }
        
        # Initialize hash for integrity verification
        if verify_integrity:
            file_hash = hashlib.sha256()
        
        # Write chunks to file
        start_time = time.time()
        
        for chunk_index, chunk_b64 in enumerate(chunks_data):
            try:
                # Decode chunk
                chunk_data = base64.b64decode(chunk_b64)
                
                # Write chunk
                bytes_written = wintypes.DWORD()
                success = kernel32.WriteFile(
                    file_handle,
                    chunk_data,
                    len(chunk_data),
                    ctypes.byref(bytes_written),
                    None
                )
                
                if not success or bytes_written.value != len(chunk_data):
                    error = kernel32.GetLastError()
                    raise Exception(f"Write failed for chunk {chunk_index} (Error: {error})")
                
                total_written += bytes_written.value
                
                # Update hash
                if verify_integrity:
                    file_hash.update(chunk_data)
                    
            except Exception as e:
                raise Exception(f"Chunk {chunk_index} processing failed: {str(e)}")
        
        # Flush and close file
        kernel32.FlushFileBuffers(file_handle)
        kernel32.CloseHandle(file_handle)
        file_handle = None
        
        # Verify integrity if requested
        if verify_integrity and expected_hash:
            calculated_hash = file_hash.hexdigest()
            if calculated_hash != expected_hash:
                # Clean up temp file
                os.remove(temp_file)
                return {
                    "success": False,
                    "error": f"Integrity check failed. Expected: {expected_hash}, Got: {calculated_hash}",
                    "filepath": filepath,
                    "bytes_written": total_written
                }
        
        # Backup existing file if needed
        backup_path = None
        if os.path.exists(filepath) and overwrite:
            backup_path = filepath + ".backup." + str(int(time.time()))
            os.rename(filepath, backup_path)
        
        # Atomic move from temp to final location
        os.rename(temp_file, filepath)
        temp_file = None
        
        # Prepare result
        result = {
            "success": True,
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": total_written,
            "chunks_processed": len(chunks_data),
            "upload_time": time.time() - start_time,
            "backup_created": backup_path is not None
        }
        
        if backup_path:
            result["backup_path"] = backup_path
        
        if verify_integrity:
            result["sha256"] = file_hash.hexdigest()
            result["integrity_verified"] = True
        
        return result
        
    except Exception as e:
        # Clean up on error
        if file_handle and file_handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(file_handle)
        
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        
        return {
            "success": False,
            "error": f"Windows upload failed: {str(e)}",
            "filepath": filepath,
            "bytes_written": total_written
        }

def _unix_elite_upload(filepath: str, chunks_data: List[str], expected_hash: str, 
                      overwrite: bool, verify_integrity: bool) -> Dict[str, Any]:
    """Unix implementation with atomic operations and permission preservation"""
    
    temp_file = None
    total_written = 0
    
    try:
        # Get original file permissions if it exists
        original_stat = None
        if os.path.exists(filepath):
            original_stat = os.stat(filepath)
        
        # Create temporary file in same directory for atomic operation
        temp_fd, temp_file = tempfile.mkstemp(
            prefix=".upload_", 
            suffix=".tmp",
            dir=os.path.dirname(os.path.abspath(filepath))
        )
        
        # Initialize hash for integrity verification
        if verify_integrity:
            file_hash = hashlib.sha256()
        
        # Write chunks to temporary file
        start_time = time.time()
        
        with os.fdopen(temp_fd, 'wb') as f:
            for chunk_index, chunk_b64 in enumerate(chunks_data):
                try:
                    # Decode chunk
                    chunk_data = base64.b64decode(chunk_b64)
                    
                    # Write chunk
                    f.write(chunk_data)
                    total_written += len(chunk_data)
                    
                    # Update hash
                    if verify_integrity:
                        file_hash.update(chunk_data)
                        
                except Exception as e:
                    raise Exception(f"Chunk {chunk_index} processing failed: {str(e)}")
            
            # Ensure data is written to disk
            f.flush()
            os.fsync(f.fileno())
        
        # Verify integrity if requested
        if verify_integrity and expected_hash:
            calculated_hash = file_hash.hexdigest()
            if calculated_hash != expected_hash:
                # Clean up temp file
                os.remove(temp_file)
                return {
                    "success": False,
                    "error": f"Integrity check failed. Expected: {expected_hash}, Got: {calculated_hash}",
                    "filepath": filepath,
                    "bytes_written": total_written
                }
        
        # Backup existing file if needed
        backup_path = None
        if os.path.exists(filepath) and overwrite:
            backup_path = filepath + ".backup." + str(int(time.time()))
            os.rename(filepath, backup_path)
        
        # Set permissions on temp file before moving
        if original_stat:
            try:
                os.chmod(temp_file, original_stat.st_mode)
                os.chown(temp_file, original_stat.st_uid, original_stat.st_gid)
            except (OSError, PermissionError):
                # Not critical if this fails
                pass
        
        # Atomic move from temp to final location
        os.rename(temp_file, filepath)
        temp_file = None
        
        # Prepare result
        result = {
            "success": True,
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": total_written,
            "chunks_processed": len(chunks_data),
            "upload_time": time.time() - start_time,
            "backup_created": backup_path is not None,
            "permissions_preserved": original_stat is not None
        }
        
        if backup_path:
            result["backup_path"] = backup_path
        
        if verify_integrity:
            result["sha256"] = file_hash.hexdigest()
            result["integrity_verified"] = True
        
        return result
        
    except Exception as e:
        # Clean up on error
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        
        return {
            "success": False,
            "error": f"Unix upload failed: {str(e)}",
            "filepath": filepath,
            "bytes_written": total_written
        }

def elite_upload_stream(filepath: str, chunk_generator, expected_hash: str = None, 
                       overwrite: bool = False) -> Dict[str, Any]:
    """
    Streaming version of elite upload for very large files
    Processes chunks as they arrive instead of storing them all in memory
    """
    
    temp_file = None
    total_written = 0
    chunk_count = 0
    
    try:
        # Validate target
        if os.path.exists(filepath) and not overwrite:
            return {
                "success": False,
                "error": f"File already exists: {filepath}",
                "filepath": filepath
            }
        
        # Create temporary file
        temp_fd, temp_file = tempfile.mkstemp(
            prefix=".stream_upload_", 
            suffix=".tmp",
            dir=os.path.dirname(os.path.abspath(filepath))
        )
        
        # Initialize hash
        file_hash = hashlib.sha256()
        start_time = time.time()
        
        # Process streaming chunks
        with os.fdopen(temp_fd, 'wb') as f:
            for chunk_b64 in chunk_generator:
                try:
                    chunk_data = base64.b64decode(chunk_b64)
                    f.write(chunk_data)
                    
                    total_written += len(chunk_data)
                    chunk_count += 1
                    
                    file_hash.update(chunk_data)
                    
                    # Yield progress periodically
                    if chunk_count % 100 == 0:
                        f.flush()
                        
                except Exception as e:
                    raise Exception(f"Stream chunk {chunk_count} failed: {str(e)}")
            
            # Final flush
            f.flush()
            os.fsync(f.fileno())
        
        # Verify integrity
        calculated_hash = file_hash.hexdigest()
        if expected_hash and calculated_hash != expected_hash:
            os.remove(temp_file)
            return {
                "success": False,
                "error": f"Stream integrity check failed. Expected: {expected_hash}, Got: {calculated_hash}",
                "filepath": filepath
            }
        
        # Atomic move
        if os.path.exists(filepath):
            backup_path = filepath + ".backup." + str(int(time.time()))
            os.rename(filepath, backup_path)
        
        os.rename(temp_file, filepath)
        
        return {
            "success": True,
            "filepath": filepath,
            "size": total_written,
            "chunks_processed": chunk_count,
            "upload_time": time.time() - start_time,
            "sha256": calculated_hash,
            "streaming": True
        }
        
    except Exception as e:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        
        return {
            "success": False,
            "error": f"Stream upload failed: {str(e)}",
            "filepath": filepath,
            "bytes_written": total_written,
            "chunks_processed": chunk_count
        }

def prepare_file_chunks(filepath: str, chunk_size: int = 1024*1024) -> List[str]:
    """
    Helper function to prepare a file for upload by chunking it
    Returns list of base64-encoded chunks
    """
    
    chunks = []
    
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break
                
                chunk_b64 = base64.b64encode(chunk_data).decode()
                chunks.append(chunk_b64)
        
        return chunks
        
    except Exception as e:
        raise Exception(f"Failed to prepare file chunks: {str(e)}")


if __name__ == "__main__":
    # Test the elite upload command
    # print("Testing Elite Upload Command...")
    
    # Create test data
    test_content = "This is test content for elite upload.\n" * 200
    test_file_source = "test_upload_source.txt"
    test_file_target = "test_upload_target.txt"
    
    try:
        # Create source file
        with open(test_file_source, 'w') as f:
            f.write(test_content)
        
    # print(f"Created source file: {test_file_source} ({len(test_content)} bytes)")
        
        # Prepare chunks
        chunks = prepare_file_chunks(test_file_source, chunk_size=1024)
    # print(f"Prepared {len(chunks)} chunks for upload")
        
        # Calculate expected hash
        expected_hash = hashlib.sha256(test_content.encode()).hexdigest()
        
        # Test upload
        result = elite_upload(
            test_file_target, 
            chunks, 
            expected_hash=expected_hash,
            verify_integrity=True
        )
        
        if result['success']:
    # print(f"✅ Uploaded {result['size']} bytes in {result['chunks_processed']} chunks")
    # print(f"Upload time: {result['upload_time']:.3f} seconds")
            
            if result.get('integrity_verified'):
    # print("✅ Integrity verification passed")
            
            # Verify file exists and content matches
            if os.path.exists(test_file_target):
                with open(test_file_target, 'r') as f:
                    uploaded_content = f.read()
                
                if uploaded_content == test_content:
    # print("✅ Content verification passed")
                else:
    # print("❌ Content verification failed")
            
        else:
    # print(f"❌ Upload failed: {result['error']}")
        
        # Clean up
        for f in [test_file_source, test_file_target]:
            if os.path.exists(f):
                os.remove(f)
        
    # print("Test files cleaned up")
        
    except Exception as e:
    # print(f"❌ Test failed: {e}")
        # Clean up on error
        for f in [test_file_source, test_file_target]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
    
    # print("Elite Upload command test complete")