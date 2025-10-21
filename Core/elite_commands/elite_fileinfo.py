#!/usr/bin/env python3
"""
Elite File Information
Advanced file metadata and forensic analysis
"""

import ctypes
import ctypes.wintypes
import sys
import os
import stat
import time
import hashlib
import subprocess
from typing import Dict, Any, List, Optional

def elite_fileinfo(filepath: str, 
                  include_hashes: bool = True,
                  include_metadata: bool = True,
                  include_forensics: bool = True) -> Dict[str, Any]:
    """
    Comprehensive file information gathering
    
    Args:
        filepath: Path to file to analyze
        include_hashes: Calculate file hashes (MD5, SHA1, SHA256)
        include_metadata: Include extended metadata
        include_forensics: Include forensic analysis
    
    Returns:
        Dict containing comprehensive file information
    """
    
    try:
        if not os.path.exists(filepath):
            return {
                "success": False,
                "error": "File not found",
                "filepath": filepath
            }
        
        # Basic file information
        file_info = _get_basic_info(filepath)
        
        # Extended attributes
        if include_metadata:
            file_info.update(_get_extended_metadata(filepath))
        
        # File hashes
        if include_hashes:
            file_info.update(_calculate_file_hashes(filepath))
        
        # Forensic analysis
        if include_forensics:
            file_info.update(_forensic_analysis(filepath))
        
        # Platform-specific information
        if sys.platform == "win32":
            file_info.update(_windows_file_info(filepath))
        else:
            file_info.update(_unix_file_info(filepath))
        
        file_info["success"] = True
        file_info["analysis_timestamp"] = time.time()
        
        return file_info
    
    except Exception as e:
        return {
            "success": False,
            "error": f"File analysis failed: {str(e)}",
            "filepath": filepath
        }

def _get_basic_info(filepath: str) -> Dict[str, Any]:
    """Get basic file information"""
    
    info = {
        "filepath": os.path.abspath(filepath),
        "filename": os.path.basename(filepath),
        "directory": os.path.dirname(os.path.abspath(filepath)),
        "extension": os.path.splitext(filepath)[1].lower()
    }
    
    try:
        stat_info = os.stat(filepath)
        
        info.update({
            "size_bytes": stat_info.st_size,
            "size_formatted": _format_bytes(stat_info.st_size),
            "created_timestamp": stat_info.st_ctime,
            "created_time": time.ctime(stat_info.st_ctime),
            "modified_timestamp": stat_info.st_mtime,
            "modified_time": time.ctime(stat_info.st_mtime),
            "accessed_timestamp": stat_info.st_atime,
            "accessed_time": time.ctime(stat_info.st_atime),
            "permissions": oct(stat_info.st_mode),
            "inode": stat_info.st_ino,
            "device": stat_info.st_dev,
            "links": stat_info.st_nlink,
            "uid": stat_info.st_uid,
            "gid": stat_info.st_gid
        })
        
        # File type detection
        info["is_file"] = os.path.isfile(filepath)
        info["is_directory"] = os.path.isdir(filepath)
        info["is_symlink"] = os.path.islink(filepath)
        info["is_executable"] = os.access(filepath, os.X_OK)
        info["is_readable"] = os.access(filepath, os.R_OK)
        info["is_writable"] = os.access(filepath, os.W_OK)
    
    except Exception as e:
        info["basic_info_error"] = str(e)
    
    return info

def _get_extended_metadata(filepath: str) -> Dict[str, Any]:
    """Get extended file metadata"""
    
    metadata = {}
    
    try:
        # MIME type detection
        try:
            import mimetypes
            mime_type, encoding = mimetypes.guess_type(filepath)
            metadata["mime_type"] = mime_type
            metadata["encoding"] = encoding
        except:
            pass
        
        # File signature analysis
        metadata.update(_analyze_file_signature(filepath))
        
        # Entropy analysis
        metadata.update(_calculate_entropy(filepath))
        
        # String analysis
        if os.path.getsize(filepath) < 10 * 1024 * 1024:  # Limit to 10MB
            metadata.update(_extract_strings(filepath))
    
    except Exception as e:
        metadata["metadata_error"] = str(e)
    
    return metadata

def _calculate_file_hashes(filepath: str) -> Dict[str, Any]:
    """Calculate file hashes"""
    
    hashes = {}
    
    try:
        # Limit hash calculation for large files
        file_size = os.path.getsize(filepath)
        
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            hashes["hash_skipped"] = "File too large for hash calculation"
            return hashes
        
        hash_algorithms = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512()
        }
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                for hasher in hash_algorithms.values():
                    hasher.update(chunk)
        
        for name, hasher in hash_algorithms.items():
            hashes[f"{name}_hash"] = hasher.hexdigest()
        
        # Calculate CRC32
        import zlib
        with open(filepath, 'rb') as f:
            crc32_hash = 0
            while chunk := f.read(8192):
                crc32_hash = zlib.crc32(chunk, crc32_hash)
        
        hashes["crc32"] = f"{crc32_hash & 0xffffffff:08x}"
    
    except Exception as e:
        hashes["hash_error"] = str(e)
    
    return hashes

def _forensic_analysis(filepath: str) -> Dict[str, Any]:
    """Perform forensic analysis on file"""
    
    forensics = {}
    
    try:
        # Check for alternate data streams (Windows)
        if sys.platform == "win32":
            forensics.update(_check_alternate_data_streams(filepath))
        
        # Check for hidden attributes
        forensics.update(_check_hidden_attributes(filepath))
        
        # Analyze file header
        forensics.update(_analyze_file_header(filepath))
        
        # Check for embedded files
        forensics.update(_check_embedded_files(filepath))
        
        # Timestamp analysis
        forensics.update(_analyze_timestamps(filepath))
    
    except Exception as e:
        forensics["forensics_error"] = str(e)
    
    return forensics

def _windows_file_info(filepath: str) -> Dict[str, Any]:
    """Windows-specific file information"""
    
    info = {}
    
    try:
        # Get file attributes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
        if attrs != -1:
            info["attributes"] = _decode_file_attributes(attrs)
        
        # Get version information for executables
        if filepath.lower().endswith(('.exe', '.dll', '.sys')):
            info.update(_get_version_info(filepath))
        
        # Get security descriptor
        info.update(_get_security_descriptor(filepath))
        
        # Get file times with higher precision
        info.update(_get_precise_file_times(filepath))
    
    except Exception as e:
        info["windows_info_error"] = str(e)
    
    return info

def _unix_file_info(filepath: str) -> Dict[str, Any]:
    """Unix-specific file information"""
    
    info = {}
    
    try:
        stat_info = os.stat(filepath)
        
        # Extended file attributes
        info["mode_octal"] = oct(stat_info.st_mode)
        info["mode_string"] = stat.filemode(stat_info.st_mode)
        
        # User and group information
        try:
            import pwd
            import grp
            
            user_info = pwd.getpwuid(stat_info.st_uid)
            group_info = grp.getgrgid(stat_info.st_gid)
            
            info["owner_name"] = user_info.pw_name
            info["group_name"] = group_info.gr_name
        except:
            pass
        
        # Extended attributes (Linux)
        try:
            import xattr
            xattrs = xattr.listxattr(filepath)
            if xattrs:
                info["extended_attributes"] = {}
                for attr in xattrs:
                    try:
                        info["extended_attributes"][attr] = xattr.getxattr(filepath, attr)
                    except:
                        pass
        except ImportError:
            pass
    
    except Exception as e:
        info["unix_info_error"] = str(e)
    
    return info

def _analyze_file_signature(filepath: str) -> Dict[str, Any]:
    """Analyze file signature/magic bytes"""
    
    signatures = {
        b'\x4D\x5A': 'PE Executable',
        b'\x7F\x45\x4C\x46': 'ELF Executable',
        b'\xFF\xD8\xFF': 'JPEG Image',
        b'\x89\x50\x4E\x47': 'PNG Image',
        b'\x47\x49\x46\x38': 'GIF Image',
        b'\x50\x4B\x03\x04': 'ZIP Archive',
        b'\x50\x4B\x05\x06': 'ZIP Archive (empty)',
        b'\x50\x4B\x07\x08': 'ZIP Archive (spanned)',
        b'\x52\x61\x72\x21': 'RAR Archive',
        b'\x1F\x8B\x08': 'GZIP Archive',
        b'\x42\x5A\x68': 'BZIP2 Archive',
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\xD0\xCF\x11\xE0': 'Microsoft Office Document',
        b'\x50\x4B\x03\x04': 'Office Open XML Document'
    }
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        detected_type = "Unknown"
        
        for signature, file_type in signatures.items():
            if header.startswith(signature):
                detected_type = file_type
                break
        
        return {
            "file_signature": header.hex(),
            "detected_type": detected_type,
            "signature_match": detected_type != "Unknown"
        }
    
    except Exception as e:
        return {"signature_error": str(e)}

def _calculate_entropy(filepath: str) -> Dict[str, Any]:
    """Calculate file entropy (randomness measure)"""
    
    try:
        import math
        
        # Limit entropy calculation for large files
        file_size = os.path.getsize(filepath)
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            return {"entropy_skipped": "File too large for entropy calculation"}
        
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                for byte in chunk:
                    byte_counts[byte] += 1
                    total_bytes += 1
        
        if total_bytes == 0:
            return {"entropy": 0.0}
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        # Entropy interpretation
        if entropy < 1.0:
            entropy_level = "Very Low (Highly structured)"
        elif entropy < 3.0:
            entropy_level = "Low (Structured)"
        elif entropy < 6.0:
            entropy_level = "Medium (Mixed content)"
        elif entropy < 7.5:
            entropy_level = "High (Compressed/Encrypted)"
        else:
            entropy_level = "Very High (Random/Encrypted)"
        
        return {
            "entropy": round(entropy, 3),
            "entropy_level": entropy_level,
            "max_entropy": 8.0
        }
    
    except Exception as e:
        return {"entropy_error": str(e)}

def _extract_strings(filepath: str, min_length: int = 4) -> Dict[str, Any]:
    """Extract printable strings from file"""
    
    try:
        strings = []
        
        with open(filepath, 'rb') as f:
            current_string = ""
            
            while byte := f.read(1):
                if not byte:
                    break
                
                char = byte[0]
                
                # Check if printable ASCII
                if 32 <= char <= 126:
                    current_string += chr(char)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            # Add final string if valid
            if len(current_string) >= min_length:
                strings.append(current_string)
        
        # Limit number of strings returned
        if len(strings) > 1000:
            strings = strings[:1000]
        
        # Analyze strings for interesting patterns
        interesting_patterns = []
        
        for s in strings:
            s_lower = s.lower()
            
            # URLs
            if any(proto in s_lower for proto in ['http://', 'https://', 'ftp://']):
                interesting_patterns.append(f"URL: {s}")
            
            # Email addresses
            elif '@' in s and '.' in s:
                interesting_patterns.append(f"Email: {s}")
            
            # File paths
            elif '\\' in s or ('/' in s and len(s) > 10):
                interesting_patterns.append(f"Path: {s}")
            
            # Registry keys
            elif s.startswith('HKEY_') or '\\SOFTWARE\\' in s:
                interesting_patterns.append(f"Registry: {s}")
        
        return {
            "total_strings": len(strings),
            "strings_sample": strings[:50],  # First 50 strings
            "interesting_patterns": interesting_patterns[:20]  # First 20 patterns
        }
    
    except Exception as e:
        return {"strings_error": str(e)}

def _check_alternate_data_streams(filepath: str) -> Dict[str, Any]:
    """Check for NTFS Alternate Data Streams (Windows)"""
    
    try:
        # Use dir command to check for ADS
        result = subprocess.run([
            'cmd', '/c', f'dir /r "{filepath}"'
        ], capture_output=True, text=True, timeout=10)
        
        ads_found = []
        
        if result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                if ':' in line and '$DATA' in line:
                    ads_found.append(line.strip())
        
        return {
            "alternate_data_streams": ads_found,
            "has_ads": len(ads_found) > 0
        }
    
    except Exception as e:
        return {"ads_error": str(e)}

def _check_hidden_attributes(filepath: str) -> Dict[str, Any]:
    """Check for hidden file attributes"""
    
    attributes = {
        "is_hidden": False,
        "is_system": False,
        "is_readonly": False,
        "is_archive": False
    }
    
    try:
        if sys.platform == "win32":
            import ctypes
            
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            FILE_ATTRIBUTE_READONLY = 0x01
            FILE_ATTRIBUTE_ARCHIVE = 0x20
            
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            
            if attrs != -1:
                attributes["is_hidden"] = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                attributes["is_system"] = bool(attrs & FILE_ATTRIBUTE_SYSTEM)
                attributes["is_readonly"] = bool(attrs & FILE_ATTRIBUTE_READONLY)
                attributes["is_archive"] = bool(attrs & FILE_ATTRIBUTE_ARCHIVE)
        
        else:
            # Unix hidden files (start with .)
            filename = os.path.basename(filepath)
            attributes["is_hidden"] = filename.startswith('.')
    
    except Exception as e:
        attributes["hidden_check_error"] = str(e)
    
    return attributes

def _analyze_file_header(filepath: str) -> Dict[str, Any]:
    """Analyze file header for structure"""
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(1024)  # Read first 1KB
        
        analysis = {
            "header_size": len(header),
            "null_bytes": header.count(b'\x00'),
            "printable_chars": sum(1 for b in header if 32 <= b <= 126),
            "high_entropy_bytes": sum(1 for b in header if b > 127)
        }
        
        # Calculate header entropy
        if header:
            byte_counts = [0] * 256
            for byte in header:
                byte_counts[byte] += 1
            
            import math
            entropy = 0.0
            total = len(header)
            
            for count in byte_counts:
                if count > 0:
                    prob = count / total
                    entropy -= prob * math.log2(prob)
            
            analysis["header_entropy"] = round(entropy, 3)
        
        return analysis
    
    except Exception as e:
        return {"header_analysis_error": str(e)}

def _check_embedded_files(filepath: str) -> Dict[str, Any]:
    """Check for embedded files or archives"""
    
    try:
        # Simple check for embedded ZIP files
        embedded_signatures = []
        
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Look for ZIP signatures
        zip_signature = b'PK\x03\x04'
        pos = 0
        while True:
            pos = content.find(zip_signature, pos)
            if pos == -1:
                break
            embedded_signatures.append(f"ZIP signature at offset {pos}")
            pos += 1
        
        # Look for other archive signatures
        signatures = {
            b'Rar!': 'RAR archive',
            b'\x1f\x8b\x08': 'GZIP archive',
            b'BZh': 'BZIP2 archive'
        }
        
        for sig, desc in signatures.items():
            pos = content.find(sig)
            if pos != -1:
                embedded_signatures.append(f"{desc} at offset {pos}")
        
        return {
            "embedded_files": embedded_signatures,
            "has_embedded": len(embedded_signatures) > 0
        }
    
    except Exception as e:
        return {"embedded_check_error": str(e)}

def _analyze_timestamps(filepath: str) -> Dict[str, Any]:
    """Analyze file timestamps for anomalies"""
    
    try:
        stat_info = os.stat(filepath)
        
        created = stat_info.st_ctime
        modified = stat_info.st_mtime
        accessed = stat_info.st_atime
        
        analysis = {
            "timestamp_order_normal": created <= modified <= accessed,
            "created_modified_diff": abs(created - modified),
            "modified_accessed_diff": abs(modified - accessed),
            "created_accessed_diff": abs(created - accessed)
        }
        
        # Check for suspicious timestamp patterns
        suspicious = []
        
        # Future timestamps
        current_time = time.time()
        if any(t > current_time + 86400 for t in [created, modified, accessed]):  # 1 day in future
            suspicious.append("Future timestamp detected")
        
        # Very old timestamps (before 1980)
        epoch_1980 = 315532800  # Jan 1, 1980
        if any(t < epoch_1980 for t in [created, modified, accessed]):
            suspicious.append("Very old timestamp (pre-1980)")
        
        # Identical timestamps (suspicious for real files)
        if created == modified == accessed:
            suspicious.append("All timestamps identical")
        
        analysis["suspicious_patterns"] = suspicious
        
        return analysis
    
    except Exception as e:
        return {"timestamp_analysis_error": str(e)}

def _decode_file_attributes(attrs: int) -> List[str]:
    """Decode Windows file attributes"""
    
    attribute_flags = {
        0x01: "READONLY",
        0x02: "HIDDEN",
        0x04: "SYSTEM",
        0x08: "VOLUME_LABEL",
        0x10: "DIRECTORY",
        0x20: "ARCHIVE",
        0x40: "DEVICE",
        0x80: "NORMAL",
        0x100: "TEMPORARY",
        0x200: "SPARSE_FILE",
        0x400: "REPARSE_POINT",
        0x800: "COMPRESSED",
        0x1000: "OFFLINE",
        0x2000: "NOT_CONTENT_INDEXED",
        0x4000: "ENCRYPTED"
    }
    
    attributes = []
    for flag, name in attribute_flags.items():
        if attrs & flag:
            attributes.append(name)
    
    return attributes

def _get_version_info(filepath: str) -> Dict[str, Any]:
    """Get version information from PE files"""
    
    try:
        # This would require more advanced PE parsing
        # For now, return a placeholder
        return {
            "version_info": "PE version parsing not implemented",
            "has_version_info": False
        }
    
    except Exception as e:
        return {"version_info_error": str(e)}

def _get_security_descriptor(filepath: str) -> Dict[str, Any]:
    """Get file security descriptor (Windows)"""
    
    try:
        # This would require advanced Windows security API calls
        # For now, return a placeholder
        return {
            "security_descriptor": "Security descriptor parsing not implemented",
            "has_custom_permissions": False
        }
    
    except Exception as e:
        return {"security_descriptor_error": str(e)}

def _get_precise_file_times(filepath: str) -> Dict[str, Any]:
    """Get precise file times using Windows API"""
    
    try:
        # This would use GetFileTime API for higher precision
        # For now, return standard times
        stat_info = os.stat(filepath)
        
        return {
            "precise_created": stat_info.st_ctime,
            "precise_modified": stat_info.st_mtime,
            "precise_accessed": stat_info.st_atime
        }
    
    except Exception as e:
        return {"precise_times_error": str(e)}

def _format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    
    if bytes_value == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(bytes_value)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"

if __name__ == "__main__":
    # Test the implementation
    import sys
    if len(sys.argv) > 1:
        result = elite_fileinfo(sys.argv[1])
        print(f"File Info Result: {result}")
    else:
        print("Usage: python elite_fileinfo.py <filepath>")