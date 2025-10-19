#!/usr/bin/env python3
"""
Python AES Bridge
Implements AES-256-CTR decryption for native payload responses
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

# Pre-shared key (must match native payload)
SIMPLE_PROTOCOL_KEY = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
])

def aes256_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt data using AES-256-CTR mode
    
    Args:
        data: Encrypted data
        key: 32-byte AES key
        nonce: 8-byte nonce (will be extended to 16 bytes for counter)
        
    Returns:
        Decrypted data
    """
    try:
        # Convert 8-byte nonce to 16-byte counter initial value
        # Use first 8 bytes of IV as nonce, rest as counter
        counter_val = int.from_bytes(nonce[:8], byteorder='big')
        
        # Create counter object (128-bit counter, first 64 bits from nonce)
        ctr = Counter.new(128, initial_value=counter_val << 64, little_endian=False)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        
        # Decrypt (CTR mode is symmetric)
        plaintext = cipher.decrypt(data)
        
        return plaintext
        
    except Exception as e:
        # If decryption fails, return original data
        return data

def decrypt_response(encrypted_data: bytes, iv: bytes) -> bytes:
    """
    Decrypt a response from native payload
    
    Args:
        encrypted_data: The encrypted response
        iv: The initialization vector (16 bytes)
        
    Returns:
        Decrypted plaintext
    """
    return aes256_ctr_decrypt(encrypted_data, SIMPLE_PROTOCOL_KEY, iv)


if __name__ == '__main__':
    # Test
    test_data = b"Hello, World!"
    test_iv = bytes([0] * 8)
    
    # Encrypt (using pycryptodome)
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    
    ctr = Counter.new(128, initial_value=0, little_endian=False)
    cipher = AES.new(SIMPLE_PROTOCOL_KEY, AES.MODE_CTR, counter=ctr)
    encrypted = cipher.encrypt(test_data)
    
    # Decrypt
    decrypted = decrypt_response(encrypted, test_iv)
    
    print(f"Original:  {test_data}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")
