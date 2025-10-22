/*
 * AES-256 Header - Advanced Cryptographic Functions
 * Minimal size implementation with compile-time obfuscation
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

// AES block size is always 16 bytes
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32  // AES-256

// Function prototypes
void aes256_encrypt_block(const uint8_t* input, uint8_t* output, const uint8_t* key);
void aes256_decrypt_block(const uint8_t* input, uint8_t* output, const uint8_t* key);
void aes256_ctr_crypt(uint8_t* data, size_t len, const uint8_t* key, uint8_t* nonce);

// Key derivation
void aes_derive_key(const uint8_t* password, size_t pass_len, const uint8_t* salt, uint8_t* key);

// Secure random
void secure_random(uint8_t* buf, size_t len);

#endif // AES_H