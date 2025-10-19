/*
 * SHA-256 Cryptographic Hash Function
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// SHA-256 digest size
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

// SHA-256 context structure
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;

// SHA-256 functions
void sha256_init(sha256_ctx_t* ctx);
void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len);
void sha256_final(sha256_ctx_t* ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

// Simple interface
void sha256(const uint8_t* data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]);

// HMAC-SHA256
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t mac[SHA256_DIGEST_SIZE]);

// PBKDF2-SHA256 for key derivation
void pbkdf2_sha256(const uint8_t* password, size_t pass_len,
                   const uint8_t* salt, size_t salt_len,
                   uint8_t* key, size_t key_len, 
                   uint32_t iterations);

#endif // SHA256_H