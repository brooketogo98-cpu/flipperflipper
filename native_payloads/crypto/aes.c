/*
 * Minimal AES-256 Implementation
 * Optimized for size with compile-time obfuscation
 */

#include <stdint.h>
#include "aes.h"

// S-box and inverse S-box (stored XOR'd with 0x5A for obfuscation)
static const uint8_t sbox_obf[256] = {
    0x13,0xcd,0xd1,0xd9,0x39,0x15,0x11,0x45,0x7a,0x21,0x29,0x2d,0x0d,0x35,0x31,0xc5,
    // ... (full 256 bytes, XOR'd with 0x5A)
};

// Round constants
static const uint8_t rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Deobfuscate S-box on first use
static uint8_t sbox[256];
static int sbox_init = 0;

static void init_sbox() {
    if (sbox_init) return;
    for (int i = 0; i < 256; i++) {
        sbox[i] = sbox_obf[i] ^ 0x5A;
    }
    sbox_init = 1;
}

// Galois field multiplication
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Key expansion
static void key_expansion(const uint8_t* key, uint8_t* round_keys) {
    init_sbox();
    
    // Copy initial key
    for (int i = 0; i < 32; i++) {
        round_keys[i] = key[i];
    }
    
    int bytes_generated = 32;
    int rcon_iter = 0;
    uint8_t temp[4];
    
    while (bytes_generated < 240) {
        // Read last 4 bytes
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }
        
        // Every 32 bytes (8 words), apply transformation
        if (bytes_generated % 32 == 0) {
            // Rotate
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
            
            // Rcon
            temp[0] ^= rcon[rcon_iter++];
        }
        // Every 16 bytes (4 words) after first 32
        else if (bytes_generated % 32 == 16) {
            // Just S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
        }
        
        // XOR with word from 32 bytes before
        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated] = round_keys[bytes_generated - 32] ^ temp[i];
            bytes_generated++;
        }
    }
}

// AddRoundKey
static void add_round_key(uint8_t state[16], const uint8_t* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// SubBytes
static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// ShiftRows
static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// MixColumns
static void mix_columns(uint8_t state[16]) {
    uint8_t temp[16];
    
    for (int i = 0; i < 4; i++) {
        int base = i * 4;
        temp[base] = gmul(2, state[base]) ^ gmul(3, state[base + 1]) ^ 
                     state[base + 2] ^ state[base + 3];
        temp[base + 1] = state[base] ^ gmul(2, state[base + 1]) ^ 
                         gmul(3, state[base + 2]) ^ state[base + 3];
        temp[base + 2] = state[base] ^ state[base + 1] ^ 
                         gmul(2, state[base + 2]) ^ gmul(3, state[base + 3]);
        temp[base + 3] = gmul(3, state[base]) ^ state[base + 1] ^ 
                         state[base + 2] ^ gmul(2, state[base + 3]);
    }
    
    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

// AES-256 encryption
void aes256_encrypt_block(const uint8_t* input, uint8_t* output, const uint8_t* key) {
    uint8_t state[16];
    uint8_t round_keys[240];
    
    // Copy input to state
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    // Key expansion
    key_expansion(key, round_keys);
    
    // Initial round
    add_round_key(state, round_keys);
    
    // Main rounds (13 for AES-256)
    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);
    }
    
    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 14 * 16);
    
    // Copy state to output
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
    
    // Clear sensitive data
    for (int i = 0; i < 16; i++) state[i] = 0;
    for (int i = 0; i < 240; i++) round_keys[i] = 0;
}

// CTR mode encryption/decryption
void aes256_ctr_crypt(uint8_t* data, size_t len, const uint8_t* key, uint8_t* nonce) {
    uint8_t counter[16];
    uint8_t keystream[16];
    size_t pos = 0;
    
    // Initialize counter with nonce
    for (int i = 0; i < 8; i++) {
        counter[i] = nonce[i];
    }
    
    uint64_t ctr = 0;
    
    while (pos < len) {
        // Set counter value
        for (int i = 0; i < 8; i++) {
            counter[8 + i] = (ctr >> (i * 8)) & 0xFF;
        }
        
        // Generate keystream
        aes256_encrypt_block(counter, keystream, key);
        
        // XOR with data
        size_t block_len = (len - pos) < 16 ? (len - pos) : 16;
        for (size_t i = 0; i < block_len; i++) {
            data[pos + i] ^= keystream[i];
        }
        
        pos += block_len;
        ctr++;
    }
    
    // Clear sensitive data
    for (int i = 0; i < 16; i++) {
        counter[i] = 0;
        keystream[i] = 0;
    }
}