/*
 * Utility Functions Header
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

// Memory management
void* stealth_alloc(size_t size);
void stealth_free(void* ptr);
void secure_zero(void* ptr, size_t size);

// String operations
size_t str_len(const char* str);
int str_cmp(const char* s1, const char* s2);
void* mem_cpy(void* dest, const void* src, size_t n);
void* mem_set(void* s, int c, size_t n);
int mem_cmp(const void* s1, const void* s2, size_t n);
char* str_str(const char* haystack, const char* needle);

// Obfuscation
void decrypt_string(uint8_t* str, uint8_t key);
uint32_t hash_string(const char* str);

// Time functions
uint64_t get_timestamp(void);
void sleep_ms(uint32_t milliseconds);

// Random
void get_random_bytes(uint8_t* buffer, size_t length);
uint32_t get_random_int(void);
void set_random_seed(uint32_t seed);
uint32_t get_tick_count(void);

// System info
int get_process_id(void);
int get_cpu_count(void);
uint64_t get_memory_size(void);

// Anti-analysis
int detect_debugger(void);
int detect_vm(void);
int detect_sandbox(void);
void anti_debug_trap(void);

// Error handling
typedef enum {
    ERR_SUCCESS = 0,
    ERR_INVALID_PARAM = -1,
    ERR_OUT_OF_MEMORY = -2,
    ERR_CONNECTION_FAILED = -3,
    ERR_TIMEOUT = -4,
    ERR_ACCESS_DENIED = -5,
    ERR_NOT_FOUND = -6,
    ERR_UNKNOWN = -99
} error_code_t;

const char* error_to_string(error_code_t err);

#endif // UTILS_H