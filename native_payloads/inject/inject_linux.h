/*
 * Linux-specific Process Injection
 */

#ifndef INJECT_LINUX_H
#define INJECT_LINUX_H

#ifdef PLATFORM_LINUX

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <dirent.h>
#include <link.h>
#include <elf.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

// Linux process information
typedef struct {
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    gid_t gid;
    char name[256];
    char cmdline[512];
    char exe_path[512];
    unsigned long virt_mem;
    unsigned long res_mem;
    int num_threads;
    int nice;
    unsigned long start_time;
} linux_process_info_t;

// Memory region information
typedef struct {
    unsigned long start;
    unsigned long end;
    char permissions[5];  // rwxp
    unsigned long offset;
    char device[16];
    unsigned long inode;
    char pathname[256];
    bool is_readable;
    bool is_writable;
    bool is_executable;
    bool is_private;
} linux_memory_region_t;

// Thread information
typedef struct {
    pid_t tid;
    pid_t tgid;
    int state;
    unsigned long start_stack;
    unsigned long start_code;
    unsigned long end_code;
} linux_thread_info_t;

// ELF injection parameters
typedef struct {
    void* elf_buffer;
    size_t elf_size;
    char* so_path;
    bool use_memfd;
    bool use_dlopen_bypass;
} inject_params_elf_t;

// Shellcode types for Linux
typedef enum {
    SHELLCODE_X86_SYSCALL,
    SHELLCODE_X64_SYSCALL,
    SHELLCODE_MMAP_EXEC,
    SHELLCODE_DLOPEN_CALL,
    SHELLCODE_MEMFD_CREATE
} linux_shellcode_type_t;

// Function prototypes
inject_status_t inject_check_ptrace_scope(void);
inject_status_t inject_set_ptrace_scope(int scope);
inject_status_t inject_parse_proc_maps(pid_t pid, linux_memory_region_t** regions, int* count);
inject_status_t inject_find_libc_base(pid_t pid, unsigned long* base);
inject_status_t inject_find_function_address(pid_t pid, const char* library, const char* function, unsigned long* addr);
inject_status_t inject_read_proc_mem(pid_t pid, unsigned long addr, void* buffer, size_t size);
inject_status_t inject_write_proc_mem(pid_t pid, unsigned long addr, const void* buffer, size_t size);

// ptrace helpers
inject_status_t inject_ptrace_attach(pid_t pid);
inject_status_t inject_ptrace_detach(pid_t pid);
inject_status_t inject_ptrace_cont(pid_t pid, int signal);
inject_status_t inject_ptrace_getregs(pid_t pid, struct user_regs_struct* regs);
inject_status_t inject_ptrace_setregs(pid_t pid, struct user_regs_struct* regs);
inject_status_t inject_ptrace_read(pid_t pid, unsigned long addr, void* buffer, size_t size);
inject_status_t inject_ptrace_write(pid_t pid, unsigned long addr, const void* buffer, size_t size);
inject_status_t inject_ptrace_syscall(pid_t pid, unsigned long number, unsigned long* args, unsigned long* result);

// Process manipulation
inject_status_t inject_stop_process(pid_t pid);
inject_status_t inject_cont_process(pid_t pid);
inject_status_t inject_create_memfd(const char* name, int* fd);
inject_status_t inject_remote_mmap(pid_t pid, size_t size, int prot, unsigned long* addr);
inject_status_t inject_remote_dlopen(pid_t pid, const char* library_path);
inject_status_t inject_remote_syscall(pid_t pid, long syscall_num, long* args, long* result);

// Shellcode generation
inject_status_t inject_generate_shellcode(linux_shellcode_type_t type, void* param, uint8_t** shellcode, size_t* size);
inject_status_t inject_build_dlopen_shellcode(const char* lib_path, uint8_t** shellcode, size_t* size);
inject_status_t inject_build_mmap_shellcode(size_t map_size, uint8_t** shellcode, size_t* size);

// Library injection helpers
inject_status_t inject_load_library_memfd(pid_t pid, void* library_data, size_t size);
inject_status_t inject_hijack_got_plt(pid_t pid, const char* function, unsigned long new_addr);

// VDSO manipulation
inject_status_t inject_find_vdso(pid_t pid, unsigned long* base, size_t* size);
inject_status_t inject_hijack_vdso(pid_t pid, const char* function, void* shellcode, size_t size);

// Anti-debugging bypass
inject_status_t inject_bypass_yama_ptrace(void);
inject_status_t inject_bypass_selinux(void);

// Cleanup
inject_status_t inject_unmap_remote(pid_t pid, unsigned long addr, size_t size);

#endif // PLATFORM_LINUX

#endif // INJECT_LINUX_H