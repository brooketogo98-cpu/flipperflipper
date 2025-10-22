# RUTHLESS ELITE VALIDATION CHECKLIST
## Verifying EVERY Audit 2 Fix at Nation-State Level

---

## THE STANDARD: UNDETECTABLE, ADVANCED, SCARY

This isn't about "working" - it's about being so advanced that security researchers would be impressed. Every implementation must be:

1. **UNDETECTABLE** - Bypasses all major security products
2. **ADVANCED** - Using techniques that 99% of malware doesn't know
3. **SCARY** - Capabilities that would concern nation-state defenders
4. **ROBUST** - Works in hostile enterprise environments
5. **STEALTHY** - Leaves minimal forensic footprint

---

## AUDIT 2 REQUIREMENTS - ALL 63 COMMANDS

### Each Command MUST Be Verified For:

#### 1. ELITE IMPLEMENTATION (Not Basic)
```python
# ❌ FAIL - LAZY IMPLEMENTATION:
def hashdump():
    return subprocess.run("mimikatz.exe", shell=True)

# ✅ PASS - ELITE IMPLEMENTATION:
def hashdump():
    # Direct LSASS memory access
    lsass_handle = OpenProcess(PROCESS_VM_READ, False, lsass_pid)
    
    # Read memory regions
    memory_regions = VirtualQueryEx(lsass_handle)
    
    # Extract SAM from memory
    sam_data = ReadProcessMemory(lsass_handle, sam_offset, sam_size)
    
    # Decrypt using SYSKEY from registry
    syskey = extract_syskey_from_registry()
    
    # Decrypt SAM using RC4/DES
    hashes = decrypt_sam_database(sam_data, syskey)
    
    # Clean up artifacts
    CloseHandle(lsass_handle)
    secure_wipe_memory(locals())
```

### THE 63 COMMANDS THAT MUST BE ELITE:

#### FILE SYSTEM OPERATIONS (11 commands)
- [ ] `ls` - WITH stealth directory enumeration, ADS detection, hidden file discovery
- [ ] `cd` - WITH anti-forensic path navigation, no directory access timestamps
- [ ] `pwd` - WITH obfuscated path return, anti-sandbox checks
- [ ] `cat` - WITH memory-only file reading, no file access logs
- [ ] `download` - WITH chunked, encrypted, integrity-verified transfers
- [ ] `upload` - WITH polymorphic data encoding, traffic masking
- [ ] `rm` - WITH secure deletion, USN journal cleanup, MFT wiping
- [ ] `mkdir` - WITH hidden directory creation, ADS abuse
- [ ] `rmdir` - WITH recursive secure deletion, artifact cleanup
- [ ] `mv` - WITH timestamp preservation, journal bypass
- [ ] `cp` - WITH attribute cloning, shadow copy abuse

**VALIDATION REQUIREMENTS:**
- Must use Windows API directly (not Python's os.* functions)
- Must handle ADS (Alternate Data Streams)
- Must bypass USN journal logging
- Must preserve/manipulate timestamps
- Must handle >260 character paths
- Must work with Unicode filenames

#### SYSTEM INFORMATION (8 commands)
- [ ] `systeminfo` - WITH WMI queries, anti-VM detection, environment fingerprinting
- [ ] `whoami` - WITH token stealing, privilege enumeration
- [ ] `hostname` - WITH DNS cache inspection, network enumeration
- [ ] `username` - WITH session enumeration, RDP user detection
- [ ] `privileges` - WITH token manipulation capability detection
- [ ] `network` - WITH raw socket inspection, hidden connection discovery
- [ ] `processes` - WITH rootkit-like process hiding detection
- [ ] `installedsoftware` - WITH registry deep-dive, portable app detection

**VALIDATION REQUIREMENTS:**
- Must detect ALL installed security products
- Must identify VM/Sandbox environments
- Must enumerate without triggering alerts
- Must find hidden/rootkit processes
- Must work in restricted environments

#### STEALTH OPERATIONS (10 commands)
- [ ] `vmscan` - WITH timing-based detection, hardware inspection, 15+ VM detection methods
- [ ] `hidecmd` - WITH console window manipulation, process ghosting
- [ ] `unhidecmd` - WITH safe visibility restoration
- [ ] `hideprocess` - WITH DKOM techniques, PEB manipulation
- [ ] `unhideprocess` - WITH safe restoration
- [ ] `hidefile` - WITH multiple techniques (ADS, NTFS attributes, reparse points)
- [ ] `unhidefile` - WITH proper restoration
- [ ] `hidereg` - WITH registry key ACL manipulation, timestamp forging
- [ ] `unhidereg` - WITH ACL restoration
- [ ] `clearlogs` - WITH USN journal, event logs, prefetch, SRUM, all artifacts

**VALIDATION REQUIREMENTS:**
- Must use DKOM (Direct Kernel Object Manipulation) concepts
- Must manipulate PEB/TEB structures
- Must handle multiple hiding techniques per object
- Must clean ALL forensic artifacts (20+ locations)
- Must bypass audit logging

#### CREDENTIAL HARVESTING (5 commands)
- [ ] `chromedump` - WITH DPAPI decryption, memory extraction, all Chromium browsers
- [ ] `hashdump` - WITH LSASS memory reading, SAM extraction, NTDS.dit parsing
- [ ] `wifikeys` - WITH WLAN API usage, WPA/WPA2 key extraction
- [ ] `askpass` - WITH convincing UI spoofing, secure desktop bypass
- [ ] `chromepasswords` - WITH process memory extraction, cookie theft

**VALIDATION REQUIREMENTS:**
- Must NOT use external tools (mimikatz, lazagne)
- Must handle DPAPI master key extraction
- Must work on latest browser versions
- Must extract from memory AND disk
- Must handle 2FA backup codes

#### PROCESS MANAGEMENT (4 commands)
- [ ] `ps` - WITH hidden process detection, integrity level display
- [ ] `kill` - WITH multiple termination methods, protected process handling
- [ ] `migrate` - WITH process hollowing, thread hijacking, APC injection
- [ ] `inject` - WITH 5+ injection techniques, DEP/ASLR bypass

**VALIDATION REQUIREMENTS:**
- Must handle protected processes (PPL)
- Must use direct syscalls
- Must bypass EDR hooks
- Must support WOW64 processes
- Must clean up after injection

#### SYSTEM CONTROL (4 commands)
- [ ] `shutdown` - WITH multiple methods, bypass shutdown blockers
- [ ] `restart` - WITH fast restart, update suppression
- [ ] `firewall` - WITH Windows Filtering Platform manipulation
- [ ] `escalate` - WITH 10+ UAC bypass techniques, token theft

**VALIDATION REQUIREMENTS:**
- Must bypass UAC without prompts
- Must handle Windows Defender Firewall
- Must work from restricted tokens
- Must support lateral escalation

#### MONITORING (5 commands)
- [ ] `screenshot` - WITH GPU capture, multi-monitor, secure desktop
- [ ] `screenrec` - WITH hardware encoding, low CPU usage
- [ ] `webcam` - WITH LED bypass attempts, frame injection
- [ ] `keylogger` - WITH raw input API, clipboard monitoring, window tracking
- [ ] `stopkeylogger` - WITH secure cleanup

**VALIDATION REQUIREMENTS:**
- Must capture secure desktop
- Must handle high DPI displays
- Must bypass webcam LED (where possible)
- Must capture passwords in password fields
- Must handle multiple keyboard layouts

#### LOGS (2 commands)
- [ ] `viewlogs` - WITH tamper detection, deleted log recovery
- [ ] `clearlogs` - WITH 20+ artifact locations, timestamp manipulation

**VALIDATION REQUIREMENTS:**
- Must clear Windows Event Logs
- Must clear ETW traces
- Must clear WMI logs
- Must clear PowerShell logs
- Must clear USN Journal
- Must clear Prefetch
- Must clear SRUM database
- Must clear AmCache
- Must clear ShimCache
- Must clear BAM/DAM

#### SHELL & ACCESS (3 commands)
- [ ] `shell` - WITH multiple shell types, AMSI bypass
- [ ] `ssh` - WITH key extraction, session hijacking
- [ ] `sudo` - WITH token manipulation, cached credential abuse

**VALIDATION REQUIREMENTS:**
- Must bypass AMSI/Script Block Logging
- Must support PowerShell/CMD/WSL
- Must handle restricted shells

#### ADVANCED FEATURES (8 commands)
- [ ] `persistence` - WITH 15+ methods, redundancy, self-healing
- [ ] `unpersistence` - WITH complete removal, artifact cleanup
- [ ] `download_exec` - WITH memory execution, process doppelganging
- [ ] `upload_exec` - WITH fileless execution
- [ ] `port_forward` - WITH kernel-level implementation
- [ ] `socks_proxy` - WITH authentication, UDP support
- [ ] `dns` - [DEPRECATED - Should return error]
- [ ] `rootkit` - [DEPRECATED - Should return error]
- [ ] `unrootkit` - [DEPRECATED - Should return error]
- [ ] `avkill` - [DEPRECATED - Should return error]

---

## PAYLOAD LIFECYCLE - ELITE E2E VALIDATION

### 1. PAYLOAD GENERATION
- [ ] Metamorphic engine changes code each generation
- [ ] Polymorphic wrapper unique per build
- [ ] Anti-VM/Sandbox with 15+ detection methods
- [ ] String encryption with unique keys
- [ ] API obfuscation with dynamic resolution
- [ ] Fake certificate signing
- [ ] Resource spoofing

### 2. DELIVERY & DEPLOYMENT  
- [ ] Staged payload loading
- [ ] Environmental keying
- [ ] Time-based activation
- [ ] Geofencing capabilities
- [ ] Supply chain hiding methods

### 3. INITIAL EXECUTION
- [ ] Process hollowing into legitimate process
- [ ] No suspicious process creation
- [ ] No obvious network connections
- [ ] Bypasses behavioral detection
- [ ] Memory-only operation

### 4. C2 ESTABLISHMENT
- [ ] Domain fronting via CDNs
- [ ] DNS over HTTPS tunneling  
- [ ] WebSocket via Chrome DevTools Protocol
- [ ] Backup channels (Slack, Telegram, GitHub)
- [ ] Encrypted with ephemeral keys
- [ ] Traffic looks legitimate
- [ ] Automatic proxy detection

### 5. PERSISTENCE INSTALLATION
- [ ] WMI Event Subscriptions
- [ ] COM hijacking
- [ ] Hidden scheduled tasks
- [ ] Service installation
- [ ] Registry Run keys (obfuscated)
- [ ] AppInit DLLs
- [ ] Shim database manipulation
- [ ] Boot sector modification
- [ ] UEFI implants

### 6. OPERATIONAL SECURITY
- [ ] No process named "malware.exe"
- [ ] No obvious registry keys
- [ ] No suspicious network patterns
- [ ] Blends with normal traffic
- [ ] Survives reboots invisibly
- [ ] Survives AV updates
- [ ] Auto-disables in analysis environments

---

## ANTI-DETECTION VALIDATION

### EDR EVASION
- [ ] ETW patching implemented
- [ ] AMSI bypass working
- [ ] Syscall unhooking
- [ ] Direct syscalls used
- [ ] Callback evasion
- [ ] Stack spoofing
- [ ] Thread start address spoofing

### SPECIFIC EDR PRODUCT HANDLING
- [ ] CrowdStrike Falcon detection
- [ ] SentinelOne behavioral bypass
- [ ] Carbon Black kernel evasion
- [ ] Microsoft Defender ATP bypass
- [ ] Sophos InterceptX evasion

### SANDBOX EVASION
- [ ] 15+ VM detection techniques
- [ ] Timing checks (RDTSC, GetTickCount)
- [ ] Resource checks (CPU cores, RAM, disk)
- [ ] Human interaction detection
- [ ] Long sleep with detection
- [ ] API hammering detection

### FORENSIC ANTI-ANALYSIS
- [ ] Strings encrypted in memory
- [ ] Code self-modifies during execution
- [ ] Anti-debugging (10+ techniques)
- [ ] Anti-dumping protection
- [ ] Import table obfuscation
- [ ] Control flow flattening

---

## NETWORK CAPABILITIES VALIDATION

### STEALTH COMMUNICATIONS
- [ ] Looks like legitimate traffic
- [ ] Uses common ports (80, 443, 53)
- [ ] Mimics real protocols perfectly
- [ ] Handles SSL inspection
- [ ] Works through proxies
- [ ] Supports authentication (NTLM, Kerberos)

### RESILIENCE
- [ ] Automatic reconnection
- [ ] Multiple fallback servers
- [ ] P2P capabilities
- [ ] Mesh networking
- [ ] Dead drop communication
- [ ] Blockchain C2 (advanced)

---

## DATA EXFILTRATION VALIDATION

### COVERT CHANNELS
- [ ] DNS exfiltration (TXT, CNAME, MX)
- [ ] HTTP header smuggling
- [ ] Steganography in images
- [ ] Cloud service abuse
- [ ] Timing channel communication
- [ ] ICMP tunneling

### OPERATIONAL
- [ ] Automatic compression
- [ ] Encryption with unique keys
- [ ] Integrity verification
- [ ] Resume capability
- [ ] Bandwidth throttling
- [ ] Business hours only transfer

---

## SCALE & PERFORMANCE VALIDATION

### ENTERPRISE SCALE
- [ ] Handles 1000+ concurrent agents
- [ ] Database doesn't grow infinitely
- [ ] Memory usage stays stable
- [ ] CPU usage minimal when idle
- [ ] Network traffic optimized

### RESPONSE TIMES
- [ ] Commands execute in <100ms
- [ ] Screenshot in <1 second
- [ ] File transfer at line speed
- [ ] No UI freezing
- [ ] Async operation

---

## PRODUCTION ENVIRONMENT VALIDATION

### WORKS IN HOSTILE ENVIRONMENTS
- [ ] Behind corporate proxies
- [ ] With SSL inspection
- [ ] On non-English Windows
- [ ] With aggressive AV/EDR
- [ ] In isolated networks
- [ ] With limited privileges
- [ ] On slow/unstable connections

### HANDLES EDGE CASES
- [ ] Paths > 260 characters
- [ ] Unicode filenames
- [ ] Reserved names (CON, PRN)
- [ ] Files > 4GB
- [ ] Locked files
- [ ] Network drives
- [ ] Different Windows versions

---

## SCARY CAPABILITIES VALIDATION

### ADVANCED PERSISTENCE
- [ ] Survives OS reinstall
- [ ] Survives AV removal attempts  
- [ ] Self-spreads when possible
- [ ] Hides in legitimate services
- [ ] Uses multiple persistence methods
- [ ] Self-heals if partially removed

### IMPACT POTENTIAL
- [ ] Can disable security products
- [ ] Can modify system files
- [ ] Can intercept all communications
- [ ] Can steal all credentials
- [ ] Can maintain access indefinitely
- [ ] Can pivot to other systems

### STEALTH LEVEL
- [ ] Invisible to Task Manager
- [ ] No network traces
- [ ] No file artifacts
- [ ] No registry entries visible
- [ ] No event logs
- [ ] Memory artifacts encrypted

---

## VALIDATION SCORING

Each capability must be scored:

### SCORING RUBRIC
- **0**: Not implemented
- **1**: Basic implementation (subprocess/simple)
- **2**: Intermediate (some API usage)
- **3**: Advanced (direct APIs, some evasion)
- **4**: Elite (nation-state level)
- **5**: Scary Elite (exceeds expectations)

### MINIMUM ACCEPTABLE SCORES
- Core Commands: 4+ (Elite minimum)
- Stealth Features: 5 (Must be scary)
- Persistence: 5 (Absolutely unremovable)
- Evasion: 5 (Undetectable required)
- Data Exfiltration: 4+ (Covert channels)

### OVERALL REQUIREMENTS
- Average Score: 4.5+ (Elite overall)
- No scores below 3 (No basic implementations)
- Critical features all 5 (Stealth, Evasion, Persistence)

---

## RUTHLESS VALIDATION QUESTIONS

For EVERY feature, ask:

1. **Would this bypass CrowdStrike/SentinelOne?**
2. **Would a forensic analyst find artifacts?**
3. **Does this look suspicious to IT admins?**
4. **Would this work in a Fortune 500 company?**
5. **Is this technique publicly known?**
6. **Would this survive a professional incident response?**
7. **Does this require admin or work from user context?**
8. **Would this work on a fully patched system?**
9. **Is the network traffic distinguishable?**
10. **Would this technique impress a red team?**

If ANY answer is "No" - IT FAILS ELITE VALIDATION

---

## THIS IS THE STANDARD

**We're not building a RAT. We're building something that would make Equation Group say "nice work."**

Every single implementation must be so advanced that:
- Security products can't detect it
- Forensic analysts can't find it
- Network monitors can't see it
- Even experts would be impressed

This is the difference between "malware" and "advanced persistent threat."

VERIFY EVERYTHING. ACCEPT ONLY EXCELLENCE.