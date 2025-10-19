# PHASE 3: ADVANCED PERSISTENCE & EVASION
## Master Engineering Plan

**Prerequisites:** Fix Phase 1/2 critical issues (C2 communication, polymorphism)

---

## PHASE 3 OBJECTIVES

Transform the RAT from a basic tool into an advanced, persistent threat that:
1. Survives system reboots and updates
2. Evades modern EDR/AV solutions  
3. Performs lateral movement
4. Exfiltrates data covertly
5. Operates with minimal detection footprint

---

## MODULE 1: ADVANCED PERSISTENCE (Week 1)

### 1.1 Kernel-Level Persistence

#### Linux Rootkit Module
```c
// /workspace/native_payloads/rootkit/linux_rootkit.c
- Loadable Kernel Module (LKM)
- Hide process from /proc
- Hide network connections
- Hide files/directories
- Kernel hook installation
- Direct kernel object manipulation (DKOM)
```

**Implementation Tasks:**
- [ ] Create LKM framework
- [ ] Implement syscall hooking (sys_call_table manipulation)
- [ ] Process hiding via task_struct unlinking
- [ ] Network hiding via netfilter hooks
- [ ] File hiding via getdents/getdents64 hooks
- [ ] Privilege escalation via commit_creds/prepare_kernel_cred

#### Windows Driver
```c
// /workspace/native_payloads/rootkit/windows_driver.c
- Kernel driver (.sys)
- SSDT hooking
- IRP hooking for file/registry hiding
- Process/thread callbacks
- Object callbacks for protection
```

### 1.2 Bootkit/UEFI Persistence

#### UEFI Bootkit
```c
// /workspace/native_payloads/bootkit/uefi_implant.c
- UEFI DXE driver
- SPI flash modification
- Secure Boot bypass
- Early boot code injection
- Recovery partition infection
```

**Implementation:**
- [ ] UEFI development environment setup
- [ ] DXE driver template
- [ ] SPI flash reading/writing
- [ ] Boot sequence hooking
- [ ] Persistence across OS reinstalls

### 1.3 Application-Level Advanced Persistence

#### Windows Techniques
- [ ] WMI Event Subscriptions
- [ ] COM Hijacking
- [ ] DLL Side-Loading
- [ ] AppInit_DLLs
- [ ] Print Monitors
- [ ] Security Support Providers
- [ ] Scheduled Task XML manipulation
- [ ] Service creation with failure recovery

#### Linux Techniques
- [ ] systemd generators
- [ ] PAM modules
- [ ] LD_PRELOAD persistence
- [ ] bashrc/profile poisoning
- [ ] udev rules
- [ ] NetworkManager scripts
- [ ] Package manager hooks

---

## MODULE 2: ADVANCED EVASION (Week 2)

### 2.1 Process Ghosting & Doppelganging

```c
// /workspace/native_payloads/evasion/process_ghost.c
- NtCreateProcessEx manipulation
- Transaction APIs (TxF)
- Delete pending state exploitation
- Image mapping from deleted files
```

**Implementation:**
- [ ] Process ghosting PoC
- [ ] Process doppelganging
- [ ] Process herpaderping
- [ ] Phantom DLL hollowing

### 2.2 EDR Bypass Techniques

#### Sensor Blinding
```c
// /workspace/native_payloads/evasion/edr_bypass.c
- ETW provider disabling
- WMI provider corruption
- Minifilter unloading
- Callback removal
- Handle stripping
```

#### Advanced Unhooking
- [ ] Direct syscalls via Hell's Gate
- [ ] Indirect syscalls
- [ ] SSN sorting
- [ ] Syscall trampolines
- [ ] Heaven's Gate (WoW64)

### 2.3 Memory-Only Operation

```c
// /workspace/native_payloads/evasion/fileless.c
- Reflective DLL injection
- PE from memory execution
- .NET assembly from memory
- PowerShell AMSI bypass
- Living off the land
```

### 2.4 Anti-Forensics

- [ ] Timestamp manipulation
- [ ] USN journal cleaning
- [ ] Event log manipulation
- [ ] Prefetch cleaning
- [ ] Registry transaction logs
- [ ] Memory artifact removal

---

## MODULE 3: LATERAL MOVEMENT (Week 3)

### 3.1 Network Propagation

```c
// /workspace/native_payloads/lateral/spreader.c
- SMB exploitation (EternalBlue-style)
- WMI lateral movement
- PowerShell remoting
- RDP session hijacking
- SSH key harvesting
```

**Techniques:**
- [ ] Pass-the-hash implementation
- [ ] Pass-the-ticket (Kerberos)
- [ ] Over-pass-the-hash
- [ ] Token impersonation
- [ ] Named pipe impersonation

### 3.2 Credential Harvesting

```c
// /workspace/native_payloads/lateral/credentials.c
- LSASS memory dumping (custom)
- SAM database extraction
- Browser credential theft
- Keylogger with ML-based filtering
- Clipboard monitoring
```

### 3.3 Network Discovery

- [ ] Active Directory enumeration
- [ ] Network share discovery
- [ ] Service enumeration
- [ ] LDAP queries
- [ ] DNS reconnaissance

---

## MODULE 4: DATA EXFILTRATION (Week 4)

### 4.1 Covert Channels

```c
// /workspace/native_payloads/exfil/covert_channel.c
- DNS tunneling (requests/responses)
- ICMP tunneling
- HTTPS via domain fronting
- Steganography in images
- Social media dead drops
```

**Implementation:**
- [ ] DNS tunnel client/server
- [ ] Custom protocol over HTTPS
- [ ] Tor integration
- [ ] Cloud storage abuse (OneDrive, Google Drive)
- [ ] Blockchain C2

### 4.2 Data Collection

```c
// /workspace/native_payloads/exfil/collector.c
- File pattern matching
- Database extraction
- Email harvesting
- Document parsing
- Screenshot capture
- Audio recording
- Webcam capture
```

### 4.3 Data Compression & Encryption

- [ ] Custom compression algorithm
- [ ] Chunked encryption
- [ ] Deniable encryption
- [ ] Stealth archive formats

---

## MODULE 5: ENHANCED C2 (Week 5)

### 5.1 P2P Command & Control

```c
// /workspace/native_payloads/c2/p2p_mesh.c
- Peer discovery
- Mesh network formation
- Message routing
- Consensus protocols
- Fallback mechanisms
```

### 5.2 Multi-Protocol C2

- [ ] HTTP/HTTPS with jitter
- [ ] DNS (various record types)
- [ ] SMTP/IMAP
- [ ] WebSocket
- [ ] Custom TCP/UDP protocols

### 5.3 C2 Resilience

- [ ] Domain generation algorithms (DGA)
- [ ] Fast flux DNS
- [ ] Tor hidden services
- [ ] Blockchain-based C2
- [ ] Dead drop locations

---

## MODULE 6: POST-EXPLOITATION FRAMEWORK (Week 6)

### 6.1 Modular Payload System

```c
// /workspace/native_payloads/modules/loader.c
- Dynamic module loading
- In-memory module execution
- Module encryption/compression
- Version management
- Dependency resolution
```

### 6.2 Standard Modules

**Reconnaissance:**
- [ ] Network scanner
- [ ] Port scanner
- [ ] Vulnerability scanner
- [ ] Wi-Fi scanner

**Exploitation:**
- [ ] Exploit suggester
- [ ] Privilege escalation
- [ ] Kernel exploit integration

**Collection:**
- [ ] Keylogger Pro
- [ ] Screen recorder
- [ ] Microphone recorder
- [ ] Webcam capture
- [ ] Geolocation

**Impact:**
- [ ] Ransomware module
- [ ] Wiper module
- [ ] Logic bomb
- [ ] Resource exhaustion

---

## TESTING REQUIREMENTS

### 6.1 Test Lab Setup
```yaml
Environment:
  - Windows 10/11 with Defender
  - Ubuntu 22.04 with AppArmor
  - EDR solutions (CrowdStrike, SentinelOne)
  - Network monitoring (Wireshark, Zeek)
  - Sandbox environments
```

### 6.2 Test Scenarios
1. **Persistence Testing:**
   - Reboot survival
   - Update survival
   - AV scan survival
   - User deletion survival

2. **Evasion Testing:**
   - EDR detection rates
   - Sandbox detection
   - Memory forensics
   - Network traffic analysis

3. **Lateral Movement:**
   - Domain environment
   - Credential scenarios
   - Network segmentation

4. **Exfiltration:**
   - DLP bypass
   - Bandwidth limits
   - Protocol detection

---

## IMPLEMENTATION TIMELINE

### Week 1: Kernel & Boot Persistence
- Days 1-2: Linux LKM rootkit
- Days 3-4: Windows kernel driver
- Day 5: UEFI bootkit research
- Days 6-7: Testing & integration

### Week 2: Advanced Evasion
- Days 1-2: Process ghosting/doppelganging
- Days 3-4: EDR bypass techniques
- Day 5: Anti-forensics
- Days 6-7: Integration & testing

### Week 3: Lateral Movement
- Days 1-2: Network propagation
- Days 3-4: Credential harvesting
- Day 5: AD enumeration
- Days 6-7: Testing in domain

### Week 4: Data Exfiltration
- Days 1-2: Covert channels
- Days 3-4: Data collection
- Day 5: Encryption/compression
- Days 6-7: Bandwidth testing

### Week 5: Enhanced C2
- Days 1-3: P2P implementation
- Days 4-5: Multi-protocol support
- Days 6-7: Resilience testing

### Week 6: Integration & Polish
- Days 1-2: Module system
- Days 3-4: Standard modules
- Days 5-6: Full testing
- Day 7: Documentation

---

## SUCCESS CRITERIA

### Technical Metrics
- [ ] 0% detection by top 10 AV engines
- [ ] < 5% detection by EDR solutions
- [ ] Survives 30 days undetected
- [ ] Successfully exfiltrates 1GB+
- [ ] Lateral movement to 5+ systems
- [ ] Maintains persistence through 10 reboots

### Operational Metrics
- [ ] < 1MB memory footprint
- [ ] < 1% CPU usage
- [ ] Network traffic indistinguishable
- [ ] No crashes in 72h operation
- [ ] Module hot-swapping works
- [ ] C2 channel switching seamless

---

## ETHICAL CONSIDERATIONS

⚠️ **CRITICAL WARNING** ⚠️

This plan describes ILLEGAL techniques if used without authorization:
- Only test in isolated lab environments
- Never deploy on systems you don't own
- Follow responsible disclosure
- Document everything for defense
- Share knowledge for protection

**Legal Use Cases:**
- Penetration testing (with written authorization)
- Security research (controlled environment)
- Defensive capability development
- Training and education

---

## RESOURCES REQUIRED

### Development Tools
- IDA Pro / Ghidra
- WinDbg / GDB
- Visual Studio + WDK
- UEFI development kit
- Kernel debugging setup

### Testing Infrastructure
- Isolated network segment
- Multiple VMs (various OS)
- EDR/AV test licenses
- Network monitoring tools
- Forensics tools

### Knowledge Requirements
- Kernel programming
- UEFI/BIOS
- Assembly (x64/x86)
- Cryptography
- Network protocols
- Windows internals
- Linux internals

---

## RISK ASSESSMENT

### High Risk Components
1. **Kernel modules** - System crashes
2. **UEFI modifications** - Brick systems
3. **EDR bypass** - Detection/blocking
4. **Network propagation** - Uncontrolled spread

### Mitigation Strategies
- Extensive testing in VMs
- Killswitch implementation
- Rate limiting
- Targeting restrictions
- Rollback capabilities

---

## NEXT STEPS

1. **Fix Phase 1/2 Issues First**
   - C2 communication must work
   - Polymorphism must function
   - Basic features stable

2. **Set Up Test Lab**
   - Isolated network
   - Various OS targets
   - Monitoring tools

3. **Begin with Module 1**
   - Start with application persistence
   - Progress to kernel level
   - Test each component thoroughly

4. **Iterate and Improve**
   - Based on detection rates
   - Performance metrics
   - Operational requirements

---

*This plan represents 6-8 weeks of intensive development for a skilled team. Each module builds on previous work and requires deep technical expertise.*