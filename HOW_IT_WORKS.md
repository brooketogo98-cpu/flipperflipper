# How Stitch Works: Terminal vs Web Interface

## Overview

Stitch is a Remote Administration Tool that lets you control remote computers. It has two ways to use it:
1. **Terminal** - Text-based command line interface
2. **Web Interface** - Graphical dashboard in your browser

**IMPORTANT**: The new web interface (web_app_real.py) is completely real. Nothing is simulated or fake. Every connection you see is a real connection. Every command executes on the actual target machine.

---

## How The Terminal Works

### Starting the Terminal
```bash
python3 main.py
```

### What Happens
1. Stitch starts a server listening on port 4040
2. Remote computers (targets) connect to this port
3. You see a command prompt: `Stitch >`
4. You can type commands to control the targets

### Example Commands
```
Stitch > clients                    # List all connected computers
Stitch > interact 1                # Select computer #1
(192.168.1.100) > sysinfo          # Get system information
(192.168.1.100) > screenshot       # Take a screenshot
(192.168.1.100) > download file.txt # Download a file
```

### How Commands Work
1. You type a command
2. Stitch encrypts it using AES encryption
3. Sends it through the socket connection to the target
4. The target executes the command
5. Sends the result back (also encrypted)
6. You see the real result in your terminal

**Everything is REAL** - no simulation!

---

## How The Web Interface Works

### Starting the Web Interface
```bash
python3 web_app_real.py
```

### What Happens
1. Stitch starts TWO servers in one process:
   - **Port 4040**: Target connection server (same as terminal)
   - **Port 5000**: Web dashboard for you to access
2. Remote computers connect to port 4040
3. You open a browser to port 5000 and see the dashboard

### Using the Dashboard

**Step 1: Login**
- Open browser to: http://localhost:5000
- Username: `admin`
- Password: `stitch2024`

**Step 2: View Connections**
- Click "Connections" tab
- See all connected computers
- **GREEN** cards = Online and connected right now
- **GRAY** cards = Offline (not currently connected)

**Step 3: Select a Connection**
- Click on any GREEN (online) connection card
- The card highlights in blue
- You've now selected this computer

**Step 4: Execute Commands**
- Click "Commands" tab
- Choose a command from the list OR type a custom command
- Click "Execute"
- See the REAL result from the target computer

### How Web Commands Work
1. You click "Execute" on the web dashboard
2. JavaScript sends the command to the Flask server
3. Flask calls the exact same Stitch code that the terminal uses
4. The command is encrypted and sent to the target through the socket
5. The target executes it and sends back the real result
6. The result appears in your browser

**Everything is REAL** - same as terminal!

---

## Key Differences

| Feature | Terminal | Web Interface |
|---------|----------|---------------|
| **Interface** | Text-based | Graphical dashboard |
| **Commands** | Type commands | Click buttons or type |
| **Connections** | List as text | Visual cards (green/gray) |
| **Real-time Updates** | Manual refresh | Auto-updates every 5 seconds |
| **Multiple Tabs** | No | Yes (Connections, Commands, Files, Logs) |
| **File Downloads** | Download to server | Download through browser |
| **Learning Curve** | Higher | Lower |
| **Best For** | Advanced users | Visual management |

---

## What Makes It "Real" (Not Simulated)

### The OLD Web Interface Problem
The original web_app.py had these issues:
- ❌ Commands didn't actually execute - just showed fake results
- ❌ Connections were simulated - not real targets
- ❌ Everything was for demonstration only
- ❌ Completely separate from the actual Stitch server

### The NEW Web Interface Solution (web_app_real.py)
- ✅ Runs a REAL Stitch server on port 4040
- ✅ Accepts REAL connections from targets
- ✅ Executes commands using the REAL stitch_lib functions
- ✅ Shows REAL results from targets
- ✅ Online/offline status reflects ACTUAL socket connections
- ✅ File downloads are REAL files from targets
- ✅ All 70+ commands work exactly like the terminal

---

## Technical Architecture

### How They Share Code

Both interfaces use the same core Stitch code:

```
Application/
├── stitch_cmd.py       # Server and command handling
├── stitch_lib.py       # Command execution
├── stitch_winshell.py  # Windows commands
├── stitch_lnxshell.py  # Linux commands
└── stitch_osxshell.py  # macOS commands
```

**Terminal Path:**
```
main.py 
  → stitch_cmd.py (creates server)
  → User types command
  → stitch_lib.py (executes on target)
  → Result displayed in terminal
```

**Web Interface Path:**
```
web_app_real.py
  → stitch_cmd.py (creates server in background thread)
  → User clicks "Execute" in browser
  → Flask route handler
  → stitch_lib.py (executes on target)
  → Result sent back to browser as JSON
  → JavaScript displays it
```

### Single Process Design

The web interface runs everything in ONE process:

```
Process: web_app_real.py
├── Thread 1: Flask web server (port 5000)
├── Thread 2: Stitch server (port 4040)
├── Thread 3: Connection monitor (checks status every 5s)
└── Shared: Single stitch_server instance
```

All threads share the same `stitch_server` object, so they all see the same connections!

---

## Connection Tracking

### How Stitch Knows Who's Connected

Inside `stitch_cmd.py`, there are two important dictionaries:

```python
inf_sock = {}   # Active socket connections
inf_port = {}   # Port numbers for each connection
```

**When a target connects:**
```python
# New connection from 192.168.1.100
inf_sock[1] = <socket object>
inf_port[1] = 50123
```

**When a target disconnects:**
```python
# Connection lost
del inf_sock[1]
del inf_port[1]
```

**How the web interface checks status:**
```python
server = get_stitch_server()
if connection_id in server.inf_sock:
    status = "ONLINE"  # Socket exists
else:
    status = "OFFLINE" # Socket gone
```

This is why the web interface shows REAL status - it's checking the actual socket dictionary!

---

## Command Execution Flow

### Terminal Example: `screenshot`

1. **User types:** `(192.168.1.100) > screenshot`
2. **Terminal calls:** `stitch_cmd.py` → `do_screenshot()`
3. **do_screenshot calls:** `stitch_lib.py` → `screenshot_target()`
4. **stitch_lib sends:** Encrypted command through socket
5. **Target receives:** Command, executes it, takes screenshot
6. **Target sends back:** Screenshot data (encrypted)
7. **stitch_lib receives:** Screenshot data, saves to file
8. **User sees:** "Screenshot saved to: screenshots/target_123.png"

### Web Example: `screenshot`

1. **User clicks:** "Screenshot" button on web dashboard
2. **JavaScript sends:** POST request to `/api/command/execute`
3. **Flask handler calls:** `stitch_cmd.py` → `do_screenshot()`
4. **do_screenshot calls:** `stitch_lib.py` → `screenshot_target()`
5. **stitch_lib sends:** Encrypted command through socket
6. **Target receives:** Command, executes it, takes screenshot
7. **Target sends back:** Screenshot data (encrypted)
8. **stitch_lib receives:** Screenshot data, saves to file
9. **Flask returns:** JSON response `{"status": "success", "file": "screenshots/target_123.png"}`
10. **JavaScript displays:** Success message and download link

**THE EXACT SAME STITCH CODE RUNS!** Steps 3-8 are identical.

---

## Real-Time Updates

### How the Dashboard Stays Current

The web interface uses **WebSocket** for real-time updates:

```javascript
// Browser connects to server via WebSocket
socket.connect();

// Server sends updates every 5 seconds
@socketio.on('connection_update')
def handle_update(data):
    // Updates dashboard with current connection count
    
// Browser receives and displays
socket.on('connection_update', function(data) {
    updateDashboard(data);
});
```

This means you see new connections appear automatically without refreshing!

---

## Security

Both terminal and web use the same security:

1. **AES Encryption**: All communication with targets is encrypted
2. **Socket Security**: Only authenticated connections allowed
3. **Web Authentication**: Login required (admin/stitch2024)
4. **Session Management**: Web interface uses Flask sessions
5. **CSRF Protection**: Prevents cross-site attacks

---

## File Management

### Downloading Files from Targets

**Terminal:**
```
(target) > download secret.txt
[+] File downloaded to: downloads/secret.txt
```

**Web Interface:**
1. Execute download command
2. File saved to server: `downloads/secret.txt`
3. Click "Files" tab
4. Click file to download to your computer

Both save files to the same location on the server!

---

## Summary

**For Regular Users:**
- Use the web interface - it's easier and prettier
- Everything you see is real
- Click connections, click commands, see results
- No need to learn command syntax

**For Advanced Users:**
- Use the terminal for faster command execution
- Better for scripting and automation
- Full shell access to targets
- More control over interactions

**For Developers:**
- The web interface is NOT a separate system
- It uses the exact same Stitch server code
- Commands execute through the same functions
- Only the interface layer is different (HTML/JS vs CLI)

**Most Important:**
- The new `web_app_real.py` is completely real
- No simulations, no fake data, no mock responses
- Every connection, command, and result is authentic
- It works exactly like the terminal, just with a prettier face!
