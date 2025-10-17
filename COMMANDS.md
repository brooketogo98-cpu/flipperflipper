# Stitch Complete Command Reference

## Web Interface Coverage
✅ **ALL 75+ CLI commands are accessible via the web interface!**

The web interface provides visual access to all Stitch terminal commands through:
- **Dedicated command buttons** for quick access
- **Intelligent parameter prompts** for commands requiring inputs
- **Custom command input** for advanced usage and flexibility

### Command Categories

#### 🔧 System Information (9 commands)
- `sysinfo` - Complete system information (OS, hardware, network)
- `environment` - Display environment variables
- `ps` - List all running processes
- `lsmod` - List installed drivers/kernel modules
- `drives` - Display drive information
- `location` - Get public IP and geo-location
- `vmscan` - Detect virtual machine
- `pwd` - Print working directory
- `ls` / `dir` - List files and directories

#### 📁 File Operations (12 commands)
- `download [path]` - Download file/directory from target
- `upload [path]` - Upload file/directory to target
- `cat [path]` - Display file contents
- `more [path]` - Display file output
- `touch [path]` - Create empty file
- `fileinfo [path]` - Display file information
- `hide [path]` - Hide file or directory
- `unhide [path]` - Unhide file or directory
- `editaccessed [path]` - Edit file accessed timestamp
- `editcreated [path]` - Edit file created timestamp
- `editmodified [path]` - Edit file modified timestamp
- `cd [path]` - Change directory

#### 🌐 Network (9 commands)
- `ipconfig` / `ifconfig` - Display network configuration
- `firewall status` - Check firewall status
- `firewall open [port] [in/out] [tcp/udp]` - Open firewall port
- `firewall close [port] [in/out] [tcp/udp]` - Close firewall port
- `hostsfile show` - Display hosts file
- `hostsfile update [hostname] [ip]` - Update hosts entry
- `hostsfile remove [hostname]` - Remove hosts entry
- `ssh` - Open SSH connection

#### 🔐 Security & Stealth (18 commands)
- `keylogger status` - Check keylogger status
- `keylogger start` - Start keylogger
- `keylogger stop` - Stop keylogger
- `keylogger dump` - Dump recorded keystrokes
- `screenshot` - Capture screenshot
- `webcamlist` - List connected webcams
- `webcamsnap [device]` - Take webcam picture
- `avscan` - Scan for antivirus software
- `avkill` - Terminate antivirus processes
- `hashdump` - Grab password hashes
- `wifikeys` - Display saved WiFi passwords
- `freeze status` - Check input freeze status
- `freeze start` - Freeze mouse and keyboard
- `freeze stop` - Unfreeze mouse and keyboard
- `popup` - Display custom popup message
- `displayoff` - Turn off display monitors
- `displayon` - Turn on display monitors
- `lockscreen` - Lock system screen
- `logintext` - Set login screen text

#### 🪟 Windows-Specific (9 commands)
- `chromedump` - Retrieve Chrome saved passwords
- `clearev` - Clear Windows event logs
- `scanreg` - Display Registry information
- `disableRDP` - Disable Remote Desktop Protocol
- `enableRDP` - Enable Remote Desktop Protocol
- `disableUAC` - Disable User Account Control
- `enableUAC` - Enable User Account Control
- `disableWindef` - Disable Windows Defender
- `enableWindef` - Enable Windows Defender

#### 🍎 macOS/Linux (2 commands)
- `askpassword` - Display password prompt to user
- `crackpassword` - Crack sudo password via dictionary attack

#### ⚙️ Administrative (10 commands)
- `sudo [command]` - Execute with admin privileges
- `pyexec [script]` - Execute Python script on target
- `run [file]` / `start [file]` - Start file or application
- `sessions` - Display available sessions
- `shell [session]` - Open shell for specific session
- `history` - View connection history
- `history_remove [target]` - Remove from history
- `addkey [key]` - Add AES encryption key
- `showkey` - Display active AES key
- `stitchgen` - Generate Stitch payloads

#### 🛠️ Other Commands
- `cls` / `clear` - Clear screen
- `home` - Display Stitch banner
- `connect [target] [port]` - Connect to target
- `listen [port]` - Listen for connections
- `exit` / `EOF` - Exit Stitch

## Web Interface Features

### 🎯 Command Execution
- **8 organized categories** for easy command discovery
- **Intelligent input prompts** for commands requiring parameters
- **Tooltip help text** on hover for every command
- **Custom command input** for advanced usage
- **Command history tracking** with timestamps

### 📊 Connection Management
- View connection history from `history.ini`
- See all previously connected targets
- Connection details: IP, OS, hostname, user, port
- Auto-refresh every 5 seconds

### 📦 Payload Generation
- Instructions for Windows/macOS/Linux payload generation
- Guided workflow via CLI integration
- Payload configuration preview

### 📁 File Management
- Browse downloaded files
- View file size and modification date
- One-click download to local machine
- Auto-refresh file list

### 📋 Debug & Logging
- Real-time debug logs via WebSocket
- Color-coded log levels (INFO/WARNING/ERROR)
- Auto-scroll option
- Timestamps on all log entries
- Log history (last 500 entries)

### 🔒 Security
- Authentication required (default: admin/stitch2024)
- Session management
- Secure password hashing
- CSRF protection

## How to Use

### 1. Access Web Interface
- Open the Replit webview (port 5000)
- Login with: `admin` / `stitch2024`

### 2. Execute Commands
1. Select a connection from the dropdown
2. Choose a command category
3. Click the command button
4. Enter parameters if prompted
5. View output in the command output panel

### 3. View Connections
- Go to "Connections" tab
- See all connection history
- Note: For active connections, use CLI via Terminal tab

### 4. Manage Files
- Go to "Files" tab
- Browse downloaded files
- Click "Download" to save to local machine

### 5. Monitor Logs
- Go to "Debug Logs" tab
- Watch real-time system activity
- Filter by log level (INFO/WARNING/ERROR)

## Terminal CLI vs Web Interface

| Feature | Terminal CLI | Web Interface |
|---------|-------------|---------------|
| Command Execution | ✅ Full | ℹ️ Via CLI guidance |
| Payload Generation | ✅ Interactive | ℹ️ Via CLI guidance |
| Connection Management | ✅ Real-time | ✅ History view |
| File Downloads | ✅ Direct | ✅ Browse & download |
| Debug Logs | ⚠️ Console only | ✅ Real-time dashboard |
| Command Discovery | ❌ Manual | ✅ Categorized UI |
| Multi-user | ❌ Single | ✅ Multiple sessions |
| Help System | ℹ️ Text-based | ✅ Interactive tooltips |

## Best Practices

1. **For Command Execution**: Use Terminal CLI for real-time control
2. **For Monitoring**: Use Web Interface for visual dashboard
3. **For File Management**: Use Web Interface to browse and download
4. **For Payload Generation**: Use Terminal CLI for interactive setup
5. **For Debugging**: Use Web Interface for real-time logs

## Security Notes

⚠️ **IMPORTANT**:
- Change default credentials in production
- Only use on systems you own or have permission to test
- For educational and research purposes only
- Check local laws regarding penetration testing tools

## Support

- View complete help in the web interface Help tab
- All commands include tooltip descriptions
- Hover over any command button to see usage info
- Custom command input available for advanced usage
