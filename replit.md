# Stitch - Cross Platform Python Remote Administration Tool

## Overview
This is a Python-based Remote Administration Tool (RAT) for educational and research purposes. The tool has been migrated from Python 2.7 to Python 3.11 to work in the Replit environment.

**IMPORTANT**: Stitch is for education/research purposes only. Use only on systems you own or have explicit permission to test.

## Project Status
- **Language**: Python 3.11 (migrated from Python 2.7)
- **Type**: Web-based interface + CLI/Terminal backend
- **Purpose**: Security research and penetration testing education
- **Ports**: 
  - Web Interface: 5000 (HTTPS via Replit)
  - RAT Server: 4040 (incoming connections)

## Recent Changes
- **October 17, 2025**: 
  - Migrated codebase from Python 2.7 to Python 3.11
  - Updated all imports to use relative imports
  - Fixed print statements and exception handling for Python 3 compatibility
  - Updated dependencies to Python 3 compatible versions
  - **Created comprehensive web interface** with Flask and SocketIO
  - Added real-time debugging and logging dashboard
  - Built command execution interface with categorized commands
  - Implemented payload generation UI
  - Added file management and download interface
  - Integrated authentication system (default: admin/stitch2024)
  - Added help/documentation section with usage guides
  - Configured dual workflow (web + RAT server)
  - Added comprehensive .gitignore for Python projects

## Architecture

### Project Structure
```
.
├── web_app.py           # Flask web interface (NEW!)
├── main.py              # CLI entry point
├── templates/           # Web interface templates (NEW!)
│   ├── login.html
│   └── dashboard.html
├── static/              # Web assets (NEW!)
│   ├── css/style.css
│   └── js/app.js
├── Application/         # Core application code
│   ├── Stitch_Vars/    # Configuration and globals
│   ├── stitch_cmd.py   # Main command interface
│   ├── stitch_gen.py   # Payload generation
│   ├── stitch_lib.py   # Library functions
│   └── stitch_utils.py # Utility functions
├── PyLib/              # Python library scripts
├── Configuration/      # Configuration files
├── Tools/              # Additional tools
├── Icons/              # Application icons
├── Elevation/          # Elevation tools
├── Cleaner/            # Cleanup utilities
├── Payloads/           # Generated payloads (not in repo)
├── Uploads/            # File uploads (not in repo)
├── Downloads/          # File downloads (not in repo)
└── Logs/               # Application logs (not in repo)
```

### Key Features
- Cross-platform support (Windows, macOS, Linux)
- AES encrypted communication
- Payload generation with installers
- Keylogger functionality
- File upload/download
- System information gathering
- Antivirus detection
- Virtual machine detection

## Dependencies
The project uses the following Python packages:
- `colorama`: Terminal colors
- `pycryptodome`: AES encryption (replaces deprecated pycrypto)
- `requests`: HTTP requests
- `Pillow`: Image processing
- `PyInstaller`: Creating executables
- `pexpect`: Pseudo-terminal automation
- `python-dateutil`: Date utilities
- `python-xlib`: X11 protocol (Linux)
- `pyudev`: Device enumeration (Linux)

## Running the Application

### Web Interface (Recommended)
The web interface runs automatically via the configured workflow. Access it through the Replit webview.

**Features:**
- 🔐 Secure authentication (default: admin/stitch2024)
- 🔌 Real-time connection monitoring
- ⚡ Command execution with categorized commands
- 📦 Payload generation for Windows/macOS/Linux
- 📁 File download management
- 📋 Real-time debug logs
- ❓ Built-in help and documentation

**Default Login:**
- Username: `admin`
- Password: `stitch2024`
- ⚠️ **IMPORTANT**: Change these credentials in production!

### CLI Mode (Alternative)
To run in terminal mode only:
```bash
python3 main.py
```

The application will:
1. Display the Stitch banner
2. Start listening on port 4040
3. Present a command prompt: `[Stitch] /path>`

## Configuration
- **No manual configuration required** - Everything is auto-generated!
- Configuration files created on first run in `Application/Stitch_Vars/`
- AES encryption keys generated automatically
- Connection history stored in `history.ini`
- Web credentials stored in-memory (change in `web_app.py` for persistence)

## Python 2 to 3 Migration Notes
Major changes made during migration:
1. Changed `import ConfigParser` → `import configparser as ConfigParser`
2. Changed `import cStringIO` → `from io import BytesIO, StringIO`
3. Changed all `print "text"` → `print("text")`
4. Changed `except Exception, e:` → `except Exception as e:`
5. Fixed all relative imports within Application package
6. Updated base64 encoding/decoding for bytes handling
7. **Critical**: Implemented bytes/str protocol for encryption layer:
   - `encrypt()` returns bytes (for socket operations)
   - `decrypt()` returns bytes (preserves binary data)
   - `st_eof` and `st_complete` are byte sentinels
   - `st_receive()` has optional `as_string` parameter for text conversion
   - `receive()` defaults to `as_string=True` for backward compatibility
   - Binary downloads use `receive(as_string=False)` to preserve data integrity
   - Helper functions like `no_error()` handle both bytes and strings

## Security & Ethics
- This tool is for **educational purposes only**
- Only use on systems you own or have explicit written permission to test
- The authors take no responsibility for misuse
- Check local laws regarding penetration testing tools

## Original Documentation
See README.md for the original project documentation and feature list.
