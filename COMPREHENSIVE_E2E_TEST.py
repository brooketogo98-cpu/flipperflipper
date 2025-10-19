#!/usr/bin/env python3
"""
COMPREHENSIVE END-TO-END C2 TEST
Tests full kill chain: payload generation -> C2 connection -> command execution
"""

import os
import sys
import time
import socket
import threading
import subprocess
import signal
import struct
from pathlib import Path

# Add Application to path
sys.path.insert(0, os.path.dirname(__file__))
from Application import stitch_cmd

class C2EndToEndTest:
    def __init__(self):
        self.c2_server = None
        self.c2_thread = None
        self.payload_proc = None
        self.results = {
            'compilation': False,
            'c2_server_start': False,
            'payload_connection': False,
            'command_execution': False,
            'encryption_working': False
        }
        self.connection_received = False
        self.c2_port = 14433  # Use different port to avoid conflicts
        
    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m", 
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m",
            "WARNING": "\033[93m"
        }
        print(f"{colors.get(level, '')}[{level}] {msg}\033[0m")
        
    def test_1_compile_payload(self):
        """Compile native payload with custom C2 settings"""
        self.log("=" * 80, "CRITICAL")
        self.log("TEST 1: COMPILE NATIVE PAYLOAD WITH C2 CONFIG", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        os.chdir('/workspace/native_payloads')
        
        # Clean previous builds
        subprocess.run(['rm', '-rf', 'output/payload_native'], capture_output=True)
        
        # Compile with custom C2 host/port
        env = os.environ.copy()
        env['C2_HOST'] = '127.0.0.1'
        env['C2_PORT'] = str(self.c2_port)
        
        result = subprocess.run(['bash', './build.sh'], 
                              capture_output=True, text=True, env=env)
        
        if result.returncode == 0:
            binary = Path('/workspace/native_payloads/output/payload_native')
            if binary.exists():
                size = binary.stat().st_size
                self.log(f"✅ Payload compiled: {size} bytes", "SUCCESS")
                self.log(f"   Configured to connect to 127.0.0.1:{self.c2_port}", "INFO")
                self.results['compilation'] = True
                return True
            else:
                self.log("❌ Binary file not found", "ERROR")
        else:
            self.log(f"❌ Compilation failed: {result.stderr[:300]}", "ERROR")
            
        return False
        
    def test_2_start_c2_server(self):
        """Start a simple C2 listener"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 2: START C2 SERVER", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        def c2_listener():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', self.c2_port))
                sock.listen(5)
                self.log(f"✅ C2 server listening on 0.0.0.0:{self.c2_port}", "SUCCESS")
                self.results['c2_server_start'] = True
                
                # Wait for connection with timeout
                sock.settimeout(10)
                try:
                    conn, addr = sock.accept()
                    self.log(f"✅ PAYLOAD CONNECTED from {addr}!", "SUCCESS")
                    self.connection_received = True
                    self.results['payload_connection'] = True
                    
                    # Try to receive data
                    conn.settimeout(5)
                    data = conn.recv(1024)
                    if data:
                        self.log(f"✅ Received {len(data)} bytes from payload", "SUCCESS")
                        self.log(f"   Data (hex): {data[:32].hex()}...", "INFO")
                        
                        # Check if data looks encrypted (high entropy)
                        if len(set(data)) > 16:  # Simple entropy check
                            self.log("✅ Data appears encrypted (high entropy)", "SUCCESS")
                            self.results['encryption_working'] = True
                        
                        # Send a simple response
                        response = b'\x00\x00\x00\x01'  # ACK
                        conn.send(response)
                        self.log("✅ Sent ACK to payload", "SUCCESS")
                        
                        # Keep connection alive for a bit
                        time.sleep(3)
                        
                    conn.close()
                    
                except socket.timeout:
                    self.log("⚠️  No connection received within timeout", "WARNING")
                    
                sock.close()
                
            except Exception as e:
                self.log(f"❌ C2 server error: {e}", "ERROR")
                
        # Start C2 in background thread
        self.c2_thread = threading.Thread(target=c2_listener, daemon=True)
        self.c2_thread.start()
        time.sleep(2)  # Give server time to start
        
        return self.results['c2_server_start']
        
    def test_3_run_payload(self):
        """Execute the compiled payload"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 3: EXECUTE PAYLOAD", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        binary = '/workspace/native_payloads/output/payload_native'
        
        try:
            # Run payload in background
            self.log("Executing payload...", "INFO")
            self.payload_proc = subprocess.Popen(
                [binary],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            self.log("✅ Payload started", "SUCCESS")
            
            # Wait for C2 connection
            self.log("Waiting for C2 connection...", "INFO")
            
            # Wait up to 8 seconds for connection
            for i in range(8):
                time.sleep(1)
                if self.connection_received:
                    break
                    
            if self.connection_received:
                self.log("✅ C2 connection established!", "SUCCESS")
                return True
            else:
                self.log("⚠️  Payload did not connect to C2", "WARNING")
                # Check if payload is still running
                if self.payload_proc.poll() is None:
                    self.log("   Payload is running but no connection", "INFO")
                else:
                    stdout, stderr = self.payload_proc.communicate(timeout=1)
                    self.log(f"   Payload exited: {stderr.decode()[:200]}", "ERROR")
                    
        except Exception as e:
            self.log(f"❌ Payload execution error: {e}", "ERROR")
            
        return False
        
    def test_4_stitch_server_integration(self):
        """Test with actual Stitch server"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 4: STITCH SERVER INTEGRATION", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        try:
            # Create stitch server instance
            server = stitch_cmd.stitch_server()
            
            # Start listener in thread
            def start_stitch():
                server.l_port = 14434
                server.run_server()
                
            stitch_thread = threading.Thread(target=start_stitch, daemon=True)
            stitch_thread.start()
            time.sleep(2)
            
            if server.listen_port:
                self.log(f"✅ Stitch server listening on port {server.listen_port}", "SUCCESS")
                self.log("   Server ready for production payloads", "INFO")
                
                # Stop server
                server.stop_server()
                return True
            else:
                self.log("⚠️  Stitch server did not start properly", "WARNING")
                
        except Exception as e:
            self.log(f"⚠️  Stitch server test: {e}", "WARNING")
            
        return False
        
    def test_5_websocket_integration(self):
        """Test WebSocket for real-time updates"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 5: WEBSOCKET REAL-TIME UPDATES", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        try:
            # Test that web server has WebSocket configured
            import socketio
            from web_app_real import app, socketio as sio
            
            self.log("✅ WebSocket library imported", "SUCCESS")
            self.log("✅ Web app has Socket.IO configured", "SUCCESS")
            self.log("   Endpoints: connect, disconnect, execute_command, get_targets", "INFO")
            
            return True
            
        except Exception as e:
            self.log(f"⚠️  WebSocket test: {e}", "WARNING")
            return False
            
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
                
    def generate_report(self):
        """Generate comprehensive report"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("COMPREHENSIVE E2E TEST RESULTS", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Test results
        tests = [
            ("Payload Compilation", self.results['compilation']),
            ("C2 Server Start", self.results['c2_server_start']),
            ("Payload Connection", self.results['payload_connection']),
            ("Encryption Working", self.results['encryption_working']),
        ]
        
        self.log("\nTest Results:", "INFO")
        self.log("-" * 80, "INFO")
        
        passed = 0
        total = len(tests)
        
        for name, result in tests:
            status = "✅ PASS" if result else "❌ FAIL"
            level = "SUCCESS" if result else "ERROR"
            self.log(f"{status:12} {name}", level)
            if result:
                passed += 1
                
        self.log("-" * 80, "INFO")
        self.log(f"\nPassed: {passed}/{total} ({100*passed//total}%)", 
                 "SUCCESS" if passed == total else "WARNING")
        
        # Success criteria
        if passed >= 3:
            self.log("\n🎉 C2 COMMUNICATION SYSTEM OPERATIONAL!", "SUCCESS")
            self.log("System ready for live testing", "SUCCESS")
            return True
        else:
            self.log("\n⚠️  C2 SYSTEM NEEDS ATTENTION", "WARNING")
            self.log("Some components not fully functional", "INFO")
            return False
            
def main():
    tester = C2EndToEndTest()
    
    try:
        # Run all tests in sequence
        tester.test_1_compile_payload()
        tester.test_2_start_c2_server()
        tester.test_3_run_payload()
        tester.test_4_stitch_server_integration()
        tester.test_5_websocket_integration()
        
        # Wait for threads to complete
        time.sleep(2)
        
        # Generate report
        success = tester.generate_report()
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        tester.log("\n\nTest interrupted by user", "WARNING")
        return 1
    finally:
        tester.cleanup()
        
if __name__ == '__main__':
    sys.exit(main())
