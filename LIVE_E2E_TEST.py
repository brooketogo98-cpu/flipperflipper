#!/usr/bin/env python3
"""
Live End-to-End Test
Tests the complete RAT system from web interface to payload execution
"""

import os
import sys
import time
import json
import socket
import threading
import subprocess
import requests
import tempfile
from pathlib import Path

class LiveE2ETest:
    def __init__(self):
        self.server_proc = None
        self.payload_proc = None
        self.server_url = 'http://localhost:19876'
        self.results = []
        
    def log(self, msg, status="INFO"):
        colors = {
            "PASS": "\033[92m",
            "FAIL": "\033[91m",
            "INFO": "\033[94m",
            "WARN": "\033[93m",
            "TEST": "\033[95m"
        }
        print(f"{colors.get(status, '')}[{status}] {msg}\033[0m")
        self.results.append({"status": status, "message": msg})
        
    def test(self, name, func):
        """Run a test and log results"""
        try:
            result = func()
            if result:
                self.log(f"✓ {name}", "PASS")
                return True
            else:
                self.log(f"✗ {name}", "FAIL")
                return False
        except Exception as e:
            self.log(f"✗ {name}: {str(e)}", "FAIL")
            return False
            
    def start_web_server(self):
        """Start the web server"""
        self.log("Starting web server...", "TEST")
        
        env = os.environ.copy()
        env['STITCH_DEBUG'] = 'true'
        env['STITCH_ADMIN_USER'] = 'admin'
        env['STITCH_ADMIN_PASSWORD'] = 'SecureTestPassword123!'
        
        self.server_proc = subprocess.Popen(
            [sys.executable, 'web_app_real.py'],
            cwd='/workspace',
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start
        time.sleep(5)
        
        # Check if server is running
        try:
            response = requests.get(f"{self.server_url}/", timeout=5)
            return response.status_code in [200, 302]
        except:
            return False
            
    def test_api_endpoints(self):
        """Test API endpoints"""
        self.log("Testing API endpoints...", "TEST")
        
        session = requests.Session()
        
        # Test login
        login_data = {
            'username': 'admin',
            'password': 'SecureTestPassword123!'
        }
        response = session.post(f"{self.server_url}/login", data=login_data)
        if response.status_code not in [200, 302]:
            return False
            
        # Test payload generation API (debug endpoint)
        payload_data = {
            'platform': 'linux',
            'c2_host': 'localhost',
            'c2_port': 4433
        }
        response = session.post(f"{self.server_url}/api/test-native-payload", json=payload_data)
        if response.status_code != 200:
            return False
            
        result = response.json()
        return result.get('success', False)
        
    def compile_payload(self):
        """Compile native payload"""
        self.log("Compiling native payload...", "TEST")
        
        result = subprocess.run(
            ['bash', 'build.sh'],
            cwd='/workspace/native_payloads',
            capture_output=True,
            text=True
        )
        
        # Check if binary exists
        payload_path = Path('/workspace/native_payloads/output/payload_native')
        return payload_path.exists() and payload_path.stat().st_size > 0
        
    def test_c2_communication(self):
        """Test C2 communication"""
        self.log("Testing C2 communication (simulated)...", "TEST")
        
        # Create a mock C2 server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind(('127.0.0.1', 4433))
            server_sock.listen(1)
            server_sock.settimeout(5)
            
            # Start payload in background
            payload_thread = threading.Thread(target=self.run_payload)
            payload_thread.daemon = True
            payload_thread.start()
            
            # Accept connection
            try:
                conn, addr = server_sock.accept()
                self.log(f"Payload connected from {addr}", "PASS")
                
                # Send a test command (ping)
                test_cmd = b'\x00\x00\x00\x01'  # Simple ping command
                conn.send(test_cmd)
                
                # Receive response
                data = conn.recv(1024)
                if data:
                    self.log("Received response from payload", "PASS")
                    return True
                    
            except socket.timeout:
                self.log("Payload connection timeout", "FAIL")
                return False
                
        except Exception as e:
            self.log(f"C2 test error: {e}", "FAIL")
            return False
        finally:
            server_sock.close()
            
    def run_payload(self):
        """Run the payload binary"""
        try:
            # Run payload (it will try to connect to our mock C2)
            subprocess.run(
                ['/workspace/native_payloads/output/payload_native'],
                timeout=3,
                capture_output=True
            )
        except subprocess.TimeoutExpired:
            pass  # Expected - payload runs indefinitely
        except Exception as e:
            self.log(f"Payload execution error: {e}", "WARN")
            
    def test_phase3_features(self):
        """Test Phase 3 advanced features"""
        self.log("Testing Phase 3 features...", "TEST")
        
        # Check if Phase 3 modules exist
        modules = [
            '/workspace/native_payloads/rootkit/stitch_rootkit.c',
            '/workspace/native_payloads/evasion/process_ghost.c',
            '/workspace/native_payloads/exfil/dns_tunnel.c',
            '/workspace/native_payloads/harvest/cred_harvester.c'
        ]
        
        for module in modules:
            if not Path(module).exists():
                self.log(f"Missing: {module}", "FAIL")
                return False
                
        # Check if commands are registered
        commands_file = Path('/workspace/native_payloads/core/commands.c')
        if commands_file.exists():
            content = commands_file.read_text()
            phase3_cmds = ['cmd_install_rootkit', 'cmd_ghost_process', 
                          'cmd_harvest_creds', 'cmd_setup_dns_tunnel']
            
            for cmd in phase3_cmds:
                if cmd not in content:
                    self.log(f"Missing command: {cmd}", "FAIL")
                    return False
                    
        return True
        
    def cleanup(self):
        """Clean up processes"""
        if self.server_proc:
            self.server_proc.terminate()
            self.server_proc.wait(timeout=5)
            
        if self.payload_proc:
            self.payload_proc.terminate()
            
    def run(self):
        """Run all tests"""
        self.log("="*60, "TEST")
        self.log("LIVE END-TO-END TEST", "TEST")
        self.log("="*60, "TEST")
        
        try:
            # Test 1: Compilation
            self.test("Payload Compilation", self.compile_payload)
            
            # Test 2: Web Server
            self.test("Web Server Startup", self.start_web_server)
            
            # Test 3: API Endpoints
            if self.server_proc:
                self.test("API Endpoints", self.test_api_endpoints)
            
            # Test 4: C2 Communication
            self.test("C2 Communication", self.test_c2_communication)
            
            # Test 5: Phase 3 Features
            self.test("Phase 3 Features", self.test_phase3_features)
            
        finally:
            self.cleanup()
            
        # Summary
        self.log("\n" + "="*60, "TEST")
        self.log("TEST SUMMARY", "TEST")
        self.log("="*60, "TEST")
        
        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')
        total = passed + failed
        
        if total > 0:
            success_rate = (passed * 100) // total
            self.log(f"Total Tests: {total}", "INFO")
            self.log(f"Passed: {passed}", "PASS")
            self.log(f"Failed: {failed}", "FAIL" if failed > 0 else "INFO")
            self.log(f"Success Rate: {success_rate}%", "INFO")
            
            if success_rate >= 80:
                self.log("\n✅ SYSTEM READY FOR DEPLOYMENT", "PASS")
            elif success_rate >= 60:
                self.log("\n⚠️  SYSTEM PARTIALLY FUNCTIONAL", "WARN")
            else:
                self.log("\n❌ SYSTEM NOT READY", "FAIL")
        
if __name__ == '__main__':
    test = LiveE2ETest()
    test.run()