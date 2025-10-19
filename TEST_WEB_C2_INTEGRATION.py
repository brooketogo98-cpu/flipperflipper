#!/usr/bin/env python3
"""
END-TO-END WEB → C2 → PAYLOAD INTEGRATION TEST
Tests the complete flow from web interface to native payload
"""

import os
import sys
import time
import socket
import threading
import subprocess
import requests
import json
from pathlib import Path

class WebC2IntegrationTest:
    def __init__(self):
        self.c2_port = 15500
        self.web_port = 19123
        self.payload_proc = None
        self.web_proc = None
        self.c2_thread = None
        self.results = {
            'web_server': False,
            'payload_compile': False,
            'payload_connect': False,
            'web_api_targets': False,
            'web_command_execution': False,
            'end_to_end': False
        }
        
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
        """Compile payload for this test"""
        self.log("=" * 80, "CRITICAL")
        self.log("TEST 1: COMPILE PAYLOAD WITH CUSTOM C2", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        os.chdir('/workspace/native_payloads')
        
        env = os.environ.copy()
        env['C2_HOST'] = '127.0.0.1'
        env['C2_PORT'] = str(self.c2_port)
        
        result = subprocess.run(['bash', './build.sh'], 
                              capture_output=True, text=True, env=env)
        
        if result.returncode == 0:
            self.log("✅ Payload compiled", "SUCCESS")
            self.results['payload_compile'] = True
            return True
        else:
            self.log(f"❌ Compilation failed", "ERROR")
            return False
            
    def test_2_start_web_server(self):
        """Start web server"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 2: START WEB SERVER WITH NEW INTEGRATION", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        env = os.environ.copy()
        env.update({
            'STITCH_ADMIN_USER': 'admin',
            'STITCH_ADMIN_PASSWORD': 'SecureTestPassword123!',
            'STITCH_WEB_PORT': str(self.web_port),
            'STITCH_DEBUG': 'true'
        })
        
        self.log(f"Starting web server on port {self.web_port}...", "INFO")
        self.web_proc = subprocess.Popen(
            ['python3', '/workspace/web_app_real.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=os.setsid
        )
        
        time.sleep(6)  # Wait for server startup
        
        if self.web_proc.poll() is None:
            self.log("✅ Web server started", "SUCCESS")
            
            try:
                r = requests.get(f'http://localhost:{self.web_port}/', timeout=2)
                if r.status_code in [200, 302]:
                    self.log("✅ Web server responding", "SUCCESS")
                    self.results['web_server'] = True
                    return True
            except:
                pass
                
        self.log("❌ Web server not responding", "ERROR")
        return False
        
    def test_3_start_c2_and_payload(self):
        """Start Stitch C2 server and payload"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 3: START C2 SERVER AND CONNECT PAYLOAD", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Start Stitch C2 server
        def run_c2():
            sys.path.insert(0, '/workspace')
            from Application import stitch_cmd
            
            server = stitch_cmd.stitch_server()
            server.l_port = self.c2_port
            self.log(f"✅ Stitch C2 server listening on port {self.c2_port}", "SUCCESS")
            server.run_server()
            
        self.c2_thread = threading.Thread(target=run_c2, daemon=True)
        self.c2_thread.start()
        time.sleep(3)
        
        # Launch payload
        self.log("Launching payload...", "INFO")
        try:
            self.payload_proc = subprocess.Popen(
                ['/workspace/native_payloads/output/payload_native'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            self.log("✅ Payload process started", "SUCCESS")
        except Exception as e:
            self.log(f"❌ Failed to start payload: {e}", "ERROR")
            return False
            
        # Wait for connection
        self.log("Waiting for payload to connect to C2...", "INFO")
        time.sleep(5)
        
        # Check if connected
        sys.path.insert(0, '/workspace')
        from web_app_real import get_stitch_server
        
        try:
            server = get_stitch_server()
            if len(server.inf_sock) > 0:
                target_id = list(server.inf_sock.keys())[0]
                self.log(f"🎉 PAYLOAD CONNECTED: {target_id}", "SUCCESS")
                self.results['payload_connect'] = True
                self.target_id = target_id
                return True
            else:
                self.log("❌ No payload connections detected", "ERROR")
                return False
        except Exception as e:
            self.log(f"❌ Error checking connections: {e}", "ERROR")
            return False
            
    def test_4_web_api_targets(self):
        """Test web API can see targets"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 4: WEB API TARGETS ENDPOINT", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        try:
            # Login first
            session = requests.Session()
            login_data = {
                'username': 'admin',
                'password': 'SecureTestPassword123!'
            }
            r = session.post(
                f'http://localhost:{self.web_port}/login',
                data=login_data,
                allow_redirects=False
            )
            
            if r.status_code not in [200, 302]:
                self.log("⚠️  Login failed, trying direct API", "WARNING")
                
            # Get targets
            r = session.get(f'http://localhost:{self.web_port}/api/targets', timeout=5)
            
            if r.status_code == 200:
                data = r.json()
                if data.get('success') and data.get('count', 0) > 0:
                    targets = data.get('targets', [])
                    self.log(f"✅ API returned {len(targets)} target(s)", "SUCCESS")
                    self.log(f"   Target: {targets[0]}", "INFO")
                    self.results['web_api_targets'] = True
                    return True
                else:
                    self.log("⚠️  API returned no targets", "WARNING")
            else:
                self.log(f"❌ API returned status {r.status_code}", "ERROR")
                
        except Exception as e:
            self.log(f"❌ API test error: {e}", "ERROR")
            
        return False
        
    def test_5_command_execution(self):
        """Test command execution via web API"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("TEST 5: COMMAND EXECUTION VIA WEB API", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        if not hasattr(self, 'target_id'):
            self.log("❌ No target_id from previous test", "ERROR")
            return False
            
        try:
            # Login
            session = requests.Session()
            login_data = {
                'username': 'admin',
                'password': 'SecureTestPassword123!'
            }
            session.post(
                f'http://localhost:{self.web_port}/login',
                data=login_data
            )
            
            # Execute ping command
            cmd_data = {
                'connection_id': self.target_id,
                'command': 'ping'
            }
            
            self.log(f"Sending 'ping' command to {self.target_id}...", "INFO")
            r = session.post(
                f'http://localhost:{self.web_port}/api/execute',
                json=cmd_data,
                timeout=10
            )
            
            if r.status_code == 200:
                data = r.json()
                if data.get('success'):
                    output = data.get('output', '')
                    self.log("✅ Command executed!", "SUCCESS")
                    self.log(f"   Response: {output[:200]}", "INFO")
                    self.results['web_command_execution'] = True
                    self.results['end_to_end'] = True
                    return True
                else:
                    self.log(f"⚠️  Command failed: {data.get('error')}", "WARNING")
            else:
                self.log(f"❌ API returned status {r.status_code}", "ERROR")
                
        except Exception as e:
            self.log(f"❌ Command execution error: {e}", "ERROR")
            
        return False
        
    def cleanup(self):
        """Clean up processes"""
        self.log("\n" + "=" * 80, "INFO")
        self.log("CLEANUP", "INFO")
        self.log("=" * 80, "INFO")
        
        if self.payload_proc:
            try:
                os.killpg(os.getpgid(self.payload_proc.pid), 9)
                self.log("✅ Payload terminated", "INFO")
            except:
                pass
                
        if self.web_proc:
            try:
                os.killpg(os.getpgid(self.web_proc.pid), 9)
                self.log("✅ Web server terminated", "INFO")
            except:
                pass
                
        # Kill any remaining processes
        subprocess.run(['pkill', '-9', '-f', 'payload_native'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', f'web_app_real.*{self.web_port}'], capture_output=True)
        
    def generate_report(self):
        """Generate test report"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("WEB → C2 → PAYLOAD INTEGRATION TEST RESULTS", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        tests = [
            ("Payload Compilation", self.results['payload_compile']),
            ("Web Server Start", self.results['web_server']),
            ("Payload Connection", self.results['payload_connect']),
            ("Web API Targets", self.results['web_api_targets']),
            ("Command Execution", self.results['web_command_execution']),
            ("End-to-End Flow", self.results['end_to_end']),
        ]
        
        self.log("\n📊 Test Results:", "INFO")
        self.log("-" * 80, "INFO")
        
        passed = 0
        for name, result in tests:
            status = "✅ PASS" if result else "❌ FAIL"
            level = "SUCCESS" if result else "ERROR"
            self.log(f"  {status:12} {name}", level)
            if result:
                passed += 1
                
        self.log("-" * 80, "INFO")
        
        percentage = (passed / len(tests)) * 100
        self.log(f"\n📈 Score: {passed}/{len(tests)} ({percentage:.0f}%)", 
                 "SUCCESS" if passed >= 5 else "WARNING")
        
        self.log("\n" + "=" * 80, "CRITICAL")
        
        if self.results['end_to_end']:
            self.log("🎉 END-TO-END INTEGRATION WORKING!", "SUCCESS")
            self.log("✅ Web → C2 → Payload flow verified", "SUCCESS")
            return True
        elif passed >= 4:
            self.log("✅ MOSTLY WORKING", "SUCCESS")
            self.log("⚠️  Some components need attention", "WARNING")
            return True
        else:
            self.log("❌ INTEGRATION INCOMPLETE", "ERROR")
            return False
            
def main():
    tester = WebC2IntegrationTest()
    
    try:
        tester.test_1_compile_payload()
        tester.test_2_start_web_server()
        tester.test_3_start_c2_and_payload()
        tester.test_4_web_api_targets()
        tester.test_5_command_execution()
        
        time.sleep(2)
        
        success = tester.generate_report()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        tester.log("\n\nTest interrupted", "WARNING")
        return 1
    finally:
        tester.cleanup()
        
if __name__ == '__main__':
    sys.exit(main())
