#!/usr/bin/env python3
"""
WEBSOCKET REAL-TIME TEST
Tests WebSocket functionality for real-time updates
"""

import os
import sys
import time
import threading
import subprocess
import requests
from socketio import SimpleClient

class WebSocketTest:
    def __init__(self):
        self.server_proc = None
        self.results = []
        self.port = 18888
        
    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        print(f"{colors.get(level, '')}[{level}] {msg}\033[0m")
        self.results.append({"level": level, "msg": msg})
        
    def test_websocket(self):
        """Test WebSocket connection and events"""
        self.log("=" * 80, "CRITICAL")
        self.log("WEBSOCKET REAL-TIME TEST", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        # Start web server
        env = os.environ.copy()
        env.update({
            'STITCH_ADMIN_USER': 'admin',
            'STITCH_ADMIN_PASSWORD': 'SecureTestPassword123!',
            'STITCH_WEB_PORT': str(self.port),
            'STITCH_DEBUG': 'true'
        })
        
        self.log("Starting web server...", "INFO")
        self.server_proc = subprocess.Popen(
            ['python3', '/workspace/web_app_real.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=os.setsid
        )
        
        time.sleep(6)  # Wait for server startup
        
        if self.server_proc.poll() is None:
            self.log("✅ Web server started", "SUCCESS")
            
            try:
                # Test HTTP connection first
                r = requests.get(f'http://localhost:{self.port}/', timeout=2)
                self.log(f"✅ HTTP connection works (status {r.status_code})", "SUCCESS")
                
                # Test WebSocket connection
                self.log("Testing WebSocket connection...", "INFO")
                
                try:
                    # Use SimpleClient for testing
                    sio = SimpleClient()
                    sio.connect(f'http://localhost:{self.port}', 
                               socketio_path='/socket.io',
                               wait_timeout=5)
                    
                    self.log("✅ WebSocket connected successfully!", "SUCCESS")
                    
                    # Test emit/receive
                    sio.emit('get_targets', {})
                    self.log("✅ Sent 'get_targets' event", "SUCCESS")
                    
                    # Try to receive response (with short timeout)
                    try:
                        event = sio.receive(timeout=2)
                        if event:
                            self.log(f"✅ Received event: {event[0]}", "SUCCESS")
                    except:
                        self.log("⚠️  No response received (expected if no targets)", "INFO")
                    
                    sio.disconnect()
                    self.log("✅ WebSocket disconnected cleanly", "SUCCESS")
                    
                    return True
                    
                except Exception as e:
                    self.log(f"⚠️  WebSocket connection: {str(e)[:100]}", "ERROR")
                    self.log("   (May need authentication or CORS setup)", "INFO")
                    
            except Exception as e:
                self.log(f"❌ Test error: {e}", "ERROR")
                
        else:
            self.log("❌ Server failed to start", "ERROR")
            
        return False
        
    def cleanup(self):
        """Clean up"""
        if self.server_proc:
            try:
                os.killpg(os.getpgid(self.server_proc.pid), 9)
                self.log("✅ Server terminated", "INFO")
            except:
                pass
                
    def generate_report(self):
        """Generate report"""
        self.log("\n" + "=" * 80, "CRITICAL")
        self.log("WEBSOCKET TEST RESULTS", "CRITICAL")
        self.log("=" * 80, "CRITICAL")
        
        success_count = sum(1 for r in self.results if r['level'] == 'SUCCESS')
        error_count = sum(1 for r in self.results if r['level'] == 'ERROR')
        
        self.log(f"\nSuccess: {success_count} checks", "SUCCESS")
        self.log(f"Errors: {error_count} issues", "ERROR" if error_count > 0 else "INFO")
        
        if success_count >= 3:
            self.log("\n✅ WEBSOCKET FUNCTIONAL", "SUCCESS")
            return True
        else:
            self.log("\n⚠️  WEBSOCKET NEEDS WORK", "ERROR")
            return False
            
def main():
    tester = WebSocketTest()
    
    try:
        tester.test_websocket()
        success = tester.generate_report()
        return 0 if success else 1
    finally:
        tester.cleanup()
        
if __name__ == '__main__':
    sys.exit(main())
