#!/usr/bin/env python3
"""
Diagnose intermittent multi-command failures
Run 20 tests to identify pattern
"""

import os, sys, time, threading, subprocess, signal
sys.path.insert(0, '/workspace')

c2_port = 18100

# Compile once
os.chdir('/workspace/native_payloads')
env = os.environ.copy()
env['C2_HOST'] = '127.0.0.1'
env['C2_PORT'] = str(c2_port)
subprocess.run(['bash', './build.sh'], capture_output=True, env=env, timeout=30)

from Application import stitch_cmd
server = stitch_cmd.stitch_server()
server.l_port = c2_port

def run():
    server.run_server()
threading.Thread(target=run, daemon=True).start()
time.sleep(3)

# Launch payload
payload_proc = subprocess.Popen(['/workspace/native_payloads/output/payload_native'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
time.sleep(5)

from native_protocol_bridge import send_command_to_native_payload

# Run 20 tests
results = []
for test_num in range(1, 21):
    # Get latest connection
    time.sleep(0.5)
    if len(server.inf_sock) == 0:
        print(f"Test {test_num}: No connection")
        results.append(0)
        continue
        
    target_id = list(server.inf_sock.keys())[-1]
    sock = server.inf_sock[target_id]
    
    # Try 3 commands rapidly
    success_count = 0
    for cmd in ['ping', 'sysinfo', 'pwd']:
        success, output = send_command_to_native_payload(sock, cmd)
        if success:
            success_count += 1
        else:
            break
        time.sleep(0.1)  # Very short delay
    
    results.append(success_count)
    status = "✅" if success_count == 3 else "❌"
    print(f"Test {test_num:2d}: {success_count}/3 {status}")

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass

# Analysis
print("\n" + "="*50)
total = len(results)
perfect = sum(1 for r in results if r == 3)
partial = sum(1 for r in results if 0 < r < 3)
failed = sum(1 for r in results if r == 0)

print(f"Perfect (3/3): {perfect}/{total} ({perfect/total*100:.0f}%)")
print(f"Partial: {partial}/{total}")
print(f"Failed: {failed}/{total}")
print(f"\nReliability: {perfect/total*100:.0f}%")

if perfect == total:
    print("\n✅ 100% RELIABLE")
else:
    print(f"\n⚠️  Only {perfect/total*100:.0f}% reliable")
