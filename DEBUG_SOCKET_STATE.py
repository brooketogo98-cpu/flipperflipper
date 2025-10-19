#!/usr/bin/env python3
"""Debug socket state between commands"""

import os, sys, time, threading, subprocess, signal, socket
sys.path.insert(0, '/workspace')

c2_port = 16400

# Compile
os.chdir('/workspace/native_payloads')
env = os.environ.copy()
env['C2_HOST'] = '127.0.0.1'
env['C2_PORT'] = str(c2_port)
result = subprocess.run(['bash', './build.sh'], capture_output=True, env=env, timeout=30)
print('✅ Compiled')

# Start C2
def run_c2():
    from Application import stitch_cmd
    server = stitch_cmd.stitch_server()
    server.l_port = c2_port
    server.run_server()
c2_thread = threading.Thread(target=run_c2, daemon=True)
c2_thread.start()
time.sleep(3)

# Launch payload
payload_proc = subprocess.Popen(['/workspace/native_payloads/output/payload_native'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
time.sleep(5)

from web_app_real import get_stitch_server
from native_protocol_bridge import native_bridge
server = get_stitch_server()

target_id = list(server.inf_sock.keys())[0]
sock = server.inf_sock[target_id]

print(f'Connected: {target_id}')

def check_socket(sock, name):
    try:
        # Check if socket is still valid
        sock.getpeername()
        print(f'  {name}: Socket valid (connected to {sock.getpeername()})')
        return True
    except Exception as e:
        print(f'  {name}: Socket INVALID - {e}')
        return False

# Test command 1
print('\\n--- Command 1: ping ---')
check_socket(sock, 'Before')

try:
    success, output = native_bridge.send_native_command(sock, 'ping')
    print(f'Result: {success}, Output: {output[:50]}')
except Exception as e:
    print(f'Exception: {e}')

check_socket(sock, 'After')
time.sleep(2)

# Test command 2
print('\\n--- Command 2: sysinfo ---')
check_socket(sock, 'Before')

# Check if socket is still in server.inf_sock
if target_id in server.inf_sock:
    print(f'  Socket still in server.inf_sock')
    sock2 = server.inf_sock[target_id]
    print(f'  Same socket object: {sock is sock2}')
else:
    print(f'  Socket NOT in server.inf_sock anymore!')

try:
    success, output = native_bridge.send_native_command(sock, 'sysinfo')
    print(f'Result: {success}, Output: {output[:50]}')
except Exception as e:
    print(f'Exception: {e}')
    import traceback
    traceback.print_exc()

check_socket(sock, 'After')

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass
