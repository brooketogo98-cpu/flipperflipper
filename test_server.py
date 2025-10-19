import subprocess
import time
import os

env = os.environ.copy()
env.update({
    'STITCH_ADMIN_USER': 'admin',
    'STITCH_ADMIN_PASSWORD': 'SecureTestPassword123!',
    'STITCH_WEB_PORT': '8888'
})

proc = subprocess.Popen(
    ['python3', 'web_app_real.py'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    env=env
)

print("Server starting...")
time.sleep(3)

if proc.poll() is None:
    print("Server is running!")
else:
    output = proc.stdout.read().decode()
    print(f"Server exited. Output:\n{output}")
