#!/usr/bin/env python3
"""
Batch fix script to accelerate Phase 2 subprocess elimination
This will create fixed versions for multiple files at once
"""

import os
import re

# Template for subprocess replacements
REPLACEMENTS = {
    # whoami replacements
    r"subprocess\.run\(\['whoami'\].*?\)": """
# Native whoami implementation
username_buffer = ctypes.create_unicode_buffer(257)
size = ctypes.c_uint(257)
if ctypes.windll.advapi32.GetUserNameW(username_buffer, ctypes.byref(size)):
    result = type('', (), {'stdout': username_buffer.value, 'returncode': 0})()
else:
    result = type('', (), {'stdout': '', 'returncode': 1})()""",
    
    # tasklist replacements
    r"subprocess\.run\(\['tasklist'.*?\], capture_output=True.*?\)": """
# Native process enumeration
from api_wrappers import get_native_api
api = get_native_api()
processes = api.list_processes()
result = type('', (), {'stdout': str(processes), 'returncode': 0})()""",
    
    # ipconfig/ifconfig replacements  
    r"subprocess\.run\(\['ipconfig', '/all'\].*?\)": """
# Native network info
import socket
hostname = socket.gethostname()
ip_addr = socket.gethostbyname(hostname)
result = type('', (), {'stdout': f'Host: {hostname}\\nIP: {ip_addr}', 'returncode': 0})()""",
    
    # netstat replacements
    r"subprocess\.run\(\['netstat'.*?\].*?\)": """
# Native connection enumeration
import psutil
connections = psutil.net_connections(kind='all')
output = '\\n'.join([f'{c.laddr} -> {c.raddr} [{c.status}]' for c in connections[:20]])
result = type('', (), {'stdout': output, 'returncode': 0})()""",
    
    # Remove subprocess import
    r"^import subprocess\n": "# subprocess removed - using native APIs\n",
    r"^import subprocess$": "# subprocess removed - using native APIs",
}

def fix_file(filepath):
    """Fix a single file by replacing subprocess calls"""
    
    print(f"Processing {filepath}...")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Apply all replacements
    for pattern, replacement in REPLACEMENTS.items():
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    
    # Add necessary imports if not present
    if "import ctypes" not in content and "ctypes." in content:
        content = "import ctypes\nfrom ctypes import wintypes\n" + content
    
    if "from api_wrappers import" not in content and "api_wrappers" in content:
        # Add sys.path fix and import
        import_section = """import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api
"""
        content = import_section + content
    
    if content != original:
        # Save fixed version
        fixed_path = filepath.replace('.py', '_fixed.py')
        with open(fixed_path, 'w') as f:
            f.write(content)
        print(f"  ✅ Created {fixed_path}")
        return True
    else:
        print(f"  ⏭️  No changes needed")
        return False

# Priority files to fix
priority_files = [
    '/workspace/Core/elite_commands/elite_whoami.py',
    '/workspace/Core/elite_commands/elite_username.py',
    '/workspace/Core/elite_commands/elite_privileges.py',
    '/workspace/Core/elite_commands/elite_network.py',
    '/workspace/Core/elite_commands/elite_systeminfo.py',
    '/workspace/Core/elite_commands/elite_processes.py',
    '/workspace/Core/elite_commands/elite_shutdown.py',
    '/workspace/Core/elite_commands/elite_restart.py',
    '/workspace/Core/elite_commands/elite_location.py',
]

if __name__ == "__main__":
    fixed_count = 0
    
    for filepath in priority_files:
        if os.path.exists(filepath):
            if fix_file(filepath):
                fixed_count += 1
    
    print(f"\n✅ Fixed {fixed_count} files")
    print("\nTo apply fixes, run:")
    print("  for f in *_fixed.py; do mv $f ${f/_fixed/}; done")