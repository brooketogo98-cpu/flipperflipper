#!/usr/bin/env python3
"""
Accurate Phase 2 progress report
"""

import os
import re

def check_file(filepath):
    """Check if a file uses subprocess"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check for actual subprocess usage (not comments)
        if re.search(r'^[^#]*subprocess\.(run|call|Popen|check_output)', content, re.MULTILINE):
            return True
        return False
    except:
        return False

# Check all elite commands
elite_dir = '/workspace/Core/elite_commands'
files = [f for f in os.listdir(elite_dir) if f.startswith('elite_') and f.endswith('.py') and not f.endswith('_old.py')]

clean_files = []
dirty_files = []

for file in sorted(files):
    filepath = os.path.join(elite_dir, file)
    if check_file(filepath):
        dirty_files.append(file)
    else:
        clean_files.append(file)

print("="*60)
print("PHASE 2 ACCURATE STATUS REPORT")
print("="*60)
print(f"\nTotal elite commands: {len(files)}")
print(f"✅ Clean (no subprocess): {len(clean_files)} ({len(clean_files)*100//len(files)}%)")
print(f"❌ Using subprocess: {len(dirty_files)} ({len(dirty_files)*100//len(files)}%)")

print("\n[Files Successfully Fixed - NO SUBPROCESS]")
for f in clean_files[:10]:
    print(f"  ✅ {f}")
if len(clean_files) > 10:
    print(f"  ... and {len(clean_files)-10} more")

print("\n[Files Still Need Fixing]")
for f in dirty_files[:10]:
    print(f"  ❌ {f}")
if len(dirty_files) > 10:
    print(f"  ... and {len(dirty_files)-10} more")

print("\n" + "="*60)
print(f"PHASE 2 COMPLETION: {len(clean_files)*100//len(files)}%")
print("="*60)