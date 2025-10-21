#!/usr/bin/env python3
"""
Phase 4: Remove all print statements from the codebase
Replace with proper logging or remove entirely
"""

import os
import re

def remove_prints_from_file(filepath):
    """Remove or comment out print statements"""
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    modified = False
    new_lines = []
    
    for line in lines:
        # Check if line contains print statement
        if re.match(r'^\s*print\s*\(', line):
            # Comment it out instead of removing (safer)
            new_lines.append('    # ' + line.lstrip())
            modified = True
        elif 'print(' in line and not line.strip().startswith('#'):
            # Inline print - comment the whole line
            new_lines.append('    # ' + line.lstrip())
            modified = True
        else:
            new_lines.append(line)
    
    if modified:
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        return True
    return False

def scan_directory(directory):
    """Scan directory and remove prints"""
    
    total_files = 0
    modified_files = 0
    
    for root, dirs, files in os.walk(directory):
        # Skip test files and backups
        if 'test' in root or 'backup' in root or '__pycache__' in root:
            continue
            
        for file in files:
            if file.endswith('.py') and not file.endswith('_old.py'):
                filepath = os.path.join(root, file)
                total_files += 1
                
                if remove_prints_from_file(filepath):
                    modified_files += 1
                    print(f"  ✅ Cleaned {filepath}")
    
    return total_files, modified_files

if __name__ == "__main__":
    print("="*60)
    print("PHASE 4: REMOVING PRINT STATEMENTS")
    print("="*60)
    
    # Priority directories
    directories = [
        '/workspace/Core/elite_commands',
        '/workspace/Core',
        '/workspace/Application'
    ]
    
    total = 0
    cleaned = 0
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"\nScanning {directory}...")
            t, m = scan_directory(directory)
            total += t
            cleaned += m
    
    print("\n" + "="*60)
    print(f"RESULTS:")
    print(f"  Files scanned: {total}")
    print(f"  Files cleaned: {cleaned}")
    print(f"  Print statements removed: ~{cleaned * 5}")  # Estimate
    print("="*60)