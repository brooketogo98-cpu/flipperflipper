#!/usr/bin/env python3
import re
import os
import sys

def fix_print_statements(content):
    # Fix print "string"
    content = re.sub(r'print\s+"([^"]*)"', r'print("\1")', content)
    content = re.sub(r"print\s+'([^']*)'", r"print('\1')", content)
    
    # Fix print variable
    content = re.sub(r'print\s+([a-zA-Z_][a-zA-Z0-9_.\[\]]*)\s*$', r'print(\1)', content, flags=re.MULTILINE)
    
    # Fix print ""
    content = re.sub(r'print\s+""', r'print("")', content)
    
    return content

def fix_imports(content):
    # Fix ConfigParser
    content = re.sub(r'import ConfigParser', r'import configparser as ConfigParser', content)
    
    # Fix cStringIO
    content = re.sub(r'import cStringIO', r'from io import BytesIO, StringIO', content)
    content = re.sub(r'cStringIO\.StringIO', r'BytesIO', content)
    
    return content

def fix_file(filepath):
    print(f"Fixing {filepath}...")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    original = content
    content = fix_print_statements(content)
    content = fix_imports(content)
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  ✓ Fixed {filepath}")
    else:
        print(f"  - No changes needed for {filepath}")

def main():
    directories = ['Application', 'PyLib', 'Cleaner']
    
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    try:
                        fix_file(filepath)
                    except Exception as e:
                        print(f"Error fixing {filepath}: {e}")

if __name__ == '__main__':
    main()
