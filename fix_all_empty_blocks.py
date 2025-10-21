#!/usr/bin/env python3
"""
Fix all empty control blocks in Python files
"""

import os
import re

def fix_empty_blocks(filepath):
    """Fix empty if/else/try/except/for/while blocks"""
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    modified = False
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check for control statements
        if re.match(r'^(\s*)(if|elif|else|try|except|finally|for|while|def|class)\s*.*:\s*$', line):
            indent = len(line) - len(line.lstrip())
            
            # Check if next line is empty or another control statement
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                next_indent = len(next_line) - len(next_line.lstrip())
                
                # If next line has same or less indentation (empty block)
                if next_line.strip() == '' or next_indent <= indent:
                    # Insert pass statement
                    lines.insert(i + 1, ' ' * (indent + 4) + 'pass\n')
                    modified = True
                elif next_line.strip().startswith('#') and not next_line.strip().startswith('# '):
                    # Only a comment, need pass
                    if i + 2 >= len(lines) or len(lines[i + 2]) - len(lines[i + 2].lstrip()) <= indent:
                        lines.insert(i + 1, ' ' * (indent + 4) + 'pass\n')
                        modified = True
        
        i += 1
    
    if modified:
        with open(filepath, 'w') as f:
            f.writelines(lines)
        return True
    
    return False

def fix_all_python_files(directory):
    """Fix all Python files in directory"""
    
    fixed_files = []
    
    for root, dirs, files in os.walk(directory):
        # Skip git and cache directories
        if '.git' in root or '__pycache__' in root:
            continue
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    if fix_empty_blocks(filepath):
                        fixed_files.append(filepath)
                        print(f"Fixed: {filepath}")
                except Exception as e:
                    print(f"Error fixing {filepath}: {e}")
    
    return fixed_files

if __name__ == "__main__":
    directories = [
        '/workspace/Core',
        '/workspace/Application',
        '/workspace'
    ]
    
    all_fixed = []
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"\nFixing Python files in {directory}...")
            fixed = fix_all_python_files(directory)
            all_fixed.extend(fixed)
    
    print(f"\n{'='*60}")
    print(f"Total files fixed: {len(all_fixed)}")
    
    if all_fixed:
        print("\nFiles fixed:")
        for f in all_fixed[:20]:  # Show first 20
            print(f"  - {f}")
        if len(all_fixed) > 20:
            print(f"  ... and {len(all_fixed) - 20} more")
    
    print("="*60)