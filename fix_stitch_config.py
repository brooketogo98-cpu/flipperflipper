#!/usr/bin/env python3
"""Fix the stitch_pyld_config.py file completely"""

import re

# Read the file
with open('/workspace/Application/stitch_pyld_config.py', 'r') as f:
    content = f.read()

# Fix the first triple-quoted string (around line 200-212)
# This one is commented out anyway, so leave it

# Fix the second triple-quoted string (around line 216-255)
# Find the pattern and fix it
pattern = r"content = '''(.*?)'''"
match = re.search(pattern, content, re.DOTALL)

if match:
    # Fix the content inside
    inner_content = match.group(1)
    
    # Fix missing values
    inner_content = inner_content.replace('BHOST =\n', "BHOST = 'localhost'\n")
    inner_content = inner_content.replace('LHOST = localhost\n', "LHOST = 'localhost'\n")
    
    # Replace in original content
    fixed = f"content = '''{inner_content}'''"
    content = re.sub(pattern, fixed, content, flags=re.DOTALL)

# Write back
with open('/workspace/Application/stitch_pyld_config.py', 'w') as f:
    f.write(content)

print("Fixed stitch_pyld_config.py")