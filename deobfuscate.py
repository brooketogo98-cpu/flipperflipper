#!/usr/bin/env python3
"""
Deobfuscation script for Configuration files
Removes exec(SEC(INFO(...))) patterns and decodes the content
"""

import base64
import zlib
import re
import os
import sys

def decode_obfuscated_file(filepath):
    """Decode a single obfuscated file"""
    print(f"Processing: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find the exec(SEC(INFO(...))) pattern
        match = re.search(r'exec\(SEC\(INFO\("(.+?)"\)\)\)', content, re.DOTALL)
        if not match:
            print(f"  No obfuscation pattern found in {filepath}")
            return False
        
        encoded_data = match.group(1)
        print(f"  Found encoded data: {len(encoded_data)} characters")
        
        # Decode base64 then decompress
        try:
            decoded_bytes = base64.b64decode(encoded_data)
            decompressed = zlib.decompress(decoded_bytes)
            decoded_content = decompressed.decode('utf-8')
            
            print(f"  Successfully decoded: {len(decoded_content)} characters")
            
            # Check for suspicious content
            suspicious_patterns = [
                b'subprocess.call',
                b'os.system', 
                b'eval(',
                b'exec(',
                b'__import__',
                b'backdoor',
                b'malware'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in decompressed:
                    print(f"  WARNING: Found suspicious pattern: {pattern}")
            
            # Save the decoded content
            clean_path = filepath.replace('.py', '_clean.py')
            with open(clean_path, 'w', encoding='utf-8') as f:
                f.write(decoded_content)
            
            print(f"  Saved clean version to: {clean_path}")
            return True
            
        except Exception as e:
            print(f"  Failed to decode: {e}")
            return False
            
    except Exception as e:
        print(f"  Error reading file: {e}")
        return False

def main():
    """Main deobfuscation process"""
    
    # Files that need deobfuscation based on grep results
    obfuscated_files = [
        'Configuration/st_encryption.py',
        'Configuration/st_osx_keylogger.py', 
        'Configuration/st_win_keylogger.py',
        'Configuration/st_protocol.py',
        'Configuration/st_main.py',
        'Configuration/st_utils.py',
        'Configuration/st_lnx_keylogger.py'
    ]
    
    print("Starting deobfuscation process...")
    print(f"Found {len(obfuscated_files)} files to process")
    
    success_count = 0
    
    for filepath in obfuscated_files:
        if os.path.exists(filepath):
            if decode_obfuscated_file(filepath):
                success_count += 1
        else:
            print(f"File not found: {filepath}")
    
    print(f"\nDeobfuscation complete: {success_count}/{len(obfuscated_files)} files processed")
    
    if success_count == len(obfuscated_files):
        print("✅ All files successfully deobfuscated!")
        return True
    else:
        print("❌ Some files failed to deobfuscate")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)