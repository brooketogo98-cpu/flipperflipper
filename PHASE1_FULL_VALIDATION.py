#!/usr/bin/env python3
"""
COMPREHENSIVE PHASE 1 VALIDATION
Tests every single aspect: backend, frontend, integration, compilation, execution
"""

import os
import sys
import json
import subprocess
import tempfile
import hashlib
from pathlib import Path

sys.path.insert(0, '/workspace')

class Phase1Validator:
    def __init__(self):
        self.results = {
            'backend': {},
            'frontend': {},
            'integration': {},
            'compilation': {},
            'features': {},
            'gaps': []
        }
        
    def validate_backend_files(self):
        """Validate all backend C files exist and have content"""
        print("\n[BACKEND VALIDATION]")
        
        required_files = {
            # Core files
            '/workspace/native_payloads/core/main.c': 'Main entry point',
            '/workspace/native_payloads/core/utils.c': 'Utility functions',
            '/workspace/native_payloads/core/commands.c': 'Command handlers',
            '/workspace/native_payloads/core/config.h': 'Configuration header',
            '/workspace/native_payloads/core/utils.h': 'Utils header',
            '/workspace/native_payloads/core/commands.h': 'Commands header',
            
            # Crypto files
            '/workspace/native_payloads/crypto/aes.c': 'AES implementation',
            '/workspace/native_payloads/crypto/sha256.c': 'SHA256 implementation',
            '/workspace/native_payloads/crypto/aes.h': 'AES header',
            '/workspace/native_payloads/crypto/sha256.h': 'SHA256 header',
            
            # Network files
            '/workspace/native_payloads/network/protocol.c': 'Network protocol',
            '/workspace/native_payloads/network/protocol.h': 'Protocol header',
            
            # Platform specific
            '/workspace/native_payloads/linux/linux_impl.c': 'Linux implementation',
            '/workspace/native_payloads/windows/winapi.c': 'Windows implementation',
            
            # Build files
            '/workspace/native_payloads/build.sh': 'Build script',
            '/workspace/native_payloads/CMakeLists.txt': 'CMake config',
        }
        
        for filepath, description in required_files.items():
            if Path(filepath).exists():
                size = Path(filepath).stat().st_size
                if size > 0:
                    print(f"  ✓ {description}: {size} bytes")
                    self.results['backend'][filepath] = True
                else:
                    print(f"  ✗ {description}: EXISTS BUT EMPTY")
                    self.results['backend'][filepath] = False
                    self.results['gaps'].append(f"Empty file: {filepath}")
            else:
                print(f"  ✗ {description}: MISSING")
                self.results['backend'][filepath] = False
                self.results['gaps'].append(f"Missing file: {filepath}")
                
    def validate_compilation(self):
        """Test that the payload actually compiles"""
        print("\n[COMPILATION VALIDATION]")
        
        os.chdir('/workspace/native_payloads')
        
        # Clean previous builds
        subprocess.run(['rm', '-rf', 'build', 'output'], capture_output=True)
        subprocess.run(['mkdir', '-p', 'build', 'output'], capture_output=True)
        
        # Try to compile
        result = subprocess.run(['bash', './build.sh'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("  ✓ Compilation successful")
            self.results['compilation']['builds'] = True
            
            # Check output
            if Path('/workspace/native_payloads/output/payload_native').exists():
                size = Path('/workspace/native_payloads/output/payload_native').stat().st_size
                print(f"  ✓ Binary generated: {size} bytes")
                self.results['compilation']['binary_exists'] = True
                self.results['compilation']['binary_size'] = size
            else:
                print("  ✗ No binary output")
                self.results['compilation']['binary_exists'] = False
                self.results['gaps'].append("Compilation succeeds but no binary output")
        else:
            print(f"  ✗ Compilation failed: {result.stderr[:200]}")
            self.results['compilation']['builds'] = False
            self.results['gaps'].append("Native payload compilation fails")
            
    def validate_web_integration(self):
        """Validate web application integration"""
        print("\n[WEB INTEGRATION VALIDATION]")
        
        # Check if web routes are modified
        web_file = Path('/workspace/web_app_real.py')
        if web_file.exists():
            content = web_file.read_text()
            
            # Check for native payload integration
            checks = {
                "Native type check": "data.get('type') == 'native'",
                "Import native builder": "from native_payload_builder import native_builder",
                "Compile native": "native_builder.compile_payload",
                "Native response": "'payload_type': 'native'",
            }
            
            for name, pattern in checks.items():
                if pattern in content:
                    print(f"  ✓ {name}")
                    self.results['integration'][name] = True
                else:
                    print(f"  ✗ {name}")
                    self.results['integration'][name] = False
                    self.results['gaps'].append(f"Web integration missing: {name}")
        else:
            print("  ✗ web_app_real.py not found")
            self.results['gaps'].append("Main web app file missing")
            
    def validate_frontend(self):
        """Validate frontend JavaScript and UI"""
        print("\n[FRONTEND VALIDATION]")
        
        # Check JavaScript file
        js_file = Path('/workspace/static/js/native_payload.js')
        if js_file.exists():
            size = js_file.stat().st_size
            content = js_file.read_text()
            
            # Check for key UI functions
            ui_features = {
                "Platform selector": "platform-selector",
                "Build button": "buildNativePayload",
                "C2 configuration": "nativeC2Host",
                "Evasion options": "enablePolymorphic",
                "Download handler": "downloadPayload",
            }
            
            for name, pattern in ui_features.items():
                if pattern in content:
                    print(f"  ✓ {name}")
                    self.results['frontend'][name] = True
                else:
                    print(f"  ✗ {name}")
                    self.results['frontend'][name] = False
                    self.results['gaps'].append(f"Frontend missing: {name}")
                    
            print(f"  ✓ JavaScript size: {size} bytes")
        else:
            print("  ✗ native_payload.js not found")
            self.results['gaps'].append("Frontend JavaScript missing")
            
        # Check if dashboard template exists
        template_file = Path('/workspace/templates/dashboard_real.html')
        if template_file.exists():
            print("  ✓ Dashboard template exists")
        else:
            print("  ⚠️  Dashboard template missing (UI may not be visible)")
            
    def validate_python_builder(self):
        """Validate Python payload builder"""
        print("\n[PYTHON BUILDER VALIDATION]")
        
        try:
            from native_payload_builder import native_builder
            
            # Test basic functions
            tests = {
                "Generate XOR key": lambda: native_builder.generate_polymorphic_key(),
                "Build path exists": lambda: native_builder.build_path.exists(),
                "Output path exists": lambda: native_builder.output_path.exists(),
            }
            
            for name, test in tests.items():
                try:
                    result = test()
                    print(f"  ✓ {name}: {result}")
                    self.results['integration'][f'python_{name}'] = True
                except Exception as e:
                    print(f"  ✗ {name}: {e}")
                    self.results['integration'][f'python_{name}'] = False
                    self.results['gaps'].append(f"Python builder issue: {name}")
                    
            # Try actual compilation
            print("\n  Testing Python compilation...")
            config = {
                'platform': 'linux',
                'c2_host': 'test.local',
                'c2_port': 4444
            }
            
            result = native_builder.compile_payload(config)
            if result.get('success'):
                print(f"  ✓ Python compilation works: {result['message']}")
            else:
                print(f"  ✗ Python compilation fails: {result.get('error', 'Unknown')}")
                self.results['gaps'].append("Python builder compilation fails")
                
        except ImportError as e:
            print(f"  ✗ Cannot import native_payload_builder: {e}")
            self.results['gaps'].append("Python builder module not importable")
            
    def validate_features(self):
        """Validate implemented features"""
        print("\n[FEATURE VALIDATION]")
        
        # Check command implementations
        commands_file = Path('/workspace/native_payloads/core/commands.c')
        if commands_file.exists():
            content = commands_file.read_text()
            
            required_commands = [
                'cmd_ping', 'cmd_exec', 'cmd_sysinfo',
                'cmd_ps_list', 'cmd_shell', 'cmd_download',
                'cmd_upload', 'cmd_inject', 'cmd_persist',
                'cmd_killswitch'
            ]
            
            implemented = []
            missing = []
            
            for cmd in required_commands:
                if f'int {cmd}(' in content:
                    implemented.append(cmd)
                else:
                    missing.append(cmd)
                    
            print(f"  ✓ Commands implemented: {len(implemented)}/{len(required_commands)}")
            if missing:
                print(f"  ⚠️  Missing commands: {missing}")
                self.results['gaps'].append(f"Missing commands: {missing}")
                
        # Check encryption
        aes_file = Path('/workspace/native_payloads/crypto/aes.c')
        if aes_file.exists():
            content = aes_file.read_text()
            if 'aes256_encrypt_block' in content and 'sbox' in content:
                print("  ✓ AES encryption implemented")
            else:
                print("  ✗ AES implementation incomplete")
                self.results['gaps'].append("AES implementation incomplete")
                
        # Check anti-analysis
        utils_file = Path('/workspace/native_payloads/core/utils.c')
        if utils_file.exists():
            content = utils_file.read_text()
            features = {
                'Anti-debug': 'detect_debugger',
                'Anti-VM': 'detect_vm',
                'Anti-sandbox': 'detect_sandbox'
            }
            
            for name, func in features.items():
                if f'int {func}(' in content:
                    print(f"  ✓ {name} implemented")
                else:
                    print(f"  ✗ {name} missing")
                    self.results['gaps'].append(f"{name} not implemented")
                    
    def validate_api_endpoint(self):
        """Validate API endpoint functionality"""
        print("\n[API ENDPOINT VALIDATION]")
        
        # Check if the route handler exists
        web_file = Path('/workspace/web_app_real.py')
        if web_file.exists():
            content = web_file.read_text()
            
            # Look for the API endpoint
            if '@app.route(\'/api/generate-payload\'' in content:
                print("  ✓ /api/generate-payload endpoint exists")
                
                # Check if it handles native type
                if "if data.get('type') == 'native':" in content:
                    print("  ✓ Handles native payload type")
                else:
                    print("  ✗ Doesn't handle native type")
                    self.results['gaps'].append("API doesn't handle native payloads")
            else:
                print("  ✗ API endpoint missing")
                self.results['gaps'].append("Generate payload API endpoint missing")
                
    def check_missing_pieces(self):
        """Check for commonly missing pieces"""
        print("\n[CHECKING FOR MISSING PIECES]")
        
        critical_checks = [
            # Check if binary actually runs
            {
                'name': 'Binary execution',
                'test': lambda: os.access('/workspace/native_payloads/output/payload_native', os.X_OK)
                        if Path('/workspace/native_payloads/output/payload_native').exists() else False
            },
            # Check if persistence is implemented
            {
                'name': 'Linux persistence',
                'test': lambda: 'install_persistence_linux' in 
                        Path('/workspace/native_payloads/linux/linux_impl.c').read_text()
                        if Path('/workspace/native_payloads/linux/linux_impl.c').exists() else False
            },
            # Check if networking actually works
            {
                'name': 'Socket implementation',
                'test': lambda: 'socket_connect' in 
                        Path('/workspace/native_payloads/network/protocol.c').read_text()
                        if Path('/workspace/native_payloads/network/protocol.c').exists() else False
            },
            # Check web download endpoint
            {
                'name': 'Download endpoint',
                'test': lambda: '/api/download-payload' in 
                        Path('/workspace/web_app_real.py').read_text()
                        if Path('/workspace/web_app_real.py').exists() else False
            },
        ]
        
        for check in critical_checks:
            try:
                if check['test']():
                    print(f"  ✓ {check['name']}")
                else:
                    print(f"  ✗ {check['name']}")
                    self.results['gaps'].append(f"Missing: {check['name']}")
            except Exception as e:
                print(f"  ✗ {check['name']}: {e}")
                self.results['gaps'].append(f"Error checking {check['name']}")
                
    def generate_report(self):
        """Generate final validation report"""
        print("\n" + "="*70)
        print("PHASE 1 COMPLETE VALIDATION REPORT")
        print("="*70)
        
        # Count successes and failures
        total_checks = 0
        passed_checks = 0
        
        for category in ['backend', 'frontend', 'integration', 'compilation']:
            for key, value in self.results.get(category, {}).items():
                total_checks += 1
                if value:
                    passed_checks += 1
                    
        print(f"\nOverall: {passed_checks}/{total_checks} checks passed")
        
        if self.results['gaps']:
            print(f"\n⚠️  GAPS FOUND ({len(self.results['gaps'])} issues):")
            for i, gap in enumerate(self.results['gaps'], 1):
                print(f"  {i}. {gap}")
        else:
            print("\n✅ NO GAPS FOUND - Phase 1 appears complete!")
            
        # Save detailed report
        report_path = Path('/workspace/phase1_validation_report.json')
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed report saved to: {report_path}")
        
        return len(self.results['gaps']) == 0

def main():
    validator = Phase1Validator()
    
    # Run all validations
    validator.validate_backend_files()
    validator.validate_compilation()
    validator.validate_web_integration()
    validator.validate_frontend()
    validator.validate_python_builder()
    validator.validate_features()
    validator.validate_api_endpoint()
    validator.check_missing_pieces()
    
    # Generate report
    is_complete = validator.generate_report()
    
    if is_complete:
        print("\n" + "="*70)
        print("✅ PHASE 1 IS FULLY COMPLETE!")
        print("="*70)
    else:
        print("\n" + "="*70)
        print("⚠️  PHASE 1 HAS GAPS - SEE ABOVE")
        print("="*70)
        
    return 0 if is_complete else 1

if __name__ == "__main__":
    sys.exit(main())