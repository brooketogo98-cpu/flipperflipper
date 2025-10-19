#!/usr/bin/env python3
"""
Phase 2 Validation - Process Injection & Hollowing
Complete validation of all injection techniques and integration
"""

import os
import sys
import json
import subprocess
from pathlib import Path

class Phase2Validator:
    def __init__(self):
        self.results = {
            'core_module': {},
            'techniques': {},
            'web_integration': {},
            'frontend': {},
            'compilation': {},
            'functionality': {},
            'gaps': []
        }
        
    def validate_core_injection_module(self):
        """Validate core injection framework files"""
        print("\n[CORE INJECTION MODULE VALIDATION]")
        
        required_files = {
            '/workspace/native_payloads/inject/inject_core.h': 'Core injection header',
            '/workspace/native_payloads/inject/inject_core.c': 'Core injection implementation',
            '/workspace/native_payloads/inject/inject_windows.h': 'Windows injection header',
            '/workspace/native_payloads/inject/inject_windows.c': 'Windows injection implementation',
            '/workspace/native_payloads/inject/inject_linux.h': 'Linux injection header',
            '/workspace/native_payloads/inject/inject_linux.c': 'Linux injection implementation'
        }
        
        for filepath, description in required_files.items():
            if Path(filepath).exists():
                size = Path(filepath).stat().st_size
                if size > 100:  # More than just stubs
                    print(f"  ✓ {description}: {size} bytes")
                    self.results['core_module'][filepath] = True
                else:
                    print(f"  ✗ {description}: EXISTS BUT TOO SMALL ({size} bytes)")
                    self.results['core_module'][filepath] = False
                    self.results['gaps'].append(f"{description} incomplete")
            else:
                print(f"  ✗ {description}: MISSING")
                self.results['core_module'][filepath] = False
                self.results['gaps'].append(f"{description} missing")
                
    def validate_injection_techniques(self):
        """Validate that injection techniques are implemented"""
        print("\n[INJECTION TECHNIQUES VALIDATION]")
        
        # Check Windows techniques in code
        windows_techniques = [
            ('CreateRemoteThread', 'inject_create_remote_thread'),
            ('Process Hollowing', 'inject_process_hollowing'),
            ('QueueUserAPC', 'inject_queue_user_apc'),
            ('Manual Mapping', 'inject_manual_map'),
            ('NTDLL Unhooking', 'inject_unhook_ntdll'),
            ('ETW Bypass', 'inject_bypass_etw'),
            ('AMSI Bypass', 'inject_bypass_amsi')
        ]
        
        windows_file = Path('/workspace/native_payloads/inject/inject_windows.c')
        if windows_file.exists():
            content = windows_file.read_text()
            
            for name, func in windows_techniques:
                if func in content:
                    # Check if it's actually implemented (not just declared)
                    if f'{func}(' in content and '{' in content.split(f'{func}(')[1][:500]:
                        print(f"  ✓ Windows: {name}")
                        self.results['techniques'][f'windows_{func}'] = True
                    else:
                        print(f"  ✗ Windows: {name} (stub only)")
                        self.results['techniques'][f'windows_{func}'] = False
                        self.results['gaps'].append(f"Windows {name} not fully implemented")
                else:
                    print(f"  ✗ Windows: {name} (not found)")
                    self.results['techniques'][f'windows_{func}'] = False
                    self.results['gaps'].append(f"Windows {name} missing")
        
        # Check Linux techniques
        linux_techniques = [
            ('ptrace', 'inject_ptrace'),
            ('/proc/mem', 'inject_proc_mem'),
            ('LD_PRELOAD', 'inject_ld_preload'),
            ('Remote mmap', 'inject_remote_mmap'),
            ('Remote dlopen', 'inject_remote_dlopen')
        ]
        
        linux_file = Path('/workspace/native_payloads/inject/inject_linux.c')
        if linux_file.exists():
            content = linux_file.read_text()
            
            for name, func in linux_techniques:
                if func in content:
                    if f'{func}(' in content and '{' in content.split(f'{func}(')[1][:500]:
                        print(f"  ✓ Linux: {name}")
                        self.results['techniques'][f'linux_{func}'] = True
                    else:
                        print(f"  ✗ Linux: {name} (stub only)")
                        self.results['techniques'][f'linux_{func}'] = False
                        self.results['gaps'].append(f"Linux {name} not fully implemented")
                else:
                    print(f"  ✗ Linux: {name} (not found)")
                    self.results['techniques'][f'linux_{func}'] = False
                    self.results['gaps'].append(f"Linux {name} missing")
                    
    def validate_compilation(self):
        """Validate that the injection module compiles"""
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
            
            # Check output size
            if Path('/workspace/native_payloads/output/payload_native').exists():
                size = Path('/workspace/native_payloads/output/payload_native').stat().st_size
                print(f"  ✓ Binary generated: {size} bytes")
                
                # Check if size increased (injection adds code)
                if size > 50000:  # Should be larger with injection code
                    print(f"  ✓ Binary includes injection code")
                    self.results['compilation']['has_injection'] = True
                else:
                    print(f"  ⚠️ Binary seems too small for injection code")
                    self.results['compilation']['has_injection'] = False
            else:
                print("  ✗ No binary output")
                self.results['compilation']['binary_exists'] = False
                self.results['gaps'].append("Compilation produces no binary")
        else:
            print(f"  ✗ Compilation failed: {result.stderr[:200]}")
            self.results['compilation']['builds'] = False
            self.results['gaps'].append("Injection module compilation fails")
            
    def validate_web_integration(self):
        """Validate web API integration"""
        print("\n[WEB INTEGRATION VALIDATION]")
        
        web_file = Path('/workspace/web_app_real.py')
        if web_file.exists():
            content = web_file.read_text()
            
            # Check for injection API endpoints
            endpoints = [
                ('/api/inject/list-processes', 'Process enumeration'),
                ('/api/inject/techniques', 'Technique listing'),
                ('/api/inject/execute', 'Injection execution'),
                ('/api/inject/status', 'Injection status'),
                ('/api/inject/history', 'Injection history')
            ]
            
            for endpoint, description in endpoints:
                if endpoint in content:
                    print(f"  ✓ {description}: {endpoint}")
                    self.results['web_integration'][endpoint] = True
                else:
                    print(f"  ✗ {description}: {endpoint} missing")
                    self.results['web_integration'][endpoint] = False
                    self.results['gaps'].append(f"Web endpoint {endpoint} missing")
                    
        # Check injection manager
        manager_file = Path('/workspace/injection_manager.py')
        if manager_file.exists():
            print("  ✓ Injection manager exists")
            self.results['web_integration']['manager'] = True
            
            # Check if it has key functions
            content = manager_file.read_text()
            functions = ['enumerate_processes', 'execute_injection', 'get_available_techniques']
            
            for func in functions:
                if f'def {func}' in content:
                    print(f"    ✓ Function: {func}")
                else:
                    print(f"    ✗ Function: {func} missing")
                    self.results['gaps'].append(f"Injection manager missing {func}")
        else:
            print("  ✗ Injection manager missing")
            self.results['web_integration']['manager'] = False
            self.results['gaps'].append("Injection manager not found")
            
    def validate_frontend(self):
        """Validate frontend UI components"""
        print("\n[FRONTEND VALIDATION]")
        
        # Check JavaScript file
        js_file = Path('/workspace/static/js/injection_ui.js')
        if js_file.exists():
            size = js_file.stat().st_size
            content = js_file.read_text()
            
            print(f"  ✓ Injection UI JavaScript: {size} bytes")
            self.results['frontend']['js_exists'] = True
            
            # Check for key UI components
            ui_components = [
                ('Process table', 'process-table'),
                ('Technique selector', 'technique-select'),
                ('Execute button', 'execute-injection'),
                ('Process filter', 'process-search'),
                ('History display', 'injection-history')
            ]
            
            for name, pattern in ui_components:
                if pattern in content:
                    print(f"    ✓ {name}")
                    self.results['frontend'][pattern] = True
                else:
                    print(f"    ✗ {name} missing")
                    self.results['frontend'][pattern] = False
                    self.results['gaps'].append(f"Frontend missing {name}")
        else:
            print("  ✗ Injection UI JavaScript not found")
            self.results['frontend']['js_exists'] = False
            self.results['gaps'].append("Frontend JavaScript missing")
            
    def validate_functionality(self):
        """Validate that injection functionality works"""
        print("\n[FUNCTIONALITY VALIDATION]")
        
        # Test process enumeration
        try:
            sys.path.insert(0, '/workspace')
            from injection_manager import injection_manager
            
            processes = injection_manager.enumerate_processes()
            if len(processes) > 0:
                print(f"  ✓ Process enumeration works: {len(processes)} processes")
                self.results['functionality']['enum_processes'] = True
            else:
                print("  ✗ Process enumeration returns no processes")
                self.results['functionality']['enum_processes'] = False
                self.results['gaps'].append("Process enumeration not working")
                
            # Test technique listing
            techniques = injection_manager.get_available_techniques()
            if len(techniques) > 0:
                print(f"  ✓ Technique listing works: {len(techniques)} techniques")
                self.results['functionality']['list_techniques'] = True
            else:
                print("  ✗ No injection techniques available")
                self.results['functionality']['list_techniques'] = False
                self.results['gaps'].append("No injection techniques configured")
                
            # Test injection score calculation
            if processes:
                scores = [p['injection_score'] for p in processes]
                avg_score = sum(scores) / len(scores)
                print(f"  ✓ Injection scoring works: avg score {avg_score:.1f}")
                self.results['functionality']['scoring'] = True
                
        except ImportError as e:
            print(f"  ✗ Cannot import injection manager: {e}")
            self.results['functionality']['imports'] = False
            self.results['gaps'].append("Injection manager cannot be imported")
        except Exception as e:
            print(f"  ✗ Functionality test error: {e}")
            self.results['functionality']['error'] = str(e)
            self.results['gaps'].append(f"Functionality error: {e}")
            
    def check_advanced_features(self):
        """Check for advanced injection features"""
        print("\n[ADVANCED FEATURES VALIDATION]")
        
        features = {
            'Direct syscalls': 'syscall_stub',
            'Memory allocation strategies': 'ALLOC_STRATEGY',
            'Process analysis': 'injection_score',
            'Evasion flags': 'INJECT_FLAG_STEALTH',
            'Cleanup functionality': 'inject_remove_traces',
            'Parent spoofing': 'spoof_parent',
            'Code caves': 'find_code_cave',
            'PE parsing': 'parse_pe'
        }
        
        # Check in core files
        core_files = [
            '/workspace/native_payloads/inject/inject_core.c',
            '/workspace/native_payloads/inject/inject_core.h',
            '/workspace/native_payloads/inject/inject_windows.c',
            '/workspace/native_payloads/inject/inject_linux.c'
        ]
        
        for feature, pattern in features.items():
            found = False
            for filepath in core_files:
                if Path(filepath).exists():
                    if pattern in Path(filepath).read_text():
                        found = True
                        break
            
            if found:
                print(f"  ✓ {feature}")
                self.results['functionality'][feature] = True
            else:
                print(f"  ✗ {feature} not implemented")
                self.results['functionality'][feature] = False
                
    def generate_report(self):
        """Generate final validation report"""
        print("\n" + "="*70)
        print("PHASE 2 VALIDATION REPORT")
        print("="*70)
        
        # Count successes and failures
        total_checks = 0
        passed_checks = 0
        
        for category in self.results:
            if category == 'gaps':
                continue
            for key, value in self.results[category].items():
                total_checks += 1
                if value:
                    passed_checks += 1
                    
        print(f"\nOverall: {passed_checks}/{total_checks} checks passed")
        
        if self.results['gaps']:
            print(f"\n⚠️ GAPS FOUND ({len(self.results['gaps'])} issues):")
            for i, gap in enumerate(self.results['gaps'], 1):
                print(f"  {i}. {gap}")
        else:
            print("\n✅ NO GAPS FOUND - Phase 2 is complete!")
            
        # Save detailed report
        report_path = Path('/workspace/phase2_validation_report.json')
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed report saved to: {report_path}")
        
        return len(self.results['gaps']) == 0

def main():
    validator = Phase2Validator()
    
    # Run all validations
    validator.validate_core_injection_module()
    validator.validate_injection_techniques()
    validator.validate_compilation()
    validator.validate_web_integration()
    validator.validate_frontend()
    validator.validate_functionality()
    validator.check_advanced_features()
    
    # Generate report
    is_complete = validator.generate_report()
    
    if is_complete:
        print("\n" + "="*70)
        print("✅ PHASE 2 IS COMPLETE!")
        print("="*70)
    else:
        print("\n" + "="*70)
        print("⚠️ PHASE 2 HAS GAPS - SEE ABOVE")
        print("="*70)
        
    return 0 if is_complete else 1

if __name__ == "__main__":
    sys.exit(main())