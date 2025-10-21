#!/usr/bin/env python3
"""
Comprehensive Elite RAT Command Testing Suite
Tests all 63 elite commands in a controlled environment
"""

import sys
import os
import time
import json
import traceback
from typing import Dict, Any, List
import importlib

# Add workspace to path
sys.path.insert(0, '/workspace')

class EliteCommandTester:
    """Comprehensive testing framework for all elite commands"""
    
    def __init__(self):
        self.test_results = {}
        self.total_commands = 0
        self.passed_commands = 0
        self.failed_commands = 0
        self.skipped_commands = 0
        
        # List all commands to test
        self.commands_to_test = [
            # Original commands (enhanced)
            'ls', 'cd', 'pwd', 'cat', 'download', 'upload', 'rm', 'mkdir',
            'rmdir', 'mv', 'cp', 'systeminfo', 'whoami', 'hostname',
            'username', 'privileges', 'network', 'processes', 'vmscan',
            'installedsoftware', 'hidefile', 'hideprocess', 'clearlogs',
            'firewall', 'escalate', 'inject', 'migrate', 'port_forward',
            'ps', 'kill', 'shell', 'hashdump', 'chromedump', 'wifikeys',
            'screenshot', 'keylogger', 'persistence', 'webcam', 'restart',
            'shutdown', 'socks_proxy',
            
            # New missing commands implemented
            'askpassword', 'avscan', 'clearev', 'crackpassword', 'drives',
            'environment', 'fileinfo', 'freeze', 'hostsfile', 'location',
            'lockscreen', 'logintext', 'lsmod', 'popup', 'scanreg',
            'ssh', 'sudo', 'sysinfo', 'touch', 'webcamlist', 'webcamsnap'
        ]
        
        self.total_commands = len(self.commands_to_test)
    
    def test_command_import(self, command_name: str) -> Dict[str, Any]:
        """Test if a command can be imported"""
        
        try:
            # Try to import the command module
            module_name = f"Core.elite_commands.elite_{command_name}"
            module = importlib.import_module(module_name)
            
            # Try to get the function
            func_name = f"elite_{command_name}"
            if hasattr(module, func_name):
                func = getattr(module, func_name)
                return {
                    "success": True,
                    "module": module_name,
                    "function": func_name,
                    "callable": callable(func)
                }
            else:
                return {
                    "success": False,
                    "error": f"Function {func_name} not found in module",
                    "module": module_name
                }
        
        except ImportError as e:
            return {
                "success": False,
                "error": f"Import failed: {str(e)}",
                "module": module_name
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "module": module_name
            }
    
    def test_command_execution(self, command_name: str) -> Dict[str, Any]:
        """Test command execution with safe parameters"""
        
        try:
            # Import the command
            module_name = f"Core.elite_commands.elite_{command_name}"
            module = importlib.import_module(module_name)
            func = getattr(module, f"elite_{command_name}")
            
            # Define safe test parameters for each command
            test_params = self._get_safe_test_params(command_name)
            
            start_time = time.time()
            
            # Execute with safe parameters
            if test_params is None:
                # Commands that should not be executed (destructive)
                return {
                    "success": True,
                    "skipped": True,
                    "reason": "Destructive command - skipped for safety",
                    "execution_time": 0
                }
            
            result = func(**test_params)
            execution_time = time.time() - start_time
            
            return {
                "success": True,
                "executed": True,
                "result": result,
                "execution_time": execution_time,
                "test_params": test_params
            }
        
        except Exception as e:
            return {
                "success": False,
                "executed": True,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "test_params": test_params if 'test_params' in locals() else None
            }
    
    def _get_safe_test_params(self, command_name: str) -> Dict[str, Any]:
        """Get safe test parameters for each command"""
        
        # Commands that should not be executed (destructive/dangerous)
        destructive_commands = {
            'rm', 'rmdir', 'kill', 'shutdown', 'restart', 'clearlogs',
            'hidefile', 'hideprocess', 'escalate', 'inject', 'migrate',
            'hashdump', 'keylogger', 'freeze', 'lockscreen', 'clearev'
        }
        
        if command_name in destructive_commands:
            return None  # Skip execution
        
        # Safe parameters for each command type
        safe_params = {
            # File system commands (read-only)
            'ls': {'directory': '/tmp'},
            'pwd': {},
            'cat': {'filepath': '/etc/hostname'},
            'cd': {'path': '/tmp'},
            'mkdir': {'dirpath': '/tmp/test_elite_mkdir'},
            'mv': {'source': '/tmp/nonexistent', 'destination': '/tmp/nonexistent2'},
            'cp': {'source': '/tmp/nonexistent', 'destination': '/tmp/nonexistent2'},
            'touch': {'filepath': '/tmp/test_elite_touch.txt'},
            'fileinfo': {'filepath': '/etc/hostname'},
            
            # System info commands (safe)
            'systeminfo': {},
            'sysinfo': {},
            'whoami': {},
            'hostname': {},
            'username': {},
            'privileges': {},
            'network': {},
            'processes': {},
            'ps': {},
            'vmscan': {},
            'installedsoftware': {},
            'environment': {'action': 'list'},
            'drives': {},
            'lsmod': {},
            
            # Network commands (read-only)
            'location': {'method': 'system'},
            'hostsfile': {'action': 'list'},
            
            # Security commands (read-only)
            'avscan': {},
            'scanreg': {'scan_type': 'security', 'deep_scan': False},
            
            # Media commands (list only)
            'webcamlist': {},
            'webcamsnap': {'device_id': 0, 'output_file': '/tmp/test_webcam.jpg'},
            
            # Interactive commands (safe parameters)
            'popup': {'message': 'Test message', 'title': 'Test', 'timeout': 1},
            'askpassword': {'title': 'Test', 'message': 'Test message'},
            'logintext': {'action': 'get'},
            
            # Network tools (safe)
            'ssh': {'host': 'localhost', 'command': 'echo test', 'username': 'test'},
            'sudo': {'command': 'whoami'},
            
            # Analysis commands
            'crackpassword': {'hash_value': 'test_hash', 'hash_type': 'md5'},
            
            # Default safe parameters
            'download': {'filepath': '/tmp/test_download.txt'},
            'upload': {'filepath': '/tmp/test_upload.txt', 'chunks_data': ['test_data']},
            'shell': {'command': 'echo test'},
            'chromedump': {},
            'wifikeys': {},
            'screenshot': {},
            'persistence': {},
            'webcam': {},
            'port_forward': {'local_port': 8080, 'remote_host': 'localhost', 'remote_port': 80},
            'socks_proxy': {'port': 1080}
        }
        
        return safe_params.get(command_name, {})
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive test of all commands"""
        
        print("🧪 Starting Comprehensive Elite RAT Command Testing")
        print(f"📊 Testing {self.total_commands} commands")
        print("=" * 60)
        
        for i, command_name in enumerate(self.commands_to_test, 1):
            print(f"\n[{i:2d}/{self.total_commands}] Testing: elite_{command_name}")
            
            # Test 1: Import test
            import_result = self.test_command_import(command_name)
            
            # Test 2: Execution test (if import successful)
            execution_result = None
            if import_result["success"]:
                execution_result = self.test_command_execution(command_name)
            
            # Store results
            self.test_results[command_name] = {
                "import_test": import_result,
                "execution_test": execution_result,
                "timestamp": time.time()
            }
            
            # Update counters
            if import_result["success"]:
                if execution_result:
                    if execution_result.get("skipped"):
                        self.skipped_commands += 1
                        print(f"    ⚠️  SKIPPED: {execution_result.get('reason', 'Safety')}")
                    elif execution_result["success"]:
                        self.passed_commands += 1
                        print(f"    ✅ PASSED: Import + Execution successful")
                    else:
                        self.failed_commands += 1
                        print(f"    ❌ FAILED: {execution_result.get('error', 'Unknown error')}")
                else:
                    self.failed_commands += 1
                    print(f"    ❌ FAILED: Execution test failed")
            else:
                self.failed_commands += 1
                print(f"    ❌ FAILED: {import_result.get('error', 'Import failed')}")
        
        # Generate summary
        summary = {
            "total_commands": self.total_commands,
            "passed": self.passed_commands,
            "failed": self.failed_commands,
            "skipped": self.skipped_commands,
            "success_rate": (self.passed_commands / self.total_commands) * 100,
            "test_timestamp": time.time(),
            "detailed_results": self.test_results
        }
        
        return summary
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive test report"""
        
        report = []
        report.append("=" * 80)
        report.append("ELITE RAT COMPREHENSIVE COMMAND TESTING REPORT")
        report.append("=" * 80)
        report.append(f"Test Date: {time.ctime(results['test_timestamp'])}")
        report.append(f"Total Commands Tested: {results['total_commands']}")
        report.append(f"Passed: {results['passed']} ({results['success_rate']:.1f}%)")
        report.append(f"Failed: {results['failed']}")
        report.append(f"Skipped: {results['skipped']}")
        report.append("")
        
        # Detailed results
        report.append("DETAILED RESULTS:")
        report.append("-" * 40)
        
        for cmd_name, cmd_results in results['detailed_results'].items():
            import_success = cmd_results['import_test']['success']
            exec_result = cmd_results['execution_test']
            
            status = "❌ FAILED"
            if import_success:
                if exec_result and exec_result.get('skipped'):
                    status = "⚠️  SKIPPED"
                elif exec_result and exec_result['success']:
                    status = "✅ PASSED"
            
            report.append(f"{status} elite_{cmd_name}")
            
            if not import_success:
                report.append(f"    Import Error: {cmd_results['import_test']['error']}")
            elif exec_result and not exec_result['success'] and not exec_result.get('skipped'):
                report.append(f"    Execution Error: {exec_result['error']}")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)

def main():
    """Main testing function"""
    
    tester = EliteCommandTester()
    
    try:
        # Run comprehensive test
        results = tester.run_comprehensive_test()
        
        # Generate and save report
        report = tester.generate_report(results)
        
        # Save results to files
        with open('/workspace/test_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        with open('/workspace/test_report.txt', 'w') as f:
            f.write(report)
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 TESTING COMPLETE!")
        print(f"📊 Results: {results['passed']}/{results['total_commands']} passed ({results['success_rate']:.1f}%)")
        print(f"📁 Detailed results saved to: test_results.json")
        print(f"📄 Report saved to: test_report.txt")
        
        return results
    
    except Exception as e:
        print(f"❌ Testing failed with error: {str(e)}")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    main()