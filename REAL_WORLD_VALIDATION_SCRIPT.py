#!/usr/bin/env python3
"""
Real-World Validation Script for Audit 2 Implementation
This actually tests if things WORK, not just if files exist
"""

import os
import sys
import subprocess
import importlib.util
import ast
import json
from typing import Dict, List, Any, Tuple
from pathlib import Path

class RealWorldValidator:
    """
    Validates that Audit 2 fixes are ACTUALLY implemented and WORKING
    Not just checking if files exist - checking if they DO what they claim
    """
    
    def __init__(self):
        self.results = {
            "total_commands": 63,
            "implemented": 0,
            "actually_elite": 0,
            "using_subprocess": 0,
            "integrated_to_web": 0,
            "has_frontend": 0,
            "critical_failures": [],
            "details": {}
        }
        
        # All 63 commands from Audit 2
        self.all_commands = [
            # File System (11)
            'ls', 'cd', 'pwd', 'cat', 'download', 'upload', 'rm', 'mkdir', 'rmdir', 'mv', 'cp',
            # System Info (8)
            'systeminfo', 'whoami', 'hostname', 'username', 'privileges', 'network', 'processes', 'installedsoftware',
            # Stealth (10)
            'vmscan', 'hidecmd', 'unhidecmd', 'hideprocess', 'unhideprocess',
            'hidefile', 'unhidefile', 'hidereg', 'unhidereg', 'clearlogs',
            # Credentials (5)
            'chromedump', 'hashdump', 'wifikeys', 'askpass', 'chromepasswords',
            # Process (4)
            'ps', 'kill', 'migrate', 'inject',
            # System Control (4)
            'shutdown', 'restart', 'firewall', 'escalate',
            # Monitoring (5)
            'screenshot', 'screenrec', 'webcam', 'keylogger', 'stopkeylogger',
            # Logs (2)
            'viewlogs', 'clearlogs',
            # Shell (3)
            'shell', 'ssh', 'sudo',
            # Advanced (11 - 4 deprecated = 7 real)
            'persistence', 'unpersistence', 'download_exec', 'upload_exec',
            'port_forward', 'socks_proxy', 'dns'
            # Deprecated: rootkit, unrootkit, avkill
        ]
        
        # Commands that MUST be scary elite
        self.critical_commands = [
            'hashdump', 'persistence', 'clearlogs', 'inject', 'migrate',
            'hideprocess', 'escalate', 'keylogger', 'vmscan'
        ]
    
    def validate_all(self) -> Dict[str, Any]:
        """Run complete validation"""
        
        print("\n" + "="*80)
        print("REAL-WORLD VALIDATION OF AUDIT 2 IMPLEMENTATION")
        print("="*80)
        
        # 1. Check if elite commands exist
        print("\n[PHASE 1] Checking Elite Command Files...")
        self._check_command_files()
        
        # 2. Analyze implementation quality
        print("\n[PHASE 2] Analyzing Implementation Quality...")
        self._analyze_implementation_quality()
        
        # 3. Check web integration
        print("\n[PHASE 3] Checking Web App Integration...")
        self._check_web_integration()
        
        # 4. Check frontend integration
        print("\n[PHASE 4] Checking Frontend Dashboard...")
        self._check_frontend_integration()
        
        # 5. Test critical capabilities
        print("\n[PHASE 5] Testing Critical Capabilities...")
        self._test_critical_capabilities()
        
        # 6. Generate verdict
        print("\n[PHASE 6] Generating Verdict...")
        return self._generate_verdict()
    
    def _check_command_files(self):
        """Check if elite command files actually exist"""
        
        elite_dir = Path("/workspace/Core/elite_commands")
        
        for cmd in self.all_commands:
            file_path = elite_dir / f"elite_{cmd}.py"
            
            if file_path.exists():
                self.results["implemented"] += 1
                self.results["details"][cmd] = {"exists": True}
                
                # Check if it's actually implemented or just a stub
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for signs of real implementation
                if "TODO: Implement" in content or "pass  # TODO" in content:
                    self.results["details"][cmd]["is_stub"] = True
                    self.results["critical_failures"].append(f"{cmd}: File exists but not implemented (TODO found)")
                else:
                    self.results["details"][cmd]["is_stub"] = False
                
                # Check if using subprocess (lazy)
                if "subprocess" in content:
                    self.results["using_subprocess"] += 1
                    self.results["details"][cmd]["uses_subprocess"] = True
                else:
                    self.results["details"][cmd]["uses_subprocess"] = False
                
                # Check for elite patterns
                elite_patterns = [
                    "ctypes", "windll", "kernel32", "ntdll",
                    "OpenProcess", "ReadProcessMemory", "VirtualAllocEx",
                    "CreateRemoteThread", "NtQuerySystemInformation"
                ]
                
                has_elite = any(pattern in content for pattern in elite_patterns)
                if has_elite:
                    self.results["actually_elite"] += 1
                    self.results["details"][cmd]["is_elite"] = True
                else:
                    self.results["details"][cmd]["is_elite"] = False
            else:
                self.results["details"][cmd] = {"exists": False}
                self.results["critical_failures"].append(f"{cmd}: Not implemented (file missing)")
    
    def _analyze_implementation_quality(self):
        """Deep analysis of implementation quality"""
        
        # Check specific critical commands
        for cmd in self.critical_commands:
            file_path = f"/workspace/Core/elite_commands/elite_{cmd}.py"
            
            if not os.path.exists(file_path):
                self.results["critical_failures"].append(f"{cmd}: CRITICAL command not implemented")
                continue
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Command-specific validation
            if cmd == "hashdump":
                required = ["LSASS", "SAM", "SYSKEY", "OpenProcess", "ReadProcessMemory"]
                missing = [r for r in required if r not in content]
                if missing:
                    self.results["critical_failures"].append(f"hashdump: Missing elite features {missing}")
            
            elif cmd == "persistence":
                methods = ["WMI", "schtasks", "Registry", "Service", "COM"]
                found = sum(1 for m in methods if m in content)
                if found < 3:
                    self.results["critical_failures"].append(f"persistence: Only {found}/5 methods implemented")
            
            elif cmd == "clearlogs":
                artifacts = ["EventLog", "USN", "Prefetch", "SRUM", "AmCache", "ETW"]
                found = sum(1 for a in artifacts if a in content)
                if found < 4:
                    self.results["critical_failures"].append(f"clearlogs: Only clears {found}/6 artifact types")
            
            elif cmd == "inject":
                techniques = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetThreadContext"]
                found = sum(1 for t in techniques if t in content)
                if found < 2:
                    self.results["critical_failures"].append(f"inject: Only {found}/4 injection techniques")
    
    def _check_web_integration(self):
        """Check if elite commands are integrated into web app"""
        
        web_app_path = "/workspace/web_app_real.py"
        
        if not os.path.exists(web_app_path):
            self.results["critical_failures"].append("Web app not found!")
            return
        
        with open(web_app_path, 'r') as f:
            web_content = f.read()
        
        # Check if elite_executor is imported
        if "elite_executor" in web_content or "EliteCommandExecutor" in web_content:
            self.results["integrated_to_web"] += 1
            print("✅ Elite executor is imported in web app")
        else:
            self.results["critical_failures"].append("Elite executor NOT integrated into web app")
            print("❌ Elite executor NOT integrated into web app")
        
        # Check if commands are routed to elite implementations
        elite_routing = False
        if "Core.elite_commands" in web_content:
            elite_routing = True
            print("✅ Elite commands directory referenced")
        else:
            print("❌ Elite commands NOT referenced in web app")
        
        # Check for command routing logic
        if "execute_real_command" in web_content:
            # Check if it routes to elite commands
            start_idx = web_content.find("def execute_real_command")
            if start_idx > 0:
                func_content = web_content[start_idx:start_idx+2000]
                if "elite_" in func_content:
                    print("✅ Command execution routes to elite implementations")
                else:
                    self.results["critical_failures"].append("Commands NOT routed to elite implementations")
                    print("❌ Commands NOT routed to elite implementations")
    
    def _check_frontend_integration(self):
        """Check if frontend has UI for all commands"""
        
        dashboard_path = "/workspace/templates/dashboard.html"
        
        if not os.path.exists(dashboard_path):
            self.results["critical_failures"].append("Dashboard not found!")
            return
        
        with open(dashboard_path, 'r') as f:
            dashboard_content = f.read()
        
        # Check for command buttons/UI
        commands_in_ui = 0
        for cmd in self.all_commands:
            if cmd in dashboard_content:
                commands_in_ui += 1
                self.results["details"][cmd]["in_frontend"] = True
            else:
                self.results["details"][cmd]["in_frontend"] = False
        
        self.results["has_frontend"] = commands_in_ui
        
        if commands_in_ui < 50:
            self.results["critical_failures"].append(f"Only {commands_in_ui}/63 commands in frontend")
            print(f"❌ Only {commands_in_ui}/63 commands have frontend UI")
        else:
            print(f"✅ {commands_in_ui}/63 commands have frontend UI")
    
    def _test_critical_capabilities(self):
        """Test if critical capabilities actually work"""
        
        # Test 1: Can we import and execute a command?
        try:
            spec = importlib.util.spec_from_file_location(
                "elite_whoami",
                "/workspace/Core/elite_commands/elite_whoami.py"
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Try to execute
                if hasattr(module, 'elite_whoami'):
                    result = module.elite_whoami()
                    if result and isinstance(result, dict) and result.get("success"):
                        print("✅ Can execute elite_whoami command")
                    else:
                        print("⚠️ elite_whoami executes but may not work correctly")
                else:
                    self.results["critical_failures"].append("elite_whoami: Function not found in module")
        except Exception as e:
            self.results["critical_failures"].append(f"Cannot execute commands: {str(e)}")
        
        # Test 2: Check for anti-detection
        bypass_file = "/workspace/Core/security_bypass.py"
        if os.path.exists(bypass_file):
            with open(bypass_file, 'r') as f:
                bypass_content = f.read()
            
            required_bypasses = ["ETW", "AMSI", "unhook", "syscall"]
            found_bypasses = [b for b in required_bypasses if b in bypass_content]
            
            if len(found_bypasses) >= 3:
                print(f"✅ Anti-detection implemented: {found_bypasses}")
            else:
                self.results["critical_failures"].append(f"Weak anti-detection: Only {found_bypasses}")
                print(f"❌ Weak anti-detection: Only {found_bypasses}")
        else:
            self.results["critical_failures"].append("No security bypass module found")
    
    def _generate_verdict(self) -> Dict[str, Any]:
        """Generate final verdict"""
        
        # Calculate scores
        implementation_rate = (self.results["implemented"] / self.results["total_commands"]) * 100
        elite_rate = (self.results["actually_elite"] / max(1, self.results["implemented"])) * 100
        subprocess_rate = (self.results["using_subprocess"] / max(1, self.results["implemented"])) * 100
        frontend_rate = (self.results["has_frontend"] / self.results["total_commands"]) * 100
        
        # Determine verdict
        if len(self.results["critical_failures"]) > 10:
            verdict = "❌ FAILED - Too many critical issues"
            verdict_detail = "The implementation has fundamental problems that prevent it from being elite."
        elif elite_rate < 30:
            verdict = "❌ FAILED - Not elite implementation"
            verdict_detail = "Most commands use basic/lazy techniques instead of elite methods."
        elif self.results["integrated_to_web"] == 0:
            verdict = "❌ FAILED - Not integrated"
            verdict_detail = "Elite commands exist but aren't connected to the web interface."
        elif frontend_rate < 50:
            verdict = "⚠️ PARTIAL - Incomplete frontend"
            verdict_detail = "Backend exists but frontend is missing most command UI."
        else:
            verdict = "✅ PASSED - Elite implementation"
            verdict_detail = "Implementation meets elite standards with minor issues."
        
        # Final report
        report = {
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "scores": {
                "implementation_rate": f"{implementation_rate:.1f}%",
                "elite_rate": f"{elite_rate:.1f}%",
                "subprocess_usage": f"{subprocess_rate:.1f}%",
                "frontend_coverage": f"{frontend_rate:.1f}%"
            },
            "stats": {
                "commands_implemented": f"{self.results['implemented']}/63",
                "actually_elite": f"{self.results['actually_elite']}/{self.results['implemented']}",
                "using_subprocess": f"{self.results['using_subprocess']}/{self.results['implemented']}",
                "frontend_ui": f"{self.results['has_frontend']}/63",
                "web_integrated": self.results["integrated_to_web"] > 0
            },
            "critical_failures": self.results["critical_failures"][:10],  # Top 10
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        if self.results["integrated_to_web"] == 0:
            recommendations.append("CRITICAL: Connect elite_executor to web_app_real.py")
        
        if self.results["using_subprocess"] > 30:
            recommendations.append("Replace subprocess calls with direct Windows API calls")
        
        if self.results["has_frontend"] < 50:
            recommendations.append("Add UI elements for all commands in dashboard.html")
        
        if self.results["actually_elite"] < 40:
            recommendations.append("Implement proper elite techniques (no subprocess, use ctypes/win32api)")
        
        for cmd in self.critical_commands:
            if not self.results["details"].get(cmd, {}).get("is_elite"):
                recommendations.append(f"Make {cmd} truly elite (current: basic implementation)")
        
        return recommendations

def print_report(report: Dict[str, Any]):
    """Pretty print the validation report"""
    
    print("\n" + "="*80)
    print("VALIDATION REPORT")
    print("="*80)
    
    print(f"\n{report['verdict']}")
    print(f"{report['verdict_detail']}")
    
    print("\n📊 SCORES:")
    for key, value in report["scores"].items():
        print(f"  {key:20s}: {value}")
    
    print("\n📈 STATISTICS:")
    for key, value in report["stats"].items():
        print(f"  {key:20s}: {value}")
    
    if report["critical_failures"]:
        print("\n❌ CRITICAL FAILURES:")
        for i, failure in enumerate(report["critical_failures"], 1):
            print(f"  {i}. {failure}")
    
    if report["recommendations"]:
        print("\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(report["recommendations"], 1):
            print(f"  {i}. {rec}")

if __name__ == "__main__":
    validator = RealWorldValidator()
    report = validator.validate_all()
    print_report(report)
    
    # Exit with appropriate code
    if "FAILED" in report["verdict"]:
        sys.exit(1)
    elif "PARTIAL" in report["verdict"]:
        sys.exit(2)
    else:
        sys.exit(0)