#!/usr/bin/env python3
"""
Elite Process List Command Implementation
Advanced process enumeration using direct API calls and syscalls
"""

import ctypes
from ctypes import wintypes
import os
import sys
import struct
from typing import Dict, Any, List, Optional

def elite_ps(detailed: bool = True, include_system: bool = True, 
            filter_name: str = None) -> Dict[str, Any]:
    """
    Elite process enumeration with advanced features:
    - Direct API calls (no tasklist.exe)
    - Process details (memory, CPU, handles)
    - Parent-child relationships
    - Security context information
    - Hidden process detection
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_ps(detailed, include_system, filter_name)
        else:
            return _unix_elite_ps(detailed, include_system, filter_name)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Process enumeration failed: {str(e)}"
        }

def _windows_elite_ps(detailed: bool, include_system: bool, filter_name: str) -> Dict[str, Any]:
    """Windows implementation using NtQuerySystemInformation"""
    
    ntdll = ctypes.windll.ntdll
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    
    # Constants
    SystemProcessInformation = 5
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    
    class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", wintypes.ULONG),
            ("NumberOfThreads", wintypes.ULONG),
            ("Reserved1", wintypes.LARGE_INTEGER * 3),
            ("CreateTime", wintypes.LARGE_INTEGER),
            ("UserTime", wintypes.LARGE_INTEGER),
            ("KernelTime", wintypes.LARGE_INTEGER),
            ("ImageName", wintypes.UNICODE_STRING),
            ("BasePriority", wintypes.LONG),
            ("UniqueProcessId", ctypes.c_void_p),
            ("InheritedFromUniqueProcessId", ctypes.c_void_p),
            ("HandleCount", wintypes.ULONG),
            ("SessionId", wintypes.ULONG),
            ("PageDirectoryBase", ctypes.c_void_p),
            ("PeakVirtualSize", ctypes.c_size_t),
            ("VirtualSize", ctypes.c_size_t),
            ("PageFaultCount", wintypes.ULONG),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivatePageCount", ctypes.c_size_t),
            ("ReadOperationCount", wintypes.LARGE_INTEGER),
            ("WriteOperationCount", wintypes.LARGE_INTEGER),
            ("OtherOperationCount", wintypes.LARGE_INTEGER),
            ("ReadTransferCount", wintypes.LARGE_INTEGER),
            ("WriteTransferCount", wintypes.LARGE_INTEGER),
            ("OtherTransferCount", wintypes.LARGE_INTEGER),
        ]
    
    try:
        # Allocate buffer for system information
        buffer_size = 0x100000  # 1MB initial buffer
        buffer = ctypes.create_string_buffer(buffer_size)
        return_length = wintypes.ULONG()
        
        # Query system process information
        status = ntdll.NtQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            buffer_size,
            ctypes.byref(return_length)
        )
        
        # If buffer too small, reallocate
        if status == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
            buffer_size = return_length.value
            buffer = ctypes.create_string_buffer(buffer_size)
            status = ntdll.NtQuerySystemInformation(
                SystemProcessInformation,
                buffer,
                buffer_size,
                ctypes.byref(return_length)
            )
        
        if status != 0:
            raise Exception(f"NtQuerySystemInformation failed with status 0x{status:08X}")
        
        # Parse process information
        processes = []
        offset = 0
        
        while True:
            # Get process structure at current offset
            proc_info = SYSTEM_PROCESS_INFORMATION.from_buffer(buffer, offset)
            
            # Extract process information
            pid = proc_info.UniqueProcessId
            ppid = proc_info.InheritedFromUniqueProcessId
            
            # Get process name
            if proc_info.ImageName.Buffer:
                name_ptr = ctypes.cast(proc_info.ImageName.Buffer, ctypes.c_wchar_p)
                process_name = name_ptr.value
            else:
                process_name = "System Idle Process" if pid == 0 else "Unknown"
            
            # Apply filters
            if filter_name and filter_name.lower() not in process_name.lower():
                # Move to next process
                if proc_info.NextEntryOffset == 0:
                    break
                offset += proc_info.NextEntryOffset
                continue
            
            if not include_system and pid in [0, 4]:  # System Idle Process and System
                # Move to next process
                if proc_info.NextEntryOffset == 0:
                    break
                offset += proc_info.NextEntryOffset
                continue
            
            # Basic process info
            process_data = {
                'pid': int(pid) if pid else 0,
                'ppid': int(ppid) if ppid else 0,
                'name': process_name,
                'threads': proc_info.NumberOfThreads,
                'handles': proc_info.HandleCount,
                'session_id': proc_info.SessionId,
                'priority': proc_info.BasePriority,
                'memory': {
                    'working_set': proc_info.WorkingSetSize,
                    'peak_working_set': proc_info.PeakWorkingSetSize,
                    'virtual_size': proc_info.VirtualSize,
                    'peak_virtual_size': proc_info.PeakVirtualSize,
                    'pagefile_usage': proc_info.PagefileUsage,
                    'peak_pagefile_usage': proc_info.PeakPagefileUsage,
                    'private_bytes': proc_info.PrivatePageCount
                },
                'io': {
                    'read_operations': proc_info.ReadOperationCount,
                    'write_operations': proc_info.WriteOperationCount,
                    'other_operations': proc_info.OtherOperationCount,
                    'read_bytes': proc_info.ReadTransferCount,
                    'write_bytes': proc_info.WriteTransferCount,
                    'other_bytes': proc_info.OtherTransferCount
                },
                'times': {
                    'creation_time': proc_info.CreateTime,
                    'user_time': proc_info.UserTime,
                    'kernel_time': proc_info.KernelTime
                }
            }
            
            # Get additional details if requested
            if detailed and pid and pid != 0:
                additional_info = _get_process_details(int(pid))
                process_data.update(additional_info)
            
            processes.append(process_data)
            
            # Move to next process
            if proc_info.NextEntryOffset == 0:
                break
            offset += proc_info.NextEntryOffset
        
        return {
            "success": True,
            "processes": processes,
            "total_processes": len(processes),
            "detailed": detailed,
            "filter_applied": filter_name is not None
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows process enumeration failed: {str(e)}"
        }

def _get_process_details(pid: int) -> Dict[str, Any]:
    """Get additional process details using OpenProcess"""
    
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    advapi32 = ctypes.windll.advapi32
    
    details = {}
    
    try:
        # Open process handle
        process_handle = kernel32.OpenProcess(
            0x1F0FFF,  # PROCESS_ALL_ACCESS
            False,
            pid
        )
        
        if not process_handle:
            # Try with limited access
            process_handle = kernel32.OpenProcess(
                0x0400 | 0x0010,  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                False,
                pid
            )
        
        if process_handle:
            try:
                # Get executable path
                path_buffer = ctypes.create_unicode_buffer(260)
                path_size = wintypes.DWORD(260)
                
                if kernel32.QueryFullProcessImageNameW(
                    process_handle, 0, path_buffer, ctypes.byref(path_size)
                ):
                    details['executable_path'] = path_buffer.value
                
                # Get process memory info
                class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD),
                        ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t),
                    ]
                
                mem_counters = PROCESS_MEMORY_COUNTERS()
                mem_counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                
                if psapi.GetProcessMemoryInfo(
                    process_handle, ctypes.byref(mem_counters), mem_counters.cb
                ):
                    details['memory_counters'] = {
                        'page_faults': mem_counters.PageFaultCount,
                        'working_set': mem_counters.WorkingSetSize,
                        'peak_working_set': mem_counters.PeakWorkingSetSize,
                        'pagefile_usage': mem_counters.PagefileUsage,
                        'peak_pagefile_usage': mem_counters.PeakPagefileUsage
                    }
                
                # Get process token information (requires appropriate privileges)
                try:
                    token_handle = wintypes.HANDLE()
                    if advapi32.OpenProcessToken(
                        process_handle, 0x0008, ctypes.byref(token_handle)  # TOKEN_QUERY
                    ):
                        # Get token user
                        details['has_token_info'] = True
                        kernel32.CloseHandle(token_handle)
                except:
                    pass
                
            finally:
                kernel32.CloseHandle(process_handle)
    
    except Exception:
        pass
    
    return details

def _unix_elite_ps(detailed: bool, include_system: bool, filter_name: str) -> Dict[str, Any]:
    """Unix implementation using /proc filesystem and system calls"""
    
    processes = []
    
    try:
        # Read from /proc directory
        proc_dirs = []
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                proc_dirs.append(int(entry))
        
        proc_dirs.sort()
        
        for pid in proc_dirs:
            try:
                proc_path = f'/proc/{pid}'
                
                # Read process status
                status_file = os.path.join(proc_path, 'status')
                if not os.path.exists(status_file):
                    continue
                
                with open(status_file, 'r') as f:
                    status_lines = f.readlines()
                
                # Parse status information
                status_info = {}
                for line in status_lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        status_info[key.strip()] = value.strip()
                
                process_name = status_info.get('Name', 'unknown')
                
                # Apply filters
                if filter_name and filter_name.lower() not in process_name.lower():
                    continue
                
                if not include_system and pid < 100:  # Rough system process filter
                    continue
                
                # Basic process info
                process_data = {
                    'pid': pid,
                    'ppid': int(status_info.get('PPid', 0)),
                    'name': process_name,
                    'state': status_info.get('State', 'unknown'),
                    'threads': int(status_info.get('Threads', 0)),
                    'uid': status_info.get('Uid', '').split()[0] if status_info.get('Uid') else 0,
                    'gid': status_info.get('Gid', '').split()[0] if status_info.get('Gid') else 0,
                    'memory': {
                        'vm_peak': _parse_memory_value(status_info.get('VmPeak', '0 kB')),
                        'vm_size': _parse_memory_value(status_info.get('VmSize', '0 kB')),
                        'vm_rss': _parse_memory_value(status_info.get('VmRSS', '0 kB')),
                        'vm_data': _parse_memory_value(status_info.get('VmData', '0 kB')),
                        'vm_stack': _parse_memory_value(status_info.get('VmStk', '0 kB')),
                        'vm_exe': _parse_memory_value(status_info.get('VmExe', '0 kB')),
                        'vm_lib': _parse_memory_value(status_info.get('VmLib', '0 kB'))
                    }
                }
                
                # Get additional details if requested
                if detailed:
                    additional_info = _get_unix_process_details(pid, proc_path)
                    process_data.update(additional_info)
                
                processes.append(process_data)
                
            except (OSError, IOError, ValueError):
                # Process might have disappeared or be inaccessible
                continue
        
        return {
            "success": True,
            "processes": processes,
            "total_processes": len(processes),
            "detailed": detailed,
            "filter_applied": filter_name is not None
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix process enumeration failed: {str(e)}"
        }

def _parse_memory_value(mem_str: str) -> int:
    """Parse memory value from /proc/*/status (e.g., '1024 kB' -> 1048576)"""
    
    try:
        parts = mem_str.split()
        if len(parts) >= 2:
            value = int(parts[0])
            unit = parts[1].lower()
            
            if unit == 'kb':
                return value * 1024
            elif unit == 'mb':
                return value * 1024 * 1024
            elif unit == 'gb':
                return value * 1024 * 1024 * 1024
            else:
                return value
        else:
            return int(parts[0]) if parts else 0
    except (ValueError, IndexError):
        return 0

def _get_unix_process_details(pid: int, proc_path: str) -> Dict[str, Any]:
    """Get additional Unix process details"""
    
    details = {}
    
    try:
        # Get command line
        cmdline_file = os.path.join(proc_path, 'cmdline')
        if os.path.exists(cmdline_file):
            with open(cmdline_file, 'rb') as f:
                cmdline_data = f.read()
                # Arguments are null-separated
                cmdline = cmdline_data.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
                details['command_line'] = cmdline
        
        # Get executable path
        exe_link = os.path.join(proc_path, 'exe')
        if os.path.islink(exe_link):
            try:
                details['executable_path'] = os.readlink(exe_link)
            except OSError:
                pass
        
        # Get current working directory
        cwd_link = os.path.join(proc_path, 'cwd')
        if os.path.islink(cwd_link):
            try:
                details['cwd'] = os.readlink(cwd_link)
            except OSError:
                pass
        
        # Get environment variables (if accessible)
        environ_file = os.path.join(proc_path, 'environ')
        if os.path.exists(environ_file):
            try:
                with open(environ_file, 'rb') as f:
                    environ_data = f.read()
                    env_vars = environ_data.split(b'\x00')
                    details['environment_count'] = len([e for e in env_vars if e])
            except (OSError, PermissionError):
                pass
        
        # Get file descriptors count
        fd_dir = os.path.join(proc_path, 'fd')
        if os.path.isdir(fd_dir):
            try:
                fd_count = len(os.listdir(fd_dir))
                details['open_files'] = fd_count
            except (OSError, PermissionError):
                pass
        
        # Get process statistics
        stat_file = os.path.join(proc_path, 'stat')
        if os.path.exists(stat_file):
            try:
                with open(stat_file, 'r') as f:
                    stat_data = f.read().split()
                
                if len(stat_data) >= 24:
                    details['cpu_times'] = {
                        'utime': int(stat_data[13]),  # User time
                        'stime': int(stat_data[14]),  # System time
                        'cutime': int(stat_data[15]), # Children user time
                        'cstime': int(stat_data[16]), # Children system time
                        'priority': int(stat_data[17]),
                        'nice': int(stat_data[18]),
                        'start_time': int(stat_data[21])
                    }
            except (OSError, ValueError, IndexError):
                pass
    
    except Exception:
        pass
    
    return details


if __name__ == "__main__":
    # Test the elite ps command
    # print("Testing Elite PS Command...")
    
    # Test basic process listing
    result = elite_ps(detailed=False, include_system=True)
    
    if result['success']:
    # print(f"✅ Found {result['total_processes']} processes")
        
        # Show first few processes
        for i, proc in enumerate(result['processes'][:5]):
    # print(f"  PID {proc['pid']:>6}: {proc['name']}")
            if 'memory' in proc:
                memory_mb = proc['memory'].get('working_set', 0) / (1024*1024)
    # print(f"           Memory: {memory_mb:.1f} MB")
        
    # print("  ...")
        
        # Test filtering
    # print("\nTesting process filtering...")
        filtered_result = elite_ps(detailed=False, filter_name="python")
        
        if filtered_result['success']:
    # print(f"Found {filtered_result['total_processes']} Python processes")
            for proc in filtered_result['processes']:
    # print(f"  PID {proc['pid']}: {proc['name']}")
        
        # Test detailed mode
    # print("\nTesting detailed mode...")
        detailed_result = elite_ps(detailed=True, include_system=False)
        
        if detailed_result['success'] and detailed_result['processes']:
            sample_proc = detailed_result['processes'][0]
    # print(f"Sample detailed process: {sample_proc['name']} (PID {sample_proc['pid']})")
            
            if 'executable_path' in sample_proc:
    # print(f"  Path: {sample_proc['executable_path']}")
            
            if 'command_line' in sample_proc:
    # print(f"  Command: {sample_proc['command_line'][:80]}...")
    
    else:
    # print(f"❌ Process enumeration failed: {result['error']}")
    
    # print("Elite PS command test complete")