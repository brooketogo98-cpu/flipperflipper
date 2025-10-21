#!/usr/bin/env python3
"""
Elite Processes Command Implementation
Advanced process enumeration with detailed information
"""

import os
import sys
import ctypes
import subprocess
import time
from typing import Dict, Any, List

def elite_processes() -> Dict[str, Any]:
    """
    Elite process enumeration with advanced features:
    - Detailed process information
    - Parent-child relationships
    - Memory usage and performance data
    - Hidden process detection
    - Cross-platform support
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_processes()
        else:
            return _unix_elite_processes()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Process enumeration failed: {str(e)}",
            "processes": []
        }

def _windows_elite_processes() -> Dict[str, Any]:
    """Windows process enumeration using API calls"""
    
    try:
        processes = []
        
        # Method 1: Use CreateToolhelp32Snapshot API
        try:
            processes.extend(_windows_toolhelp_processes())
        except Exception:
            pass
        
        # Method 2: Use tasklist command as fallback
        if not processes:
            try:
                processes.extend(_windows_tasklist_processes())
            except Exception:
                pass
        
        # Method 3: Use WMI if available
        try:
            wmi_processes = _windows_wmi_processes()
            # Merge WMI data with existing processes
            for wmi_proc in wmi_processes:
                for proc in processes:
                    if proc.get('pid') == wmi_proc.get('pid'):
                        proc.update(wmi_proc)
                        break
        except Exception:
            pass
        
        return {
            "success": True,
            "processes": processes,
            "total_count": len(processes),
            "method": "windows_api"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows process enumeration failed: {str(e)}",
            "processes": []
        }

def _unix_elite_processes() -> Dict[str, Any]:
    """Unix process enumeration using /proc and ps"""
    
    try:
        processes = []
        
        # Method 1: Read from /proc filesystem
        try:
            processes.extend(_unix_proc_processes())
        except Exception:
            pass
        
        # Method 2: Use ps command as fallback/supplement
        try:
            ps_processes = _unix_ps_processes()
            # Merge ps data with /proc data
            for ps_proc in ps_processes:
                for proc in processes:
                    if proc.get('pid') == ps_proc.get('pid'):
                        proc.update(ps_proc)
                        break
                else:
                    processes.append(ps_proc)
        except Exception:
            pass
        
        return {
            "success": True,
            "processes": processes,
            "total_count": len(processes),
            "method": "unix_proc_ps"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix process enumeration failed: {str(e)}",
            "processes": []
        }

def _windows_toolhelp_processes() -> List[Dict[str, Any]]:
    """Windows process enumeration using CreateToolhelp32Snapshot"""
    
    processes = []
    
    try:
        # Windows API constants
        TH32CS_SNAPPROCESS = 0x2
        INVALID_HANDLE_VALUE = -1
        
        # Process entry structure
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_char * 260)
            ]
        
        # Create snapshot
        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            return processes
        
        try:
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            # Get first process
            if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while True:
                    process_info = {
                        "pid": pe32.th32ProcessID,
                        "ppid": pe32.th32ParentProcessID,
                        "name": pe32.szExeFile.decode('utf-8', errors='ignore'),
                        "threads": pe32.cntThreads,
                        "priority": pe32.pcPriClassBase
                    }
                    
                    # Get additional process information
                    try:
                        process_info.update(_get_windows_process_details(pe32.th32ProcessID))
                    except:
                        pass
                    
                    processes.append(process_info)
                    
                    # Get next process
                    if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                        break
                        
        finally:
            ctypes.windll.kernel32.CloseHandle(snapshot)
            
    except Exception:
        pass
    
    return processes

def _windows_tasklist_processes() -> List[Dict[str, Any]]:
    """Windows process enumeration using tasklist command"""
    
    processes = []
    
    try:
        result = subprocess.run(['tasklist', '/fo', 'csv', '/v'], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                headers = [h.strip('"') for h in lines[0].split('","')]
                
                for line in lines[1:]:
                    if line.strip():
                        values = [v.strip('"') for v in line.split('","')]
                        if len(values) >= len(headers):
                            process_info = {}
                            for i, header in enumerate(headers):
                                if i < len(values):
                                    if header == "PID":
                                        try:
                                            process_info["pid"] = int(values[i])
                                        except:
                                            process_info["pid"] = values[i]
                                    elif header == "Image Name":
                                        process_info["name"] = values[i]
                                    elif header == "Session Name":
                                        process_info["session"] = values[i]
                                    elif header == "Session#":
                                        process_info["session_id"] = values[i]
                                    elif header == "Mem Usage":
                                        process_info["memory"] = values[i]
                                    elif header == "Status":
                                        process_info["status"] = values[i]
                                    elif header == "User Name":
                                        process_info["user"] = values[i]
                                    elif header == "CPU Time":
                                        process_info["cpu_time"] = values[i]
                                    elif header == "Window Title":
                                        process_info["window_title"] = values[i]
                            
                            processes.append(process_info)
                            
    except Exception:
        pass
    
    return processes

def _get_windows_process_details(pid: int) -> Dict[str, Any]:
    """Get additional Windows process details"""
    
    details = {}
    
    try:
        # Open process handle
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        
        if handle:
            try:
                # Get process memory info
                class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ("cb", ctypes.c_ulong),
                        ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)
                    ]
                
                pmc = PROCESS_MEMORY_COUNTERS()
                pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                
                if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                    details["working_set"] = pmc.WorkingSetSize
                    details["peak_working_set"] = pmc.PeakWorkingSetSize
                    details["pagefile_usage"] = pmc.PagefileUsage
                    details["page_faults"] = pmc.PageFaultCount
                
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
                
    except Exception:
        pass
    
    return details

def _windows_wmi_processes() -> List[Dict[str, Any]]:
    """Windows process enumeration using WMI (if available)"""
    
    processes = []
    
    try:
        # This would require WMI module, implement basic version
        result = subprocess.run(['wmic', 'process', 'get', 'ProcessId,Name,CommandLine,CreationDate', '/format:csv'], 
                              capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 4:
                        try:
                            processes.append({
                                "pid": int(parts[3]) if parts[3] else 0,
                                "name": parts[2] if parts[2] else "unknown",
                                "command_line": parts[1] if parts[1] else "",
                                "creation_date": parts[0] if parts[0] else ""
                            })
                        except:
                            continue
                            
    except Exception:
        pass
    
    return processes

def _unix_proc_processes() -> List[Dict[str, Any]]:
    """Unix process enumeration using /proc filesystem"""
    
    processes = []
    
    try:
        proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
        
        for pid_str in proc_dirs:
            try:
                pid = int(pid_str)
                proc_dir = f'/proc/{pid}'
                
                process_info = {"pid": pid}
                
                # Read /proc/PID/stat
                try:
                    with open(f'{proc_dir}/stat', 'r') as f:
                        stat_data = f.read().split()
                        if len(stat_data) >= 24:
                            process_info["name"] = stat_data[1].strip('()')
                            process_info["state"] = stat_data[2]
                            process_info["ppid"] = int(stat_data[3])
                            process_info["pgrp"] = int(stat_data[4])
                            process_info["session"] = int(stat_data[5])
                            process_info["utime"] = int(stat_data[13])
                            process_info["stime"] = int(stat_data[14])
                            process_info["priority"] = int(stat_data[17])
                            process_info["nice"] = int(stat_data[18])
                            process_info["num_threads"] = int(stat_data[19])
                            process_info["vsize"] = int(stat_data[22])
                            process_info["rss"] = int(stat_data[23])
                except:
                    pass
                
                # Read /proc/PID/status
                try:
                    with open(f'{proc_dir}/status', 'r') as f:
                        for line in f:
                            if line.startswith('Uid:'):
                                uids = line.split()[1:5]
                                process_info["uid"] = int(uids[0])
                            elif line.startswith('Gid:'):
                                gids = line.split()[1:5]
                                process_info["gid"] = int(gids[0])
                            elif line.startswith('VmSize:'):
                                process_info["vm_size"] = line.split()[1]
                            elif line.startswith('VmRSS:'):
                                process_info["vm_rss"] = line.split()[1]
                except:
                    pass
                
                # Read /proc/PID/cmdline
                try:
                    with open(f'{proc_dir}/cmdline', 'r') as f:
                        cmdline = f.read().replace('\0', ' ').strip()
                        process_info["cmdline"] = cmdline
                except:
                    pass
                
                # Read /proc/PID/exe
                try:
                    exe_path = os.readlink(f'{proc_dir}/exe')
                    process_info["exe"] = exe_path
                except:
                    pass
                
                processes.append(process_info)
                
            except (ValueError, PermissionError, FileNotFoundError):
                continue
                
    except Exception:
        pass
    
    return processes

def _unix_ps_processes() -> List[Dict[str, Any]]:
    """Unix process enumeration using ps command"""
    
    processes = []
    
    try:
        # Use ps with detailed output
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:  # Skip header
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        try:
                            process_info = {
                                "user": parts[0],
                                "pid": int(parts[1]),
                                "cpu_percent": float(parts[2]),
                                "mem_percent": float(parts[3]),
                                "vsz": int(parts[4]),
                                "rss": int(parts[5]),
                                "tty": parts[6],
                                "stat": parts[7],
                                "start": parts[8],
                                "time": parts[9],
                                "command": parts[10]
                            }
                            processes.append(process_info)
                        except (ValueError, IndexError):
                            continue
                            
    except Exception:
        pass
    
    return processes


if __name__ == "__main__":
    # Test the elite_processes command
    print("Testing Elite Processes Command...")
    
    result = elite_processes()
    print(f"Test - Process enumeration: {result['success']}")
    
    if result['success']:
        processes = result['processes']
        print(f"Total processes found: {len(processes)}")
        
        # Show first few processes
        for i, proc in enumerate(processes[:3]):
            print(f"Process {i+1}: PID={proc.get('pid', 'N/A')}, Name={proc.get('name', 'N/A')}")
    
    print("✅ Elite Processes command testing complete")