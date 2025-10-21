#!/usr/bin/env python3
"""
Elite Kill Command Implementation
Advanced process termination using direct API calls and multiple methods
"""

import ctypes
from ctypes import wintypes
import os
import sys
import signal
import time
from typing import Dict, Any, List, Union

def elite_kill(target: Union[int, str], method: str = "terminate", 
              force: bool = False, timeout: int = 10) -> Dict[str, Any]:
    """
    Elite process termination with advanced features:
    - Multiple termination methods
    - Direct API calls (no taskkill.exe)
    - Graceful shutdown attempts
    - Force termination if needed
    - Process tree termination
    """
    
    try:
        # Handle target specification
        if isinstance(target, str):
            # Target is process name, find PIDs
            pids = _find_processes_by_name(target)
            if not pids:
                return {
                    "success": False,
                    "error": f"No processes found with name: {target}",
                    "target": target
                }
        else:
            # Target is PID
            pids = [target]
        
        # Terminate processes
        results = []
        for pid in pids:
            if sys.platform == 'win32':
                result = _windows_elite_kill(pid, method, force, timeout)
            else:
                result = _unix_elite_kill(pid, method, force, timeout)
            
            result['pid'] = pid
            results.append(result)
        
        # Summarize results
        successful = sum(1 for r in results if r['success'])
        
        return {
            "success": successful > 0,
            "target": target,
            "method": method,
            "results": results,
            "total_processes": len(results),
            "successful_terminations": successful,
            "failed_terminations": len(results) - successful
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Kill operation failed: {str(e)}",
            "target": target
        }

def _find_processes_by_name(name: str) -> List[int]:
    """Find process IDs by name"""
    
    pids = []
    
    try:
        if sys.platform == 'win32':
            # Use CreateToolhelp32Snapshot
            kernel32 = ctypes.windll.kernel32
            
            # Constants
            TH32CS_SNAPPROCESS = 0x00000002
            INVALID_HANDLE_VALUE = -1
            
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
            
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snapshot == INVALID_HANDLE_VALUE:
                return pids
            
            try:
                pe32 = PROCESSENTRY32()
                pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
                
                if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                    while True:
                        process_name = pe32.szExeFile.decode('utf-8', errors='ignore')
                        
                        # Match process name (case insensitive)
                        if name.lower() in process_name.lower():
                            pids.append(pe32.th32ProcessID)
                        
                        if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                            break
            finally:
                kernel32.CloseHandle(snapshot)
        
        else:
            # Unix: scan /proc directory
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    try:
                        pid = int(entry)
                        comm_file = f'/proc/{pid}/comm'
                        
                        if os.path.exists(comm_file):
                            with open(comm_file, 'r') as f:
                                process_name = f.read().strip()
                            
                            if name.lower() in process_name.lower():
                                pids.append(pid)
                    except (OSError, ValueError):
                        continue
    
    except Exception:
        pass
    
    return pids

def _windows_elite_kill(pid: int, method: str, force: bool, timeout: int) -> Dict[str, Any]:
    """Windows implementation using TerminateProcess and other APIs"""
    
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    
    # Constants
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_INFORMATION = 0x0400
    WM_CLOSE = 0x0010
    WM_QUIT = 0x0012
    STILL_ACTIVE = 259
    
    try:
        # First, try to open the process
        process_handle = kernel32.OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
            False,
            pid
        )
        
        if not process_handle:
            error = kernel32.GetLastError()
            if error == 5:  # Access denied
                return {
                    "success": False,
                    "error": f"Access denied to process {pid} (requires admin privileges)",
                    "method": method
                }
            else:
                return {
                    "success": False,
                    "error": f"Cannot open process {pid} (Error: {error})",
                    "method": method
                }
        
        try:
            start_time = time.time()
            
            # Choose termination method
            if method == "graceful" and not force:
                # Try graceful shutdown first
                success = _windows_graceful_shutdown(pid, timeout)
                
                if success:
                    return {
                        "success": True,
                        "method": "graceful",
                        "termination_time": time.time() - start_time
                    }
                elif not force:
                    return {
                        "success": False,
                        "error": f"Graceful shutdown failed for process {pid}",
                        "method": "graceful"
                    }
                # If force=True, fall through to terminate
            
            # Direct termination
            if method in ["terminate", "force"] or force:
                success = kernel32.TerminateProcess(process_handle, 1)
                
                if success:
                    # Wait for process to actually terminate
                    wait_result = kernel32.WaitForSingleObject(process_handle, timeout * 1000)
                    
                    return {
                        "success": True,
                        "method": "terminate",
                        "termination_time": time.time() - start_time,
                        "wait_result": wait_result
                    }
                else:
                    error = kernel32.GetLastError()
                    return {
                        "success": False,
                        "error": f"TerminateProcess failed (Error: {error})",
                        "method": "terminate"
                    }
            
            # Debug break method (for debugging processes)
            elif method == "debug":
                success = kernel32.DebugBreakProcess(process_handle)
                
                return {
                    "success": success,
                    "method": "debug",
                    "termination_time": time.time() - start_time
                }
            
            else:
                return {
                    "success": False,
                    "error": f"Unknown termination method: {method}",
                    "method": method
                }
        
        finally:
            kernel32.CloseHandle(process_handle)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows kill failed: {str(e)}",
            "method": method
        }

def _windows_graceful_shutdown(pid: int, timeout: int) -> bool:
    """Attempt graceful shutdown of Windows process"""
    
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    
    try:
        # Find main window of the process
        def enum_windows_proc(hwnd, lparam):
            process_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            
            if process_id.value == pid:
                # Found window belonging to target process
                # Try WM_CLOSE first
                user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
                return False  # Stop enumeration
            
            return True  # Continue enumeration
        
        # Enumerate windows
        enum_proc = wintypes.WNDENUMPROC(enum_windows_proc)
        user32.EnumWindows(enum_proc, 0)
        
        # Wait for process to terminate
        process_handle = kernel32.OpenProcess(0x400, False, pid)  # PROCESS_QUERY_INFORMATION
        if process_handle:
            try:
                wait_result = kernel32.WaitForSingleObject(process_handle, timeout * 1000)
                return wait_result == 0  # WAIT_OBJECT_0
            finally:
                kernel32.CloseHandle(process_handle)
    
    except Exception:
        pass
    
    return False

def _unix_elite_kill(pid: int, method: str, force: bool, timeout: int) -> Dict[str, Any]:
    """Unix implementation using kill() system call"""
    
    try:
        start_time = time.time()
        
        # Check if process exists
        try:
            os.kill(pid, 0)  # Signal 0 just checks existence
        except ProcessLookupError:
            return {
                "success": False,
                "error": f"Process {pid} not found",
                "method": method
            }
        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied to signal process {pid}",
                "method": method
            }
        
        # Choose termination method
        if method == "graceful" and not force:
            # Try SIGTERM first (graceful)
            try:
                os.kill(pid, signal.SIGTERM)
                
                # Wait for process to terminate
                for _ in range(timeout * 10):  # Check every 100ms
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.1)
                    except ProcessLookupError:
                        # Process terminated
                        return {
                            "success": True,
                            "method": "graceful (SIGTERM)",
                            "termination_time": time.time() - start_time
                        }
                
                # Process didn't terminate gracefully
                if not force:
                    return {
                        "success": False,
                        "error": f"Process {pid} did not respond to SIGTERM",
                        "method": "graceful"
                    }
                # Fall through to SIGKILL if force=True
            
            except OSError as e:
                return {
                    "success": False,
                    "error": f"Failed to send SIGTERM to process {pid}: {str(e)}",
                    "method": "graceful"
                }
        
        # Force termination with SIGKILL
        if method in ["terminate", "force"] or force:
            try:
                os.kill(pid, signal.SIGKILL)
                
                # SIGKILL cannot be caught, so process should terminate immediately
                # But still wait a bit to confirm
                for _ in range(50):  # Wait up to 5 seconds
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.1)
                    except ProcessLookupError:
                        # Process terminated
                        return {
                            "success": True,
                            "method": "force (SIGKILL)",
                            "termination_time": time.time() - start_time
                        }
                
                # Process still exists (very unusual for SIGKILL)
                return {
                    "success": False,
                    "error": f"Process {pid} survived SIGKILL (zombie or kernel process?)",
                    "method": "force"
                }
            
            except OSError as e:
                return {
                    "success": False,
                    "error": f"Failed to send SIGKILL to process {pid}: {str(e)}",
                    "method": "force"
                }
        
        # Other signal methods
        elif method == "stop":
            os.kill(pid, signal.SIGSTOP)
            return {
                "success": True,
                "method": "stop (SIGSTOP)",
                "termination_time": time.time() - start_time
            }
        
        elif method == "continue":
            os.kill(pid, signal.SIGCONT)
            return {
                "success": True,
                "method": "continue (SIGCONT)",
                "termination_time": time.time() - start_time
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown termination method: {method}",
                "method": method
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix kill failed: {str(e)}",
            "method": method
        }

def elite_kill_tree(pid: int, method: str = "terminate", force: bool = False) -> Dict[str, Any]:
    """
    Kill process and all its children (process tree termination)
    """
    
    try:
        # Find all child processes
        children = _find_child_processes(pid)
        
        # Kill children first (depth-first)
        child_results = []
        for child_pid in children:
            result = elite_kill(child_pid, method, force)
            child_results.extend(result['results'])
        
        # Kill parent process
        parent_result = elite_kill(pid, method, force)
        
        # Combine results
        all_results = child_results + parent_result['results']
        successful = sum(1 for r in all_results if r['success'])
        
        return {
            "success": successful > 0,
            "target": pid,
            "method": method,
            "tree_termination": True,
            "results": all_results,
            "total_processes": len(all_results),
            "successful_terminations": successful,
            "failed_terminations": len(all_results) - successful,
            "children_killed": len(child_results)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Process tree termination failed: {str(e)}",
            "target": pid
        }

def _find_child_processes(parent_pid: int) -> List[int]:
    """Find all child processes of a given parent PID"""
    
    children = []
    
    try:
        if sys.platform == 'win32':
            # Use WMI or process enumeration to find children
            # For now, simplified implementation
            pass
        else:
            # Unix: scan /proc for processes with matching PPID
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    try:
                        pid = int(entry)
                        stat_file = f'/proc/{pid}/stat'
                        
                        if os.path.exists(stat_file):
                            with open(stat_file, 'r') as f:
                                stat_data = f.read().split()
                            
                            if len(stat_data) >= 4:
                                ppid = int(stat_data[3])
                                if ppid == parent_pid:
                                    children.append(pid)
                                    # Recursively find grandchildren
                                    children.extend(_find_child_processes(pid))
                    except (OSError, ValueError, IndexError):
                        continue
    
    except Exception:
        pass
    
    return children


if __name__ == "__main__":
    # Test the elite kill command
    # print("Testing Elite Kill Command...")
    
    # Create a test process to kill
    import subprocess
    
    if sys.platform == 'win32':
        test_cmd = ["ping", "-n", "30", "127.0.0.1"]
    else:
        test_cmd = ["sleep", "30"]
    
    try:
        # Start test process
        test_process = subprocess.Popen(test_cmd)
        test_pid = test_process.pid
        
    # print(f"Started test process: PID {test_pid}")
        
        # Wait a moment for process to start
        time.sleep(1)
        
        # Test kill by PID
        result = elite_kill(test_pid, method="graceful", force=True, timeout=5)
        
        if result['success']:
    # print(f"✅ Successfully killed process {test_pid}")
            if result.get('results') and len(result['results']) > 0:
    # print(f"Method: {result['results'][0].get('method', 'unknown')}")
    # print(f"Time: {result['results'][0].get('termination_time', 0):.3f} seconds")
        else:
    # print(f"❌ Failed to kill process: {result.get('error', 'Unknown error')}")
            # Clean up manually
            test_process.terminate()
        
        # Test kill by name (should find no processes now)
        if sys.platform == 'win32':
            name_test = elite_kill("ping.exe", method="terminate")
        else:
            name_test = elite_kill("sleep", method="terminate")
        
        if name_test['success']:
    # print(f"✅ Found and killed {name_test['successful_terminations']} processes by name")
        else:
    # print("ℹ️ No processes found by name (expected after previous kill)")
        
        # Test process tree termination
    # print("\nTesting process tree termination...")
        
        # Create parent process with child
        if sys.platform == 'win32':
            tree_cmd = ["cmd", "/c", "ping -n 60 127.0.0.1"]
        else:
            tree_cmd = ["bash", "-c", "sleep 60"]
        
        tree_process = subprocess.Popen(tree_cmd)
        tree_pid = tree_process.pid
        
    # print(f"Started process tree: PID {tree_pid}")
        time.sleep(1)
        
        tree_result = elite_kill_tree(tree_pid, method="terminate", force=True)
        
        if tree_result['success']:
    # print(f"✅ Successfully killed process tree")
    # print(f"Total processes: {tree_result['total_processes']}")
    # print(f"Children killed: {tree_result['children_killed']}")
        else:
    # print(f"❌ Process tree kill failed: {tree_result.get('error', 'Unknown error')}")
            # Clean up manually
            tree_process.terminate()
    
    except Exception as e:
    # print(f"❌ Test failed: {e}")
    
    # print("Elite Kill command test complete")