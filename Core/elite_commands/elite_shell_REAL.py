#!/usr/bin/env python3
"""
REAL Elite Shell Implementation - No FakeProcess, actual execution
"""

import os
import sys
import ctypes
from ctypes import wintypes
import time
import select
import fcntl
import errno
import signal
import struct
from typing import Dict, Any, Optional

def elite_shell(command: str, timeout: int = 30, capture_output: bool = True, 
               working_directory: str = None, environment: dict = None) -> Dict[str, Any]:
    """
    REAL shell command execution with native implementation
    """
    try:
        if sys.platform == 'win32':
            return _windows_shell_real(command, timeout, capture_output, working_directory, environment)
        else:
            return _unix_shell_real(command, timeout, capture_output, working_directory, environment)
    except Exception as e:
        return {
            "success": False,
            "error": f"Shell execution failed: {str(e)}",
            "command": command
        }

def _unix_shell_real(command: str, timeout: int, capture_output: bool,
                    working_directory: str, environment: dict) -> Dict[str, Any]:
    """
    REAL Unix implementation using os.fork() and exec() - NO subprocess!
    """
    import pty
    import termios
    import tty
    
    start_time = time.time()
    
    # Prepare environment
    env = os.environ.copy()
    if environment:
        env.update(environment)
    
    # Save current directory
    old_cwd = os.getcwd()
    if working_directory:
        os.chdir(working_directory)
    
    try:
        if capture_output:
            # Create pipes for stdout/stderr
            stdout_r, stdout_w = os.pipe()
            stderr_r, stderr_w = os.pipe()
            
            # Make pipes non-blocking
            fcntl.fcntl(stdout_r, fcntl.F_SETFL, os.O_NONBLOCK)
            fcntl.fcntl(stderr_r, fcntl.F_SETFL, os.O_NONBLOCK)
        
        # Fork process
        pid = os.fork()
        
        if pid == 0:  # Child process
            try:
                if capture_output:
                    # Redirect stdout/stderr to pipes
                    os.dup2(stdout_w, 1)
                    os.dup2(stderr_w, 2)
                    os.close(stdout_r)
                    os.close(stderr_r)
                    os.close(stdout_w)
                    os.close(stderr_w)
                
                # Execute command
                if '/' in command or command.startswith('./'):
                    # Direct executable
                    args = command.split()
                    os.execve(args[0], args, env)
                else:
                    # Use shell
                    os.execve('/bin/sh', ['/bin/sh', '-c', command], env)
                    
            except Exception as e:
                # If exec fails, exit child
                os._exit(1)
                
        else:  # Parent process
            if capture_output:
                # Close write ends
                os.close(stdout_w)
                os.close(stderr_w)
                
                stdout_data = b''
                stderr_data = b''
                
                # Set up timeout
                deadline = time.time() + timeout if timeout > 0 else float('inf')
                
                while True:
                    # Check if child is still running
                    pid_status, exit_code = os.waitpid(pid, os.WNOHANG)
                    
                    if pid_status != 0:
                        # Child has exited
                        # Read any remaining data
                        try:
                            stdout_data += os.read(stdout_r, 4096)
                        except OSError:
                            pass
                        try:
                            stderr_data += os.read(stderr_r, 4096)
                        except OSError:
                            pass
                        break
                    
                    # Check timeout
                    if time.time() > deadline:
                        # Kill child process
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(0.1)
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        
                        return {
                            "success": False,
                            "error": f"Command timed out after {timeout} seconds",
                            "command": command,
                            "timeout": True,
                            "pid": pid,
                            "execution_time": time.time() - start_time
                        }
                    
                    # Read available data
                    ready, _, _ = select.select([stdout_r, stderr_r], [], [], 0.1)
                    
                    for fd in ready:
                        try:
                            if fd == stdout_r:
                                chunk = os.read(stdout_r, 4096)
                                if chunk:
                                    stdout_data += chunk
                            elif fd == stderr_r:
                                chunk = os.read(stderr_r, 4096)
                                if chunk:
                                    stderr_data += chunk
                        except OSError as e:
                            if e.errno != errno.EAGAIN:
                                raise
                
                # Close pipes
                os.close(stdout_r)
                os.close(stderr_r)
                
                # Get exit code
                exit_code = exit_code >> 8 if pid_status != 0 else 0
                
                return {
                    "success": exit_code == 0,
                    "command": command,
                    "exit_code": exit_code,
                    "stdout": stdout_data.decode('utf-8', errors='replace'),
                    "stderr": stderr_data.decode('utf-8', errors='replace'),
                    "pid": pid,
                    "execution_time": time.time() - start_time,
                    "timeout": False
                }
            else:
                # No output capture - just wait
                pid_status, exit_status = os.waitpid(pid, 0)
                exit_code = exit_status >> 8
                
                return {
                    "success": exit_code == 0,
                    "command": command,
                    "exit_code": exit_code,
                    "pid": pid,
                    "execution_time": time.time() - start_time
                }
                
    finally:
        # Restore directory
        os.chdir(old_cwd)

def _windows_shell_real(command: str, timeout: int, capture_output: bool,
                       working_directory: str, environment: dict) -> Dict[str, Any]:
    """
    REAL Windows implementation using CreateProcess - already implemented correctly in original
    """
    kernel32 = ctypes.windll.kernel32
    
    # Constants
    CREATE_NO_WINDOW = 0x08000000
    STARTF_USESTDHANDLES = 0x00000100
    STARTF_USESHOWWINDOW = 0x00000001
    SW_HIDE = 0
    INFINITE = 0xFFFFFFFF
    WAIT_TIMEOUT = 0x00000102
    
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]
    
    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]
    
    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]
    
    stdout_read = stdout_write = stderr_read = stderr_write = None
    
    if capture_output:
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.bInheritHandle = True
        
        stdout_read = wintypes.HANDLE()
        stdout_write = wintypes.HANDLE()
        stderr_read = wintypes.HANDLE()
        stderr_write = wintypes.HANDLE()
        
        kernel32.CreatePipe(ctypes.byref(stdout_read), ctypes.byref(stdout_write),
                           ctypes.byref(sa), 0)
        kernel32.CreatePipe(ctypes.byref(stderr_read), ctypes.byref(stderr_write),
                           ctypes.byref(sa), 0)
        
        kernel32.SetHandleInformation(stdout_read, 1, 0)
        kernel32.SetHandleInformation(stderr_read, 1, 0)
    
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(STARTUPINFO)
    startup_info.dwFlags = STARTF_USESHOWWINDOW
    startup_info.wShowWindow = SW_HIDE
    
    if capture_output:
        startup_info.dwFlags |= STARTF_USESTDHANDLES
        startup_info.hStdOutput = stdout_write
        startup_info.hStdError = stderr_write
        startup_info.hStdInput = kernel32.GetStdHandle(-10)
    
    process_info = PROCESS_INFORMATION()
    
    # Prepare environment
    env_block = None
    if environment:
        env_vars = [f"{k}={v}" for k, v in environment.items()]
        env_block = "\0".join(env_vars) + "\0\0"
    
    start_time = time.time()
    
    # Create process
    success = kernel32.CreateProcessW(
        None, command, None, None,
        True if capture_output else False,
        CREATE_NO_WINDOW,
        env_block, working_directory,
        ctypes.byref(startup_info),
        ctypes.byref(process_info)
    )
    
    if not success:
        return {
            "success": False,
            "error": f"CreateProcess failed (Error: {kernel32.GetLastError()})",
            "command": command
        }
    
    if capture_output:
        kernel32.CloseHandle(stdout_write)
        kernel32.CloseHandle(stderr_write)
    
    # Wait for completion
    wait_result = kernel32.WaitForSingleObject(
        process_info.hProcess,
        timeout * 1000 if timeout > 0 else INFINITE
    )
    
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(exit_code))
    
    stdout_data = stderr_data = ""
    if capture_output:
        stdout_data = _read_pipe(stdout_read)
        stderr_data = _read_pipe(stderr_read)
        kernel32.CloseHandle(stdout_read)
        kernel32.CloseHandle(stderr_read)
    
    kernel32.CloseHandle(process_info.hProcess)
    kernel32.CloseHandle(process_info.hThread)
    
    if wait_result == WAIT_TIMEOUT:
        kernel32.TerminateProcess(process_info.hProcess, 1)
        return {
            "success": False,
            "error": f"Timeout after {timeout} seconds",
            "command": command,
            "timeout": True,
            "pid": process_info.dwProcessId
        }
    
    return {
        "success": exit_code.value == 0,
        "command": command,
        "exit_code": exit_code.value,
        "stdout": stdout_data,
        "stderr": stderr_data,
        "pid": process_info.dwProcessId,
        "execution_time": time.time() - start_time
    }

def _read_pipe(pipe_handle):
    """Read all data from a pipe"""
    kernel32 = ctypes.windll.kernel32
    output = b""
    buffer = ctypes.create_string_buffer(4096)
    bytes_read = wintypes.DWORD()
    
    while kernel32.ReadFile(pipe_handle, buffer, 4096, ctypes.byref(bytes_read), None):
        if bytes_read.value == 0:
            break
        output += buffer.raw[:bytes_read.value]
    
    return output.decode('utf-8', errors='replace')

# Test if this actually works
if __name__ == "__main__":
    print("Testing REAL shell implementation...")
    
    # Test simple command
    result = elite_shell("echo 'This is REAL execution'", timeout=5)
    if result['success']:
        print(f"✅ SUCCESS: {result['stdout'].strip()}")
    else:
        print(f"❌ FAILED: {result.get('error', 'Unknown error')}")
    
    # Test command with output
    result = elite_shell("ls -la /tmp | head -5" if sys.platform != 'win32' else "dir C:\\ /B", timeout=5)
    if result['success']:
        print(f"✅ Directory listing:\n{result['stdout'][:200]}")
    else:
        print(f"❌ Failed: {result.get('error')}")