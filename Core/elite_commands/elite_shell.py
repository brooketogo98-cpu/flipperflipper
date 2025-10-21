#!/usr/bin/env python3
"""
Elite Shell Command Implementation
Direct command execution without cmd.exe using Windows API or direct syscalls
"""

import ctypes
from ctypes import wintypes
import os
import sys
import subprocess
import threading
import time
import tempfile
from typing import Dict, Any, Optional

def elite_shell(command: str, timeout: int = 30, capture_output: bool = True, 
               working_directory: str = None, environment: dict = None) -> Dict[str, Any]:
    """
    Elite shell command execution with advanced features:
    - Direct API calls (no cmd.exe)
    - Process isolation
    - Output capture
    - Timeout handling
    - Environment control
    - Working directory control
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_shell(command, timeout, capture_output, working_directory, environment)
        else:
            return _unix_elite_shell(command, timeout, capture_output, working_directory, environment)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Shell execution failed: {str(e)}",
            "command": command
        }

def _windows_elite_shell(command: str, timeout: int, capture_output: bool, 
                        working_directory: str, environment: dict) -> Dict[str, Any]:
    """Windows implementation using CreateProcess API directly"""
    
    kernel32 = ctypes.windll.kernel32
    
    # Constants
    CREATE_NO_WINDOW = 0x08000000
    CREATE_NEW_CONSOLE = 0x00000010
    NORMAL_PRIORITY_CLASS = 0x00000020
    STARTF_USESTDHANDLES = 0x00000100
    STARTF_USESHOWWINDOW = 0x00000001
    SW_HIDE = 0
    INFINITE = 0xFFFFFFFF
    WAIT_TIMEOUT = 0x00000102
    WAIT_OBJECT_0 = 0x00000000
    
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
    
    # Prepare command
    # Avoid cmd.exe by using direct executable paths when possible
    if not command.startswith('"') and not os.path.isabs(command.split()[0]):
        # Try to find executable in PATH
        executable = command.split()[0]
        full_path = _find_executable(executable)
        if full_path:
            command = command.replace(executable, full_path, 1)
    
    # Setup pipes for output capture if needed
    stdout_read = stdout_write = None
    stderr_read = stderr_write = None
    
    if capture_output:
        # Create pipes
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.bInheritHandle = True
        sa.lpSecurityDescriptor = None
        
        # Create stdout pipe
        stdout_read = wintypes.HANDLE()
        stdout_write = wintypes.HANDLE()
        if not kernel32.CreatePipe(
            ctypes.byref(stdout_read),
            ctypes.byref(stdout_write),
            ctypes.byref(sa),
            0
        ):
            raise Exception("Failed to create stdout pipe")
        
        # Create stderr pipe
        stderr_read = wintypes.HANDLE()
        stderr_write = wintypes.HANDLE()
        if not kernel32.CreatePipe(
            ctypes.byref(stderr_read),
            ctypes.byref(stderr_write),
            ctypes.byref(sa),
            0
        ):
            raise Exception("Failed to create stderr pipe")
        
        # Make read handles non-inheritable
        kernel32.SetHandleInformation(stdout_read, 1, 0)  # HANDLE_FLAG_INHERIT = 1
        kernel32.SetHandleInformation(stderr_read, 1, 0)
    
    # Setup startup info
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(STARTUPINFO)
    startup_info.dwFlags = STARTF_USESHOWWINDOW
    startup_info.wShowWindow = SW_HIDE
    
    if capture_output:
        startup_info.dwFlags |= STARTF_USESTDHANDLES
        startup_info.hStdOutput = stdout_write
        startup_info.hStdError = stderr_write
        startup_info.hStdInput = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    
    # Setup process info
    process_info = PROCESS_INFORMATION()
    
    # Prepare environment block
    env_block = None
    if environment:
        env_vars = []
        for key, value in environment.items():
            env_vars.append(f"{key}={value}")
        env_block = "\0".join(env_vars) + "\0\0"
    
    try:
        start_time = time.time()
        
        # Create process
        success = kernel32.CreateProcessW(
            None,  # lpApplicationName
            command,  # lpCommandLine
            None,  # lpProcessAttributes
            None,  # lpThreadAttributes
            True if capture_output else False,  # bInheritHandles
            CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,  # dwCreationFlags
            env_block,  # lpEnvironment
            working_directory,  # lpCurrentDirectory
            ctypes.byref(startup_info),  # lpStartupInfo
            ctypes.byref(process_info)  # lpProcessInformation
        )
        
        if not success:
            error = kernel32.GetLastError()
            raise Exception(f"CreateProcess failed (Error: {error})")
        
        # Close write handles (child process owns them now)
        if capture_output:
            kernel32.CloseHandle(stdout_write)
            kernel32.CloseHandle(stderr_write)
        
        # Wait for process completion with timeout
        wait_result = kernel32.WaitForSingleObject(
            process_info.hProcess,
            timeout * 1000 if timeout > 0 else INFINITE
        )
        
        # Get exit code
        exit_code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(exit_code))
        
        execution_time = time.time() - start_time
        
        # Handle timeout
        if wait_result == WAIT_TIMEOUT:
            # Terminate process
            kernel32.TerminateProcess(process_info.hProcess, 1)
            
            result = {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": command,
                "execution_time": execution_time,
                "timeout": True,
                "pid": process_info.dwProcessId
            }
        else:
            # Read output if captured
            stdout_data = stderr_data = ""
            
            if capture_output:
                stdout_data = _read_pipe_output(stdout_read)
                stderr_data = _read_pipe_output(stderr_read)
            
            result = {
                "success": exit_code.value == 0,
                "command": command,
                "exit_code": exit_code.value,
                "execution_time": execution_time,
                "pid": process_info.dwProcessId,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "timeout": False
            }
        
        # Clean up handles
        kernel32.CloseHandle(process_info.hProcess)
        kernel32.CloseHandle(process_info.hThread)
        
        if capture_output:
            kernel32.CloseHandle(stdout_read)
            kernel32.CloseHandle(stderr_read)
        
        return result
        
    except Exception as e:
        # Clean up on error
        if process_info.hProcess:
            kernel32.CloseHandle(process_info.hProcess)
        if process_info.hThread:
            kernel32.CloseHandle(process_info.hThread)
        
        if capture_output:
            for handle in [stdout_read, stdout_write, stderr_read, stderr_write]:
                if handle:
                    kernel32.CloseHandle(handle)
        
        return {
            "success": False,
            "error": f"Windows shell execution failed: {str(e)}",
            "command": command
        }

def _read_pipe_output(pipe_handle: wintypes.HANDLE) -> str:
    """Read output from a pipe handle"""
    
    kernel32 = ctypes.windll.kernel32
    output = b""
    
    try:
        while True:
            buffer = ctypes.create_string_buffer(4096)
            bytes_read = wintypes.DWORD()
            
            success = kernel32.ReadFile(
                pipe_handle,
                buffer,
                4096,
                ctypes.byref(bytes_read),
                None
            )
            
            if not success or bytes_read.value == 0:
                break
            
            output += buffer.raw[:bytes_read.value]
    
    except Exception:
        pass
    
    try:
        return output.decode('utf-8', errors='replace')
    except:
        return output.decode('latin1', errors='replace')

def _find_executable(name: str) -> Optional[str]:
    """Find executable in PATH"""
    
    try:
        # Common Windows executables
        if sys.platform == 'win32':
            if not name.endswith('.exe'):
                name += '.exe'
            
            # Check common system directories first
            system_dirs = [
                os.environ.get('WINDIR', 'C:\\Windows') + '\\System32',
                os.environ.get('WINDIR', 'C:\\Windows'),
                os.environ.get('WINDIR', 'C:\\Windows') + '\\SysWOW64'
            ]
            
            for directory in system_dirs:
                full_path = os.path.join(directory, name)
                if os.path.isfile(full_path):
                    return full_path
        
        # Search PATH
        path_dirs = os.environ.get('PATH', '').split(os.pathsep)
        for directory in path_dirs:
            if directory:
                full_path = os.path.join(directory, name)
                if os.path.isfile(full_path):
                    return full_path
    
    except Exception:
        pass
    
    return None

def _unix_elite_shell(command: str, timeout: int, capture_output: bool, 
                     working_directory: str, environment: dict) -> Dict[str, Any]:
    """Unix implementation using subprocess with security enhancements"""
    
    try:
        start_time = time.time()
        
        # Prepare environment
        env = os.environ.copy()
        if environment:
            env.update(environment)
        
        # Execute command
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            stdin=subprocess.PIPE,
            cwd=working_directory,
            env=env,
            text=True,
            preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        
        try:
            stdout_data, stderr_data = process.communicate(timeout=timeout)
            execution_time = time.time() - start_time
            
            return {
                "success": process.returncode == 0,
                "command": command,
                "exit_code": process.returncode,
                "execution_time": execution_time,
                "pid": process.pid,
                "stdout": stdout_data or "",
                "stderr": stderr_data or "",
                "timeout": False
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            execution_time = time.time() - start_time
            
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": command,
                "execution_time": execution_time,
                "timeout": True,
                "pid": process.pid
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix shell execution failed: {str(e)}",
            "command": command
        }

def elite_shell_interactive(command: str, input_data: str = "", timeout: int = 30) -> Dict[str, Any]:
    """
    Interactive shell execution with input/output handling
    """
    
    try:
        if sys.platform == 'win32':
            # Windows interactive implementation would be more complex
            # For now, fall back to regular execution with input
            pass
        
        # Use subprocess for interactive mode
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True
        )
        
        stdout_data, stderr_data = process.communicate(input=input_data, timeout=timeout)
        
        return {
            "success": process.returncode == 0,
            "command": command,
            "exit_code": process.returncode,
            "stdout": stdout_data,
            "stderr": stderr_data,
            "interactive": True
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Interactive shell failed: {str(e)}",
            "command": command
        }


if __name__ == "__main__":
    # Test the elite shell command
    print("Testing Elite Shell Command...")
    
    # Test basic command
    if sys.platform == 'win32':
        test_commands = [
            "echo Hello World",
            "dir /b",
            "whoami",
            "systeminfo | findstr /C:\"OS Name\""
        ]
    else:
        test_commands = [
            "echo Hello World",
            "ls -la",
            "whoami",
            "uname -a"
        ]
    
    for cmd in test_commands:
        print(f"\nTesting command: {cmd}")
        
        result = elite_shell(cmd, timeout=10)
        
        if result['success']:
            print(f"✅ Command succeeded (exit code: {result['exit_code']})")
            print(f"Execution time: {result['execution_time']:.3f} seconds")
            if result.get('stdout'):
                print(f"Output: {result['stdout'].strip()[:100]}...")
        else:
            print(f"❌ Command failed: {result.get('error', 'Unknown error')}")
            if result.get('stderr'):
                print(f"Error output: {result['stderr'].strip()[:100]}...")
    
    # Test timeout
    print("\nTesting timeout handling...")
    if sys.platform == 'win32':
        timeout_cmd = "ping -n 10 127.0.0.1"
    else:
        timeout_cmd = "sleep 10"
    
    result = elite_shell(timeout_cmd, timeout=2)
    if result.get('timeout'):
        print("✅ Timeout handling works correctly")
    else:
        print("⚠️ Timeout handling may not be working")
    
    print("Elite Shell command test complete")