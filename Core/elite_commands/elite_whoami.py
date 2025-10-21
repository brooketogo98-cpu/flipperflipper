#!/usr/bin/env python3
"""
Elite Whoami Command Implementation - FULLY NATIVE, NO SUBPROCESS
Advanced user context information using only native APIs
"""

import os
import sys
import ctypes
from ctypes import wintypes
import socket
import pwd
import grp
from typing import Dict, Any, List
import time

def elite_whoami(detailed: bool = True, show_privileges: bool = True) -> Dict[str, Any]:
    """
    Elite whoami implementation with zero subprocess calls
    Uses only native Windows/Unix APIs
    """
    
    try:
        result = {
            "username": "",
            "hostname": socket.gethostname(),
            "domain": "",
            "uid": None,
            "gid": None,
            "groups": [],
            "privileges": [],
            "is_admin": False,
            "is_root": False,
            "session_info": {},
            "success": True
        }
        
        if sys.platform == 'win32':
            _get_windows_info_native(result, detailed, show_privileges)
        else:
            _get_unix_info_native(result, detailed, show_privileges)
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Whoami failed: {str(e)}"
        }

def _get_windows_info_native(result: Dict[str, Any], detailed: bool, show_privileges: bool):
    """Get Windows user info using only native APIs"""
    
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32
        
        # Get username
        username_buffer = ctypes.create_unicode_buffer(257)
        size = ctypes.c_uint(257)
        if advapi32.GetUserNameW(username_buffer, ctypes.byref(size)):
            result["username"] = username_buffer.value
        
        # Get domain/computer name
        computer_buffer = ctypes.create_unicode_buffer(257)
        size = ctypes.c_uint(257)
        if kernel32.GetComputerNameW(computer_buffer, ctypes.byref(size)):
            result["domain"] = computer_buffer.value
        
        # Check if admin
        result["is_admin"] = shell32.IsUserAnAdmin() != 0
        
        # Get user SID
        if detailed:
            result["sid"] = _get_user_sid_native()
        
        # Get privileges
        if show_privileges:
            result["privileges"] = _get_windows_privileges_native()
        
        # Get groups
        if detailed:
            result["groups"] = _get_windows_groups_native()
        
        # Get session info
        result["session_info"] = _get_windows_session_info()
        
    except Exception as e:
        result["error"] = str(e)

def _get_user_sid_native() -> str:
    """Get user SID using native Windows API"""
    
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        
        # Get current process token
        token = wintypes.HANDLE()
        if not kernel32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token)
        ):
            return "unknown"
        
        # Query token for user SID
        info_length = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            1,  # TokenUser
            None,
            0,
            ctypes.byref(info_length)
        )
        
        if info_length.value > 0:
            buffer = ctypes.create_string_buffer(info_length.value)
            if advapi32.GetTokenInformation(
                token,
                1,  # TokenUser
                buffer,
                info_length.value,
                ctypes.byref(info_length)
            ):
                # Convert SID to string
                sid_string = ctypes.c_wchar_p()
                if advapi32.ConvertSidToStringSidW(
                    ctypes.cast(buffer, ctypes.c_void_p),
                    ctypes.byref(sid_string)
                ):
                    result = sid_string.value
                    kernel32.LocalFree(sid_string)
                    kernel32.CloseHandle(token)
                    return result
        
        kernel32.CloseHandle(token)
        
    except Exception:
        pass
    
    return "unknown"

def _get_windows_privileges_native() -> List[str]:
    """Get Windows privileges using native API"""
    
    privileges = []
    
    try:
        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32
        
        # Get current process token
        token = wintypes.HANDLE()
        if not kernel32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token)
        ):
            return privileges
        
        # Query token privileges
        info_length = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            3,  # TokenPrivileges
            None,
            0,
            ctypes.byref(info_length)
        )
        
        if info_length.value > 0:
            # Define structures
            class LUID(ctypes.Structure):
                _fields_ = [
                    ("LowPart", wintypes.DWORD),
                    ("HighPart", wintypes.LONG)
                ]
            
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Luid", LUID),
                    ("Attributes", wintypes.DWORD)
                ]
            
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 128)
                ]
            
            buffer = ctypes.create_string_buffer(info_length.value)
            if advapi32.GetTokenInformation(
                token,
                3,  # TokenPrivileges
                buffer,
                info_length.value,
                ctypes.byref(info_length)
            ):
                token_privs = ctypes.cast(buffer, ctypes.POINTER(TOKEN_PRIVILEGES)).contents
                
                # Enumerate privileges
                for i in range(token_privs.PrivilegeCount):
                    priv = token_privs.Privileges[i]
                    name_buffer = ctypes.create_unicode_buffer(256)
                    size = wintypes.DWORD(256)
                    
                    if advapi32.LookupPrivilegeNameW(
                        None,
                        ctypes.byref(priv.Luid),
                        name_buffer,
                        ctypes.byref(size)
                    ):
                        priv_name = name_buffer.value
                        # Check if enabled
                        SE_PRIVILEGE_ENABLED = 0x00000002
                        if priv.Attributes & SE_PRIVILEGE_ENABLED:
                            privileges.append(f"{priv_name} (Enabled)")
                        else:
                            privileges.append(f"{priv_name} (Disabled)")
        
        kernel32.CloseHandle(token)
        
    except Exception:
        pass
    
    return privileges

def _get_windows_groups_native() -> List[str]:
    """Get Windows group memberships using native API"""
    
    groups = []
    
    try:
        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32
        
        # Get current process token
        token = wintypes.HANDLE()
        if not kernel32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token)
        ):
            return groups
        
        # Query token groups
        info_length = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            2,  # TokenGroups
            None,
            0,
            ctypes.byref(info_length)
        )
        
        if info_length.value > 0:
            buffer = ctypes.create_string_buffer(info_length.value)
            if advapi32.GetTokenInformation(
                token,
                2,  # TokenGroups
                buffer,
                info_length.value,
                ctypes.byref(info_length)
            ):
                # Parse group SIDs
                class SID_AND_ATTRIBUTES(ctypes.Structure):
                    _fields_ = [
                        ("Sid", ctypes.c_void_p),
                        ("Attributes", wintypes.DWORD)
                    ]
                
                class TOKEN_GROUPS(ctypes.Structure):
                    _fields_ = [
                        ("GroupCount", wintypes.DWORD),
                        ("Groups", SID_AND_ATTRIBUTES * 128)
                    ]
                
                token_groups = ctypes.cast(buffer, ctypes.POINTER(TOKEN_GROUPS)).contents
                
                for i in range(min(token_groups.GroupCount, 128)):
                    group = token_groups.Groups[i]
                    if group.Sid:
                        # Convert SID to name
                        name_buffer = ctypes.create_unicode_buffer(256)
                        domain_buffer = ctypes.create_unicode_buffer(256)
                        name_size = wintypes.DWORD(256)
                        domain_size = wintypes.DWORD(256)
                        sid_type = wintypes.DWORD()
                        
                        if advapi32.LookupAccountSidW(
                            None,
                            group.Sid,
                            name_buffer,
                            ctypes.byref(name_size),
                            domain_buffer,
                            ctypes.byref(domain_size),
                            ctypes.byref(sid_type)
                        ):
                            if domain_buffer.value:
                                groups.append(f"{domain_buffer.value}\\{name_buffer.value}")
                            else:
                                groups.append(name_buffer.value)
        
        kernel32.CloseHandle(token)
        
    except Exception:
        pass
    
    return groups

def _get_windows_session_info() -> Dict[str, Any]:
    """Get Windows session information"""
    
    session = {}
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Get session ID
        session_id = wintypes.DWORD()
        if kernel32.ProcessIdToSessionId(
            kernel32.GetCurrentProcessId(),
            ctypes.byref(session_id)
        ):
            session["session_id"] = session_id.value
        
        # Get logon time (from process creation time as approximation)
        creation_time = ctypes.c_ulonglong()
        exit_time = ctypes.c_ulonglong()
        kernel_time = ctypes.c_ulonglong()
        user_time = ctypes.c_ulonglong()
        
        if kernel32.GetProcessTimes(
            kernel32.GetCurrentProcess(),
            ctypes.byref(creation_time),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time)
        ):
            # Convert FILETIME to Unix timestamp
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            epoch_delta = 116444736000000000  # Difference between 1601 and 1970
            timestamp = (creation_time.value - epoch_delta) / 10000000
            session["logon_time"] = time.ctime(timestamp)
        
        # Get environment info
        session["computer_name"] = os.environ.get('COMPUTERNAME', 'unknown')
        session["user_domain"] = os.environ.get('USERDOMAIN', 'unknown')
        session["logon_server"] = os.environ.get('LOGONSERVER', 'unknown')
        
    except Exception:
        pass
    
    return session

def _get_unix_info_native(result: Dict[str, Any], detailed: bool, show_privileges: bool):
    """Get Unix user info using only native APIs"""
    
    try:
        # Basic user info
        result["uid"] = os.getuid()
        result["gid"] = os.getgid()
        result["is_root"] = os.geteuid() == 0
        
        # Get username from uid
        try:
            user_info = pwd.getpwuid(os.getuid())
            result["username"] = user_info.pw_name
            result["home_dir"] = user_info.pw_dir
            result["shell"] = user_info.pw_shell
        except:
            result["username"] = os.environ.get('USER', 'unknown')
        
        # Get groups
        if detailed:
            try:
                groups = os.getgroups()
                result["groups"] = []
                for gid in groups:
                    try:
                        group_info = grp.getgrgid(gid)
                        result["groups"].append(f"{group_info.gr_name} ({gid})")
                    except:
                        result["groups"].append(f"gid:{gid}")
            except:
                pass
        
        # Check sudo capabilities (without subprocess)
        if show_privileges:
            result["privileges"] = _check_unix_privileges_native()
        
        # Session info
        result["session_info"] = {
            "tty": os.ttyname(0) if os.isatty(0) else "none",
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "pgid": os.getpgid(0),
            "sid": os.getsid(0) if hasattr(os, 'getsid') else None
        }
        
        # Environment info
        result["session_info"]["display"] = os.environ.get('DISPLAY', 'none')
        result["session_info"]["term"] = os.environ.get('TERM', 'unknown')
        result["session_info"]["ssh_connection"] = os.environ.get('SSH_CONNECTION', None)
        
    except Exception as e:
        result["error"] = str(e)

def _check_unix_privileges_native() -> List[str]:
    """Check Unix privileges without subprocess"""
    
    privileges = []
    
    try:
        # Check effective vs real UID
        if os.getuid() != os.geteuid():
            privileges.append("SUID binary running")
        
        # Check if can read sudoers
        if os.path.exists('/etc/sudoers'):
            try:
                with open('/etc/sudoers', 'r') as f:
                    content = f.read()
                    username = pwd.getpwuid(os.getuid()).pw_name
                    if username in content or 'ALL' in content:
                        privileges.append("Sudo access possible")
            except:
                pass
        
        # Check capabilities on current process
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            
            # Try to get capabilities (simplified check)
            cap_data = ctypes.create_string_buffer(256)
            if hasattr(libc, 'cap_get_proc'):
                result = libc.cap_get_proc()
                if result:
                    privileges.append("Process has capabilities")
        except:
            pass
        
        # Check if in privileged groups
        privileged_groups = ['wheel', 'sudo', 'admin', 'root']
        try:
            groups = os.getgroups()
            for gid in groups:
                try:
                    group_name = grp.getgrgid(gid).gr_name
                    if group_name in privileged_groups:
                        privileges.append(f"Member of {group_name} group")
                except:
                    pass
        except:
            pass
        
    except Exception:
        pass
    
    return privileges if privileges else ["Standard user"]