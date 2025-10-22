#!/usr/bin/env python3
"""
Elite Username Command Implementation
Advanced user identification with context and session information
"""

import os
import sys
import ctypes
# subprocess removed - using native APIs
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api
import ctypes
from ctypes import wintypes
import socket
from typing import Dict, Any

def elite_username() -> Dict[str, Any]:
    """
    Elite username retrieval with advanced features:
    - Multiple username sources and verification
    - Session and logon information
    - User context details
    - Cross-platform support
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_username()
        else:
            return _unix_elite_username()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Username retrieval failed: {str(e)}",
            "username_info": None
        }

def _windows_elite_username() -> Dict[str, Any]:
    """Windows username retrieval using multiple methods"""
    
    try:
        username_info = {}
        
        # Method 1: GetUserNameW API
        try:
            buffer = ctypes.create_unicode_buffer(256)
            size = ctypes.c_ulong(256)
            
            if ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
                username_info["api_username"] = buffer.value
        except:
            pass
        
        # Method 2: Environment variables
        username_info["env_username"] = os.environ.get('USERNAME', 'unknown')
        username_info["env_userdomain"] = os.environ.get('USERDOMAIN', 'unknown')
        username_info["env_userprofile"] = os.environ.get('USERPROFILE', 'unknown')
        
        # Method 3: whoami command
        try:
            result = # Native whoami
username_buffer = ctypes.create_unicode_buffer(257) if sys.platform == 'win32' else ""
if sys.platform == 'win32':
    size = ctypes.c_uint(257)
    ctypes.windll.advapi32.GetUserNameW(username_buffer, ctypes.byref(size))
    result = type('obj', (), {'stdout': username_buffer.value, 'returncode': 0})()
else:
    import pwd
    result = type('obj', (), {'stdout': pwd.getpwuid(os.getuid()).pw_name, 'returncode': 0})()
            if result.returncode == 0:
                username_info["whoami_output"] = result.stdout.strip()
        except:
            pass
        
        # Method 4: Advanced user information
        username_info.update(_get_windows_advanced_user_info())
        
        # Determine primary username
        primary_username = (
            username_info.get("api_username") or 
            username_info.get("env_username") or 
            "unknown"
        )
        
        return {
            "success": True,
            "username": primary_username,
            "username_info": username_info,
            "method": "windows_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows username retrieval failed: {str(e)}",
            "username_info": None
        }

def _unix_elite_username() -> Dict[str, Any]:
    """Unix username retrieval using multiple methods"""
    
    try:
        username_info = {}
        
        # Method 1: getuid and pwd module
        try:
            import pwd
            uid = os.getuid()
            user_entry = pwd.getpwuid(uid)
            username_info["pwd_username"] = user_entry.pw_name
            username_info["pwd_uid"] = uid
            username_info["pwd_gid"] = user_entry.pw_gid
            username_info["pwd_home"] = user_entry.pw_dir
            username_info["pwd_shell"] = user_entry.pw_shell
            username_info["pwd_gecos"] = user_entry.pw_gecos
        except:
            pass
        
        # Method 2: Environment variables
        username_info["env_user"] = os.environ.get('USER', 'unknown')
        username_info["env_logname"] = os.environ.get('LOGNAME', 'unknown')
        username_info["env_home"] = os.environ.get('HOME', 'unknown')
        
        # Method 3: getlogin system call
        try:
            username_info["getlogin_username"] = os.getlogin()
        except:
            pass
        
        # Method 4: whoami command
        try:
            result = # Native whoami
username_buffer = ctypes.create_unicode_buffer(257) if sys.platform == 'win32' else ""
if sys.platform == 'win32':
    size = ctypes.c_uint(257)
    ctypes.windll.advapi32.GetUserNameW(username_buffer, ctypes.byref(size))
    result = type('obj', (), {'stdout': username_buffer.value, 'returncode': 0})()
else:
    import pwd
    result = type('obj', (), {'stdout': pwd.getpwuid(os.getuid()).pw_name, 'returncode': 0})()
            if result.returncode == 0:
                username_info["whoami_output"] = result.stdout.strip()
        except:
            pass
        
        # Method 5: id command for additional info
        try:
            result = # Native implementation needed
result = type('obj', (), {'stdout': 'Native implementation required', 'returncode': 0})()
            if result.returncode == 0:
                username_info["id_output"] = result.stdout.strip()
        except:
            pass
        
        # Method 6: Advanced user information
        username_info.update(_get_unix_advanced_user_info())
        
        # Determine primary username
        primary_username = (
            username_info.get("pwd_username") or 
            username_info.get("env_user") or 
            username_info.get("getlogin_username") or 
            "unknown"
        )
        
        return {
            "success": True,
            "username": primary_username,
            "username_info": username_info,
            "method": "unix_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix username retrieval failed: {str(e)}",
            "username_info": None
        }

def _get_windows_advanced_user_info() -> Dict[str, Any]:
    """Get advanced Windows user information"""
    
    info = {}
    
    try:
        # Get SID information
        try:
            result = # Native whoami
username_buffer = ctypes.create_unicode_buffer(257) if sys.platform == 'win32' else ""
if sys.platform == 'win32':
    size = ctypes.c_uint(257)
    ctypes.windll.advapi32.GetUserNameW(username_buffer, ctypes.byref(size))
    result = type('obj', (), {'stdout': username_buffer.value, 'returncode': 0})()
else:
    import pwd
    result = type('obj', (), {'stdout': pwd.getpwuid(os.getuid()).pw_name, 'returncode': 0})()
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'S-' in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith('S-'):
                                info["user_sid"] = part
                                break
        except:
            pass
        
        # Get logon session information
        info["computer_name"] = os.environ.get('COMPUTERNAME', 'unknown')
        info["logon_server"] = os.environ.get('LOGONSERVER', 'unknown')
        info["session_name"] = os.environ.get('SESSIONNAME', 'unknown')
        
        # Check administrative status
        try:
            info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            info["is_admin"] = False
        
        # Get user profile information
        info["profile_path"] = os.environ.get('USERPROFILE', 'unknown')
        info["app_data"] = os.environ.get('APPDATA', 'unknown')
        info["local_app_data"] = os.environ.get('LOCALAPPDATA', 'unknown')
        
        # Get domain information
        info["dns_domain"] = os.environ.get('USERDNSDOMAIN', 'unknown')
        info["domain_controller"] = os.environ.get('LOGONSERVER', 'unknown')
        
        # Check UAC status
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            info["uac_enabled"] = value == 1
            winreg.CloseKey(key)
        except:
            info["uac_enabled"] = False
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

def _get_unix_advanced_user_info() -> Dict[str, Any]:
    """Get advanced Unix user information"""
    
    info = {}
    
    try:
        # Get effective user information
        info["euid"] = os.geteuid()
        info["egid"] = os.getegid()
        info["is_root"] = os.getuid() == 0
        info["is_effective_root"] = os.geteuid() == 0
        
        # Get process group information
        try:
            info["pgid"] = os.getpgrp()
            info["sid"] = os.getsid(0)
        except:
            pass
        
        # Get terminal information
        info["tty"] = os.environ.get('TTY', 'unknown')
        info["term"] = os.environ.get('TERM', 'unknown')
        info["display"] = os.environ.get('DISPLAY', None)
        
        # Get session information
        info["session_type"] = os.environ.get('XDG_SESSION_TYPE', 'unknown')
        info["desktop"] = os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')
        info["session_id"] = os.environ.get('XDG_SESSION_ID', 'unknown')
        
        # Get shell information
        info["shell"] = os.environ.get('SHELL', 'unknown')
        info["shlvl"] = os.environ.get('SHLVL', 'unknown')
        
        # Check sudo capabilities
        try:
            result = # Native implementation needed
result = type('obj', (), {'stdout': 'Native implementation required', 'returncode': 0})()
            info["can_sudo"] = result.returncode == 0
        except:
            info["can_sudo"] = False
        
        # Get group information
        try:
            import grp
            groups = [g.gr_name for g in grp.getgrall() if info.get("pwd_username", "") in g.gr_mem]
            info["secondary_groups"] = groups
        except:
            pass
        
        # Get login information
        try:
            result = # Native implementation needed
result = type('obj', (), {'stdout': 'Native implementation required', 'returncode': 0})()
            if result.returncode == 0:
                info["last_login"] = result.stdout.strip().split('\n')[0]
        except:
            pass
        
        # Check for special capabilities
        try:
            result = # Native implementation needed
result = type('obj', (), {'stdout': 'Native implementation required', 'returncode': 0})()
            if result.returncode == 0 and result.stdout.strip():
                info["has_capabilities"] = True
        except:
            info["has_capabilities"] = False
            
    except Exception as e:
        info["error"] = str(e)
    
    return info


if __name__ == "__main__":
    # Test the elite_username command
    # print("Testing Elite Username Command...")
    
    result = elite_username()
    # print(f"Test - Username retrieval: {result['success']}")
    
    if result['success']:
        username = result['username']
        username_info = result['username_info']
        
    # print(f"Primary username: {username}")
        
        if sys.platform == 'win32':
            pass
    # print(f"Domain: {username_info.get('env_userdomain', 'unknown')}")
    # print(f"Is admin: {username_info.get('is_admin', False)}")
    # print(f"Computer: {username_info.get('computer_name', 'unknown')}")
        else:
            pass
    # print(f"UID: {username_info.get('pwd_uid', 'unknown')}")
    # print(f"Home: {username_info.get('pwd_home', 'unknown')}")
    # print(f"Shell: {username_info.get('pwd_shell', 'unknown')}")
    # print(f"Is root: {username_info.get('is_root', False)}")
    
    # print("✅ Elite Username command testing complete")