#!/usr/bin/env python3
"""
Elite WhoAmI Command Implementation
Advanced user identification with privilege and group information
"""

import os
import sys
import ctypes
import subprocess
from typing import Dict, Any, List

def elite_whoami() -> Dict[str, Any]:
    """
    Elite user identification with advanced features:
    - Current user details
    - Group memberships
    - Privilege information
    - Security context
    - Cross-platform support
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_whoami()
        else:
            return _unix_elite_whoami()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"User identification failed: {str(e)}",
            "user_info": None
        }

def _windows_elite_whoami() -> Dict[str, Any]:
    """Windows user identification using API calls"""
    
    try:
        user_info = {}
        
        # Get current username
        username_buffer = ctypes.create_unicode_buffer(256)
        username_size = ctypes.c_ulong(256)
        
        if ctypes.windll.advapi32.GetUserNameW(username_buffer, ctypes.byref(username_size)):
            user_info["username"] = username_buffer.value
        else:
            user_info["username"] = os.environ.get('USERNAME', 'unknown')
        
        # Get domain information
        user_info["domain"] = os.environ.get('USERDOMAIN', 'unknown')
        user_info["logon_server"] = os.environ.get('LOGONSERVER', 'unknown')
        
        # Check if user is administrator
        user_info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        # Get SID (Security Identifier)
        user_info["sid"] = _get_windows_user_sid()
        
        # Get user privileges
        user_info["privileges"] = _get_windows_user_privileges()
        
        # Get group memberships
        user_info["groups"] = _get_windows_user_groups()
        
        # Get additional user information
        user_info["profile_path"] = os.environ.get('USERPROFILE', 'unknown')
        user_info["home_drive"] = os.environ.get('HOMEDRIVE', 'unknown')
        user_info["home_path"] = os.environ.get('HOMEPATH', 'unknown')
        
        # Check UAC status
        user_info["uac_enabled"] = _check_uac_status()
        
        return {
            "success": True,
            "user_info": user_info,
            "method": "windows_api"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows user identification failed: {str(e)}",
            "user_info": None
        }

def _unix_elite_whoami() -> Dict[str, Any]:
    """Unix user identification using system calls"""
    
    try:
        user_info = {}
        
        # Get current user information
        import pwd
        import grp
        
        # Get user ID and details
        uid = os.getuid()
        gid = os.getgid()
        
        user_entry = pwd.getpwuid(uid)
        user_info["username"] = user_entry.pw_name
        user_info["uid"] = uid
        user_info["gid"] = gid
        user_info["home_directory"] = user_entry.pw_dir
        user_info["shell"] = user_entry.pw_shell
        user_info["gecos"] = user_entry.pw_gecos
        
        # Check if user is root
        user_info["is_root"] = uid == 0
        
        # Get effective user/group IDs
        user_info["euid"] = os.geteuid()
        user_info["egid"] = os.getegid()
        
        # Get group memberships
        user_info["groups"] = _get_unix_user_groups(user_info["username"])
        
        # Get primary group name
        try:
            primary_group = grp.getgrgid(gid)
            user_info["primary_group"] = primary_group.gr_name
        except:
            user_info["primary_group"] = str(gid)
        
        # Check sudo privileges
        user_info["can_sudo"] = _check_sudo_privileges()
        
        # Get additional environment information
        user_info["display"] = os.environ.get('DISPLAY', None)
        user_info["session_type"] = os.environ.get('XDG_SESSION_TYPE', 'unknown')
        user_info["desktop"] = os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')
        
        return {
            "success": True,
            "user_info": user_info,
            "method": "unix_syscalls"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix user identification failed: {str(e)}",
            "user_info": None
        }

def _get_windows_user_sid() -> str:
    """Get Windows user SID"""
    
    try:
        # Use whoami command to get SID
        result = subprocess.run(['whoami', '/user'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'S-' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('S-'):
                            return part
        return "unknown"
        
    except Exception:
        return "unknown"

def _get_windows_user_privileges() -> List[str]:
    """Get Windows user privileges"""
    
    privileges = []
    
    try:
        # Use whoami command to get privileges
        result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            in_privileges_section = False
            
            for line in lines:
                line = line.strip()
                if 'Privilege Name' in line:
                    in_privileges_section = True
                    continue
                elif in_privileges_section and line and not line.startswith('='):
                    parts = line.split()
                    if parts:
                        privilege = parts[0]
                        if privilege and privilege != 'Privilege':
                            privileges.append(privilege)
                            
    except Exception:
        pass
    
    return privileges

def _get_windows_user_groups() -> List[str]:
    """Get Windows user group memberships"""
    
    groups = []
    
    try:
        # Use whoami command to get groups
        result = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            in_groups_section = False
            
            for line in lines:
                line = line.strip()
                if 'Group Name' in line:
                    in_groups_section = True
                    continue
                elif in_groups_section and line and not line.startswith('='):
                    parts = line.split()
                    if parts:
                        group = parts[0]
                        if group and group != 'Group' and '\\' in group:
                            groups.append(group)
                            
    except Exception:
        pass
    
    return groups

def _get_unix_user_groups(username: str) -> List[str]:
    """Get Unix user group memberships"""
    
    groups = []
    
    try:
        import grp
        
        # Get all groups and check membership
        for group in grp.getgrall():
            if username in group.gr_mem:
                groups.append(group.gr_name)
                
        # Also add primary group
        try:
            import pwd
            user_entry = pwd.getpwnam(username)
            primary_group = grp.getgrgid(user_entry.pw_gid)
            if primary_group.gr_name not in groups:
                groups.insert(0, primary_group.gr_name)
        except:
            pass
            
    except Exception:
        pass
    
    return groups

def _check_uac_status() -> bool:
    """Check if UAC is enabled on Windows"""
    
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        )
        
        value, _ = winreg.QueryValueEx(key, "EnableLUA")
        winreg.CloseKey(key)
        
        return value == 1
        
    except Exception:
        return False

def _check_sudo_privileges() -> bool:
    """Check if user has sudo privileges on Unix"""
    
    try:
        # Try sudo -n (non-interactive) to check privileges
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
        return result.returncode == 0
        
    except Exception:
        return False


if __name__ == "__main__":
    # Test the elite_whoami command
    print("Testing Elite WhoAmI Command...")
    
    result = elite_whoami()
    print(f"Test - User identification: {result['success']}")
    
    if result['success']:
        user_info = result['user_info']
        print(f"Username: {user_info.get('username', 'unknown')}")
        if sys.platform == 'win32':
            print(f"Is Admin: {user_info.get('is_admin', False)}")
            print(f"Domain: {user_info.get('domain', 'unknown')}")
        else:
            print(f"UID: {user_info.get('uid', 'unknown')}")
            print(f"Is Root: {user_info.get('is_root', False)}")
        print(f"Groups: {len(user_info.get('groups', []))}")
    
    print("✅ Elite WhoAmI command testing complete")