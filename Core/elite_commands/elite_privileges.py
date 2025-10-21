#!/usr/bin/env python3
"""
Elite Privileges Command Implementation
Advanced privilege enumeration and security context analysis
"""

import os
import sys
import ctypes
import subprocess
from typing import Dict, Any, List

def elite_privileges() -> Dict[str, Any]:
    """
    Elite privilege enumeration with advanced features:
    - Current user privileges and rights
    - Group memberships and permissions
    - Security context analysis
    - Privilege escalation opportunities
    - Cross-platform support
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_privileges()
        else:
            return _unix_elite_privileges()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Privilege enumeration failed: {str(e)}",
            "privileges": None
        }

def _windows_elite_privileges() -> Dict[str, Any]:
    """Windows privilege enumeration using API calls and commands"""
    
    try:
        privilege_info = {
            "user_privileges": _get_windows_user_privileges(),
            "group_memberships": _get_windows_group_memberships(),
            "security_context": _get_windows_security_context(),
            "escalation_opportunities": _analyze_windows_escalation_opportunities()
        }
        
        return {
            "success": True,
            "privileges": privilege_info,
            "method": "windows_api_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows privilege enumeration failed: {str(e)}",
            "privileges": None
        }

def _unix_elite_privileges() -> Dict[str, Any]:
    """Unix privilege enumeration using system calls and commands"""
    
    try:
        privilege_info = {
            "user_info": _get_unix_user_info(),
            "group_memberships": _get_unix_group_memberships(),
            "sudo_privileges": _get_unix_sudo_privileges(),
            "file_capabilities": _get_unix_file_capabilities(),
            "escalation_opportunities": _analyze_unix_escalation_opportunities()
        }
        
        return {
            "success": True,
            "privileges": privilege_info,
            "method": "unix_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix privilege enumeration failed: {str(e)}",
            "privileges": None
        }

def _get_windows_user_privileges() -> Dict[str, Any]:
    """Get Windows user privileges using whoami command"""
    
    privileges = {
        "enabled_privileges": [],
        "disabled_privileges": [],
        "privilege_descriptions": {}
    }
    
    try:
        # Use whoami /priv to get detailed privilege information
        result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            in_privileges_section = False
            
            for line in lines:
                line = line.strip()
                if 'Privilege Name' in line and 'Description' in line:
                    in_privileges_section = True
                    continue
                elif in_privileges_section and line and not line.startswith('='):
                    parts = line.split()
                    if len(parts) >= 2:
                        privilege_name = parts[0]
                        status = parts[-1] if parts[-1] in ['Enabled', 'Disabled'] else 'Unknown'
                        
                        # Extract description (everything between name and status)
                        description_parts = parts[1:-1] if len(parts) > 2 else []
                        description = ' '.join(description_parts) if description_parts else 'No description'
                        
                        if status == 'Enabled':
                            privileges["enabled_privileges"].append(privilege_name)
                        elif status == 'Disabled':
                            privileges["disabled_privileges"].append(privilege_name)
                        
                        privileges["privilege_descriptions"][privilege_name] = description
        
        # Also check for administrative privileges
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            privileges["is_administrator"] = is_admin
        except:
            privileges["is_administrator"] = False
            
    except Exception as e:
        privileges["error"] = str(e)
    
    return privileges

def _get_windows_group_memberships() -> List[Dict[str, Any]]:
    """Get Windows group memberships with detailed information"""
    
    groups = []
    
    try:
        # Use whoami /groups to get group information
        result = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            in_groups_section = False
            
            for line in lines:
                line = line.strip()
                if 'Group Name' in line and 'Type' in line:
                    in_groups_section = True
                    continue
                elif in_groups_section and line and not line.startswith('='):
                    parts = line.split()
                    if len(parts) >= 3:
                        group_name = parts[0]
                        sid = parts[1] if len(parts) > 1 else 'Unknown'
                        group_type = parts[2] if len(parts) > 2 else 'Unknown'
                        attributes = ' '.join(parts[3:]) if len(parts) > 3 else 'Unknown'
                        
                        groups.append({
                            "name": group_name,
                            "sid": sid,
                            "type": group_type,
                            "attributes": attributes
                        })
                        
    except Exception:
        pass
    
    return groups

def _get_windows_security_context() -> Dict[str, Any]:
    """Get Windows security context information"""
    
    context = {}
    
    try:
        # Get user SID and domain information
        result = subprocess.run(['whoami', '/user'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'S-' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('S-'):
                            context["user_sid"] = part
                            break
        
        # Get logon session information
        context["username"] = os.environ.get('USERNAME', 'unknown')
        context["domain"] = os.environ.get('USERDOMAIN', 'unknown')
        context["logon_server"] = os.environ.get('LOGONSERVER', 'unknown')
        context["computer_name"] = os.environ.get('COMPUTERNAME', 'unknown')
        
        # Check UAC status
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            context["uac_enabled"] = value == 1
            winreg.CloseKey(key)
        except:
            context["uac_enabled"] = False
        
        # Check if running in elevated context
        context["is_elevated"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    except Exception as e:
        context["error"] = str(e)
    
    return context

def _analyze_windows_escalation_opportunities() -> List[Dict[str, Any]]:
    """Analyze Windows privilege escalation opportunities"""
    
    opportunities = []
    
    try:
        # Check for dangerous privileges
        dangerous_privileges = [
            "SeDebugPrivilege",
            "SeBackupPrivilege", 
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege"
        ]
        
        # Get current privileges
        result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout.lower()
            for priv in dangerous_privileges:
                if priv.lower() in output:
                    if 'enabled' in output:
                        risk_level = "HIGH"
                        description = f"{priv} is enabled - can be used for privilege escalation"
                    else:
                        risk_level = "MEDIUM"
                        description = f"{priv} is available but disabled - may be enableable"
                    
                    opportunities.append({
                        "type": "dangerous_privilege",
                        "privilege": priv,
                        "risk_level": risk_level,
                        "description": description
                    })
        
        # Check for admin group membership
        result = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout.lower()
            if 'administrators' in output:
                opportunities.append({
                    "type": "group_membership",
                    "group": "Administrators",
                    "risk_level": "HIGH",
                    "description": "User is member of Administrators group"
                })
        
        # Check UAC bypass opportunities
        if not ctypes.windll.shell32.IsUserAnAdmin():
            opportunities.append({
                "type": "uac_bypass",
                "risk_level": "MEDIUM",
                "description": "UAC bypass techniques may be applicable"
            })
            
    except Exception:
        pass
    
    return opportunities

def _get_unix_user_info() -> Dict[str, Any]:
    """Get Unix user information"""
    
    user_info = {}
    
    try:
        import pwd
        
        # Get current user details
        uid = os.getuid()
        gid = os.getgid()
        euid = os.geteuid()
        egid = os.getegid()
        
        user_entry = pwd.getpwuid(uid)
        
        user_info.update({
            "uid": uid,
            "gid": gid,
            "euid": euid,
            "egid": egid,
            "username": user_entry.pw_name,
            "home_dir": user_entry.pw_dir,
            "shell": user_entry.pw_shell,
            "gecos": user_entry.pw_gecos,
            "is_root": uid == 0,
            "is_effective_root": euid == 0
        })
        
    except Exception as e:
        user_info["error"] = str(e)
    
    return user_info

def _get_unix_group_memberships() -> List[Dict[str, Any]]:
    """Get Unix group memberships"""
    
    groups = []
    
    try:
        import grp
        import pwd
        
        username = pwd.getpwuid(os.getuid()).pw_name
        
        # Get all groups user is member of
        user_groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
        
        # Add primary group
        primary_gid = os.getgid()
        try:
            primary_group = grp.getgrgid(primary_gid)
            if primary_group.gr_name not in user_groups:
                user_groups.insert(0, primary_group.gr_name)
        except:
            pass
        
        # Get detailed group information
        for group_name in user_groups:
            try:
                group_entry = grp.getgrnam(group_name)
                groups.append({
                    "name": group_name,
                    "gid": group_entry.gr_gid,
                    "members": group_entry.gr_mem
                })
            except:
                groups.append({
                    "name": group_name,
                    "gid": "unknown",
                    "members": []
                })
                
    except Exception:
        pass
    
    return groups

def _get_unix_sudo_privileges() -> Dict[str, Any]:
    """Get Unix sudo privileges"""
    
    sudo_info = {}
    
    try:
        # Check if user can sudo
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=3)
        sudo_info["can_sudo_without_password"] = result.returncode == 0
        
        # Try to get sudo rules
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                sudo_info["sudo_rules"] = result.stdout
            else:
                sudo_info["sudo_rules"] = "Cannot retrieve sudo rules"
        except:
            sudo_info["sudo_rules"] = "sudo command not available or permission denied"
        
        # Check if user is in sudo/wheel group
        import grp
        try:
            sudo_groups = ['sudo', 'wheel', 'admin']
            user_groups = [g.gr_name for g in grp.getgrall() if os.getlogin() in g.gr_mem]
            sudo_info["in_sudo_group"] = any(sg in user_groups for sg in sudo_groups)
        except:
            sudo_info["in_sudo_group"] = False
            
    except Exception as e:
        sudo_info["error"] = str(e)
    
    return sudo_info

def _get_unix_file_capabilities() -> List[Dict[str, Any]]:
    """Get Unix file capabilities that could be exploited"""
    
    capabilities = []
    
    try:
        # Check for SUID/SGID binaries
        common_paths = ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin']
        
        for path in common_paths:
            if os.path.exists(path):
                try:
                    for filename in os.listdir(path):
                        filepath = os.path.join(path, filename)
                        if os.path.isfile(filepath):
                            stat_info = os.stat(filepath)
                            mode = stat_info.st_mode
                            
                            # Check for SUID bit
                            if mode & 0o4000:  # SUID
                                capabilities.append({
                                    "type": "suid",
                                    "path": filepath,
                                    "owner_uid": stat_info.st_uid,
                                    "risk_level": "HIGH" if stat_info.st_uid == 0 else "MEDIUM"
                                })
                            
                            # Check for SGID bit
                            if mode & 0o2000:  # SGID
                                capabilities.append({
                                    "type": "sgid", 
                                    "path": filepath,
                                    "owner_gid": stat_info.st_gid,
                                    "risk_level": "MEDIUM"
                                })
                except (PermissionError, FileNotFoundError):
                    continue
                    
    except Exception:
        pass
    
    return capabilities

def _analyze_unix_escalation_opportunities() -> List[Dict[str, Any]]:
    """Analyze Unix privilege escalation opportunities"""
    
    opportunities = []
    
    try:
        # Check if running as root
        if os.getuid() == 0:
            opportunities.append({
                "type": "already_root",
                "risk_level": "INFO",
                "description": "Already running as root user"
            })
            return opportunities
        
        # Check sudo access
        try:
            result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
            if result.returncode == 0:
                opportunities.append({
                    "type": "sudo_access",
                    "risk_level": "HIGH",
                    "description": "User has passwordless sudo access"
                })
        except:
            pass
        
        # Check for writable /etc/passwd or /etc/shadow
        sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        for filepath in sensitive_files:
            if os.path.exists(filepath) and os.access(filepath, os.W_OK):
                opportunities.append({
                    "type": "writable_sensitive_file",
                    "file": filepath,
                    "risk_level": "CRITICAL",
                    "description": f"Sensitive file {filepath} is writable"
                })
        
        # Check for world-writable directories in PATH
        path_env = os.environ.get('PATH', '')
        for path_dir in path_env.split(':'):
            if os.path.exists(path_dir):
                stat_info = os.stat(path_dir)
                if stat_info.st_mode & 0o002:  # World writable
                    opportunities.append({
                        "type": "writable_path_directory",
                        "directory": path_dir,
                        "risk_level": "HIGH",
                        "description": f"PATH directory {path_dir} is world-writable"
                    })
                    
    except Exception:
        pass
    
    return opportunities


if __name__ == "__main__":
    # Test the elite_privileges command
    print("Testing Elite Privileges Command...")
    
    result = elite_privileges()
    print(f"Test - Privilege enumeration: {result['success']}")
    
    if result['success']:
        privileges = result['privileges']
        
        if sys.platform == 'win32':
            print(f"Enabled privileges: {len(privileges.get('user_privileges', {}).get('enabled_privileges', []))}")
            print(f"Group memberships: {len(privileges.get('group_memberships', []))}")
            print(f"Is administrator: {privileges.get('security_context', {}).get('is_elevated', False)}")
        else:
            user_info = privileges.get('user_info', {})
            print(f"UID: {user_info.get('uid', 'unknown')}")
            print(f"Is root: {user_info.get('is_root', False)}")
            print(f"Group memberships: {len(privileges.get('group_memberships', []))}")
        
        print(f"Escalation opportunities: {len(privileges.get('escalation_opportunities', []))}")
    
    print("✅ Elite Privileges command testing complete")