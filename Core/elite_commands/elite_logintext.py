#!/usr/bin/env python3
"""
Elite Login Text Manipulation
Advanced login message and banner modification
"""

import ctypes
import sys
import os
import subprocess
import winreg
import time
from typing import Dict, Any, Optional

def elite_logintext(action: str = "get",
                   message: str = None,
                   title: str = None,
                   backup: bool = True) -> Dict[str, Any]:
    """
    Advanced login text and banner manipulation
    
    Args:
        action: Action to perform (get, set, clear, backup, restore, legal)
        message: Login message text
        title: Login message title
        backup: Create backup before modifications
    
    Returns:
        Dict containing operation results
    """
    
    try:
        if sys.platform == "win32":
            return _windows_logintext(action, message, title, backup)
        elif sys.platform == "darwin":
            return _macos_logintext(action, message, title, backup)
        else:
            return _linux_logintext(action, message, title, backup)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Login text operation failed: {str(e)}",
            "action": action
        }

def _windows_logintext(action: str, message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Windows login text manipulation"""
    
    try:
        if action == "get":
            return _get_windows_login_text()
        elif action == "set":
            return _set_windows_login_text(message, title, backup)
        elif action == "clear":
            return _clear_windows_login_text(backup)
        elif action == "backup":
            return _backup_windows_login_text()
        elif action == "restore":
            return _restore_windows_login_text(message)  # message as backup file
        elif action == "legal":
            return _set_windows_legal_notice(message, title, backup)
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "available_actions": ["get", "set", "clear", "backup", "restore", "legal"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": action,
            "platform": "Windows"
        }

def _get_windows_login_text() -> Dict[str, Any]:
    """Get current Windows login text"""
    
    try:
        login_info = {}
        
        # Registry path for login messages
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                # Legal notice caption
                try:
                    caption, _ = winreg.QueryValueEx(key, "legalnoticecaption")
                    login_info["legal_notice_caption"] = caption
                except FileNotFoundError:
                    login_info["legal_notice_caption"] = None
                
                # Legal notice text
                try:
                    text, _ = winreg.QueryValueEx(key, "legalnoticetext")
                    login_info["legal_notice_text"] = text
                except FileNotFoundError:
                    login_info["legal_notice_text"] = None
        
        except Exception as e:
            login_info["registry_error"] = str(e)
        
        # Check Winlogon settings
        winlogon_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path) as key:
                # Welcome message
                try:
                    welcome, _ = winreg.QueryValueEx(key, "Welcome")
                    login_info["welcome_message"] = welcome
                except FileNotFoundError:
                    login_info["welcome_message"] = None
                
                # Logon message
                try:
                    logon_msg, _ = winreg.QueryValueEx(key, "LogonPrompt")
                    login_info["logon_prompt"] = logon_msg
                except FileNotFoundError:
                    login_info["logon_prompt"] = None
        
        except Exception as e:
            login_info["winlogon_error"] = str(e)
        
        # Get additional login screen customizations
        login_info.update(_get_windows_login_customizations())
        
        return {
            "success": True,
            "action": "get",
            "platform": "Windows",
            "login_info": login_info,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "get"
        }

def _set_windows_login_text(message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Set Windows login text"""
    
    if not message:
        return {
            "success": False,
            "error": "Message text is required"
        }
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _backup_windows_login_text()
            if backup_result["success"]:
                backup_info = backup_result
        
        # Registry path for login messages
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                # Set legal notice caption
                if title:
                    winreg.SetValueEx(key, "legalnoticecaption", 0, winreg.REG_SZ, title)
                
                # Set legal notice text
                winreg.SetValueEx(key, "legalnoticetext", 0, winreg.REG_SZ, message)
        
        except FileNotFoundError:
            # Create the key if it doesn't exist
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                if title:
                    winreg.SetValueEx(key, "legalnoticecaption", 0, winreg.REG_SZ, title)
                winreg.SetValueEx(key, "legalnoticetext", 0, winreg.REG_SZ, message)
        
        return {
            "success": True,
            "action": "set",
            "message": message,
            "title": title,
            "backup_info": backup_info,
            "platform": "Windows",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "set",
            "message": message,
            "title": title
        }

def _clear_windows_login_text(backup: bool) -> Dict[str, Any]:
    """Clear Windows login text"""
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _backup_windows_login_text()
            if backup_result["success"]:
                backup_info = backup_result
        
        cleared_values = []
        
        # Registry path for login messages
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                # Clear legal notice caption
                try:
                    winreg.DeleteValue(key, "legalnoticecaption")
                    cleared_values.append("legalnoticecaption")
                except FileNotFoundError:
                    pass
                
                # Clear legal notice text
                try:
                    winreg.DeleteValue(key, "legalnoticetext")
                    cleared_values.append("legalnoticetext")
                except FileNotFoundError:
                    pass
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Registry access failed: {str(e)}",
                "action": "clear"
            }
        
        return {
            "success": True,
            "action": "clear",
            "cleared_values": cleared_values,
            "backup_info": backup_info,
            "platform": "Windows",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "clear"
        }

def _backup_windows_login_text() -> Dict[str, Any]:
    """Backup Windows login text settings"""
    
    try:
        # Get current settings
        current_settings = _get_windows_login_text()
        
        if not current_settings["success"]:
            return current_settings
        
        # Create backup file
        timestamp = int(time.time())
        backup_filename = f"windows_login_backup_{timestamp}.json"
        
        import json
        with open(backup_filename, 'w') as f:
            json.dump(current_settings, f, indent=2, default=str)
        
        return {
            "success": True,
            "action": "backup",
            "backup_file": backup_filename,
            "timestamp": timestamp,
            "platform": "Windows"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "backup"
        }

def _restore_windows_login_text(backup_file: str) -> Dict[str, Any]:
    """Restore Windows login text from backup"""
    
    if not backup_file or not os.path.exists(backup_file):
        return {
            "success": False,
            "error": "Backup file not found",
            "backup_file": backup_file
        }
    
    try:
        # Load backup data
        import json
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
        
        login_info = backup_data.get("login_info", {})
        
        # Restore legal notice settings
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        restored_values = []
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                # Restore caption
                caption = login_info.get("legal_notice_caption")
                if caption:
                    winreg.SetValueEx(key, "legalnoticecaption", 0, winreg.REG_SZ, caption)
                    restored_values.append("legalnoticecaption")
                
                # Restore text
                text = login_info.get("legal_notice_text")
                if text:
                    winreg.SetValueEx(key, "legalnoticetext", 0, winreg.REG_SZ, text)
                    restored_values.append("legalnoticetext")
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Registry restore failed: {str(e)}",
                "action": "restore"
            }
        
        return {
            "success": True,
            "action": "restore",
            "backup_file": backup_file,
            "restored_values": restored_values,
            "platform": "Windows",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "restore",
            "backup_file": backup_file
        }

def _set_windows_legal_notice(message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Set Windows legal notice (pre-login message)"""
    
    # This is the same as set_windows_login_text but with explicit legal notice focus
    return _set_windows_login_text(message, title, backup)

def _get_windows_login_customizations() -> Dict[str, Any]:
    """Get additional Windows login screen customizations"""
    
    customizations = {}
    
    try:
        # Check for custom login background
        bg_path = r"SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bg_path) as key:
                try:
                    no_lock_screen, _ = winreg.QueryValueEx(key, "NoLockScreen")
                    customizations["no_lock_screen"] = bool(no_lock_screen)
                except FileNotFoundError:
                    pass
                
                try:
                    lock_screen_image, _ = winreg.QueryValueEx(key, "LockScreenImage")
                    customizations["lock_screen_image"] = lock_screen_image
                except FileNotFoundError:
                    pass
        
        except FileNotFoundError:
            pass
        
        # Check for login screen overlay
        overlay_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, overlay_path) as key:
                try:
                    background_path, _ = winreg.QueryValueEx(key, "Background")
                    customizations["login_background"] = background_path
                except FileNotFoundError:
                    pass
        
        except FileNotFoundError:
            pass
    
    except Exception as e:
        customizations["customization_error"] = str(e)
    
    return customizations

def _macos_logintext(action: str, message: str, title: str, backup: bool) -> Dict[str, Any]:
    """macOS login text manipulation"""
    
    try:
        if action == "get":
            return _get_macos_login_text()
        elif action == "set":
            return _set_macos_login_text(message, title, backup)
        elif action == "clear":
            return _clear_macos_login_text(backup)
        else:
            return {
                "success": False,
                "error": f"Action '{action}' not fully implemented for macOS",
                "available_actions": ["get", "set", "clear"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": action,
            "platform": "macOS"
        }

def _get_macos_login_text() -> Dict[str, Any]:
    """Get macOS login text"""
    
    try:
        login_info = {}
        
        # Check for login window text
        try:
            result = subprocess.run([
                "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "LoginwindowText"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                login_info["loginwindow_text"] = result.stdout.strip()
            else:
                login_info["loginwindow_text"] = None
        
        except Exception as e:
            login_info["loginwindow_error"] = str(e)
        
        # Check for other login customizations
        try:
            result = subprocess.run([
                "defaults", "read", "/Library/Preferences/com.apple.loginwindow"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                login_info["loginwindow_prefs"] = result.stdout
        
        except Exception:
            pass
        
        return {
            "success": True,
            "action": "get",
            "platform": "macOS",
            "login_info": login_info,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "get"
        }

def _set_macos_login_text(message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Set macOS login text"""
    
    if not message:
        return {
            "success": False,
            "error": "Message text is required"
        }
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _get_macos_login_text()
            if backup_result["success"]:
                timestamp = int(time.time())
                backup_filename = f"macos_login_backup_{timestamp}.json"
                
                import json
                with open(backup_filename, 'w') as f:
                    json.dump(backup_result, f, indent=2, default=str)
                
                backup_info = {"backup_file": backup_filename}
        
        # Set login window text
        result = subprocess.run([
            "defaults", "write", "/Library/Preferences/com.apple.loginwindow", 
            "LoginwindowText", message
        ], timeout=10)
        
        if result.returncode == 0:
            return {
                "success": True,
                "action": "set",
                "message": message,
                "title": title,
                "backup_info": backup_info,
                "platform": "macOS",
                "timestamp": time.time()
            }
        else:
            return {
                "success": False,
                "error": "Failed to set login text",
                "action": "set"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "set"
        }

def _clear_macos_login_text(backup: bool) -> Dict[str, Any]:
    """Clear macOS login text"""
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _get_macos_login_text()
            if backup_result["success"]:
                timestamp = int(time.time())
                backup_filename = f"macos_login_backup_{timestamp}.json"
                
                import json
                with open(backup_filename, 'w') as f:
                    json.dump(backup_result, f, indent=2, default=str)
                
                backup_info = {"backup_file": backup_filename}
        
        # Delete login window text
        result = subprocess.run([
            "defaults", "delete", "/Library/Preferences/com.apple.loginwindow", "LoginwindowText"
        ], timeout=10)
        
        return {
            "success": result.returncode == 0,
            "action": "clear",
            "backup_info": backup_info,
            "platform": "macOS",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "clear"
        }

def _linux_logintext(action: str, message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Linux login text manipulation"""
    
    try:
        if action == "get":
            return _get_linux_login_text()
        elif action == "set":
            return _set_linux_login_text(message, title, backup)
        elif action == "clear":
            return _clear_linux_login_text(backup)
        else:
            return {
                "success": False,
                "error": f"Action '{action}' not fully implemented for Linux",
                "available_actions": ["get", "set", "clear"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": action,
            "platform": "Linux"
        }

def _get_linux_login_text() -> Dict[str, Any]:
    """Get Linux login text"""
    
    try:
        login_info = {}
        
        # Check /etc/issue (pre-login message)
        try:
            with open('/etc/issue', 'r') as f:
                login_info["issue"] = f.read()
        except Exception as e:
            login_info["issue_error"] = str(e)
        
        # Check /etc/issue.net (network login message)
        try:
            with open('/etc/issue.net', 'r') as f:
                login_info["issue_net"] = f.read()
        except Exception as e:
            login_info["issue_net_error"] = str(e)
        
        # Check /etc/motd (message of the day)
        try:
            with open('/etc/motd', 'r') as f:
                login_info["motd"] = f.read()
        except Exception as e:
            login_info["motd_error"] = str(e)
        
        # Check for GDM/LightDM customizations
        login_info.update(_get_linux_dm_customizations())
        
        return {
            "success": True,
            "action": "get",
            "platform": "Linux",
            "login_info": login_info,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "get"
        }

def _set_linux_login_text(message: str, title: str, backup: bool) -> Dict[str, Any]:
    """Set Linux login text"""
    
    if not message:
        return {
            "success": False,
            "error": "Message text is required"
        }
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _get_linux_login_text()
            if backup_result["success"]:
                timestamp = int(time.time())
                backup_filename = f"linux_login_backup_{timestamp}.json"
                
                import json
                with open(backup_filename, 'w') as f:
                    json.dump(backup_result, f, indent=2, default=str)
                
                backup_info = {"backup_file": backup_filename}
        
        modified_files = []
        
        # Set /etc/issue
        try:
            with open('/etc/issue', 'w') as f:
                if title:
                    f.write(f"{title}\n\n")
                f.write(f"{message}\n")
            modified_files.append("/etc/issue")
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write /etc/issue: {str(e)}",
                "action": "set"
            }
        
        # Set /etc/motd
        try:
            with open('/etc/motd', 'w') as f:
                if title:
                    f.write(f"{title}\n")
                    f.write("=" * len(title) + "\n\n")
                f.write(f"{message}\n")
            modified_files.append("/etc/motd")
        except Exception as e:
            # MOTD failure is not critical
            pass
        
        return {
            "success": True,
            "action": "set",
            "message": message,
            "title": title,
            "modified_files": modified_files,
            "backup_info": backup_info,
            "platform": "Linux",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "set"
        }

def _clear_linux_login_text(backup: bool) -> Dict[str, Any]:
    """Clear Linux login text"""
    
    try:
        # Create backup if requested
        backup_info = None
        if backup:
            backup_result = _get_linux_login_text()
            if backup_result["success"]:
                timestamp = int(time.time())
                backup_filename = f"linux_login_backup_{timestamp}.json"
                
                import json
                with open(backup_filename, 'w') as f:
                    json.dump(backup_result, f, indent=2, default=str)
                
                backup_info = {"backup_file": backup_filename}
        
        cleared_files = []
        
        # Clear /etc/issue
        try:
            with open('/etc/issue', 'w') as f:
                f.write("")
            cleared_files.append("/etc/issue")
        except Exception:
            pass
        
        # Clear /etc/motd
        try:
            with open('/etc/motd', 'w') as f:
                f.write("")
            cleared_files.append("/etc/motd")
        except Exception:
            pass
        
        return {
            "success": True,
            "action": "clear",
            "cleared_files": cleared_files,
            "backup_info": backup_info,
            "platform": "Linux",
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "clear"
        }

def _get_linux_dm_customizations() -> Dict[str, Any]:
    """Get Linux display manager customizations"""
    
    customizations = {}
    
    # Check GDM settings
    gdm_paths = [
        "/etc/gdm3/greeter.dconf-defaults",
        "/etc/gdm/custom.conf"
    ]
    
    for path in gdm_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    customizations[f"gdm_{os.path.basename(path)}"] = f.read()
            except Exception:
                pass
    
    # Check LightDM settings
    lightdm_paths = [
        "/etc/lightdm/lightdm.conf",
        "/etc/lightdm/lightdm-gtk-greeter.conf"
    ]
    
    for path in lightdm_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    customizations[f"lightdm_{os.path.basename(path)}"] = f.read()
            except Exception:
                pass
    
    return customizations

# Utility functions
def create_custom_login_banner(company_name: str, warning_text: str) -> Dict[str, Any]:
    """Create a custom login banner with company branding"""
    
    banner_text = f"""
╔══════════════════════════════════════════════════════════════╗
║                        {company_name:^30}                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  {warning_text:<58}  ║
║                                                              ║
║  This system is for authorized users only. All activities   ║
║  are monitored and logged. Unauthorized access is           ║
║  prohibited and will be prosecuted to the full extent       ║
║  of the law.                                                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    return {
        "banner_text": banner_text,
        "company_name": company_name,
        "warning_text": warning_text
    }

def set_legal_compliance_banner() -> Dict[str, Any]:
    """Set a legal compliance login banner"""
    
    legal_text = """WARNING: This is a private computer system. Unauthorized access is prohibited by law. All activities on this system are monitored and recorded. By accessing this system, you consent to such monitoring and recording. Any unauthorized access or use may result in criminal prosecution and/or civil liability."""
    
    return elite_logintext("legal", legal_text, "LEGAL NOTICE")

if __name__ == "__main__":
    # Test the implementation
    result = elite_logintext("get")
    print(f"Login Text Result: {result}")