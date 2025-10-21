#!/usr/bin/env python3
"""
Elite Environment Variables
Advanced environment variable enumeration and manipulation
"""

import ctypes
import sys
import os
import subprocess
import time
from typing import Dict, Any, List, Optional

# Conditional imports for Windows
try:
    import ctypes.wintypes
    import winreg
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

def elite_environment(action: str = "list", 
                     var_name: str = None, 
                     var_value: str = None,
                     scope: str = "all") -> Dict[str, Any]:
    """
    Advanced environment variable operations
    
    Args:
        action: Action to perform (list, get, set, delete, backup, restore)
        var_name: Variable name for get/set/delete operations
        var_value: Variable value for set operations
        scope: Scope for operations (all, user, system, process)
    
    Returns:
        Dict containing environment information and operation results
    """
    
    try:
        if action == "list":
            return _list_environment_variables(scope)
        elif action == "get":
            return _get_environment_variable(var_name, scope)
        elif action == "set":
            return _set_environment_variable(var_name, var_value, scope)
        elif action == "delete":
            return _delete_environment_variable(var_name, scope)
        elif action == "backup":
            return _backup_environment_variables(scope)
        elif action == "restore":
            return _restore_environment_variables(var_name)  # var_name as backup file
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "available_actions": ["list", "get", "set", "delete", "backup", "restore"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Environment operation failed: {str(e)}",
            "action": action
        }

def _list_environment_variables(scope: str) -> Dict[str, Any]:
    """List environment variables from specified scope"""
    
    variables = {}
    
    try:
        if sys.platform == "win32":
            if scope in ["all", "process"]:
                variables["process"] = _get_process_environment()
            
            if scope in ["all", "user"]:
                variables["user"] = _get_user_environment()
            
            if scope in ["all", "system"]:
                variables["system"] = _get_system_environment()
            
            if scope in ["all", "volatile"]:
                variables["volatile"] = _get_volatile_environment()
        
        else:
            # Unix/Linux
            variables["process"] = dict(os.environ)
            
            # Try to get user profile variables
            try:
                with open(os.path.expanduser("~/.bashrc"), 'r') as f:
                    variables["bashrc"] = _parse_shell_variables(f.read())
            except:
                pass
            
            try:
                with open(os.path.expanduser("~/.profile"), 'r') as f:
                    variables["profile"] = _parse_shell_variables(f.read())
            except:
                pass
        
        # Calculate statistics
        stats = _calculate_environment_stats(variables)
        
        return {
            "success": True,
            "platform": sys.platform,
            "scope": scope,
            "variables": variables,
            "statistics": stats,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scope": scope
        }

def _get_process_environment() -> Dict[str, str]:
    """Get current process environment variables"""
    
    return dict(os.environ)

def _get_user_environment() -> Dict[str, str]:
    """Get user environment variables from registry (Windows)"""
    
    variables = {}
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    variables[name] = {
                        "value": value,
                        "type": _get_registry_type_name(reg_type),
                        "source": "user_registry"
                    }
                    i += 1
                except OSError:
                    break
    
    except Exception as e:
        variables["_error"] = str(e)
    
    return variables

def _get_system_environment() -> Dict[str, str]:
    """Get system environment variables from registry (Windows)"""
    
    variables = {}
    
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    variables[name] = {
                        "value": value,
                        "type": _get_registry_type_name(reg_type),
                        "source": "system_registry"
                    }
                    i += 1
                except OSError:
                    break
    
    except Exception as e:
        variables["_error"] = str(e)
    
    return variables

def _get_volatile_environment() -> Dict[str, str]:
    """Get volatile environment variables (Windows)"""
    
    variables = {}
    
    try:
        # Current user volatile environment
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               r"Volatile Environment") as key:
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        variables[name] = {
                            "value": value,
                            "type": _get_registry_type_name(reg_type),
                            "source": "user_volatile"
                        }
                        i += 1
                    except OSError:
                        break
        except:
            pass
        
        # Session-specific volatile environment
        try:
            session_id = _get_current_session_id()
            if session_id:
                session_key = f"Volatile Environment\\{session_id}"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, session_key) as key:
                    i = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, i)
                            variables[f"session_{name}"] = {
                                "value": value,
                                "type": _get_registry_type_name(reg_type),
                                "source": "session_volatile"
                            }
                            i += 1
                        except OSError:
                            break
        except:
            pass
    
    except Exception as e:
        variables["_error"] = str(e)
    
    return variables

def _get_environment_variable(var_name: str, scope: str) -> Dict[str, Any]:
    """Get specific environment variable"""
    
    if not var_name:
        return {
            "success": False,
            "error": "Variable name is required"
        }
    
    results = {}
    
    try:
        if sys.platform == "win32":
            if scope in ["all", "process"]:
                results["process"] = os.environ.get(var_name)
            
            if scope in ["all", "user"]:
                results["user"] = _get_registry_variable(
                    winreg.HKEY_CURRENT_USER, "Environment", var_name)
            
            if scope in ["all", "system"]:
                results["system"] = _get_registry_variable(
                    winreg.HKEY_LOCAL_MACHINE, 
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    var_name)
        else:
            results["process"] = os.environ.get(var_name)
        
        # Find the effective value
        effective_value = None
        for source in ["process", "user", "system"]:
            if source in results and results[source] is not None:
                effective_value = results[source]
                break
        
        return {
            "success": True,
            "variable_name": var_name,
            "effective_value": effective_value,
            "all_sources": results,
            "scope": scope
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "variable_name": var_name
        }

def _set_environment_variable(var_name: str, var_value: str, scope: str) -> Dict[str, Any]:
    """Set environment variable"""
    
    if not var_name:
        return {
            "success": False,
            "error": "Variable name is required"
        }
    
    if var_value is None:
        var_value = ""
    
    results = {}
    
    try:
        if scope in ["all", "process"]:
            # Set in current process
            os.environ[var_name] = var_value
            results["process"] = "success"
        
        if sys.platform == "win32":
            if scope in ["all", "user"]:
                # Set in user registry
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 
                                       0, winreg.KEY_ALL_ACCESS) as key:
                        winreg.SetValueEx(key, var_name, 0, winreg.REG_EXPAND_SZ, var_value)
                    results["user"] = "success"
                    
                    # Broadcast change
                    _broadcast_environment_change()
                
                except Exception as e:
                    results["user"] = f"failed: {str(e)}"
            
            if scope in ["all", "system"]:
                # Set in system registry (requires admin)
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                                       0, winreg.KEY_ALL_ACCESS) as key:
                        winreg.SetValueEx(key, var_name, 0, winreg.REG_EXPAND_SZ, var_value)
                    results["system"] = "success"
                    
                    # Broadcast change
                    _broadcast_environment_change()
                
                except Exception as e:
                    results["system"] = f"failed: {str(e)}"
        
        success = any("success" in str(result) for result in results.values())
        
        return {
            "success": success,
            "variable_name": var_name,
            "variable_value": var_value,
            "scope": scope,
            "results": results
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "variable_name": var_name,
            "variable_value": var_value
        }

def _delete_environment_variable(var_name: str, scope: str) -> Dict[str, Any]:
    """Delete environment variable"""
    
    if not var_name:
        return {
            "success": False,
            "error": "Variable name is required"
        }
    
    results = {}
    
    try:
        if scope in ["all", "process"]:
            # Remove from current process
            if var_name in os.environ:
                del os.environ[var_name]
                results["process"] = "deleted"
            else:
                results["process"] = "not_found"
        
        if sys.platform == "win32":
            if scope in ["all", "user"]:
                # Delete from user registry
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment",
                                       0, winreg.KEY_ALL_ACCESS) as key:
                        winreg.DeleteValue(key, var_name)
                    results["user"] = "deleted"
                    
                    # Broadcast change
                    _broadcast_environment_change()
                
                except FileNotFoundError:
                    results["user"] = "not_found"
                except Exception as e:
                    results["user"] = f"failed: {str(e)}"
            
            if scope in ["all", "system"]:
                # Delete from system registry (requires admin)
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                                       0, winreg.KEY_ALL_ACCESS) as key:
                        winreg.DeleteValue(key, var_name)
                    results["system"] = "deleted"
                    
                    # Broadcast change
                    _broadcast_environment_change()
                
                except FileNotFoundError:
                    results["system"] = "not_found"
                except Exception as e:
                    results["system"] = f"failed: {str(e)}"
        
        success = any("deleted" in str(result) for result in results.values())
        
        return {
            "success": success,
            "variable_name": var_name,
            "scope": scope,
            "results": results
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "variable_name": var_name
        }

def _backup_environment_variables(scope: str) -> Dict[str, Any]:
    """Backup environment variables to file"""
    
    try:
        # Get all variables
        env_data = _list_environment_variables(scope)
        
        if not env_data["success"]:
            return env_data
        
        # Create backup filename
        timestamp = int(time.time())
        backup_file = f"env_backup_{scope}_{timestamp}.json"
        
        # Save to file
        import json
        with open(backup_file, 'w') as f:
            json.dump(env_data, f, indent=2, default=str)
        
        return {
            "success": True,
            "backup_file": backup_file,
            "scope": scope,
            "timestamp": timestamp,
            "variables_backed_up": sum(len(vars_dict) for vars_dict in env_data["variables"].values())
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scope": scope
        }

def _restore_environment_variables(backup_file: str) -> Dict[str, Any]:
    """Restore environment variables from backup file"""
    
    try:
        if not backup_file or not os.path.exists(backup_file):
            return {
                "success": False,
                "error": "Backup file not found"
            }
        
        # Load backup data
        import json
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
        
        restored = {}
        errors = {}
        
        # Restore variables
        for scope, variables in backup_data.get("variables", {}).items():
            if scope.startswith("_"):
                continue
            
            restored[scope] = 0
            errors[scope] = []
            
            for var_name, var_info in variables.items():
                try:
                    if isinstance(var_info, dict):
                        var_value = var_info.get("value", "")
                    else:
                        var_value = str(var_info)
                    
                    result = _set_environment_variable(var_name, var_value, scope)
                    
                    if result["success"]:
                        restored[scope] += 1
                    else:
                        errors[scope].append(f"{var_name}: {result.get('error', 'unknown error')}")
                
                except Exception as e:
                    errors[scope].append(f"{var_name}: {str(e)}")
        
        total_restored = sum(restored.values())
        
        return {
            "success": total_restored > 0,
            "backup_file": backup_file,
            "restored_counts": restored,
            "total_restored": total_restored,
            "errors": errors
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "backup_file": backup_file
        }

def _get_registry_variable(hive: int, subkey: str, var_name: str) -> Optional[str]:
    """Get variable from registry"""
    
    try:
        with winreg.OpenKey(hive, subkey) as key:
            value, reg_type = winreg.QueryValueEx(key, var_name)
            return value
    except:
        return None

def _get_registry_type_name(reg_type: int) -> str:
    """Convert registry type to name"""
    
    types = {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ"
    }
    
    return types.get(reg_type, f"Unknown({reg_type})")

def _get_current_session_id() -> Optional[str]:
    """Get current Windows session ID"""
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        session_id = ctypes.wintypes.DWORD()
        process_id = kernel32.GetCurrentProcessId()
        
        success = kernel32.ProcessIdToSessionId(process_id, ctypes.byref(session_id))
        
        if success:
            return str(session_id.value)
    
    except:
        pass
    
    return None

def _broadcast_environment_change():
    """Broadcast environment change to all windows"""
    
    try:
        user32 = ctypes.windll.user32
        
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        
        user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,  # 5 second timeout
            None
        )
    
    except:
        pass

def _parse_shell_variables(content: str) -> Dict[str, str]:
    """Parse shell script variables"""
    
    variables = {}
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Look for export statements
        if line.startswith('export ') and '=' in line:
            try:
                var_part = line[7:]  # Remove 'export '
                name, value = var_part.split('=', 1)
                
                # Remove quotes
                value = value.strip('"\'')
                
                variables[name] = value
            except:
                continue
        
        # Look for regular assignments
        elif '=' in line and not line.startswith('#'):
            try:
                name, value = line.split('=', 1)
                
                # Remove quotes
                value = value.strip('"\'')
                
                variables[name] = value
            except:
                continue
    
    return variables

def _calculate_environment_stats(variables: Dict[str, Dict]) -> Dict[str, Any]:
    """Calculate environment variable statistics"""
    
    stats = {
        "total_variables": 0,
        "by_scope": {},
        "common_variables": [],
        "longest_name": "",
        "longest_value": "",
        "path_variables": []
    }
    
    all_names = set()
    
    for scope, vars_dict in variables.items():
        if scope.startswith("_"):
            continue
        
        count = len(vars_dict)
        stats["by_scope"][scope] = count
        stats["total_variables"] += count
        
        for name, value in vars_dict.items():
            all_names.add(name)
            
            # Track longest name and value
            if len(name) > len(stats["longest_name"]):
                stats["longest_name"] = name
            
            value_str = str(value)
            if len(value_str) > len(stats["longest_value"]):
                stats["longest_value"] = value_str
            
            # Track PATH-like variables
            if "path" in name.lower() and (";" in value_str or ":" in value_str):
                stats["path_variables"].append(name)
    
    # Find common variable names across scopes
    scope_count = len([s for s in variables.keys() if not s.startswith("_")])
    if scope_count > 1:
        for name in all_names:
            count = sum(1 for scope, vars_dict in variables.items() 
                       if not scope.startswith("_") and name in vars_dict)
            if count > 1:
                stats["common_variables"].append(name)
    
    return stats

if __name__ == "__main__":
    # Test the implementation
    result = elite_environment("list", scope="all")
    print(f"Environment Variables Result: {result}")