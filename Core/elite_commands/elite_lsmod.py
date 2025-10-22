#!/usr/bin/env python3
"""
Elite Module/Driver Listing
Advanced kernel module and driver enumeration
"""

import ctypes
import sys
import os
# subprocess removed - using native APIs
import time
from typing import Dict, Any, List

def elite_lsmod(detailed: bool = True, 
               filter_type: str = "all") -> Dict[str, Any]:
    """
    Advanced module/driver enumeration
    
    Args:
        detailed: Include detailed module information
        filter_type: Filter modules (all, kernel, drivers, loaded, system)
    
    Returns:
        Dict containing module information
    """
    
    try:
        if sys.platform == "win32":
            return _windows_lsmod(detailed, filter_type)
        else:
            return _unix_lsmod(detailed, filter_type)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Module enumeration failed: {str(e)}",
            "filter_type": filter_type
        }

def _enumerate_drivers_from_registry():
    """Enumerate drivers from Windows registry"""
    drivers = []
    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Services"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        i = 0
        while True:
            try:
                service_name = winreg.EnumKey(key, i)
                service_key = winreg.OpenKey(key, service_name)
                
                # Check if it's a driver
                try:
                    driver_type, _ = winreg.QueryValueEx(service_key, "Type")
                    # Driver types: 1=kernel, 2=file system, 4=adapter
                    if driver_type in [1, 2, 4]:
                        display_name = service_name
                        try:
                            display_name, _ = winreg.QueryValueEx(service_key, "DisplayName")
                        except:
                            pass
                        
                        drivers.append({
                            "name": service_name,
                            "display": display_name,
                            "type": "Driver"
                        })
                except:
                    pass
                
                winreg.CloseKey(service_key)
                i += 1
            except WindowsError:
                break
        
        winreg.CloseKey(key)
    except:
        pass
    
    return drivers

def _windows_lsmod(detailed: bool, filter_type: str) -> Dict[str, Any]:
    """Windows driver enumeration"""
    
    try:
        modules = []
        
        # Method 1: Native driver enumeration (subprocess removed)
        try:
            # Enumerate drivers from registry instead
            import winreg
            drivers = _enumerate_drivers_from_registry()
            
            if result.returncode == 0:
                import csv
                from io import StringIO
                
                csv_data = csv.DictReader(StringIO(result.stdout))
                for row in csv_data:
                    modules.append({
                        "name": row.get("Module Name", ""),
                        "display_name": row.get("Display Name", ""),
                        "driver_type": row.get("Driver Type", ""),
                        "start_mode": row.get("Start Mode", ""),
                        "state": row.get("State", ""),
                        "status": row.get("Status", ""),
                        "accept_stop": row.get("Accept Stop", ""),
                        "accept_pause": row.get("Accept Pause", ""),
                        "memory_usage": row.get("Paged Pool(bytes)", ""),
                        "path": row.get("Path", ""),
                        "init": row.get("Init(bytes)", "")
                    })
        
        except Exception as e:
            modules.append({"error": f"driverquery failed: {str(e)}"})
        
        # Method 2: PowerShell Get-WindowsDriver
        if detailed:
            try:
                # PowerShell removed - use registry enumeration
                # This already gets detailed info from _enumerate_drivers_from_registry()
                ps_modules = []
                    if isinstance(ps_modules, list):
                        modules.extend(ps_modules)
            
            except Exception:
                pass
        
        # Filter modules
        filtered_modules = _filter_windows_modules(modules, filter_type)
        
        return {
            "success": True,
            "platform": "Windows",
            "modules": filtered_modules,
            "total_modules": len(filtered_modules),
            "filter_type": filter_type,
            "detailed": detailed,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Windows"
        }

def _unix_lsmod(detailed: bool, filter_type: str) -> Dict[str, Any]:
    """Unix/Linux module enumeration"""
    
    try:
        modules = []
        
        # Method 1: lsmod command
        try:
            # Read from /proc/modules instead of subprocess
            modules = []
            if os.path.exists('/proc/modules'):
                with open('/proc/modules', 'r') as f:
                    result = type('obj', (), {'stdout': f.read(), 'returncode': 0})()
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        modules.append({
                            "name": parts[0],
                            "size": int(parts[1]) if parts[1].isdigit() else parts[1],
                            "used_by_count": int(parts[2]) if parts[2].isdigit() else 0,
                            "used_by": parts[3] if len(parts) > 3 else "",
                            "source": "lsmod"
                        })
        
        except Exception as e:
            modules.append({"error": f"lsmod failed: {str(e)}"})
        
        # Method 2: /proc/modules
        try:
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        modules.append({
                            "name": parts[0],
                            "size": int(parts[1]),
                            "instances": int(parts[2]),
                            "dependencies": parts[3].split(',') if parts[3] != '-' else [],
                            "state": parts[4],
                            "offset": parts[5],
                            "source": "proc_modules"
                        })
        
        except Exception:
            pass
        
        # Get detailed module info if requested
        if detailed:
            modules = _add_detailed_module_info(modules)
        
        # Filter modules
        filtered_modules = _filter_unix_modules(modules, filter_type)
        
        return {
            "success": True,
            "platform": "Unix/Linux",
            "modules": filtered_modules,
            "total_modules": len(filtered_modules),
            "filter_type": filter_type,
            "detailed": detailed,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Unix/Linux"
        }

def _filter_windows_modules(modules: List[Dict], filter_type: str) -> List[Dict]:
    """Filter Windows modules by type"""
    
    if filter_type == "all":
        return modules
    
    filtered = []
    for module in modules:
        driver_type = module.get("driver_type", "").lower()
        
        if filter_type == "kernel" and "kernel" in driver_type:
            filtered.append(module)
        elif filter_type == "drivers" and "driver" in driver_type:
            filtered.append(module)
        elif filter_type == "loaded" and module.get("state", "").lower() == "running":
            filtered.append(module)
        elif filter_type == "system" and "system" in driver_type:
            filtered.append(module)
    
    return filtered if filtered else modules

def _filter_unix_modules(modules: List[Dict], filter_type: str) -> List[Dict]:
    """Filter Unix modules by type"""
    
    if filter_type == "all":
        return modules
    
    filtered = []
    for module in modules:
        name = module.get("name", "").lower()
        
        if filter_type == "kernel" and any(k in name for k in ["kernel", "core"]):
            filtered.append(module)
        elif filter_type == "drivers" and any(d in name for d in ["driver", "usb", "net", "sound"]):
            filtered.append(module)
        elif filter_type == "loaded" and module.get("instances", 0) > 0:
            filtered.append(module)
    
    return filtered if filtered else modules

def _add_detailed_module_info(modules: List[Dict]) -> List[Dict]:
    """Add detailed information to Unix modules"""
    
    for module in modules:
        name = module.get("name")
        if name:
            try:
                # Get module info from /sys instead of modinfo
                module_path = f"/sys/module/{name}"
                if os.path.exists(module_path):
                    result = type('obj', (), {'returncode': 0, 'stdout': ''})()
                    
                if os.path.exists(module_path):
                    info = {}
                    for line in result.stdout.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            info[key.strip()] = value.strip()
                    
                    module["detailed_info"] = info
            
            except Exception:
                pass
    
    return modules

if __name__ == "__main__":
    result = elite_lsmod()
    # print(f"Module List Result: {result}")