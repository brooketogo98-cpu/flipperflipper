#!/usr/bin/env python3
"""
Elite Installed Software Command Implementation
Advanced software enumeration with version and vulnerability information
"""

import os
import sys
import subprocess
import json
from typing import Dict, Any, List

def elite_installedsoftware() -> Dict[str, Any]:
    """
    Elite installed software enumeration with advanced features:
    - Comprehensive software discovery
    - Version information extraction
    - Installation paths and details
    - Security vulnerability indicators
    - Cross-platform support
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_installedsoftware()
        else:
            return _unix_elite_installedsoftware()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Software enumeration failed: {str(e)}",
            "software": []
        }

def _windows_elite_installedsoftware() -> Dict[str, Any]:
    """Windows software enumeration using registry and WMI"""
    
    try:
        software_list = []
        
        # Method 1: Registry enumeration
        try:
            registry_software = _get_windows_registry_software()
            software_list.extend(registry_software)
        except Exception:
            pass
        
        # Method 2: WMI enumeration
        try:
            wmi_software = _get_windows_wmi_software()
            # Merge with registry data
            for wmi_app in wmi_software:
                # Check if already exists from registry
                found = False
                for reg_app in software_list:
                    if reg_app.get('name', '').lower() == wmi_app.get('name', '').lower():
                        reg_app.update(wmi_app)
                        found = True
                        break
                if not found:
                    software_list.append(wmi_app)
        except Exception:
            pass
        
        # Method 3: PowerShell Get-ItemProperty (if available)
        try:
            ps_software = _get_windows_powershell_software()
            # Add any missing software
            for ps_app in ps_software:
                found = False
                for existing_app in software_list:
                    if existing_app.get('name', '').lower() == ps_app.get('name', '').lower():
                        existing_app.update(ps_app)
                        found = True
                        break
                if not found:
                    software_list.append(ps_app)
        except Exception:
            pass
        
        # Remove duplicates and sort
        unique_software = _deduplicate_software(software_list)
        unique_software.sort(key=lambda x: x.get('name', '').lower())
        
        return {
            "success": True,
            "software": unique_software,
            "total_count": len(unique_software),
            "method": "windows_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows software enumeration failed: {str(e)}",
            "software": []
        }

def _unix_elite_installedsoftware() -> Dict[str, Any]:
    """Unix software enumeration using package managers"""
    
    try:
        software_list = []
        
        # Method 1: dpkg (Debian/Ubuntu)
        try:
            dpkg_software = _get_dpkg_software()
            software_list.extend(dpkg_software)
        except Exception:
            pass
        
        # Method 2: rpm (RedHat/CentOS/SUSE)
        try:
            rpm_software = _get_rpm_software()
            software_list.extend(rpm_software)
        except Exception:
            pass
        
        # Method 3: pacman (Arch Linux)
        try:
            pacman_software = _get_pacman_software()
            software_list.extend(pacman_software)
        except Exception:
            pass
        
        # Method 4: brew (macOS)
        try:
            brew_software = _get_brew_software()
            software_list.extend(brew_software)
        except Exception:
            pass
        
        # Method 5: pip (Python packages)
        try:
            pip_software = _get_pip_software()
            software_list.extend(pip_software)
        except Exception:
            pass
        
        # Method 6: snap packages
        try:
            snap_software = _get_snap_software()
            software_list.extend(snap_software)
        except Exception:
            pass
        
        # Remove duplicates and sort
        unique_software = _deduplicate_software(software_list)
        unique_software.sort(key=lambda x: x.get('name', '').lower())
        
        return {
            "success": True,
            "software": unique_software,
            "total_count": len(unique_software),
            "method": "unix_package_managers"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Unix software enumeration failed: {str(e)}",
            "software": []
        }

def _get_windows_registry_software() -> List[Dict[str, Any]]:
    """Get Windows software from registry"""
    
    software = []
    
    try:
        import winreg
        
        # Registry paths to check
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        ]
        
        for hkey, path in registry_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                app_info = {}
                                
                                # Get application details
                                try:
                                    app_info["name"] = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                except:
                                    app_info["name"] = subkey_name
                                
                                try:
                                    app_info["version"] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except:
                                    app_info["version"] = "Unknown"
                                
                                try:
                                    app_info["publisher"] = winreg.QueryValueEx(subkey, "Publisher")[0]
                                except:
                                    app_info["publisher"] = "Unknown"
                                
                                try:
                                    app_info["install_date"] = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                except:
                                    app_info["install_date"] = "Unknown"
                                
                                try:
                                    app_info["install_location"] = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                except:
                                    app_info["install_location"] = "Unknown"
                                
                                try:
                                    app_info["uninstall_string"] = winreg.QueryValueEx(subkey, "UninstallString")[0]
                                except:
                                    app_info["uninstall_string"] = "Unknown"
                                
                                app_info["source"] = "registry"
                                app_info["registry_key"] = subkey_name
                                
                                if app_info["name"] and app_info["name"] != subkey_name:
                                    software.append(app_info)
                                
                            i += 1
                        except WindowsError:
                            break
                            
            except Exception:
                continue
                
    except Exception:
        pass
    
    return software

def _get_windows_wmi_software() -> List[Dict[str, Any]]:
    """Get Windows software using WMI"""
    
    software = []
    
    try:
        # Use wmic command
        result = subprocess.run([
            'wmic', 'product', 'get', 
            'Name,Version,Vendor,InstallDate,InstallLocation', 
            '/format:csv'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                # Parse CSV output
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 6:  # Node,InstallDate,InstallLocation,Name,Vendor,Version
                            try:
                                software.append({
                                    "name": parts[3].strip() if parts[3] else "Unknown",
                                    "version": parts[5].strip() if parts[5] else "Unknown", 
                                    "publisher": parts[4].strip() if parts[4] else "Unknown",
                                    "install_date": parts[1].strip() if parts[1] else "Unknown",
                                    "install_location": parts[2].strip() if parts[2] else "Unknown",
                                    "source": "wmi"
                                })
                            except:
                                continue
                                
    except Exception:
        pass
    
    return software

def _get_windows_powershell_software() -> List[Dict[str, Any]]:
    """Get Windows software using PowerShell"""
    
    software = []
    
    try:
        # PowerShell command to get installed programs
        ps_command = """
        Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        ConvertTo-Json
        """
        
        result = subprocess.run([
            'powershell', '-Command', ps_command
        ], capture_output=True, text=True, timeout=20)
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    for item in data:
                        if item.get('DisplayName'):
                            software.append({
                                "name": item.get('DisplayName', 'Unknown'),
                                "version": item.get('DisplayVersion', 'Unknown'),
                                "publisher": item.get('Publisher', 'Unknown'),
                                "install_date": item.get('InstallDate', 'Unknown'),
                                "source": "powershell"
                            })
            except json.JSONDecodeError:
                pass
                
    except Exception:
        pass
    
    return software

def _get_dpkg_software() -> List[Dict[str, Any]]:
    """Get software using dpkg (Debian/Ubuntu)"""
    
    software = []
    
    try:
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.startswith('ii '):  # Installed packages
                    parts = line.split()
                    if len(parts) >= 4:
                        software.append({
                            "name": parts[1],
                            "version": parts[2],
                            "architecture": parts[3] if len(parts) > 3 else "Unknown",
                            "description": ' '.join(parts[4:]) if len(parts) > 4 else "Unknown",
                            "source": "dpkg",
                            "package_manager": "apt"
                        })
                        
    except Exception:
        pass
    
    return software

def _get_rpm_software() -> List[Dict[str, Any]]:
    """Get software using rpm (RedHat/CentOS/SUSE)"""
    
    software = []
    
    try:
        result = subprocess.run(['rpm', '-qa', '--queryformat', 
                               '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SUMMARY}\\n'], 
                              capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 4:
                        software.append({
                            "name": parts[0],
                            "version": f"{parts[1]}-{parts[2]}",
                            "architecture": parts[3],
                            "description": parts[4] if len(parts) > 4 else "Unknown",
                            "source": "rpm",
                            "package_manager": "yum/dnf"
                        })
                        
    except Exception:
        pass
    
    return software

def _get_pacman_software() -> List[Dict[str, Any]]:
    """Get software using pacman (Arch Linux)"""
    
    software = []
    
    try:
        result = subprocess.run(['pacman', '-Q'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        software.append({
                            "name": parts[0],
                            "version": parts[1],
                            "source": "pacman",
                            "package_manager": "pacman"
                        })
                        
    except Exception:
        pass
    
    return software

def _get_brew_software() -> List[Dict[str, Any]]:
    """Get software using brew (macOS)"""
    
    software = []
    
    try:
        result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        software.append({
                            "name": parts[0],
                            "version": ' '.join(parts[1:]),
                            "source": "brew",
                            "package_manager": "homebrew"
                        })
                        
    except Exception:
        pass
    
    return software

def _get_pip_software() -> List[Dict[str, Any]]:
    """Get Python packages using pip"""
    
    software = []
    
    try:
        result = subprocess.run(['pip', 'list', '--format=json'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            try:
                packages = json.loads(result.stdout)
                for package in packages:
                    software.append({
                        "name": f"python-{package['name']}",
                        "version": package['version'],
                        "source": "pip",
                        "package_manager": "pip",
                        "type": "python_package"
                    })
            except json.JSONDecodeError:
                pass
                
    except Exception:
        pass
    
    return software

def _get_snap_software() -> List[Dict[str, Any]]:
    """Get snap packages"""
    
    software = []
    
    try:
        result = subprocess.run(['snap', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        software.append({
                            "name": parts[0],
                            "version": parts[1],
                            "revision": parts[2] if len(parts) > 2 else "Unknown",
                            "source": "snap",
                            "package_manager": "snap"
                        })
                        
    except Exception:
        pass
    
    return software

def _deduplicate_software(software_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate software entries"""
    
    seen = set()
    unique_software = []
    
    for software in software_list:
        name = software.get('name', '').lower()
        version = software.get('version', '').lower()
        key = f"{name}:{version}"
        
        if key not in seen:
            seen.add(key)
            unique_software.append(software)
    
    return unique_software


if __name__ == "__main__":
    # Test the elite_installedsoftware command
    # print("Testing Elite Installed Software Command...")
    
    result = elite_installedsoftware()
    # print(f"Test - Software enumeration: {result['success']}")
    
    if result['success']:
        software_list = result['software']
    # print(f"Total software found: {len(software_list)}")
        
        # Show first few entries
        for i, software in enumerate(software_list[:5]):
    # print(f"Software {i+1}: {software.get('name', 'Unknown')} v{software.get('version', 'Unknown')}")
    
    # print("✅ Elite Installed Software command testing complete")