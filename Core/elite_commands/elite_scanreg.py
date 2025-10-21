#!/usr/bin/env python3
"""
Elite Registry Scanner
Advanced Windows registry scanning and analysis
"""

import ctypes
import sys
import os
import time
import re
from typing import Dict, Any, List, Optional

# Conditional imports for Windows
try:
    import winreg
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

def elite_scanreg(scan_type: str = "security",
                 registry_path: str = None,
                 search_term: str = None,
                 deep_scan: bool = False) -> Dict[str, Any]:
    """
    Advanced Windows registry scanning
    
    Args:
        scan_type: Type of scan (security, malware, startup, network, all)
        registry_path: Specific registry path to scan
        search_term: Search for specific keys/values
        deep_scan: Perform deep recursive scanning
    
    Returns:
        Dict containing registry scan results
    """
    
    if sys.platform != "win32":
        return {
            "success": False,
            "error": "Registry scanning is only available on Windows",
            "platform": sys.platform
        }
    
    try:
        if scan_type == "security":
            return _scan_security_registry(deep_scan)
        elif scan_type == "malware":
            return _scan_malware_registry(deep_scan)
        elif scan_type == "startup":
            return _scan_startup_registry(deep_scan)
        elif scan_type == "network":
            return _scan_network_registry(deep_scan)
        elif scan_type == "all":
            return _scan_all_registry(deep_scan)
        elif scan_type == "search":
            return _search_registry(search_term, registry_path, deep_scan)
        else:
            return {
                "success": False,
                "error": f"Unknown scan type: {scan_type}",
                "available_types": ["security", "malware", "startup", "network", "all", "search"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Registry scan failed: {str(e)}",
            "scan_type": scan_type
        }

def _scan_security_registry(deep_scan: bool) -> Dict[str, Any]:
    """Scan registry for security-related entries"""
    
    try:
        security_findings = []
        
        # Security-related registry paths
        security_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        ]
        
        for hive, path in security_paths:
            try:
                findings = _scan_registry_path(hive, path, "security", deep_scan)
                security_findings.extend(findings)
            except Exception as e:
                security_findings.append({
                    "path": path,
                    "error": str(e),
                    "type": "scan_error"
                })
        
        # Analyze findings
        analysis = _analyze_security_findings(security_findings)
        
        return {
            "success": True,
            "scan_type": "security",
            "findings": security_findings,
            "total_findings": len(security_findings),
            "analysis": analysis,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "security"
        }

def _scan_malware_registry(deep_scan: bool) -> Dict[str, Any]:
    """Scan registry for malware indicators"""
    
    try:
        malware_findings = []
        
        # Common malware registry locations
        malware_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\exefile\shell\open\command"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
        ]
        
        for hive, path in malware_paths:
            try:
                findings = _scan_registry_path(hive, path, "malware", deep_scan)
                malware_findings.extend(findings)
            except Exception as e:
                malware_findings.append({
                    "path": path,
                    "error": str(e),
                    "type": "scan_error"
                })
        
        # Check for suspicious patterns
        suspicious_findings = _check_suspicious_patterns(malware_findings)
        
        return {
            "success": True,
            "scan_type": "malware",
            "findings": malware_findings,
            "suspicious_findings": suspicious_findings,
            "total_findings": len(malware_findings),
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "malware"
        }

def _scan_startup_registry(deep_scan: bool) -> Dict[str, Any]:
    """Scan registry for startup programs"""
    
    try:
        startup_findings = []
        
        # Startup registry locations
        startup_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for hive, path in startup_paths:
            try:
                findings = _scan_registry_path(hive, path, "startup", deep_scan)
                startup_findings.extend(findings)
            except Exception as e:
                startup_findings.append({
                    "path": path,
                    "error": str(e),
                    "type": "scan_error"
                })
        
        # Analyze startup programs
        analysis = _analyze_startup_programs(startup_findings)
        
        return {
            "success": True,
            "scan_type": "startup",
            "findings": startup_findings,
            "analysis": analysis,
            "total_findings": len(startup_findings),
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "startup"
        }

def _scan_network_registry(deep_scan: bool) -> Dict[str, Any]:
    """Scan registry for network configuration"""
    
    try:
        network_findings = []
        
        # Network-related registry paths
        network_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\NetworkProvider")
        ]
        
        for hive, path in network_paths:
            try:
                findings = _scan_registry_path(hive, path, "network", deep_scan)
                network_findings.extend(findings)
            except Exception as e:
                network_findings.append({
                    "path": path,
                    "error": str(e),
                    "type": "scan_error"
                })
        
        return {
            "success": True,
            "scan_type": "network",
            "findings": network_findings,
            "total_findings": len(network_findings),
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "network"
        }

def _scan_all_registry(deep_scan: bool) -> Dict[str, Any]:
    """Perform comprehensive registry scan"""
    
    try:
        all_results = {}
        
        # Run all scan types
        scan_types = ["security", "malware", "startup", "network"]
        
        for scan_type in scan_types:
            if scan_type == "security":
                result = _scan_security_registry(deep_scan)
            elif scan_type == "malware":
                result = _scan_malware_registry(deep_scan)
            elif scan_type == "startup":
                result = _scan_startup_registry(deep_scan)
            elif scan_type == "network":
                result = _scan_network_registry(deep_scan)
            
            all_results[scan_type] = result
        
        # Consolidate results
        total_findings = sum(r.get("total_findings", 0) for r in all_results.values())
        
        return {
            "success": True,
            "scan_type": "all",
            "results": all_results,
            "total_findings": total_findings,
            "deep_scan": deep_scan,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "all"
        }

def _search_registry(search_term: str, registry_path: str, deep_scan: bool) -> Dict[str, Any]:
    """Search registry for specific terms"""
    
    if not search_term:
        return {
            "success": False,
            "error": "Search term is required"
        }
    
    try:
        search_results = []
        
        # Define search scope
        if registry_path:
            # Search specific path
            search_paths = [(winreg.HKEY_LOCAL_MACHINE, registry_path)]
        else:
            # Search common locations
            search_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM")
            ]
        
        for hive, path in search_paths:
            try:
                results = _search_registry_path(hive, path, search_term, deep_scan)
                search_results.extend(results)
            except Exception as e:
                search_results.append({
                    "path": path,
                    "error": str(e),
                    "type": "search_error"
                })
        
        return {
            "success": True,
            "scan_type": "search",
            "search_term": search_term,
            "registry_path": registry_path,
            "results": search_results,
            "total_results": len(search_results),
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_type": "search",
            "search_term": search_term
        }

def _scan_registry_path(hive: int, path: str, scan_type: str, deep_scan: bool) -> List[Dict[str, Any]]:
    """Scan a specific registry path"""
    
    findings = []
    
    try:
        with winreg.OpenKey(hive, path) as key:
            # Enumerate values
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    
                    finding = {
                        "hive": _get_hive_name(hive),
                        "path": path,
                        "name": name,
                        "value": value,
                        "type": _get_registry_type_name(reg_type),
                        "scan_type": scan_type
                    }
                    
                    # Add analysis based on scan type
                    if scan_type == "security":
                        finding.update(_analyze_security_value(name, value))
                    elif scan_type == "malware":
                        finding.update(_analyze_malware_value(name, value))
                    elif scan_type == "startup":
                        finding.update(_analyze_startup_value(name, value))
                    
                    findings.append(finding)
                    i += 1
                
                except OSError:
                    break
            
            # Enumerate subkeys if deep scan
            if deep_scan:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = f"{path}\\{subkey_name}"
                        
                        # Recursively scan subkey
                        subkey_findings = _scan_registry_path(hive, subkey_path, scan_type, False)
                        findings.extend(subkey_findings)
                        
                        i += 1
                    
                    except OSError:
                        break
    
    except Exception as e:
        findings.append({
            "hive": _get_hive_name(hive),
            "path": path,
            "error": str(e),
            "type": "access_error"
        })
    
    return findings

def _search_registry_path(hive: int, path: str, search_term: str, deep_scan: bool) -> List[Dict[str, Any]]:
    """Search for specific term in registry path"""
    
    results = []
    search_lower = search_term.lower()
    
    try:
        with winreg.OpenKey(hive, path) as key:
            # Search values
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    
                    # Check if search term matches
                    if (search_lower in name.lower() or 
                        search_lower in str(value).lower()):
                        
                        results.append({
                            "hive": _get_hive_name(hive),
                            "path": path,
                            "name": name,
                            "value": value,
                            "type": _get_registry_type_name(reg_type),
                            "match_type": "value"
                        })
                    
                    i += 1
                
                except OSError:
                    break
            
            # Search subkeys if deep scan
            if deep_scan:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        
                        # Check if subkey name matches
                        if search_lower in subkey_name.lower():
                            results.append({
                                "hive": _get_hive_name(hive),
                                "path": path,
                                "name": subkey_name,
                                "type": "key",
                                "match_type": "key_name"
                            })
                        
                        # Recursively search subkey
                        subkey_path = f"{path}\\{subkey_name}"
                        subkey_results = _search_registry_path(hive, subkey_path, search_term, False)
                        results.extend(subkey_results)
                        
                        i += 1
                    
                    except OSError:
                        break
    
    except Exception:
        pass
    
    return results

def _analyze_security_value(name: str, value: Any) -> Dict[str, Any]:
    """Analyze registry value for security implications"""
    
    analysis = {"security_level": "normal"}
    
    name_lower = name.lower()
    value_str = str(value).lower()
    
    # Check for security-related settings
    if "uac" in name_lower or "enablelua" in name_lower:
        if value == 0:
            analysis["security_level"] = "high"
            analysis["issue"] = "UAC disabled"
    
    elif "disableantispyware" in name_lower:
        if value == 1:
            analysis["security_level"] = "high"
            analysis["issue"] = "Windows Defender disabled"
    
    elif "password" in name_lower:
        analysis["security_level"] = "medium"
        analysis["note"] = "Password-related setting"
    
    return analysis

def _analyze_malware_value(name: str, value: Any) -> Dict[str, Any]:
    """Analyze registry value for malware indicators"""
    
    analysis = {"suspicion_level": "low"}
    
    value_str = str(value).lower()
    
    # Suspicious file locations
    suspicious_paths = [
        "temp", "appdata", "programdata", "system32", "syswow64"
    ]
    
    if any(path in value_str for path in suspicious_paths):
        analysis["suspicion_level"] = "medium"
        analysis["reason"] = "Suspicious file location"
    
    # Suspicious file extensions
    suspicious_extensions = [
        ".tmp", ".bat", ".cmd", ".vbs", ".js", ".jar"
    ]
    
    if any(ext in value_str for ext in suspicious_extensions):
        analysis["suspicion_level"] = "high"
        analysis["reason"] = "Suspicious file extension"
    
    # Check for obfuscation
    if len(value_str) > 100 and not value_str.isascii():
        analysis["suspicion_level"] = "high"
        analysis["reason"] = "Possible obfuscated content"
    
    return analysis

def _analyze_startup_value(name: str, value: Any) -> Dict[str, Any]:
    """Analyze startup registry value"""
    
    analysis = {"startup_type": "normal"}
    
    value_str = str(value)
    
    # Check if file exists
    if os.path.exists(value_str):
        analysis["file_exists"] = True
        analysis["file_size"] = os.path.getsize(value_str)
    else:
        analysis["file_exists"] = False
        analysis["startup_type"] = "suspicious"
    
    # Check for command line arguments
    if " " in value_str:
        parts = value_str.split()
        analysis["executable"] = parts[0]
        analysis["arguments"] = " ".join(parts[1:])
    
    return analysis

def _get_hive_name(hive: int) -> str:
    """Get registry hive name"""
    
    hive_names = {
        winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
        winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
        winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
        winreg.HKEY_USERS: "HKEY_USERS",
        winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
    }
    
    return hive_names.get(hive, f"Unknown({hive})")

def _get_registry_type_name(reg_type: int) -> str:
    """Get registry type name"""
    
    type_names = {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ"
    }
    
    return type_names.get(reg_type, f"Unknown({reg_type})")

def _analyze_security_findings(findings: List[Dict]) -> Dict[str, Any]:
    """Analyze security scan findings"""
    
    analysis = {
        "total_issues": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "recommendations": []
    }
    
    for finding in findings:
        security_level = finding.get("security_level", "normal")
        
        if security_level == "high":
            analysis["high_risk"] += 1
            analysis["total_issues"] += 1
        elif security_level == "medium":
            analysis["medium_risk"] += 1
            analysis["total_issues"] += 1
    
    # Generate recommendations
    if analysis["high_risk"] > 0:
        analysis["recommendations"].append("Review high-risk security settings immediately")
    
    if analysis["medium_risk"] > 0:
        analysis["recommendations"].append("Consider reviewing medium-risk settings")
    
    return analysis

def _check_suspicious_patterns(findings: List[Dict]) -> List[Dict]:
    """Check for suspicious patterns in findings"""
    
    suspicious = []
    
    for finding in findings:
        suspicion_level = finding.get("suspicion_level", "low")
        
        if suspicion_level in ["high", "medium"]:
            suspicious.append(finding)
    
    return suspicious

def _analyze_startup_programs(findings: List[Dict]) -> Dict[str, Any]:
    """Analyze startup program findings"""
    
    analysis = {
        "total_programs": len(findings),
        "missing_files": 0,
        "suspicious_programs": 0,
        "common_programs": []
    }
    
    for finding in findings:
        if not finding.get("file_exists", True):
            analysis["missing_files"] += 1
        
        if finding.get("startup_type") == "suspicious":
            analysis["suspicious_programs"] += 1
        
        # Track common program names
        name = finding.get("name", "")
        if name and name not in analysis["common_programs"]:
            analysis["common_programs"].append(name)
    
    return analysis

if __name__ == "__main__":
    result = elite_scanreg("security")
    # print(f"Registry Scan Result: {result}")