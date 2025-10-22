#!/usr/bin/env python3
"""
Elite Hostname Command Implementation
Advanced hostname retrieval with network information
"""

import os
import sys
import socket
import ctypes
from typing import Dict, Any

def elite_hostname() -> Dict[str, Any]:
    """
    Elite hostname retrieval with advanced features:
    - Multiple hostname sources
    - FQDN resolution
    - Network interface information
    - Cross-platform support
    """
    
    try:
        hostname_info = {}
        
        # Method 1: Socket gethostname
        try:
            hostname_info["hostname"] = socket.gethostname()
        except Exception:
            hostname_info["hostname"] = "unknown"
        
        # Method 2: FQDN (Fully Qualified Domain Name)
        try:
            hostname_info["fqdn"] = socket.getfqdn()
        except Exception:
            hostname_info["fqdn"] = hostname_info["hostname"]
        
        # Method 3: Platform-specific methods
        if sys.platform == 'win32':
            hostname_info.update(_get_windows_hostname_info())
        else:
            hostname_info.update(_get_unix_hostname_info())
        
        # Method 4: Environment variables
        hostname_info["env_hostname"] = (
            os.environ.get('COMPUTERNAME') or 
            os.environ.get('HOSTNAME') or 
            "unknown"
        )
        
        # Additional network information
        hostname_info["domain"] = _get_domain_name()
        hostname_info["ip_addresses"] = _get_local_ip_addresses()
        
        return {
            "success": True,
            "hostname_info": hostname_info,
            "method": "elite_comprehensive"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Hostname retrieval failed: {str(e)}",
            "hostname_info": None
        }

def _get_windows_hostname_info() -> Dict[str, Any]:
    """Get Windows-specific hostname information"""
    
    info = {}
    
    try:
        # Use GetComputerNameW API
        buffer = ctypes.create_unicode_buffer(256)
        size = ctypes.c_ulong(256)
        
        if ctypes.windll.kernel32.GetComputerNameW(buffer, ctypes.byref(size)):
            info["api_hostname"] = buffer.value
        
        # Get DNS hostname
        dns_buffer = ctypes.create_unicode_buffer(256)
        dns_size = ctypes.c_ulong(256)
        
        if ctypes.windll.kernel32.GetComputerNameExW(2, dns_buffer, ctypes.byref(dns_size)):  # ComputerNameDnsHostname = 2
            info["dns_hostname"] = dns_buffer.value
        
        # Get NetBIOS name
        netbios_buffer = ctypes.create_unicode_buffer(256)
        netbios_size = ctypes.c_ulong(256)
        
        if ctypes.windll.kernel32.GetComputerNameExW(0, netbios_buffer, ctypes.byref(netbios_size)):  # ComputerNameNetBIOS = 0
            info["netbios_name"] = netbios_buffer.value
        
        # Domain information
        info["domain"] = os.environ.get('USERDOMAIN', 'unknown')
        info["logon_server"] = os.environ.get('LOGONSERVER', 'unknown')
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

def _get_unix_hostname_info() -> Dict[str, Any]:
    """Get Unix-specific hostname information"""
    
    info = {}
    
    try:
        # Try reading /etc/hostname
        try:
            with open('/etc/hostname', 'r') as f:
                info["etc_hostname"] = f.read().strip()
        except:
            info["etc_hostname"] = "unknown"
        
        # Try reading /proc/sys/kernel/hostname
        try:
            with open('/proc/sys/kernel/hostname', 'r') as f:
                info["kernel_hostname"] = f.read().strip()
        except:
            info["kernel_hostname"] = "unknown"
        
        # Try uname system call
        try:
            import platform
            info["uname_hostname"] = platform.node()
        except:
            info["uname_hostname"] = "unknown"
        
        # Domain information from /etc/resolv.conf
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('domain '):
                        info["resolv_domain"] = line.split()[1]
                        break
                    elif line.startswith('search '):
                        info["search_domains"] = line.split()[1:]
        except:
            pass
            
    except Exception as e:
        info["error"] = str(e)
    
    return info

def _get_domain_name() -> str:
    """Get domain name"""
    
    try:
        # Try to get domain from FQDN
        fqdn = socket.getfqdn()
        if '.' in fqdn:
            return '.'.join(fqdn.split('.')[1:])
        
        # Platform-specific methods
        if sys.platform == 'win32':
            return os.environ.get('USERDNSDOMAIN', 'unknown')
        else:
            # Try reading /etc/resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('domain '):
                            return line.split()[1]
            except:
                pass
        
        return "unknown"
        
    except Exception:
        return "unknown"

def _get_local_ip_addresses() -> list:
    """Get local IP addresses"""
    
    ip_addresses = []
    
    try:
        # Method 1: Connect to external address to find local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            ip_addresses.append(local_ip)
        except:
            pass
        
        # Method 2: Get all interface addresses
        try:
            hostname = socket.gethostname()
            ip_list = socket.gethostbyname_ex(hostname)[2]
            for ip in ip_list:
                if ip not in ip_addresses and not ip.startswith('127.'):
                    ip_addresses.append(ip)
        except:
            pass
        
        # Always include localhost
        if '127.0.0.1' not in ip_addresses:
            ip_addresses.append('127.0.0.1')
            
    except Exception:
        pass
    
    return ip_addresses


if __name__ == "__main__":
    # Test the elite_hostname command
    # print("Testing Elite Hostname Command...")
    
    result = elite_hostname()
    # print(f"Test - Hostname retrieval: {result['success']}")
    
    if result['success']:
        hostname_info = result['hostname_info']
    # print(f"Hostname: {hostname_info.get('hostname', 'unknown')}")
    # print(f"FQDN: {hostname_info.get('fqdn', 'unknown')}")
    # print(f"Domain: {hostname_info.get('domain', 'unknown')}")
    # print(f"IP Addresses: {hostname_info.get('ip_addresses', [])}")
    
    # print("✅ Elite Hostname command testing complete")