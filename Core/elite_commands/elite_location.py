#!/usr/bin/env python3
"""
Elite Location Command Implementation - FULLY NATIVE, NO SUBPROCESS
Advanced geolocation using only native APIs and direct network calls
"""

import os
import sys
import socket
import json
import ssl
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional
import struct
import ctypes

def elite_location(detailed: bool = True) -> Dict[str, Any]:
    """
    Elite location gathering with ZERO subprocess calls
    Uses only native APIs and direct network requests
    """
    
    try:
        result = {
            "success": True,
            "public_ip": None,
            "local_ips": [],
            "location": {},
            "network_info": {},
            "wifi_info": {},
            "gps": {}
        }
        
        # Get local IPs
        result["local_ips"] = _get_local_ips()
        
        # Get public IP and geolocation
        public_info = _get_public_ip_and_location()
        result["public_ip"] = public_info.get("ip")
        result["location"] = public_info.get("location", {})
        
        # Get network information
        result["network_info"] = _get_network_info()
        
        # Get WiFi information if available
        if sys.platform == 'win32':
            result["wifi_info"] = _get_windows_wifi_info()
        else:
            result["wifi_info"] = _get_unix_wifi_info()
        
        # Try to get GPS if available (mobile devices)
        if detailed:
            result["gps"] = _try_get_gps()
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Location gathering failed: {str(e)}"
        }

def _get_local_ips() -> list:
    """Get all local IP addresses"""
    
    local_ips = []
    
    try:
        # Method 1: Using socket
        hostname = socket.gethostname()
        local_ips.append(socket.gethostbyname(hostname))
        
        # Method 2: Get all IPs
        try:
            host_entry = socket.gethostbyname_ex(hostname)
            local_ips.extend(host_entry[2])
        except:
            pass
        
        # Method 3: Connect to external server to find local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip not in local_ips:
                local_ips.append(local_ip)
        except:
            pass
        
        # Remove duplicates
        local_ips = list(set(local_ips))
        
    except:
        pass
    
    return local_ips

def _get_public_ip_and_location() -> Dict[str, Any]:
    """Get public IP and geolocation using native HTTPS requests"""
    
    result = {
        "ip": None,
        "location": {}
    }
    
    # List of IP/geolocation services to try
    services = [
        ("https://ipapi.co/json/", None),
        ("https://ipinfo.io/json", None),
        ("https://api.ipify.org?format=json", "ip"),
        ("https://api.myip.com", None)
    ]
    
    for service_url, ip_field in services:
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Make request
            req = urllib.request.Request(
                service_url,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                # Extract IP
                if ip_field:
                    result["ip"] = data.get(ip_field)
                else:
                    result["ip"] = data.get("ip") or data.get("query")
                
                # Extract location info
                result["location"] = {
                    "country": data.get("country") or data.get("country_name"),
                    "region": data.get("region") or data.get("region_name"),
                    "city": data.get("city"),
                    "postal": data.get("postal") or data.get("zip"),
                    "latitude": data.get("latitude") or data.get("lat"),
                    "longitude": data.get("longitude") or data.get("lon"),
                    "timezone": data.get("timezone") or data.get("time_zone"),
                    "isp": data.get("isp") or data.get("org"),
                    "asn": data.get("asn")
                }
                
                # Remove None values
                result["location"] = {k: v for k, v in result["location"].items() if v is not None}
                
                if result["ip"]:
                    break
                    
        except Exception:
            continue
    
    return result

def _get_network_info() -> Dict[str, Any]:
    """Get network configuration info"""
    
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "default_gateway": None,
        "dns_servers": [],
        "mac_addresses": []
    }
    
    if sys.platform == 'win32':
        info.update(_get_windows_network_info())
    else:
        info.update(_get_unix_network_info())
    
    return info

def _get_windows_network_info() -> Dict[str, Any]:
    """Get Windows network info using native APIs"""
    
    info = {
        "interfaces": []
    }
    
    try:
        # Get network adapters using WMI through ctypes
        import uuid
        mac = ':'.join(('%012X' % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        info["primary_mac"] = mac
        
        # Get DNS servers from registry
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            )
            try:
                dns, _ = winreg.QueryValueEx(key, "NameServer")
                if dns:
                    info["dns_servers"] = dns.split(',')
            except:
                pass
            
            try:
                dhcp_dns, _ = winreg.QueryValueEx(key, "DhcpNameServer")
                if dhcp_dns and not info.get("dns_servers"):
                    info["dns_servers"] = dhcp_dns.split(' ')
            except:
                pass
            
            winreg.CloseKey(key)
        except:
            pass
        
        # Get default gateway
        try:
            # Use GetIpForwardTable via ctypes
            iphlpapi = ctypes.windll.iphlpapi
            
            class MIB_IPFORWARDROW(ctypes.Structure):
                _fields_ = [
                    ("dwForwardDest", ctypes.c_uint32),
                    ("dwForwardMask", ctypes.c_uint32),
                    ("dwForwardPolicy", ctypes.c_uint32),
                    ("dwForwardNextHop", ctypes.c_uint32),
                    ("dwForwardIfIndex", ctypes.c_uint32),
                    ("dwForwardType", ctypes.c_uint32),
                    ("dwForwardProto", ctypes.c_uint32),
                    ("dwForwardAge", ctypes.c_uint32),
                    ("dwForwardNextHopAS", ctypes.c_uint32),
                    ("dwForwardMetric1", ctypes.c_uint32),
                    ("dwForwardMetric2", ctypes.c_uint32),
                    ("dwForwardMetric3", ctypes.c_uint32),
                    ("dwForwardMetric4", ctypes.c_uint32),
                    ("dwForwardMetric5", ctypes.c_uint32)
                ]
            
            class MIB_IPFORWARDTABLE(ctypes.Structure):
                _fields_ = [
                    ("dwNumEntries", ctypes.c_uint32),
                    ("table", MIB_IPFORWARDROW * 1)
                ]
            
            size = ctypes.c_uint32(0)
            iphlpapi.GetIpForwardTable(None, ctypes.byref(size), False)
            
            if size.value > 0:
                buffer = ctypes.create_string_buffer(size.value)
                if iphlpapi.GetIpForwardTable(buffer, ctypes.byref(size), False) == 0:
                    forward_table = ctypes.cast(buffer, ctypes.POINTER(MIB_IPFORWARDTABLE)).contents
                    
                    for i in range(forward_table.dwNumEntries):
                        if forward_table.table[i].dwForwardDest == 0:  # Default route
                            gateway_ip = socket.inet_ntoa(
                                struct.pack('!I', forward_table.table[i].dwForwardNextHop)
                            )
                            info["default_gateway"] = gateway_ip
                            break
        except:
            pass
        
    except Exception:
        pass
    
    return info

def _get_unix_network_info() -> Dict[str, Any]:
    """Get Unix network info using native methods"""
    
    info = {}
    
    try:
        # Get MAC address
        import uuid
        mac = ':'.join(('%012X' % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        info["primary_mac"] = mac
        
        # Get DNS servers from resolv.conf
        if os.path.exists('/etc/resolv.conf'):
            dns_servers = []
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns = line.split()[1]
                        dns_servers.append(dns)
            info["dns_servers"] = dns_servers
        
        # Get default gateway from /proc
        if os.path.exists('/proc/net/route'):
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == '00000000':  # Default route
                        gateway_hex = fields[2]
                        # Convert hex to IP
                        gateway_ip = socket.inet_ntoa(struct.pack('<I', int(gateway_hex, 16)))
                        info["default_gateway"] = gateway_ip
                        break
        
    except Exception:
        pass
    
    return info

def _get_windows_wifi_info() -> Dict[str, Any]:
    """Get Windows WiFi information using native APIs"""
    
    wifi_info = {
        "connected": False,
        "ssid": None,
        "signal_strength": None,
        "nearby_networks": []
    }
    
    try:
        # Use Windows WLAN API via ctypes
        wlanapi = ctypes.windll.wlanapi
        
        # WLAN structures
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)
            ]
        
        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_int)
            ]
        
        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", ctypes.c_ulong),
                ("dwIndex", ctypes.c_ulong),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)
            ]
        
        # Open WLAN handle
        negotiated_version = ctypes.c_ulong()
        client_handle = ctypes.c_void_p()
        
        if wlanapi.WlanOpenHandle(
            2,  # Client version
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(client_handle)
        ) == 0:
            
            # Enumerate interfaces
            interface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            
            if wlanapi.WlanEnumInterfaces(
                client_handle,
                None,
                ctypes.byref(interface_list)
            ) == 0:
                
                if interface_list.contents.dwNumberOfItems > 0:
                    wifi_info["connected"] = True
                    
                    # Get current connection info
                    # This would require additional WLAN API calls
                    # For now, mark as connected if interface exists
                    
                wlanapi.WlanFreeMemory(interface_list)
            
            wlanapi.WlanCloseHandle(client_handle, None)
            
    except Exception:
        pass
    
    # Fallback: Check for saved WiFi profiles
    try:
        wifi_dir = os.path.join(
            os.environ.get('ProgramData', 'C:\\ProgramData'),
            'Microsoft\\Wlansvc\\Profiles\\Interfaces'
        )
        
        if os.path.exists(wifi_dir):
            for root, dirs, files in os.walk(wifi_dir):
                for file in files:
                    if file.endswith('.xml'):
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if '<name>' in content:
                                    start = content.find('<name>') + 6
                                    end = content.find('</name>')
                                    ssid = content[start:end]
                                    if ssid and ssid not in [n['ssid'] for n in wifi_info['nearby_networks']]:
                                        wifi_info['nearby_networks'].append({
                                            'ssid': ssid,
                                            'saved': True
                                        })
                        except:
                            continue
    except:
        pass
    
    return wifi_info

def _get_unix_wifi_info() -> Dict[str, Any]:
    """Get Unix WiFi information using native methods"""
    
    wifi_info = {
        "connected": False,
        "ssid": None,
        "signal_strength": None,
        "nearby_networks": []
    }
    
    try:
        # Check /proc/net/wireless for signal info
        if os.path.exists('/proc/net/wireless'):
            with open('/proc/net/wireless', 'r') as f:
                lines = f.readlines()
                if len(lines) > 2:  # Skip headers
                    for line in lines[2:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            interface = parts[0].rstrip(':')
                            signal = parts[2]
                            wifi_info['connected'] = True
                            wifi_info['signal_strength'] = signal
                            break
        
        # Check NetworkManager connections
        nm_dir = '/etc/NetworkManager/system-connections'
        if os.path.exists(nm_dir):
            for file in os.listdir(nm_dir):
                try:
                    filepath = os.path.join(nm_dir, file)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if '[wifi]' in content:
                            for line in content.split('\n'):
                                if line.startswith('ssid='):
                                    ssid = line.split('=')[1]
                                    wifi_info['nearby_networks'].append({
                                        'ssid': ssid,
                                        'saved': True
                                    })
                                    break
                except:
                    continue
        
        # Check wpa_supplicant config
        wpa_conf = '/etc/wpa_supplicant/wpa_supplicant.conf'
        if os.path.exists(wpa_conf):
            try:
                with open(wpa_conf, 'r') as f:
                    content = f.read()
                    import re
                    ssids = re.findall(r'ssid="([^"]+)"', content)
                    for ssid in ssids:
                        if ssid not in [n['ssid'] for n in wifi_info['nearby_networks']]:
                            wifi_info['nearby_networks'].append({
                                'ssid': ssid,
                                'saved': True
                            })
            except:
                pass
    
    except Exception:
        pass
    
    return wifi_info

def _try_get_gps() -> Dict[str, Any]:
    """Try to get GPS coordinates if available"""
    
    gps_info = {
        "available": False,
        "latitude": None,
        "longitude": None,
        "accuracy": None
    }
    
    # On mobile devices or systems with GPS hardware,
    # this would interface with GPS APIs
    # For now, return empty GPS info
    
    return gps_info