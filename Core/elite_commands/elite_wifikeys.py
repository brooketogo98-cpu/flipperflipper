#!/usr/bin/env python3
"""
Elite WiFi Keys Command Implementation
Advanced WiFi password extraction from system stores
"""

import os
import sys
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

def elite_wifikeys() -> Dict[str, Any]:
    """
    Elite WiFi password extraction with advanced features:
    - Windows WLAN profiles extraction
    - Linux NetworkManager secrets
    - macOS Keychain access
    - WPA/WPA2/WEP support
    - Hidden network detection
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_wifi_extraction()
        elif sys.platform == 'darwin':
            return _macos_wifi_extraction()
        else:
            return _linux_wifi_extraction()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"WiFi key extraction failed: {str(e)}",
            "networks": []
        }

def _windows_wifi_extraction() -> Dict[str, Any]:
    """Extract WiFi passwords on Windows using netsh"""
    
    networks = []
    
    try:
        # Get list of WiFi profiles
        profiles_result = subprocess.run(
            ['netsh', 'wlan', 'show', 'profiles'],
            capture_output=True, text=True, timeout=30
        )
        
        if profiles_result.returncode != 0:
            return {
                "success": False,
                "error": "Failed to enumerate WiFi profiles",
                "networks": []
            }
        
        # Parse profile names
        profile_names = []
        for line in profiles_result.stdout.split('\n'):
            if 'All User Profile' in line:
                # Extract profile name
                parts = line.split(':')
                if len(parts) > 1:
                    profile_name = parts[1].strip()
                    profile_names.append(profile_name)
        
        # Get password for each profile
        for profile_name in profile_names:
            try:
                # Get profile details with key
                profile_result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'profile', f'name={profile_name}', 'key=clear'],
                    capture_output=True, text=True, timeout=10
                )
                
                if profile_result.returncode == 0:
                    network_info = _parse_windows_wifi_profile(profile_result.stdout, profile_name)
                    if network_info:
                        networks.append(network_info)
            
            except Exception:
                # Continue with other profiles if one fails
                continue
        
        return {
            "success": len(networks) > 0,
            "networks": networks,
            "total_networks": len(networks),
            "method": "windows_netsh",
            "profiles_found": len(profile_names)
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows WiFi extraction failed: {str(e)}",
            "networks": []
        }

def _parse_windows_wifi_profile(profile_output: str, profile_name: str) -> Dict[str, Any]:
    """Parse Windows WiFi profile output"""
    
    try:
        network_info = {
            "ssid": profile_name,
            "password": "",
            "security": "",
            "authentication": "",
            "encryption": ""
        }
        
        lines = profile_output.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'Key Content' in line and ':' in line:
                password = line.split(':', 1)[1].strip()
                network_info["password"] = password
            
            elif 'Authentication' in line and ':' in line:
                auth = line.split(':', 1)[1].strip()
                network_info["authentication"] = auth
            
            elif 'Cipher' in line and ':' in line:
                cipher = line.split(':', 1)[1].strip()
                network_info["encryption"] = cipher
            
            elif 'Security key' in line and ':' in line:
                security = line.split(':', 1)[1].strip()
                network_info["security"] = security
        
        # Only return if we found a password
        if network_info["password"]:
            return network_info
    
    except Exception:
        pass
    
    return None

def _linux_wifi_extraction() -> Dict[str, Any]:
    """Extract WiFi passwords on Linux from NetworkManager"""
    
    networks = []
    
    try:
        # Method 1: NetworkManager connection files
        nm_connections_dir = "/etc/NetworkManager/system-connections"
        
        if os.path.exists(nm_connections_dir) and os.access(nm_connections_dir, os.R_OK):
            for filename in os.listdir(nm_connections_dir):
                if filename.endswith('.nmconnection') or not '.' in filename:
                    connection_file = os.path.join(nm_connections_dir, filename)
                    
                    try:
                        network_info = _parse_nm_connection_file(connection_file)
                        if network_info:
                            networks.append(network_info)
                    except Exception:
                        continue
        
        # Method 2: Try nmcli if available
        if not networks:
            try:
                nmcli_result = subprocess.run(
                    ['nmcli', '-s', '-g', 'NAME,TYPE,DEVICE', 'connection', 'show'],
                    capture_output=True, text=True, timeout=10
                )
                
                if nmcli_result.returncode == 0:
                    for line in nmcli_result.stdout.strip().split('\n'):
                        if line and 'wifi' in line.lower():
                            parts = line.split(':')
                            if len(parts) >= 1:
                                ssid = parts[0]
                                
                                # Get password for this connection
                                try:
                                    pwd_result = subprocess.run(
                                        ['nmcli', '-s', '-g', '802-11-wireless-security.psk', 
                                         'connection', 'show', ssid],
                                        capture_output=True, text=True, timeout=5
                                    )
                                    
                                    if pwd_result.returncode == 0 and pwd_result.stdout.strip():
                                        networks.append({
                                            "ssid": ssid,
                                            "password": pwd_result.stdout.strip(),
                                            "security": "WPA/WPA2",
                                            "method": "nmcli"
                                        })
                                
                                except Exception:
                                    continue
            
            except Exception:
                pass
        
        # Method 3: wpa_supplicant.conf
        if not networks:
            wpa_conf_paths = [
                "/etc/wpa_supplicant/wpa_supplicant.conf",
                "/etc/wpa_supplicant.conf"
            ]
            
            for conf_path in wpa_conf_paths:
                if os.path.exists(conf_path):
                    try:
                        wpa_networks = _parse_wpa_supplicant_conf(conf_path)
                        networks.extend(wpa_networks)
                    except Exception:
                        continue
        
        return {
            "success": len(networks) > 0,
            "networks": networks,
            "total_networks": len(networks),
            "method": "linux_networkmanager"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Linux WiFi extraction failed: {str(e)}",
            "networks": []
        }

def _parse_nm_connection_file(connection_file: str) -> Dict[str, Any]:
    """Parse NetworkManager connection file"""
    
    try:
        with open(connection_file, 'r') as f:
            content = f.read()
        
        network_info = {
            "ssid": "",
            "password": "",
            "security": "",
            "method": "networkmanager"
        }
        
        # Parse INI-style format
        current_section = ""
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
            elif '=' in line:
                key, value = line.split('=', 1)
                
                if current_section == 'wifi' and key == 'ssid':
                    network_info["ssid"] = value
                elif current_section == 'wifi-security' and key == 'psk':
                    network_info["password"] = value
                elif current_section == 'wifi-security' and key == 'key-mgmt':
                    network_info["security"] = value
        
        if network_info["ssid"] and network_info["password"]:
            return network_info
    
    except Exception:
        pass
    
    return None

def _parse_wpa_supplicant_conf(conf_path: str) -> List[Dict[str, Any]]:
    """Parse wpa_supplicant.conf file"""
    
    networks = []
    
    try:
        with open(conf_path, 'r') as f:
            content = f.read()
        
        # Parse network blocks
        network_blocks = []
        current_block = ""
        in_network = False
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('network={'):
                in_network = True
                current_block = line + '\n'
            elif line == '}' and in_network:
                current_block += line
                network_blocks.append(current_block)
                current_block = ""
                in_network = False
            elif in_network:
                current_block += line + '\n'
        
        # Parse each network block
        for block in network_blocks:
            network_info = {
                "ssid": "",
                "password": "",
                "security": "WPA/WPA2",
                "method": "wpa_supplicant"
            }
            
            for line in block.split('\n'):
                line = line.strip()
                
                if line.startswith('ssid='):
                    ssid = line.split('=', 1)[1].strip('"')
                    network_info["ssid"] = ssid
                elif line.startswith('psk='):
                    psk = line.split('=', 1)[1].strip('"')
                    network_info["password"] = psk
                elif line.startswith('key_mgmt='):
                    key_mgmt = line.split('=', 1)[1]
                    network_info["security"] = key_mgmt
            
            if network_info["ssid"] and network_info["password"]:
                networks.append(network_info)
    
    except Exception:
        pass
    
    return networks

def _macos_wifi_extraction() -> Dict[str, Any]:
    """Extract WiFi passwords on macOS using security command"""
    
    networks = []
    
    try:
        # Get WiFi network list
        airport_result = subprocess.run(
            ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
            capture_output=True, text=True, timeout=10
        )
        
        if airport_result.returncode == 0:
            # Parse network list
            ssids = []
            for line in airport_result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if parts:
                        ssid = parts[0]
                        ssids.append(ssid)
            
            # Get passwords from keychain
            for ssid in ssids:
                try:
                    keychain_result = subprocess.run(
                        ['security', 'find-generic-password', '-D', 'AirPort network password',
                         '-a', ssid, '-w'],
                        capture_output=True, text=True, timeout=5
                    )
                    
                    if keychain_result.returncode == 0:
                        password = keychain_result.stdout.strip()
                        if password:
                            networks.append({
                                "ssid": ssid,
                                "password": password,
                                "security": "WPA/WPA2",
                                "method": "macos_keychain"
                            })
                
                except Exception:
                    continue
        
        return {
            "success": len(networks) > 0,
            "networks": networks,
            "total_networks": len(networks),
            "method": "macos_security_framework"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"macOS WiFi extraction failed: {str(e)}",
            "networks": []
        }


if __name__ == "__main__":
    # Test the elite wifikeys command
    print("Testing Elite WiFi Keys Command...")
    
    result = elite_wifikeys()
    
    if result['success']:
        print(f"✅ WiFi key extraction successful!")
        print(f"Total networks: {result['total_networks']}")
        print(f"Method: {result['method']}")
        
        for network in result['networks']:
            print(f"  SSID: {network['ssid']}")
            print(f"    Password: {network['password']}")
            print(f"    Security: {network['security']}")
    else:
        print(f"❌ WiFi key extraction failed: {result.get('error', 'No networks found')}")
    
    print("Elite WiFi Keys command test complete")