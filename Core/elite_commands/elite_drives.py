#!/usr/bin/env python3
"""
Elite Drive Enumeration
Advanced disk and storage device enumeration
"""

import ctypes
import ctypes.wintypes
import sys
import os
import subprocess
import time
import psutil
from typing import Dict, Any, List, Optional

def elite_drives(include_network: bool = True, 
                include_removable: bool = True,
                detailed_info: bool = True) -> Dict[str, Any]:
    """
    Comprehensive drive and storage enumeration
    
    Args:
        include_network: Include network drives
        include_removable: Include removable drives
        detailed_info: Include detailed drive information
    
    Returns:
        Dict containing drive information and statistics
    """
    
    try:
        if sys.platform == "win32":
            return _windows_drives(include_network, include_removable, detailed_info)
        else:
            return _unix_drives(include_network, include_removable, detailed_info)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Drive enumeration failed: {str(e)}",
            "drives": []
        }

def _windows_drives(include_network: bool, include_removable: bool, detailed_info: bool) -> Dict[str, Any]:
    """Windows drive enumeration using multiple methods"""
    
    drives = []
    
    # Method 1: GetLogicalDrives API
    api_drives = _get_logical_drives_api()
    drives.extend(api_drives)
    
    # Method 2: WMI enumeration
    wmi_drives = _get_wmi_drives()
    drives = _merge_drive_info(drives, wmi_drives)
    
    # Method 3: Volume enumeration
    volume_drives = _get_volume_drives()
    drives = _merge_drive_info(drives, volume_drives)
    
    # Method 4: Registry enumeration
    registry_drives = _get_registry_drives()
    drives = _merge_drive_info(drives, registry_drives)
    
    # Filter drives based on options
    filtered_drives = _filter_drives(drives, include_network, include_removable)
    
    # Add detailed information if requested
    if detailed_info:
        for drive in filtered_drives:
            _add_detailed_info(drive)
    
    # Get system storage statistics
    storage_stats = _get_storage_statistics(filtered_drives)
    
    return {
        "success": True,
        "platform": "Windows",
        "timestamp": time.time(),
        "drives": filtered_drives,
        "total_drives": len(filtered_drives),
        "storage_statistics": storage_stats,
        "enumeration_methods": ["API", "WMI", "Volume", "Registry"]
    }

def _get_logical_drives_api() -> List[Dict[str, Any]]:
    """Get drives using GetLogicalDrives API"""
    
    drives = []
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Get logical drive mask
        drive_mask = kernel32.GetLogicalDrives()
        
        for i in range(26):  # A-Z
            if drive_mask & (1 << i):
                drive_letter = chr(ord('A') + i)
                drive_path = f"{drive_letter}:\\"
                
                # Get drive type
                drive_type = kernel32.GetDriveTypeW(drive_path)
                drive_type_name = _get_drive_type_name(drive_type)
                
                # Get volume information
                volume_name = ctypes.create_unicode_buffer(256)
                file_system = ctypes.create_unicode_buffer(256)
                serial_number = ctypes.wintypes.DWORD()
                max_component_length = ctypes.wintypes.DWORD()
                file_system_flags = ctypes.wintypes.DWORD()
                
                success = kernel32.GetVolumeInformationW(
                    drive_path,
                    volume_name, 256,
                    ctypes.byref(serial_number),
                    ctypes.byref(max_component_length),
                    ctypes.byref(file_system_flags),
                    file_system, 256
                )
                
                # Get disk space
                free_bytes = ctypes.c_ulonglong()
                total_bytes = ctypes.c_ulonglong()
                
                kernel32.GetDiskFreeSpaceExW(
                    drive_path,
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    None
                )
                
                drives.append({
                    "drive_letter": drive_letter,
                    "drive_path": drive_path,
                    "drive_type": drive_type_name,
                    "drive_type_code": drive_type,
                    "volume_name": volume_name.value if success else "Unknown",
                    "file_system": file_system.value if success else "Unknown",
                    "serial_number": f"{serial_number.value:08X}" if success else "Unknown",
                    "total_bytes": total_bytes.value,
                    "free_bytes": free_bytes.value,
                    "used_bytes": total_bytes.value - free_bytes.value,
                    "detection_method": "API"
                })
    
    except Exception as e:
        pass
    
    return drives

def _get_wmi_drives() -> List[Dict[str, Any]]:
    """Get drives using WMI"""
    
    drives = []
    
    try:
        import wmi
        c = wmi.WMI()
        
        # Get logical disks
        for disk in c.Win32_LogicalDisk():
            drives.append({
                "drive_letter": disk.DeviceID.replace(":", ""),
                "drive_path": disk.DeviceID + "\\",
                "drive_type": _convert_wmi_drive_type(disk.DriveType),
                "volume_name": disk.VolumeName or "Unknown",
                "file_system": disk.FileSystem or "Unknown",
                "serial_number": disk.VolumeSerialNumber or "Unknown",
                "total_bytes": int(disk.Size) if disk.Size else 0,
                "free_bytes": int(disk.FreeSpace) if disk.FreeSpace else 0,
                "used_bytes": int(disk.Size) - int(disk.FreeSpace) if disk.Size and disk.FreeSpace else 0,
                "compressed": disk.Compressed,
                "description": disk.Description,
                "detection_method": "WMI"
            })
        
        # Get physical disks for additional info
        physical_disks = {}
        for disk in c.Win32_DiskDrive():
            physical_disks[disk.Index] = {
                "model": disk.Model,
                "interface_type": disk.InterfaceType,
                "media_type": disk.MediaType,
                "size": int(disk.Size) if disk.Size else 0,
                "partitions": disk.Partitions
            }
        
        # Add physical disk info to logical drives
        for drive in drives:
            # This is simplified - would need partition mapping
            drive["physical_disk_info"] = physical_disks.get(0, {})
    
    except Exception as e:
        # Fallback to PowerShell WMI
        try:
            ps_result = subprocess.run([
                "powershell.exe", "-Command",
                "Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, DriveType, VolumeName, FileSystem, Size, FreeSpace"
            ], capture_output=True, text=True, timeout=30)
            
            # Parse PowerShell output (simplified)
            if ps_result.stdout:
                drives.append({
                    "drive_letter": "PS",
                    "drive_path": "PowerShell",
                    "detection_method": "PowerShell-WMI",
                    "note": "Parsed from PowerShell WMI query"
                })
        
        except Exception:
            pass
    
    return drives

def _get_volume_drives() -> List[Dict[str, Any]]:
    """Get drives using volume enumeration"""
    
    drives = []
    
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Find first volume
        volume_name = ctypes.create_unicode_buffer(256)
        handle = kernel32.FindFirstVolumeW(volume_name, 256)
        
        if handle != -1:
            while True:
                volume = volume_name.value
                
                # Get volume paths
                path_names = ctypes.create_unicode_buffer(1024)
                path_length = ctypes.wintypes.DWORD()
                
                success = kernel32.GetVolumePathNamesForVolumeNameW(
                    volume,
                    path_names, 1024,
                    ctypes.byref(path_length)
                )
                
                if success and path_names.value:
                    drives.append({
                        "volume_guid": volume,
                        "volume_paths": path_names.value.split('\x00')[:-1],
                        "detection_method": "Volume"
                    })
                
                # Find next volume
                if not kernel32.FindNextVolumeW(handle, volume_name, 256):
                    break
            
            kernel32.FindVolumeClose(handle)
    
    except Exception as e:
        pass
    
    return drives

def _get_registry_drives() -> List[Dict[str, Any]]:
    """Get drive information from registry"""
    
    drives = []
    
    try:
        import winreg
        
        # Check mounted devices
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as key:
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    if value_name.startswith("\\DosDevices\\"):
                        drive_letter = value_name.replace("\\DosDevices\\", "").replace(":", "")
                        
                        drives.append({
                            "drive_letter": drive_letter,
                            "registry_key": value_name,
                            "device_data": value_data,
                            "detection_method": "Registry"
                        })
                    
                    i += 1
                
                except OSError:
                    break
    
    except Exception as e:
        pass
    
    return drives

def _merge_drive_info(drives1: List[Dict], drives2: List[Dict]) -> List[Dict]:
    """Merge drive information from different sources"""
    
    merged = {}
    
    # Add drives from first list
    for drive in drives1:
        key = drive.get("drive_letter", drive.get("volume_guid", str(len(merged))))
        merged[key] = drive
    
    # Merge drives from second list
    for drive in drives2:
        key = drive.get("drive_letter", drive.get("volume_guid", str(len(merged))))
        
        if key in merged:
            # Merge information
            existing = merged[key]
            for k, v in drive.items():
                if k not in existing or existing[k] in ["Unknown", "", None]:
                    existing[k] = v
            
            # Combine detection methods
            methods = existing.get("detection_methods", [existing.get("detection_method", "")])
            new_method = drive.get("detection_method", "")
            if new_method and new_method not in methods:
                methods.append(new_method)
            existing["detection_methods"] = methods
        else:
            merged[key] = drive
    
    return list(merged.values())

def _filter_drives(drives: List[Dict], include_network: bool, include_removable: bool) -> List[Dict]:
    """Filter drives based on options"""
    
    filtered = []
    
    for drive in drives:
        drive_type = drive.get("drive_type", "").lower()
        
        # Skip network drives if not requested
        if not include_network and "network" in drive_type:
            continue
        
        # Skip removable drives if not requested
        if not include_removable and drive_type in ["removable", "cd-rom", "floppy"]:
            continue
        
        filtered.append(drive)
    
    return filtered

def _add_detailed_info(drive: Dict[str, Any]) -> None:
    """Add detailed information to drive"""
    
    try:
        drive_path = drive.get("drive_path", "")
        
        if drive_path and os.path.exists(drive_path):
            # Get additional file system info
            try:
                stat_info = os.statvfs(drive_path) if hasattr(os, 'statvfs') else None
                if stat_info:
                    drive["block_size"] = stat_info.f_bsize
                    drive["fragment_size"] = stat_info.f_frsize
                    drive["total_blocks"] = stat_info.f_blocks
                    drive["free_blocks"] = stat_info.f_bavail
            except:
                pass
            
            # Get directory listing stats
            try:
                items = os.listdir(drive_path)
                drive["root_items_count"] = len(items)
                drive["root_directories"] = len([item for item in items if os.path.isdir(os.path.join(drive_path, item))])
                drive["root_files"] = len([item for item in items if os.path.isfile(os.path.join(drive_path, item))])
            except:
                drive["root_items_count"] = 0
                drive["root_directories"] = 0
                drive["root_files"] = 0
        
        # Calculate usage percentage
        total = drive.get("total_bytes", 0)
        free = drive.get("free_bytes", 0)
        
        if total > 0:
            drive["usage_percentage"] = ((total - free) / total) * 100
        else:
            drive["usage_percentage"] = 0
        
        # Format sizes for readability
        drive["total_size_formatted"] = _format_bytes(total)
        drive["free_size_formatted"] = _format_bytes(free)
        drive["used_size_formatted"] = _format_bytes(total - free)
    
    except Exception as e:
        drive["detailed_info_error"] = str(e)

def _get_storage_statistics(drives: List[Dict]) -> Dict[str, Any]:
    """Calculate overall storage statistics"""
    
    stats = {
        "total_drives": len(drives),
        "drive_types": {},
        "file_systems": {},
        "total_capacity": 0,
        "total_free": 0,
        "total_used": 0,
        "average_usage_percentage": 0
    }
    
    usage_percentages = []
    
    for drive in drives:
        # Count drive types
        drive_type = drive.get("drive_type", "Unknown")
        stats["drive_types"][drive_type] = stats["drive_types"].get(drive_type, 0) + 1
        
        # Count file systems
        file_system = drive.get("file_system", "Unknown")
        stats["file_systems"][file_system] = stats["file_systems"].get(file_system, 0) + 1
        
        # Sum capacities
        total = drive.get("total_bytes", 0)
        free = drive.get("free_bytes", 0)
        
        stats["total_capacity"] += total
        stats["total_free"] += free
        stats["total_used"] += (total - free)
        
        # Collect usage percentages
        usage_pct = drive.get("usage_percentage", 0)
        if usage_pct > 0:
            usage_percentages.append(usage_pct)
    
    # Calculate average usage
    if usage_percentages:
        stats["average_usage_percentage"] = sum(usage_percentages) / len(usage_percentages)
    
    # Format total sizes
    stats["total_capacity_formatted"] = _format_bytes(stats["total_capacity"])
    stats["total_free_formatted"] = _format_bytes(stats["total_free"])
    stats["total_used_formatted"] = _format_bytes(stats["total_used"])
    
    return stats

def _get_drive_type_name(drive_type: int) -> str:
    """Convert Windows drive type code to name"""
    
    drive_types = {
        0: "Unknown",
        1: "Invalid",
        2: "Removable",
        3: "Fixed",
        4: "Network",
        5: "CD-ROM",
        6: "RAM"
    }
    
    return drive_types.get(drive_type, f"Unknown({drive_type})")

def _convert_wmi_drive_type(wmi_type: int) -> str:
    """Convert WMI drive type to standard name"""
    
    wmi_types = {
        0: "Unknown",
        1: "Invalid",
        2: "Removable",
        3: "Fixed",
        4: "Network",
        5: "CD-ROM",
        6: "RAM"
    }
    
    return wmi_types.get(wmi_type, f"Unknown({wmi_type})")

def _format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    
    if bytes_value == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit_index = 0
    size = float(bytes_value)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"

def _unix_drives(include_network: bool, include_removable: bool, detailed_info: bool) -> Dict[str, Any]:
    """Unix/Linux drive enumeration"""
    
    drives = []
    
    try:
        # Use psutil for cross-platform compatibility
        disk_partitions = psutil.disk_partitions(all=True)
        
        for partition in disk_partitions:
            try:
                # Get disk usage
                usage = psutil.disk_usage(partition.mountpoint)
                
                drive_info = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "file_system": partition.fstype,
                    "mount_options": partition.opts,
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "used_bytes": usage.used,
                    "usage_percentage": (usage.used / usage.total) * 100 if usage.total > 0 else 0,
                    "detection_method": "psutil"
                }
                
                # Determine drive type
                if "network" in partition.fstype.lower() or partition.device.startswith("//"):
                    drive_info["drive_type"] = "Network"
                elif "/dev/sr" in partition.device or "/dev/cdrom" in partition.device:
                    drive_info["drive_type"] = "CD-ROM"
                elif "/dev/fd" in partition.device:
                    drive_info["drive_type"] = "Floppy"
                elif "usb" in partition.device.lower() or "removable" in partition.opts.lower():
                    drive_info["drive_type"] = "Removable"
                else:
                    drive_info["drive_type"] = "Fixed"
                
                # Apply filters
                drive_type = drive_info["drive_type"].lower()
                
                if not include_network and drive_type == "network":
                    continue
                
                if not include_removable and drive_type in ["removable", "cd-rom", "floppy"]:
                    continue
                
                # Add detailed info if requested
                if detailed_info:
                    _add_unix_detailed_info(drive_info)
                
                drives.append(drive_info)
            
            except (PermissionError, OSError):
                # Skip inaccessible drives
                continue
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "drives": []
        }
    
    # Get storage statistics
    storage_stats = _get_storage_statistics(drives)
    
    return {
        "success": True,
        "platform": "Unix/Linux",
        "timestamp": time.time(),
        "drives": drives,
        "total_drives": len(drives),
        "storage_statistics": storage_stats
    }

def _add_unix_detailed_info(drive: Dict[str, Any]) -> None:
    """Add detailed information for Unix drives"""
    
    try:
        mountpoint = drive.get("mountpoint", "")
        
        if mountpoint and os.path.exists(mountpoint):
            # Get directory stats
            try:
                items = os.listdir(mountpoint)
                drive["root_items_count"] = len(items)
                drive["root_directories"] = len([item for item in items if os.path.isdir(os.path.join(mountpoint, item))])
                drive["root_files"] = len([item for item in items if os.path.isfile(os.path.join(mountpoint, item))])
            except:
                drive["root_items_count"] = 0
                drive["root_directories"] = 0
                drive["root_files"] = 0
        
        # Format sizes
        total = drive.get("total_bytes", 0)
        free = drive.get("free_bytes", 0)
        used = drive.get("used_bytes", 0)
        
        drive["total_size_formatted"] = _format_bytes(total)
        drive["free_size_formatted"] = _format_bytes(free)
        drive["used_size_formatted"] = _format_bytes(used)
    
    except Exception as e:
        drive["detailed_info_error"] = str(e)

if __name__ == "__main__":
    # Test the implementation
    result = elite_drives()
    print(f"Drive Enumeration Result: {result}")