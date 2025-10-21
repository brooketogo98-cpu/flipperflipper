#!/usr/bin/env python3
"""
Elite Webcam List
Advanced webcam and camera device enumeration
"""

import ctypes
import sys
import os
import subprocess
from typing import Dict, Any, List

def elite_webcamlist(detailed: bool = True) -> Dict[str, Any]:
    """
    Enumerate available webcam and camera devices
    
    Args:
        detailed: Include detailed device information
    
    Returns:
        Dict containing webcam device information
    """
    
    try:
        if sys.platform == "win32":
            return _windows_webcamlist(detailed)
        else:
            return _unix_webcamlist(detailed)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Webcam enumeration failed: {str(e)}"
        }

def _windows_webcamlist(detailed: bool) -> Dict[str, Any]:
    """Windows webcam enumeration"""
    
    try:
        devices = []
        
        # Method 1: PowerShell Get-PnpDevice
        try:
            ps_cmd = '''
            Get-PnpDevice | Where-Object {
                $_.Class -eq "Camera" -or 
                $_.Class -eq "Image" -or
                $_.FriendlyName -like "*camera*" -or
                $_.FriendlyName -like "*webcam*"
            } | Select-Object FriendlyName, InstanceId, Status, Class | ConvertTo-Json
            '''
            
            result = subprocess.run([
                "powershell", "-Command", ps_cmd
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                ps_devices = json.loads(result.stdout)
                
                if isinstance(ps_devices, dict):
                    ps_devices = [ps_devices]
                
                for device in ps_devices:
                    devices.append({
                        "name": device.get("FriendlyName", "Unknown"),
                        "instance_id": device.get("InstanceId", ""),
                        "status": device.get("Status", "Unknown"),
                        "class": device.get("Class", "Unknown"),
                        "method": "PowerShell"
                    })
        
        except Exception as e:
            devices.append({"error": f"PowerShell method failed: {str(e)}"})
        
        # Method 2: WMI Win32_PnPEntity
        try:
            wmi_cmd = '''
            Get-WmiObject Win32_PnPEntity | Where-Object {
                $_.Name -like "*camera*" -or 
                $_.Name -like "*webcam*" -or
                $_.Description -like "*camera*"
            } | Select-Object Name, Description, DeviceID, Status | ConvertTo-Json
            '''
            
            result = subprocess.run([
                "powershell", "-Command", wmi_cmd
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                wmi_devices = json.loads(result.stdout)
                
                if isinstance(wmi_devices, dict):
                    wmi_devices = [wmi_devices]
                
                for device in wmi_devices:
                    devices.append({
                        "name": device.get("Name", "Unknown"),
                        "description": device.get("Description", ""),
                        "device_id": device.get("DeviceID", ""),
                        "status": device.get("Status", "Unknown"),
                        "method": "WMI"
                    })
        
        except Exception as e:
            devices.append({"error": f"WMI method failed: {str(e)}"})
        
        # Method 3: DirectShow devices (if available)
        if detailed:
            try:
                # This would require DirectShow COM interfaces
                # For now, add placeholder
                devices.append({
                    "note": "DirectShow enumeration not implemented",
                    "method": "DirectShow"
                })
            except Exception:
                pass
        
        # Remove duplicates and errors
        clean_devices = []
        seen_names = set()
        
        for device in devices:
            if "error" in device or "note" in device:
                continue
            
            name = device.get("name", "")
            if name and name not in seen_names:
                seen_names.add(name)
                clean_devices.append(device)
        
        return {
            "success": True,
            "platform": "Windows",
            "devices": clean_devices,
            "total_devices": len(clean_devices),
            "detailed": detailed,
            "methods_used": ["PowerShell", "WMI"]
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Windows"
        }

def _unix_webcamlist(detailed: bool) -> Dict[str, Any]:
    """Unix/Linux webcam enumeration"""
    
    try:
        devices = []
        
        # Method 1: /dev/video* devices
        try:
            video_devices = []
            for i in range(10):  # Check /dev/video0 through /dev/video9
                device_path = f"/dev/video{i}"
                if os.path.exists(device_path):
                    video_devices.append(device_path)
            
            for device_path in video_devices:
                device_info = {
                    "device_path": device_path,
                    "name": f"Video Device {device_path[-1]}",
                    "method": "dev_video"
                }
                
                # Get device capabilities if detailed
                if detailed:
                    try:
                        # Use v4l2-ctl if available
                        result = subprocess.run([
                            "v4l2-ctl", "--device", device_path, "--info"
                        ], capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0:
                            device_info["v4l2_info"] = result.stdout.strip()
                    
                    except FileNotFoundError:
                        pass
                
                devices.append(device_info)
        
        except Exception as e:
            devices.append({"error": f"/dev/video enumeration failed: {str(e)}"})
        
        # Method 2: lsusb for USB cameras
        try:
            result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                usb_cameras = []
                
                for line in result.stdout.split('\n'):
                    line_lower = line.lower()
                    if any(keyword in line_lower for keyword in ['camera', 'webcam', 'video']):
                        usb_cameras.append(line.strip())
                
                for camera in usb_cameras:
                    devices.append({
                        "name": camera,
                        "type": "USB Camera",
                        "method": "lsusb"
                    })
        
        except FileNotFoundError:
            devices.append({"note": "lsusb not available"})
        except Exception as e:
            devices.append({"error": f"lsusb failed: {str(e)}"})
        
        # Method 3: Check for camera applications
        try:
            camera_apps = ["cheese", "guvcview", "camorama", "kamoso"]
            available_apps = []
            
            for app in camera_apps:
                try:
                    result = subprocess.run(["which", app], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        available_apps.append(app)
                except:
                    pass
            
            if available_apps:
                devices.append({
                    "available_camera_apps": available_apps,
                    "method": "camera_apps"
                })
        
        except Exception:
            pass
        
        # Clean up devices
        clean_devices = [d for d in devices if "error" not in d]
        
        return {
            "success": True,
            "platform": "Unix/Linux",
            "devices": clean_devices,
            "total_devices": len([d for d in clean_devices if "device_path" in d or "type" in d]),
            "detailed": detailed,
            "methods_used": ["dev_video", "lsusb", "camera_apps"]
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Unix/Linux"
        }

if __name__ == "__main__":
    result = elite_webcamlist()
    # print(f"Webcam List Result: {result}")