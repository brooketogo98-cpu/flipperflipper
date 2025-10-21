#!/usr/bin/env python3
"""
Elite Webcam Snapshot
Advanced webcam capture and image acquisition
"""

import ctypes
import sys
import os
import subprocess
import time
from typing import Dict, Any, Optional

def elite_webcamsnap(device_id: int = 0,
                    output_file: str = None,
                    resolution: str = "640x480",
                    format: str = "jpg") -> Dict[str, Any]:
    """
    Capture image from webcam
    
    Args:
        device_id: Camera device ID (0 for default)
        output_file: Output filename (auto-generated if None)
        resolution: Image resolution (e.g., "640x480", "1280x720")
        format: Image format (jpg, png, bmp)
    
    Returns:
        Dict containing capture results
    """
    
    try:
        if sys.platform == "win32":
            return _windows_webcamsnap(device_id, output_file, resolution, format)
        else:
            return _unix_webcamsnap(device_id, output_file, resolution, format)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Webcam capture failed: {str(e)}",
            "device_id": device_id
        }

def _windows_webcamsnap(device_id: int, output_file: str, resolution: str, format: str) -> Dict[str, Any]:
    """Windows webcam capture"""
    
    try:
        # Generate output filename if not provided
        if not output_file:
            timestamp = int(time.time())
            output_file = f"webcam_capture_{timestamp}.{format}"
        
        methods_tried = []
        
        # Method 1: PowerShell with .NET System.Drawing
        try:
            ps_script = f'''
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Try to capture from webcam using DirectShow
try {{
    $webcam = New-Object -ComObject WIA.DeviceManager
    $device = $webcam.DeviceInfos.Item(1)
    $img = $device.Items.Item(1)
    $imageFile = $img.Transfer()
    $imageFile.SaveFile("{output_file}")
    Write-Output "SUCCESS"
}} catch {{
    Write-Output "FAILED: $($_.Exception.Message)"
}}
'''
            
            result = subprocess.run([
                "powershell", "-Command", ps_script
            ], capture_output=True, text=True, timeout=30)
            
            methods_tried.append({
                "method": "PowerShell_WIA",
                "success": "SUCCESS" in result.stdout,
                "output": result.stdout.strip()
            })
            
            if "SUCCESS" in result.stdout and os.path.exists(output_file):
                return {
                    "success": True,
                    "method": "PowerShell_WIA",
                    "output_file": output_file,
                    "device_id": device_id,
                    "resolution": resolution,
                    "format": format,
                    "file_size": os.path.getsize(output_file),
                    "timestamp": time.time()
                }
        
        except Exception as e:
            methods_tried.append({
                "method": "PowerShell_WIA",
                "success": False,
                "error": str(e)
            })
        
        # Method 2: ffmpeg (if available)
        try:
            # Use ffmpeg to capture from DirectShow
            ffmpeg_cmd = [
                "ffmpeg", "-y",  # Overwrite output
                "-f", "dshow",   # DirectShow input
                "-i", f"video=USB Video Device",  # Default camera name
                "-frames:v", "1",  # Capture one frame
                "-s", resolution,  # Set resolution
                output_file
            ]
            
            result = subprocess.run(ffmpeg_cmd, capture_output=True, text=True, timeout=15)
            
            methods_tried.append({
                "method": "ffmpeg",
                "success": result.returncode == 0 and os.path.exists(output_file),
                "return_code": result.returncode
            })
            
            if result.returncode == 0 and os.path.exists(output_file):
                return {
                    "success": True,
                    "method": "ffmpeg",
                    "output_file": output_file,
                    "device_id": device_id,
                    "resolution": resolution,
                    "format": format,
                    "file_size": os.path.getsize(output_file),
                    "timestamp": time.time()
                }
        
        except FileNotFoundError:
            methods_tried.append({
                "method": "ffmpeg",
                "success": False,
                "error": "ffmpeg not found"
            })
        except Exception as e:
            methods_tried.append({
                "method": "ffmpeg",
                "success": False,
                "error": str(e)
            })
        
        # Method 3: Try Python opencv (if available)
        try:
            import cv2
            
            cap = cv2.VideoCapture(device_id)
            
            if cap.isOpened():
                # Set resolution
                width, height = resolution.split('x')
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, int(width))
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, int(height))
                
                ret, frame = cap.read()
                
                if ret:
                    cv2.imwrite(output_file, frame)
                    cap.release()
                    
                    methods_tried.append({
                        "method": "opencv",
                        "success": True
                    })
                    
                    return {
                        "success": True,
                        "method": "opencv",
                        "output_file": output_file,
                        "device_id": device_id,
                        "resolution": resolution,
                        "format": format,
                        "file_size": os.path.getsize(output_file),
                        "timestamp": time.time()
                    }
                else:
                    cap.release()
                    methods_tried.append({
                        "method": "opencv",
                        "success": False,
                        "error": "Failed to capture frame"
                    })
            else:
                methods_tried.append({
                    "method": "opencv",
                    "success": False,
                    "error": "Failed to open camera"
                })
        
        except ImportError:
            methods_tried.append({
                "method": "opencv",
                "success": False,
                "error": "OpenCV not available"
            })
        except Exception as e:
            methods_tried.append({
                "method": "opencv",
                "success": False,
                "error": str(e)
            })
        
        return {
            "success": False,
            "platform": "Windows",
            "error": "All capture methods failed",
            "methods_tried": methods_tried,
            "device_id": device_id
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Windows"
        }

def _unix_webcamsnap(device_id: int, output_file: str, resolution: str, format: str) -> Dict[str, Any]:
    """Unix/Linux webcam capture"""
    
    try:
        # Generate output filename if not provided
        if not output_file:
            timestamp = int(time.time())
            output_file = f"webcam_capture_{timestamp}.{format}"
        
        device_path = f"/dev/video{device_id}"
        
        if not os.path.exists(device_path):
            return {
                "success": False,
                "error": f"Camera device {device_path} not found",
                "device_id": device_id
            }
        
        methods_tried = []
        
        # Method 1: fswebcam
        try:
            fswebcam_cmd = [
                "fswebcam",
                "-d", device_path,
                "-r", resolution,
                "--no-banner",
                "--save", output_file
            ]
            
            result = subprocess.run(fswebcam_cmd, capture_output=True, text=True, timeout=15)
            
            methods_tried.append({
                "method": "fswebcam",
                "success": result.returncode == 0 and os.path.exists(output_file),
                "return_code": result.returncode
            })
            
            if result.returncode == 0 and os.path.exists(output_file):
                return {
                    "success": True,
                    "method": "fswebcam",
                    "output_file": output_file,
                    "device_path": device_path,
                    "resolution": resolution,
                    "format": format,
                    "file_size": os.path.getsize(output_file),
                    "timestamp": time.time()
                }
        
        except FileNotFoundError:
            methods_tried.append({
                "method": "fswebcam",
                "success": False,
                "error": "fswebcam not found"
            })
        except Exception as e:
            methods_tried.append({
                "method": "fswebcam",
                "success": False,
                "error": str(e)
            })
        
        # Method 2: ffmpeg
        try:
            ffmpeg_cmd = [
                "ffmpeg", "-y",
                "-f", "v4l2",
                "-i", device_path,
                "-frames:v", "1",
                "-s", resolution,
                output_file
            ]
            
            result = subprocess.run(ffmpeg_cmd, capture_output=True, text=True, timeout=15)
            
            methods_tried.append({
                "method": "ffmpeg",
                "success": result.returncode == 0 and os.path.exists(output_file),
                "return_code": result.returncode
            })
            
            if result.returncode == 0 and os.path.exists(output_file):
                return {
                    "success": True,
                    "method": "ffmpeg",
                    "output_file": output_file,
                    "device_path": device_path,
                    "resolution": resolution,
                    "format": format,
                    "file_size": os.path.getsize(output_file),
                    "timestamp": time.time()
                }
        
        except FileNotFoundError:
            methods_tried.append({
                "method": "ffmpeg",
                "success": False,
                "error": "ffmpeg not found"
            })
        except Exception as e:
            methods_tried.append({
                "method": "ffmpeg",
                "success": False,
                "error": str(e)
            })
        
        # Method 3: OpenCV (if available)
        try:
            import cv2
            
            cap = cv2.VideoCapture(device_id)
            
            if cap.isOpened():
                # Set resolution
                width, height = resolution.split('x')
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, int(width))
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, int(height))
                
                ret, frame = cap.read()
                
                if ret:
                    cv2.imwrite(output_file, frame)
                    cap.release()
                    
                    methods_tried.append({
                        "method": "opencv",
                        "success": True
                    })
                    
                    return {
                        "success": True,
                        "method": "opencv",
                        "output_file": output_file,
                        "device_path": device_path,
                        "resolution": resolution,
                        "format": format,
                        "file_size": os.path.getsize(output_file),
                        "timestamp": time.time()
                    }
                else:
                    cap.release()
                    methods_tried.append({
                        "method": "opencv",
                        "success": False,
                        "error": "Failed to capture frame"
                    })
            else:
                methods_tried.append({
                    "method": "opencv",
                    "success": False,
                    "error": "Failed to open camera"
                })
        
        except ImportError:
            methods_tried.append({
                "method": "opencv",
                "success": False,
                "error": "OpenCV not available"
            })
        except Exception as e:
            methods_tried.append({
                "method": "opencv",
                "success": False,
                "error": str(e)
            })
        
        return {
            "success": False,
            "platform": "Unix/Linux",
            "error": "All capture methods failed",
            "methods_tried": methods_tried,
            "device_path": device_path
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Unix/Linux"
        }

if __name__ == "__main__":
    result = elite_webcamsnap()
    # print(f"Webcam Snap Result: {result}")