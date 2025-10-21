#!/usr/bin/env python3
"""
Elite Screenshot Command Implementation
Advanced screen capture using DWM API and multiple fallback methods
"""

import os
import sys
import base64
import io
import time
from typing import Dict, Any, Optional

def elite_screenshot(monitor: int = 0, format: str = "PNG", quality: int = 85) -> Dict[str, Any]:
    """
    Elite screenshot capture with advanced features:
    - Multiple capture methods (DWM API, GDI, cross-platform)
    - Multi-monitor support
    - Format options (PNG, JPEG, BMP)
    - Quality control
    - Stealth capture (no window focus changes)
    """
    
    try:
        if sys.platform == 'win32':
            return _windows_elite_screenshot(monitor, format, quality)
        else:
            return _unix_elite_screenshot(monitor, format, quality)
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Screenshot capture failed: {str(e)}",
            "monitor": monitor
        }

def _windows_elite_screenshot(monitor: int, format: str, quality: int) -> Dict[str, Any]:
    """Windows implementation using DWM API and GDI"""
    
    try:
        # Method 1: Try DWM (Desktop Window Manager) API for best quality
        try:
            screenshot_data = _capture_with_dwm(monitor, format, quality)
            if screenshot_data:
                return {
                    "success": True,
                    "image_data": screenshot_data,
                    "format": format,
                    "method": "DWM_API",
                    "monitor": monitor,
                    "timestamp": time.time()
                }
        except Exception:
            pass
        
        # Method 2: GDI BitBlt (more compatible)
        try:
            screenshot_data = _capture_with_gdi(monitor, format, quality)
            if screenshot_data:
                return {
                    "success": True,
                    "image_data": screenshot_data,
                    "format": format,
                    "method": "GDI_BitBlt",
                    "monitor": monitor,
                    "timestamp": time.time()
                }
        except Exception:
            pass
        
        # Method 3: Python libraries fallback
        return _capture_with_python_libs(monitor, format, quality)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Windows screenshot failed: {str(e)}",
            "monitor": monitor
        }

def _capture_with_dwm(monitor: int, format: str, quality: int) -> Optional[str]:
    """Capture screenshot using DWM API (Windows 10+)"""
    
    try:
        import ctypes
        from ctypes import wintypes
        
        # This would implement DWM API capture
        # For now, return None to fall back to other methods
        return None
    
    except Exception:
        return None

def _capture_with_gdi(monitor: int, format: str, quality: int) -> Optional[str]:
    """Capture screenshot using GDI BitBlt"""
    
    try:
        import ctypes
        from ctypes import wintypes
        
        # Get device contexts
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        
        # Get screen dimensions
        screen_width = user32.GetSystemMetrics(0)  # SM_CXSCREEN
        screen_height = user32.GetSystemMetrics(1)  # SM_CYSCREEN
        
        # Create device contexts
        hdc_screen = user32.GetDC(None)
        hdc_memory = gdi32.CreateCompatibleDC(hdc_screen)
        
        # Create bitmap
        bitmap = gdi32.CreateCompatibleBitmap(hdc_screen, screen_width, screen_height)
        gdi32.SelectObject(hdc_memory, bitmap)
        
        # Copy screen to memory DC
        gdi32.BitBlt(
            hdc_memory, 0, 0, screen_width, screen_height,
            hdc_screen, 0, 0, 0x00CC0020  # SRCCOPY
        )
        
        # Get bitmap data
        # This would extract the bitmap data and convert to desired format
        # For now, return None to fall back
        
        # Clean up
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(hdc_memory)
        user32.ReleaseDC(None, hdc_screen)
        
        return None  # Fallback for now
    
    except Exception:
        return None

def _capture_with_python_libs(monitor: int, format: str, quality: int) -> Dict[str, Any]:
    """Capture screenshot using Python libraries"""
    
    methods_tried = []
    
    # Method 1: mss (fastest)
    try:
        import mss
        
        with mss.mss() as sct:
            if monitor == 0:
                # Capture all monitors
                screenshot = sct.grab(sct.monitors[0])
            else:
                # Capture specific monitor
                if monitor < len(sct.monitors):
                    screenshot = sct.grab(sct.monitors[monitor])
                else:
                    screenshot = sct.grab(sct.monitors[1])  # First real monitor
            
            # Convert to PIL Image
            from PIL import Image
            img = Image.frombytes('RGB', screenshot.size, screenshot.bgra, 'raw', 'BGRX')
            
            # Save to buffer
            buffer = io.BytesIO()
            if format.upper() == 'JPEG':
                img.save(buffer, format='JPEG', quality=quality)
            else:
                img.save(buffer, format='PNG')
            
            screenshot_b64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_data": screenshot_b64,
                "format": format,
                "method": "mss_library",
                "monitor": monitor,
                "timestamp": time.time(),
                "dimensions": {"width": screenshot.width, "height": screenshot.height}
            }
    
    except ImportError:
        methods_tried.append("mss (not available)")
    except Exception as e:
        methods_tried.append(f"mss (failed: {str(e)[:30]})")
    
    # Method 2: PIL ImageGrab
    try:
        from PIL import ImageGrab
        
        screenshot = ImageGrab.grab()
        buffer = io.BytesIO()
        
        if format.upper() == 'JPEG':
            screenshot.save(buffer, format='JPEG', quality=quality)
        else:
            screenshot.save(buffer, format='PNG')
        
        screenshot_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            "success": True,
            "image_data": screenshot_b64,
            "format": format,
            "method": "PIL_ImageGrab",
            "monitor": monitor,
            "timestamp": time.time(),
            "dimensions": {"width": screenshot.width, "height": screenshot.height}
        }
    
    except ImportError:
        methods_tried.append("PIL ImageGrab (not available)")
    except Exception as e:
        methods_tried.append(f"PIL ImageGrab (failed: {str(e)[:30]})")
    
    # Method 3: pyautogui
    try:
        import pyautogui
        
        screenshot = pyautogui.screenshot()
        buffer = io.BytesIO()
        
        if format.upper() == 'JPEG':
            screenshot.save(buffer, format='JPEG', quality=quality)
        else:
            screenshot.save(buffer, format='PNG')
        
        screenshot_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            "success": True,
            "image_data": screenshot_b64,
            "format": format,
            "method": "pyautogui",
            "monitor": monitor,
            "timestamp": time.time(),
            "dimensions": {"width": screenshot.width, "height": screenshot.height}
        }
    
    except ImportError:
        methods_tried.append("pyautogui (not available)")
    except Exception as e:
        methods_tried.append(f"pyautogui (failed: {str(e)[:30]})")
    
    # All methods failed
    return {
        "success": False,
        "error": "All screenshot methods failed",
        "methods_tried": methods_tried,
        "monitor": monitor
    }

def _unix_elite_screenshot(monitor: int, format: str, quality: int) -> Dict[str, Any]:
    """Unix implementation using X11 and other methods"""
    
    methods_tried = []
    
    # Method 1: mss (cross-platform)
    try:
        import mss
        
        with mss.mss() as sct:
            if monitor == 0:
                screenshot = sct.grab(sct.monitors[0])
            else:
                if monitor < len(sct.monitors):
                    screenshot = sct.grab(sct.monitors[monitor])
                else:
                    screenshot = sct.grab(sct.monitors[1])
            
            # Convert to PIL Image
            from PIL import Image
            img = Image.frombytes('RGB', screenshot.size, screenshot.rgb, 'raw', 'RGB')
            
            # Save to buffer
            buffer = io.BytesIO()
            if format.upper() == 'JPEG':
                img.save(buffer, format='JPEG', quality=quality)
            else:
                img.save(buffer, format='PNG')
            
            screenshot_b64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_data": screenshot_b64,
                "format": format,
                "method": "mss_unix",
                "monitor": monitor,
                "timestamp": time.time(),
                "dimensions": {"width": screenshot.width, "height": screenshot.height}
            }
    
    except ImportError:
        methods_tried.append("mss (not available)")
    except Exception as e:
        methods_tried.append(f"mss (failed: {str(e)[:30]})")
    
    # Method 2: X11 direct capture
    try:
        screenshot_data = _capture_with_x11(monitor, format, quality)
        if screenshot_data:
            return screenshot_data
    except Exception as e:
        methods_tried.append(f"X11 (failed: {str(e)[:30]})")
    
    # Method 3: scrot command line tool
    try:
        screenshot_data = _capture_with_scrot(format, quality)
        if screenshot_data:
            return screenshot_data
    except Exception as e:
        methods_tried.append(f"scrot (failed: {str(e)[:30]})")
    
    return {
        "success": False,
        "error": "All Unix screenshot methods failed",
        "methods_tried": methods_tried,
        "monitor": monitor
    }

def _capture_with_x11(monitor: int, format: str, quality: int) -> Optional[Dict[str, Any]]:
    """Capture screenshot using X11 directly"""
    
    try:
        # This would implement X11 XGetImage
        # For now, return None to indicate not implemented
        return None
    
    except Exception:
        return None

def _capture_with_scrot(format: str, quality: int) -> Optional[Dict[str, Any]]:
    """Capture screenshot using scrot command line tool"""
    
    try:
        import subprocess
        import tempfile
        
        # Create temporary file
        temp_file = tempfile.mktemp(suffix=f'.{format.lower()}')
        
        # Run scrot
        cmd = ['scrot', temp_file]
        if quality < 100 and format.upper() == 'JPEG':
            cmd.extend(['-q', str(quality)])
        
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        
        if result.returncode == 0 and os.path.exists(temp_file):
            # Read screenshot data
            with open(temp_file, 'rb') as f:
                screenshot_data = f.read()
            
            # Clean up
            os.remove(temp_file)
            
            # Get image dimensions if possible
            dimensions = {"width": 0, "height": 0}
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(screenshot_data))
                dimensions = {"width": img.width, "height": img.height}
            except:
                pass
            
            return {
                "success": True,
                "image_data": base64.b64encode(screenshot_data).decode(),
                "format": format,
                "method": "scrot_command",
                "monitor": 0,
                "timestamp": time.time(),
                "dimensions": dimensions
            }
    
    except Exception:
        pass
    
    return None


if __name__ == "__main__":
    # Test the elite screenshot command
    print("Testing Elite Screenshot Command...")
    
    result = elite_screenshot()
    
    if result['success']:
        print(f"✅ Screenshot capture successful!")
        print(f"Method: {result['method']}")
        print(f"Format: {result['format']}")
        print(f"Dimensions: {result.get('dimensions', 'unknown')}")
        print(f"Data size: {len(result['image_data'])} characters (base64)")
    else:
        print(f"❌ Screenshot failed: {result['error']}")
        if 'methods_tried' in result:
            print(f"Methods tried: {result['methods_tried']}")
    
    print("Elite Screenshot command test complete")