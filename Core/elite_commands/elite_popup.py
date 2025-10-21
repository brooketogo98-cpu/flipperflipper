#!/usr/bin/env python3
"""
Elite Popup Messages
Advanced popup and notification system
"""

import ctypes
import sys
import os
import subprocess
import time
import threading
from typing import Dict, Any, Optional

def elite_popup(message: str = "System Notification",
               title: str = "Alert",
               popup_type: str = "info",
               timeout: int = 0,
               buttons: str = "ok") -> Dict[str, Any]:
    """
    Advanced popup message system
    
    Args:
        message: Message text to display
        title: Popup window title
        popup_type: Type of popup (info, warning, error, question, custom)
        timeout: Auto-close timeout in seconds (0 = no timeout)
        buttons: Button configuration (ok, yes_no, ok_cancel, retry_cancel)
    
    Returns:
        Dict containing popup results and user response
    """
    
    try:
        if sys.platform == "win32":
            return _windows_popup(message, title, popup_type, timeout, buttons)
        else:
            return _unix_popup(message, title, popup_type, timeout, buttons)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Popup creation failed: {str(e)}",
            "message": message,
            "title": title
        }

def _windows_popup(message: str, title: str, popup_type: str, timeout: int, buttons: str) -> Dict[str, Any]:
    """Windows popup implementation"""
    
    try:
        user32 = ctypes.windll.user32
        
        # Map popup types to Windows MessageBox types
        type_map = {
            "info": 0x40,      # MB_ICONINFORMATION
            "warning": 0x30,   # MB_ICONWARNING
            "error": 0x10,     # MB_ICONERROR
            "question": 0x20,  # MB_ICONQUESTION
            "custom": 0x00     # No icon
        }
        
        # Map button types
        button_map = {
            "ok": 0x00,           # MB_OK
            "yes_no": 0x04,       # MB_YESNO
            "ok_cancel": 0x01,    # MB_OKCANCEL
            "retry_cancel": 0x05, # MB_RETRYCANCEL
            "yes_no_cancel": 0x03 # MB_YESNOCANCEL
        }
        
        # Build MessageBox flags
        mb_type = type_map.get(popup_type, 0x40)
        mb_buttons = button_map.get(buttons, 0x00)
        mb_flags = mb_type | mb_buttons
        
        # Add topmost flag
        mb_flags |= 0x40000  # MB_TOPMOST
        
        start_time = time.time()
        
        if timeout > 0:
            # Use MessageBoxTimeout for timed popups
            result = user32.MessageBoxTimeoutW(
                None,           # hWnd
                message,        # lpText
                title,          # lpCaption
                mb_flags,       # uType
                0,              # wLanguageId
                timeout * 1000  # dwTimeout (milliseconds)
            )
        else:
            # Use regular MessageBox
            result = user32.MessageBoxW(
                None,      # hWnd
                message,   # lpText
                title,     # lpCaption
                mb_flags   # uType
            )
        
        # Map return values to responses
        response_map = {
            1: "OK",
            2: "Cancel",
            3: "Abort",
            4: "Retry",
            5: "Ignore",
            6: "Yes",
            7: "No",
            32000: "Timeout"  # TIMEOUT return value
        }
        
        response = response_map.get(result, f"Unknown({result})")
        
        return {
            "success": True,
            "platform": "Windows",
            "message": message,
            "title": title,
            "popup_type": popup_type,
            "buttons": buttons,
            "timeout": timeout,
            "user_response": response,
            "response_code": result,
            "display_time": time.time() - start_time,
            "timestamp": time.time()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "platform": "Windows"
        }

def _unix_popup(message: str, title: str, popup_type: str, timeout: int, buttons: str) -> Dict[str, Any]:
    """Unix/Linux popup implementation"""
    
    methods_tried = []
    
    # Method 1: zenity (GNOME)
    try:
        zenity_args = ["zenity"]
        
        # Map popup types to zenity options
        if popup_type == "info":
            zenity_args.append("--info")
        elif popup_type == "warning":
            zenity_args.append("--warning")
        elif popup_type == "error":
            zenity_args.append("--error")
        elif popup_type == "question":
            zenity_args.append("--question")
        else:
            zenity_args.append("--info")
        
        zenity_args.extend(["--title", title, "--text", message])
        
        if timeout > 0:
            zenity_args.extend(["--timeout", str(timeout)])
        
        start_time = time.time()
        result = subprocess.run(zenity_args, timeout=timeout + 5 if timeout > 0 else 30)
        
        response = "OK" if result.returncode == 0 else "Cancel"
        if result.returncode == 5:  # Timeout
            response = "Timeout"
        
        methods_tried.append({
            "method": "zenity",
            "success": True,
            "response": response
        })
        
        return {
            "success": True,
            "platform": "Unix/Linux",
            "method": "zenity",
            "message": message,
            "title": title,
            "popup_type": popup_type,
            "user_response": response,
            "response_code": result.returncode,
            "display_time": time.time() - start_time,
            "methods_tried": methods_tried
        }
    
    except FileNotFoundError:
        methods_tried.append({
            "method": "zenity",
            "success": False,
            "error": "Command not found"
        })
    except Exception as e:
        methods_tried.append({
            "method": "zenity",
            "success": False,
            "error": str(e)
        })
    
    # Method 2: kdialog (KDE)
    try:
        kdialog_args = ["kdialog"]
        
        # Map popup types to kdialog options
        if popup_type == "info":
            kdialog_args.append("--msgbox")
        elif popup_type == "warning":
            kdialog_args.append("--sorry")
        elif popup_type == "error":
            kdialog_args.append("--error")
        elif popup_type == "question":
            kdialog_args.append("--yesno")
        else:
            kdialog_args.append("--msgbox")
        
        kdialog_args.extend([message, "--title", title])
        
        start_time = time.time()
        result = subprocess.run(kdialog_args, timeout=timeout + 5 if timeout > 0 else 30)
        
        response = "OK" if result.returncode == 0 else "Cancel"
        
        methods_tried.append({
            "method": "kdialog",
            "success": True,
            "response": response
        })
        
        return {
            "success": True,
            "platform": "Unix/Linux",
            "method": "kdialog",
            "message": message,
            "title": title,
            "popup_type": popup_type,
            "user_response": response,
            "response_code": result.returncode,
            "display_time": time.time() - start_time,
            "methods_tried": methods_tried
        }
    
    except FileNotFoundError:
        methods_tried.append({
            "method": "kdialog",
            "success": False,
            "error": "Command not found"
        })
    except Exception as e:
        methods_tried.append({
            "method": "kdialog",
            "success": False,
            "error": str(e)
        })
    
    # Method 3: xmessage (X11 fallback)
    try:
        xmessage_args = ["xmessage", "-center", f"{title}: {message}"]
        
        if timeout > 0:
            xmessage_args.extend(["-timeout", str(timeout)])
        
        start_time = time.time()
        result = subprocess.run(xmessage_args, timeout=timeout + 5 if timeout > 0 else 30)
        
        response = "OK" if result.returncode == 0 else "Cancel"
        
        methods_tried.append({
            "method": "xmessage",
            "success": True,
            "response": response
        })
        
        return {
            "success": True,
            "platform": "Unix/Linux",
            "method": "xmessage",
            "message": message,
            "title": title,
            "user_response": response,
            "response_code": result.returncode,
            "display_time": time.time() - start_time,
            "methods_tried": methods_tried
        }
    
    except FileNotFoundError:
        methods_tried.append({
            "method": "xmessage",
            "success": False,
            "error": "Command not found"
        })
    except Exception as e:
        methods_tried.append({
            "method": "xmessage",
            "success": False,
            "error": str(e)
        })
    
    return {
        "success": False,
        "platform": "Unix/Linux",
        "error": "No suitable popup method found",
        "methods_tried": methods_tried
    }

def create_persistent_popup(message: str, title: str, interval: int = 300) -> Dict[str, Any]:
    """Create a popup that reappears at intervals"""
    
    def popup_thread():
        while True:
            elite_popup(message, title, "warning", 30)
            time.sleep(interval)
    
    thread = threading.Thread(target=popup_thread, daemon=True)
    thread.start()
    
    return {
        "success": True,
        "message": "Persistent popup started",
        "interval": interval,
        "thread_id": thread.ident
    }

def create_fake_system_popup() -> Dict[str, Any]:
    """Create a fake system notification popup"""
    
    messages = [
        ("Windows Security", "Your computer is at risk. Click OK to run a security scan."),
        ("System Update", "Critical updates are available. Restart now to install."),
        ("Virus Alert", "Threat detected! Click OK to remove immediately."),
        ("License Expired", "Your Windows license has expired. Click OK to renew.")
    ]
    
    import random
    title, message = random.choice(messages)
    
    return elite_popup(message, title, "warning", 0, "ok")

if __name__ == "__main__":
    result = elite_popup("Test message", "Test Title", "info")
    print(f"Popup Result: {result}")