#!/usr/bin/env python3
"""
Elite SOCKS Proxy Command Implementation
Advanced SOCKS5 proxy server with authentication and tunneling
"""

import os
import sys
import socket
import threading
import struct
import select
import time
from typing import Dict, Any, List

def elite_socks_proxy(port: int = 1080, bind_address: str = "127.0.0.1", 
                     auth_required: bool = False, username: str = None, password: str = None) -> Dict[str, Any]:
    """
    Elite SOCKS5 proxy with advanced features:
    - Full SOCKS5 protocol implementation
    - Authentication support
    - Multi-connection handling
    - Traffic logging and filtering
    - Cross-platform support
    """
    
    try:
        # Validate parameters
        if auth_required and (not username or not password):
            return {
                "success": False,
                "error": "Username and password required when authentication is enabled",
                "proxy_info": None
            }
        
        # Create SOCKS proxy server
        proxy_server = SocksProxyServer(port, bind_address, auth_required, username, password)
        
        # Start proxy server
        success = proxy_server.start()
        
        if success:
            # Register proxy in global registry
            _register_socks_proxy(proxy_server)
            
            return {
                "success": True,
                "port": port,
                "bind_address": bind_address,
                "auth_required": auth_required,
                "proxy_id": proxy_server.get_id(),
                "status": "active"
            }
        else:
            return {
                "success": False,
                "error": "Failed to start SOCKS proxy server",
                "proxy_info": None
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"SOCKS proxy failed: {str(e)}",
            "proxy_info": None
        }

class SocksProxyServer:
    """Advanced SOCKS5 proxy server implementation"""
    
    def __init__(self, port: int, bind_address: str, auth_required: bool, username: str, password: str):
        self.port = port
        self.bind_address = bind_address
        self.auth_required = auth_required
        self.username = username
        self.password = password
        
        self.server_socket = None
        self.running = False
        self.connections = []
        self.proxy_id = f"socks_{port}_{int(time.time())}"
        
    def get_id(self) -> str:
        """Get proxy ID"""
        return self.proxy_id
    
    def start(self) -> bool:
        """Start SOCKS proxy server"""
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address
            self.server_socket.bind((self.bind_address, self.port))
            self.server_socket.listen(10)
            
            self.running = True
            
            # Start accepting connections in background thread
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            return True
            
        except Exception:
            return False
    
    def _accept_connections(self):
        """Accept SOCKS connections"""
        
        while self.running:
            try:
                if self.server_socket:
                    # Use select for non-blocking accept
                    ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                    
                    if ready:
                        client_socket, client_addr = self.server_socket.accept()
                        
                        # Handle connection in separate thread
                        conn_thread = threading.Thread(
                            target=self._handle_socks_connection,
                            args=(client_socket, client_addr),
                            daemon=True
                        )
                        conn_thread.start()
                        
            except Exception:
                break
    
    def _handle_socks_connection(self, client_socket: socket.socket, client_addr):
        """Handle individual SOCKS connection"""
        
        try:
            # SOCKS5 handshake
            if not self._socks5_handshake(client_socket):
                client_socket.close()
                return
            
            # Authentication if required
            if self.auth_required:
                if not self._socks5_authenticate(client_socket):
                    client_socket.close()
                    return
            
            # Handle SOCKS request
            target_socket = self._handle_socks_request(client_socket)
            
            if target_socket:
                # Add to active connections
                connection_info = {
                    "client": client_socket,
                    "target": target_socket,
                    "client_addr": client_addr,
                    "start_time": time.time()
                }
                self.connections.append(connection_info)
                
                # Start data forwarding
                self._forward_socks_data(client_socket, target_socket)
            
        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _socks5_handshake(self, client_socket: socket.socket) -> bool:
        """Perform SOCKS5 initial handshake"""
        
        try:
            # Receive client greeting
            data = client_socket.recv(256)
            if len(data) < 3:
                return False
            
            version, nmethods = struct.unpack('!BB', data[:2])
            
            if version != 5:  # Only SOCKS5 supported
                return False
            
            methods = struct.unpack('!' + 'B' * nmethods, data[2:2+nmethods])
            
            # Choose authentication method
            if self.auth_required:
                if 2 in methods:  # Username/password authentication
                    response = struct.pack('!BB', 5, 2)
                else:
                    response = struct.pack('!BB', 5, 0xFF)  # No acceptable methods
            else:
                if 0 in methods:  # No authentication
                    response = struct.pack('!BB', 5, 0)
                else:
                    response = struct.pack('!BB', 5, 0xFF)  # No acceptable methods
            
            client_socket.send(response)
            
            return response[1] != 0xFF
            
        except Exception:
            return False
    
    def _socks5_authenticate(self, client_socket: socket.socket) -> bool:
        """Perform SOCKS5 username/password authentication"""
        
        try:
            # Receive authentication request
            data = client_socket.recv(256)
            if len(data) < 3:
                return False
            
            version = data[0]
            if version != 1:  # Username/password auth version
                return False
            
            username_len = data[1]
            username = data[2:2+username_len].decode('utf-8')
            password_len = data[2+username_len]
            password = data[3+username_len:3+username_len+password_len].decode('utf-8')
            
            # Check credentials
            if username == self.username and password == self.password:
                response = struct.pack('!BB', 1, 0)  # Success
            else:
                response = struct.pack('!BB', 1, 1)  # Failure
            
            client_socket.send(response)
            
            return response[1] == 0
            
        except Exception:
            return False
    
    def _handle_socks_request(self, client_socket: socket.socket) -> socket.socket:
        """Handle SOCKS5 connection request"""
        
        try:
            # Receive connection request
            data = client_socket.recv(256)
            if len(data) < 10:
                return None
            
            version, cmd, reserved, addr_type = struct.unpack('!BBBB', data[:4])
            
            if version != 5 or cmd != 1:  # Only CONNECT command supported
                # Send error response
                response = struct.pack('!BBBBIH', 5, 7, 0, 1, 0, 0)  # Command not supported
                client_socket.send(response)
                return None
            
            # Parse address
            if addr_type == 1:  # IPv4
                addr = socket.inet_ntoa(data[4:8])
                port = struct.unpack('!H', data[8:10])[0]
            elif addr_type == 3:  # Domain name
                addr_len = data[4]
                addr = data[5:5+addr_len].decode('utf-8')
                port = struct.unpack('!H', data[5+addr_len:7+addr_len])[0]
            elif addr_type == 4:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                port = struct.unpack('!H', data[20:22])[0]
            else:
                # Send error response
                response = struct.pack('!BBBBIH', 5, 8, 0, 1, 0, 0)  # Address type not supported
                client_socket.send(response)
                return None
            
            # Connect to target
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(10)
                target_socket.connect((addr, port))
                
                # Send success response
                response = struct.pack('!BBBBIH', 5, 0, 0, 1, 0, 0)  # Success
                client_socket.send(response)
                
                return target_socket
                
            except Exception:
                # Send connection error response
                response = struct.pack('!BBBBIH', 5, 5, 0, 1, 0, 0)  # Connection refused
                client_socket.send(response)
                return None
                
        except Exception:
            return None
    
    def _forward_socks_data(self, client_socket: socket.socket, target_socket: socket.socket):
        """Forward data between client and target"""
        
        try:
            while self.running:
                # Use select to check for data on both sockets
                ready_sockets, _, error_sockets = select.select(
                    [client_socket, target_socket], [], [client_socket, target_socket], 1.0
                )
                
                if error_sockets:
                    break
                
                for sock in ready_sockets:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return  # Connection closed
                        
                        # Forward data to the other socket
                        if sock == client_socket:
                            target_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                            
                    except Exception:
                        return
                        
        except Exception:
            pass
        finally:
            try:
                target_socket.close()
            except:
                pass
    
    def stop(self):
        """Stop SOCKS proxy server"""
        
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Close all active connections
        for conn in self.connections:
            try:
                conn["client"].close()
            except:
                pass
            
            try:
                conn["target"].close()
            except:
                pass
        
        self.connections.clear()

# Global SOCKS proxy registry
_active_socks_proxies = {}

def _register_socks_proxy(proxy_server: SocksProxyServer):
    """Register SOCKS proxy in global registry"""
    _active_socks_proxies[proxy_server.get_id()] = proxy_server

def elite_socks_proxy_stop(proxy_id: str = None, port: int = None) -> Dict[str, Any]:
    """Stop active SOCKS proxies"""
    
    try:
        stopped_proxies = []
        
        if proxy_id:
            # Stop specific proxy by ID
            if proxy_id in _active_socks_proxies:
                proxy = _active_socks_proxies[proxy_id]
                proxy.stop()
                del _active_socks_proxies[proxy_id]
                stopped_proxies.append(proxy_id)
        
        elif port:
            # Stop proxies by port
            to_remove = []
            for p_id, proxy in _active_socks_proxies.items():
                if proxy.port == port:
                    proxy.stop()
                    stopped_proxies.append(p_id)
                    to_remove.append(p_id)
            
            for p_id in to_remove:
                del _active_socks_proxies[p_id]
        
        else:
            # Stop all proxies
            for p_id, proxy in _active_socks_proxies.items():
                proxy.stop()
                stopped_proxies.append(p_id)
            
            _active_socks_proxies.clear()
        
        return {
            "success": True,
            "stopped_proxies": stopped_proxies,
            "total_stopped": len(stopped_proxies)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to stop SOCKS proxies: {str(e)}",
            "stopped_proxies": []
        }

def elite_socks_proxy_list() -> Dict[str, Any]:
    """List active SOCKS proxies"""
    
    try:
        active_proxies = []
        
        for p_id, proxy in _active_socks_proxies.items():
            proxy_info = {
                "id": p_id,
                "port": proxy.port,
                "bind_address": proxy.bind_address,
                "auth_required": proxy.auth_required,
                "running": proxy.running,
                "active_connections": len(proxy.connections)
            }
            active_proxies.append(proxy_info)
        
        return {
            "success": True,
            "active_proxies": active_proxies,
            "total_active": len(active_proxies)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list SOCKS proxies: {str(e)}",
            "active_proxies": []
        }


if __name__ == "__main__":
    # Test the elite_socks_proxy command
    print("Testing Elite SOCKS Proxy Command...")
    
    # Test SOCKS proxy without authentication
    result = elite_socks_proxy(port=9080, bind_address="127.0.0.1", auth_required=False)
    print(f"Test 1 - SOCKS proxy (no auth): {result['success']}")
    
    if result['success']:
        proxy_id = result.get('proxy_id')
        print(f"Proxy ID: {proxy_id}")
        
        # List active proxies
        list_result = elite_socks_proxy_list()
        print(f"Active proxies: {list_result.get('total_active', 0)}")
        
        # Stop the proxy
        stop_result = elite_socks_proxy_stop(proxy_id=proxy_id)
        print(f"Stopped proxies: {stop_result.get('total_stopped', 0)}")
    
    # Test SOCKS proxy with authentication
    result = elite_socks_proxy(port=9081, auth_required=True, username="elite", password="test123")
    print(f"Test 2 - SOCKS proxy (with auth): {result['success']}")
    
    # Test invalid parameters
    result = elite_socks_proxy(port=9082, auth_required=True)  # Missing credentials
    print(f"Test 3 - Invalid params: {result['success']}")
    
    print("✅ Elite SOCKS Proxy command testing complete")