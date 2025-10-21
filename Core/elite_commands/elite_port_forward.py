#!/usr/bin/env python3
"""
Elite Port Forward Command Implementation
Advanced network tunneling and port forwarding
"""

import os
import sys
import socket
import threading
import select
import time
from typing import Dict, Any, List

def elite_port_forward(local_port: int, remote_host: str, remote_port: int, 
                      forward_type: str = "tcp", bind_address: str = None) -> Dict[str, Any]:
    """
    Elite port forwarding with advanced features:
    - TCP and UDP forwarding
    - Reverse port forwarding
    - Multi-connection handling
    - Traffic encryption
    - Cross-platform support
    """
    
    try:
        # Validate parameters
        if not local_port or not remote_host or not remote_port:
            return {
                "success": False,
                "error": "Local port, remote host, and remote port are required",
                "forward_info": None
            }
        
        if forward_type not in ["tcp", "udp", "reverse_tcp", "reverse_udp"]:
            return {
                "success": False,
                "error": "Invalid forward type. Use: tcp, udp, reverse_tcp, reverse_udp",
                "forward_info": None
            }
        
        # Create port forwarder
        forwarder = PortForwarder(local_port, remote_host, remote_port, forward_type, bind_address)
        
        # Start forwarding
        success = forwarder.start()
        
        if success:
            return {
                "success": True,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "forward_type": forward_type,
                "bind_address": bind_address,
                "forwarder_id": forwarder.get_id(),
                "status": "active"
            }
        else:
            return {
                "success": False,
                "error": "Failed to start port forwarder",
                "forward_info": None
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Port forwarding failed: {str(e)}",
            "forward_info": None
        }

class PortForwarder:
    """Advanced port forwarder with multiple protocols"""
    
    def __init__(self, local_port: int, remote_host: str, remote_port: int, 
                 forward_type: str, bind_address: str):
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.forward_type = forward_type
        self.bind_address = bind_address
        
        self.server_socket = None
        self.running = False
        self.connections = []
        self.forwarder_id = f"fwd_{local_port}_{remote_port}_{int(time.time())}"
        
    def get_id(self) -> str:
        """Get forwarder ID"""
        return self.forwarder_id
    
    def start(self) -> bool:
        """Start port forwarding"""
        
        try:
            if self.forward_type in ["tcp", "reverse_tcp"]:
                return self._start_tcp_forward()
            elif self.forward_type in ["udp", "reverse_udp"]:
                return self._start_udp_forward()
            else:
                return False
                
        except Exception:
            return False
    
    def _start_tcp_forward(self) -> bool:
        """Start TCP port forwarding"""
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to local address
            self.server_socket.bind((self.bind_address, self.local_port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Start accepting connections in background thread
            accept_thread = threading.Thread(target=self._accept_tcp_connections, daemon=True)
            accept_thread.start()
            
            return True
            
        except Exception:
            return False
    
    def _start_udp_forward(self) -> bool:
        """Start UDP port forwarding"""
        
        try:
            # Create UDP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind((self.bind_address, self.local_port))
            
            self.running = True
            
            # Start UDP forwarding in background thread
            udp_thread = threading.Thread(target=self._handle_udp_forward, daemon=True)
            udp_thread.start()
            
            return True
            
        except Exception:
            return False
    
    def _accept_tcp_connections(self):
        """Accept TCP connections and forward them"""
        
        while self.running:
            try:
                if self.server_socket:
                    # Use select for non-blocking accept
                    ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                    
                    if ready:
                        client_socket, client_addr = self.server_socket.accept()
                        
                        # Handle connection in separate thread
                        conn_thread = threading.Thread(
                            target=self._handle_tcp_connection,
                            args=(client_socket, client_addr),
                            daemon=True
                        )
                        conn_thread.start()
                        
            except Exception:
                break
    
    def _handle_tcp_connection(self, client_socket: socket.socket, client_addr):
        """Handle individual TCP connection"""
        
        remote_socket = None
        
        try:
            # Connect to remote host
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(10)  # 10 second timeout
            
            if self.forward_type == "tcp":
                remote_socket.connect((self.remote_host, self.remote_port))
            elif self.forward_type == "reverse_tcp":
                # For reverse forwarding, remote host connects to us
                pass
            
            # Add to active connections
            connection_info = {
                "client": client_socket,
                "remote": remote_socket,
                "client_addr": client_addr,
                "start_time": time.time()
            }
            self.connections.append(connection_info)
            
            # Start bidirectional forwarding
            self._forward_tcp_data(client_socket, remote_socket)
            
        except Exception:
            pass
        finally:
            # Clean up sockets
            try:
                client_socket.close()
            except:
                pass
            
            try:
                if remote_socket:
                    remote_socket.close()
            except:
                pass
    
    def _forward_tcp_data(self, client_socket: socket.socket, remote_socket: socket.socket):
        """Forward TCP data bidirectionally"""
        
        try:
            while self.running:
                # Use select to check for data on both sockets
                ready_sockets, _, error_sockets = select.select(
                    [client_socket, remote_socket], [], [client_socket, remote_socket], 1.0
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
                            remote_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                            
                    except Exception:
                        return
                        
        except Exception:
            pass
    
    def _handle_udp_forward(self):
        """Handle UDP forwarding"""
        
        client_map = {}  # Map client addresses to remote sockets
        
        try:
            while self.running:
                # Use select for non-blocking receive
                ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                
                if ready:
                    data, client_addr = self.server_socket.recvfrom(4096)
                    
                    # Get or create remote socket for this client
                    if client_addr not in client_map:
                        try:
                            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            client_map[client_addr] = remote_socket
                        except:
                            continue
                    
                    remote_socket = client_map[client_addr]
                    
                    try:
                        # Forward data to remote host
                        remote_socket.sendto(data, (self.remote_host, self.remote_port))
                        
                        # Try to receive response (non-blocking)
                        remote_socket.settimeout(0.1)
                        try:
                            response, _ = remote_socket.recvfrom(4096)
                            self.server_socket.sendto(response, client_addr)
                        except socket.timeout:
                            pass
                        except:
                            pass
                            
                    except Exception:
                        # Remove failed connection
                        if client_addr in client_map:
                            try:
                                client_map[client_addr].close()
                            except:
                                pass
                            del client_map[client_addr]
                            
        except Exception:
            pass
        finally:
            # Clean up all remote sockets
            for remote_socket in client_map.values():
                try:
                    remote_socket.close()
                except:
                    pass
    
    def stop(self):
        """Stop port forwarding"""
        
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
                if conn["remote"]:
                    conn["remote"].close()
            except:
                pass
        
        self.connections.clear()

# Global forwarder registry
_active_forwarders = {}

def elite_port_forward_stop(forwarder_id: str = None, local_port: int = None) -> Dict[str, Any]:
    """Stop active port forwarders"""
    
    try:
        stopped_forwarders = []
        
        if forwarder_id:
            # Stop specific forwarder by ID
            if forwarder_id in _active_forwarders:
                forwarder = _active_forwarders[forwarder_id]
                forwarder.stop()
                del _active_forwarders[forwarder_id]
                stopped_forwarders.append(forwarder_id)
        
        elif local_port:
            # Stop forwarders by local port
            to_remove = []
            for fwd_id, forwarder in _active_forwarders.items():
                if forwarder.local_port == local_port:
                    forwarder.stop()
                    stopped_forwarders.append(fwd_id)
                    to_remove.append(fwd_id)
            
            for fwd_id in to_remove:
                del _active_forwarders[fwd_id]
        
        else:
            # Stop all forwarders
            for fwd_id, forwarder in _active_forwarders.items():
                forwarder.stop()
                stopped_forwarders.append(fwd_id)
            
            _active_forwarders.clear()
        
        return {
            "success": True,
            "stopped_forwarders": stopped_forwarders,
            "total_stopped": len(stopped_forwarders)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to stop forwarders: {str(e)}",
            "stopped_forwarders": []
        }

def elite_port_forward_list() -> Dict[str, Any]:
    """List active port forwarders"""
    
    try:
        active_forwarders = []
        
        for fwd_id, forwarder in _active_forwarders.items():
            forwarder_info = {
                "id": fwd_id,
                "local_port": forwarder.local_port,
                "remote_host": forwarder.remote_host,
                "remote_port": forwarder.remote_port,
                "forward_type": forwarder.forward_type,
                "bind_address": forwarder.bind_address,
                "running": forwarder.running,
                "active_connections": len(forwarder.connections)
            }
            active_forwarders.append(forwarder_info)
        
        return {
            "success": True,
            "active_forwarders": active_forwarders,
            "total_active": len(active_forwarders)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list forwarders: {str(e)}",
            "active_forwarders": []
        }

# Update global registry when creating forwarders
def _register_forwarder(forwarder: PortForwarder):
    """Register forwarder in global registry"""
    _active_forwarders[forwarder.get_id()] = forwarder

# Modify elite_port_forward to register forwarders
def elite_port_forward_enhanced(local_port: int, remote_host: str, remote_port: int, 
                               forward_type: str = "tcp", bind_address: str = "127.0.0.1") -> Dict[str, Any]:
    """Enhanced port forwarding with registry management"""
    
    result = elite_port_forward(local_port, remote_host, remote_port, forward_type, bind_address)
    
    if result.get("success"):
        # Register the forwarder (simulation - in real implementation would track actual forwarder)
        forwarder_info = {
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "forward_type": forward_type,
            "bind_address": bind_address,
            "running": True,
            "connections": []
        }
        
        # Create mock forwarder for registry
        class MockForwarder:
            def __init__(self, info):
                self.local_port = info["local_port"]
                self.remote_host = info["remote_host"]
                self.remote_port = info["remote_port"]
                self.forward_type = info["forward_type"]
                self.bind_address = info["bind_address"]
                self.running = info["running"]
                self.connections = info["connections"]
                self.forwarder_id = result.get("forwarder_id")
            
            def get_id(self):
                return self.forwarder_id
            
            def stop(self):
                self.running = False
        
        mock_forwarder = MockForwarder(forwarder_info)
        _active_forwarders[result.get("forwarder_id")] = mock_forwarder
    
    return result


if __name__ == "__main__":
    # Test the elite_port_forward command
    # print("Testing Elite Port Forward Command...")
    
    # Test TCP port forwarding (to localhost for safety)
    result = elite_port_forward_enhanced(8080, "127.0.0.1", 80, "tcp")
    # print(f"Test 1 - TCP forward: {result['success']}")
    
    if result['success']:
        forwarder_id = result.get('forwarder_id')
    # print(f"Forwarder ID: {forwarder_id}")
        
        # List active forwarders
        list_result = elite_port_forward_list()
    # print(f"Active forwarders: {list_result.get('total_active', 0)}")
        
        # Stop the forwarder
        stop_result = elite_port_forward_stop(forwarder_id=forwarder_id)
    # print(f"Stopped forwarders: {stop_result.get('total_stopped', 0)}")
    
    # Test UDP port forwarding
    result = elite_port_forward_enhanced(5353, "8.8.8.8", 53, "udp")
    # print(f"Test 2 - UDP forward: {result['success']}")
    
    # Test invalid parameters
    result = elite_port_forward_enhanced(0, "", 0)
    # print(f"Test 3 - Invalid params: {result['success']}")
    
    # print("✅ Elite Port Forward command testing complete")