#!/usr/bin/env python3
"""
Elite SSH Client
Advanced SSH connection and command execution
"""

import subprocess
import sys
import os
import time
from typing import Dict, Any, Optional

def elite_ssh(host: str = None,
             username: str = None,
             password: str = None,
             command: str = None,
             key_file: str = None,
             port: int = 22) -> Dict[str, Any]:
    """
    Advanced SSH client functionality
    
    Args:
        host: Target host to connect to
        username: SSH username
        password: SSH password (not recommended)
        command: Command to execute remotely
        key_file: Path to SSH private key
        port: SSH port (default 22)
    
    Returns:
        Dict containing SSH operation results
    """
    
    try:
        if not host:
            return {
                "success": False,
                "error": "Host is required for SSH connection"
            }
        
        # Build SSH command
        ssh_cmd = ["ssh"]
        
        # Add port if not default
        if port != 22:
            ssh_cmd.extend(["-p", str(port)])
        
        # Add key file if provided
        if key_file and os.path.exists(key_file):
            ssh_cmd.extend(["-i", key_file])
        
        # Add connection options
        ssh_cmd.extend([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10"
        ])
        
        # Add user@host
        if username:
            ssh_cmd.append(f"{username}@{host}")
        else:
            ssh_cmd.append(host)
        
        # Add command if provided
        if command:
            ssh_cmd.append(command)
        
        start_time = time.time()
        
        # Execute SSH command
        if password:
            # Use sshpass if available for password authentication
            try:
                result = subprocess.run([
                    "sshpass", "-p", password
                ] + ssh_cmd, capture_output=True, text=True, timeout=30)
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "sshpass not available for password authentication",
                    "note": "Use key-based authentication instead"
                }
        else:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        
        execution_time = time.time() - start_time
        
        return {
            "success": result.returncode == 0,
            "host": host,
            "username": username,
            "port": port,
            "command": command,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "execution_time": execution_time,
            "timestamp": time.time()
        }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "SSH connection timed out",
            "host": host,
            "timeout": 30
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"SSH operation failed: {str(e)}",
            "host": host
        }

if __name__ == "__main__":
    result = elite_ssh("example.com", "user", command="whoami")
    print(f"SSH Result: {result}")