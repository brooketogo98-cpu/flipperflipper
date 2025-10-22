#!/usr/bin/env python3
"""
Central Configuration Loader
All components MUST use this instead of hardcoded values
"""

import os
import yaml
import json
from typing import Any, Dict, Optional
from pathlib import Path

class ConfigLoader:
    """
    Singleton configuration loader for the entire system
    """
    _instance = None
    _config = None
    _config_path = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config_path: str = None):
        if self._config is None:
            if config_path is None:
                # Default paths to check
                paths = [
                    '/workspace/config.yaml',
                    './config.yaml',
                    '../config.yaml',
                    os.path.expanduser('~/.elite/config.yaml'),
                    '/etc/elite/config.yaml'
                ]
                
                for path in paths:
                    if os.path.exists(path):
                        config_path = path
                        break
                        
                if config_path is None:
                    raise FileNotFoundError("No config.yaml found in standard locations")
            
            self._config_path = config_path
            self.reload()
    
    def reload(self):
        """Reload configuration from file"""
        with open(self._config_path, 'r') as f:
            self._config = yaml.safe_load(f)
        
        # Apply environment variable overrides
        self._apply_env_overrides()
        
    def _apply_env_overrides(self):
        """
        Override config with environment variables
        Format: ELITE_SECTION_KEY=value
        Example: ELITE_C2_PORT=5555
        """
        for key, value in os.environ.items():
            if key.startswith('ELITE_'):
                parts = key[6:].lower().split('_', 1)
                if len(parts) == 2:
                    section, setting = parts
                    if section in self._config:
                        # Convert value to appropriate type
                        if setting in self._config[section]:
                            original_type = type(self._config[section][setting])
                            if original_type == bool:
                                value = value.lower() in ('true', '1', 'yes')
                            elif original_type == int:
                                value = int(value)
                            elif original_type == float:
                                value = float(value)
                        
                        self._config[section][setting] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        Example: config.get('c2.port') returns 4444
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value if value is not None else default
    
    def get_section(self, section: str) -> Dict:
        """Get entire configuration section"""
        return self._config.get(section, {})
    
    def set(self, key: str, value: Any):
        """
        Set configuration value (runtime only, doesn't save to file)
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, path: str = None):
        """Save current configuration to file"""
        save_path = path or self._config_path
        
        # Create backup
        if os.path.exists(save_path):
            backup_path = f"{save_path}.backup"
            with open(save_path, 'r') as f:
                backup = f.read()
            with open(backup_path, 'w') as f:
                f.write(backup)
        
        # Save new config
        with open(save_path, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False)
    
    # Convenience properties for common settings
    @property
    def c2_host(self) -> str:
        return self.get('c2.host', '0.0.0.0')
    
    @property
    def c2_port(self) -> int:
        return self.get('c2.port', 4444)
    
    @property
    def webapp_host(self) -> str:
        return self.get('webapp.host', '0.0.0.0')
    
    @property
    def webapp_port(self) -> int:
        return self.get('webapp.port', 5000)
    
    @property
    def database_path(self) -> str:
        return self.get('database.path', '/workspace/data/elite.db')
    
    @property
    def log_level(self) -> str:
        return self.get('logging.level', 'INFO')
    
    @property
    def stealth_mode(self) -> bool:
        return self.get('stealth.hide_console', True)
    
    @property
    def beacon_interval(self) -> int:
        return self.get('c2.beacon_interval', 60)
    
    @property
    def beacon_jitter(self) -> int:
        return self.get('c2.beacon_jitter', 10)

# Global instance
config = ConfigLoader()

# Test the loader
if __name__ == "__main__":
    print("Testing Configuration Loader")
    print("-" * 50)
    
    # Test loading
    try:
        config = ConfigLoader()
        print(f"✅ Config loaded from: {config._config_path}")
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        exit(1)
    
    # Test getting values
    print(f"\nC2 Settings:")
    print(f"  Host: {config.c2_host}")
    print(f"  Port: {config.c2_port}")
    print(f"  Beacon: {config.beacon_interval}s ± {config.beacon_jitter}s")
    
    print(f"\nWeb App Settings:")
    print(f"  Host: {config.webapp_host}")
    print(f"  Port: {config.webapp_port}")
    
    print(f"\nStealth Settings:")
    print(f"  Hide Console: {config.stealth_mode}")
    print(f"  Console Output: {config.get('logging.console_output')}")
    
    # Test dot notation
    print(f"\nDot Notation Test:")
    print(f"  c2.auth_token: {config.get('c2.auth_token')}")
    print(f"  features.keylogger: {config.get('features.keylogger')}")
    
    # Test environment override
    os.environ['ELITE_C2_PORT'] = '5555'
    config.reload()
    print(f"\nAfter env override (ELITE_C2_PORT=5555):")
    print(f"  C2 Port: {config.c2_port}")
    
    print("\n✅ Configuration loader working correctly!")