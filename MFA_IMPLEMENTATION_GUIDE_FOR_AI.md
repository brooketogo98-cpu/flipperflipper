# Complete MFA Implementation Guide for AI Developer

## 🎯 Purpose of This Document

You are an AI assistant tasked with implementing Multi-Factor Authentication (MFA) for the Oranolio/Stitch RAT web interface. This document assumes **you know absolutely nothing** about the project and will guide you through **every single step** - from understanding what's there now, to implementing every line of code, to testing it all works.

**Read this document completely before starting. Follow steps in exact order.**

---

## 📋 Table of Contents

1. [Understanding the Current System](#1-understanding-the-current-system)
2. [What You're Going to Build](#2-what-youre-going-to-build)
3. [Prerequisites and Setup](#3-prerequisites-and-setup)
4. [Step-by-Step Implementation](#4-step-by-step-implementation)
5. [Testing Your Implementation](#5-testing-your-implementation)
6. [Troubleshooting](#6-troubleshooting)
7. [Final Checklist](#7-final-checklist)

---

## 1. Understanding the Current System

### 1.1 What is This System?

This is a Flask-based web application for remote administration. It has:
- A login page where users enter username and password
- A dashboard after login
- Various features for remote system management

### 1.2 Current Files You Need to Know About

#### **MOST IMPORTANT FILES:**

1. **`/workspace/web_app_real.py`** (Lines 525-581)
   - This is the main Flask application
   - Contains the `/login` route
   - This is where users currently log in with just username + password
   - **You will modify this file heavily**

2. **`/workspace/config.py`** (Lines 1-385)
   - Configuration settings for the entire application
   - Contains security settings, database paths, etc.
   - **You will add MFA configuration here**

3. **`/workspace/auth_utils.py`** (Lines 1-339)
   - Authentication utilities
   - Has functions for password checking, failed login tracking, API keys
   - **You will reference this for patterns to follow**

4. **`/workspace/templates/login.html`** (Lines 1-315)
   - The HTML template for the login page
   - **You won't modify this much, but you'll create similar pages**

#### **DATABASE LOCATION:**
- SQLite database (if enabled): `/workspace/Application/stitch.db`
- User credentials stored in Python dict variable `USERS` in `web_app_real.py`
- **You will create new MFA tables in database**

### 1.3 How Login Works Right Now

```
Step 1: User visits /login
        ↓
Step 2: User enters username + password
        ↓
Step 3: web_app_real.py checks credentials using check_password_hash()
        ↓
Step 4: If valid: Create session, redirect to /dashboard
        If invalid: Show error, track failed attempt
```

**THE PROBLEM:** If someone steals the password, they have full access. No second factor.

### 1.4 What's Already Secure

✅ Passwords are hashed (not stored as plaintext)
✅ Failed login attempts are tracked
✅ CSRF protection is enabled
✅ Sessions are secure (HTTPOnly cookies)
✅ Rate limiting prevents brute force

**What's MISSING:** Multi-Factor Authentication (MFA/2FA)

---

## 2. What You're Going to Build

### 2.1 The Goal

Implement **TOTP-based Two-Factor Authentication** that works with:
- Microsoft Authenticator
- Google Authenticator  
- Authy
- Any app that supports TOTP (Time-based One-Time Password)

### 2.2 User Experience After Your Implementation

#### **First-Time Login:**
```
1. User enters username + password
2. ✅ Password is correct
3. → Redirect to /mfa/setup
4. Page shows:
   - A QR code to scan
   - A text code for manual entry
   - Instructions
5. User scans QR code with Microsoft Authenticator (or any auth app)
6. App shows 6-digit code that changes every 30 seconds
7. User enters the 6-digit code to verify setup
8. ✅ Code is correct
9. System generates 10 backup recovery codes
10. User downloads/saves backup codes
11. → Redirect to dashboard
12. ✅ Login complete
```

#### **Every Subsequent Login:**
```
1. User enters username + password
2. ✅ Password is correct
3. → Redirect to /mfa/verify
4. Page shows:
   - Input box for 6-digit code
   - Link to use backup code instead
5. User opens Microsoft Authenticator app
6. App shows 6-digit code (e.g., 123456)
7. User enters 123456
8. ✅ Code is correct
9. → Redirect to dashboard
10. ✅ Login complete
```

#### **If User Loses Phone/Authenticator:**
```
1. User enters username + password
2. ✅ Password is correct
3. → Redirect to /mfa/verify
4. User clicks "Lost your device? Use backup code"
5. User enters one of their 10 backup codes
6. ✅ Backup code is valid
7. System removes that code from database (one-time use)
8. → Redirect to dashboard
9. System prompts user to reset MFA
10. User scans new QR code
11. ✅ New MFA configured
```

### 2.3 Technical Architecture

You will build:

1. **Database Tables:**
   - `user_mfa` - stores TOTP secrets and backup codes
   - `mfa_audit_log` - logs all MFA events

2. **Python Module:**
   - `mfa_manager.py` - handles all MFA logic

3. **Flask Routes:**
   - `/mfa/setup` - setup MFA for first time
   - `/mfa/verify` - verify MFA code on login
   - `/mfa/backup-codes` - show backup codes once
   - `/mfa/manage` - reset/manage MFA settings

4. **HTML Templates:**
   - `mfa_setup.html` - shows QR code and setup instructions
   - `mfa_verify.html` - asks for 6-digit code
   - `mfa_backup_codes.html` - displays backup codes
   - `mfa_manage.html` - MFA settings page

5. **Modified Files:**
   - `web_app_real.py` - update `/login` route
   - `config.py` - add MFA configuration

---

## 3. Prerequisites and Setup

### 3.1 Check Python Version

```bash
# Run this command
python3 --version

# Should output: Python 3.8 or higher
# If not, you need to upgrade Python
```

### 3.2 Install Required Packages

**Create a file:** `/workspace/mfa_requirements.txt`

```txt
pyotp==2.9.0
qrcode==7.4.2
pillow==10.1.0
cryptography==41.0.7
```

**Install packages:**

```bash
cd /workspace
pip3 install -r mfa_requirements.txt

# Verify installation:
python3 -c "import pyotp; print('✅ pyotp installed')"
python3 -c "import qrcode; print('✅ qrcode installed')"
python3 -c "from PIL import Image; print('✅ pillow installed')"
python3 -c "from cryptography.fernet import Fernet; print('✅ cryptography installed')"
```

If any import fails, the package didn't install correctly. Fix before continuing.

### 3.3 Understand the Dependencies

- **pyotp:** Generates and verifies TOTP codes (the 6-digit numbers)
- **qrcode:** Creates QR code images
- **pillow:** Image library needed by qrcode
- **cryptography:** Encrypts TOTP secrets before storing in database

### 3.4 Backup Current System

```bash
cd /workspace

# Backup the entire directory
tar -czf backup_before_mfa_$(date +%Y%m%d_%H%M%S).tar.gz \
    web_app_real.py \
    config.py \
    auth_utils.py \
    templates/

# Verify backup created
ls -lh backup_before_mfa_*.tar.gz

# You should see a file like: backup_before_mfa_20251022_120000.tar.gz
```

**CRITICAL:** If anything goes wrong, you can restore:
```bash
tar -xzf backup_before_mfa_20251022_120000.tar.gz
```

---

## 4. Step-by-Step Implementation

### STEP 1: Create the MFA Manager Module

**Create new file:** `/workspace/mfa_manager.py`

**Copy this ENTIRE code:**

```python
#!/usr/bin/env python3
"""
Multi-Factor Authentication Manager
Handles TOTP setup, verification, and backup codes

This module provides all MFA functionality:
- Generate TOTP secrets
- Create QR codes for authenticator apps
- Verify TOTP tokens
- Manage backup recovery codes
- Encrypt/decrypt secrets for database storage
"""

import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from config import Config

class MFAManager:
    """
    Main class for handling all MFA operations
    """
    
    def __init__(self):
        """Initialize MFA manager with encryption"""
        self.encryption_key = self._get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        self.issuer_name = Config.APP_NAME  # e.g., "Oranolio RAT"
    
    def _get_encryption_key(self):
        """
        Get or generate encryption key for TOTP secrets
        
        The TOTP secret is sensitive and must be encrypted before storing.
        This function ensures we have a persistent encryption key.
        
        Returns:
            bytes: Fernet encryption key
        """
        key_file = Config.APPLICATION_DIR / '.mfa_encryption_key'
        
        # Check if key already exists
        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    key = f.read()
                    # Verify it's a valid Fernet key
                    Fernet(key)  # Will raise exception if invalid
                    return key
            except Exception as e:
                print(f"⚠️  Existing MFA key invalid: {e}")
                print("   Generating new key (existing MFA setups will be invalidated)")
        
        # Generate new encryption key
        key = Fernet.generate_key()
        
        try:
            # Ensure directory exists
            Config.APPLICATION_DIR.mkdir(parents=True, exist_ok=True)
            
            # Save key to file
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set restrictive permissions (Unix/Linux only)
            try:
                os.chmod(key_file, 0o600)  # Owner read/write only
                print(f"✅ MFA encryption key generated: {key_file}")
            except Exception:
                print(f"✅ MFA encryption key generated: {key_file}")
                print("   (Could not set file permissions on Windows)")
        
        except Exception as e:
            print(f"❌ ERROR: Could not save MFA encryption key: {e}")
            print("   MFA will not work correctly!")
            raise
        
        return key
    
    def generate_secret(self):
        """
        Generate a new TOTP secret
        
        This is a random base32-encoded string that will be shared between
        the server and the user's authenticator app.
        
        Returns:
            str: Base32-encoded secret (e.g., "JBSWY3DPEHPK3PXP")
        """
        return pyotp.random_base32()
    
    def encrypt_secret(self, secret):
        """
        Encrypt TOTP secret for storage in database
        
        Args:
            secret (str): Plain TOTP secret
        
        Returns:
            str: Encrypted secret (safe to store)
        """
        encrypted_bytes = self.cipher.encrypt(secret.encode())
        return encrypted_bytes.decode('utf-8')
    
    def decrypt_secret(self, encrypted_secret):
        """
        Decrypt TOTP secret from database
        
        Args:
            encrypted_secret (str): Encrypted secret from database
        
        Returns:
            str: Plain TOTP secret
        """
        decrypted_bytes = self.cipher.decrypt(encrypted_secret.encode())
        return decrypted_bytes.decode('utf-8')
    
    def get_provisioning_uri(self, username, secret):
        """
        Generate provisioning URI for QR code
        
        This URI encodes all information needed by the authenticator app:
        - The secret
        - The account name (username)
        - The issuer (app name)
        
        Format: otpauth://totp/Issuer:username?secret=SECRET&issuer=Issuer
        
        Args:
            username (str): User's username
            secret (str): TOTP secret
        
        Returns:
            str: Provisioning URI
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, provisioning_uri):
        """
        Generate QR code image from provisioning URI
        
        Creates a PNG image of the QR code and converts it to base64
        for easy embedding in HTML.
        
        Args:
            provisioning_uri (str): The provisioning URI
        
        Returns:
            str: Data URI for <img> tag (data:image/png;base64,...)
        """
        # Create QR code
        qr = qrcode.QRCode(
            version=1,  # Size (1 = 21x21 modules)
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,  # Pixels per module
            border=4,     # Modules on border
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return f"data:image/png;base64,{img_base64}"
    
    def verify_token(self, secret, token):
        """
        Verify a TOTP token
        
        Checks if the provided 6-digit token is valid for the secret.
        Allows 1 time step (30 seconds) before/after current time to
        account for clock drift.
        
        Args:
            secret (str): TOTP secret
            token (str): 6-digit code from user
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not token or not secret:
            return False
        
        # Remove spaces and ensure it's 6 digits
        token = token.replace(' ', '').strip()
        
        if len(token) != 6 or not token.isdigit():
            return False
        
        totp = pyotp.TOTP(secret)
        
        # Verify with 1 window = ±30 seconds tolerance
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self, count=10):
        """
        Generate backup recovery codes
        
        Creates random 8-character codes for account recovery.
        Uses characters safe for typing: uppercase letters and numbers,
        excluding easily confused characters (0, O, 1, I, L).
        
        Args:
            count (int): Number of codes to generate (default: 10)
        
        Returns:
            list: List of backup codes (e.g., ["ABCD1234", "EFGH5678", ...])
        """
        # Character set: no easily confused characters
        charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(charset) for _ in range(8))
            codes.append(code)
        
        return codes
    
    def hash_backup_code(self, code):
        """
        Hash a backup code for secure storage
        
        Backup codes are hashed like passwords - we never store them plain.
        
        Args:
            code (str): Backup code to hash
        
        Returns:
            str: SHA-256 hash of the code
        """
        return hashlib.sha256(code.encode()).hexdigest()
    
    def verify_backup_code(self, code, hashed_codes_json):
        """
        Verify a backup code and remove it from the list
        
        Backup codes are one-time use. After verification, the code
        is removed from the database.
        
        Args:
            code (str): Code entered by user
            hashed_codes_json (str): JSON array of hashed codes from database
        
        Returns:
            tuple: (is_valid: bool, remaining_codes_json: str)
        """
        # Parse hashed codes from JSON
        try:
            hashed_codes = json.loads(hashed_codes_json)
        except:
            return False, hashed_codes_json
        
        # Hash the provided code
        code_hash = self.hash_backup_code(code.strip().upper())
        
        # Check if it matches any stored hash
        if code_hash in hashed_codes:
            # Remove the used code
            hashed_codes.remove(code_hash)
            return True, json.dumps(hashed_codes)
        
        return False, hashed_codes_json
    
    def get_remaining_backup_codes_count(self, hashed_codes_json):
        """
        Get count of remaining backup codes
        
        Args:
            hashed_codes_json (str): JSON array of hashed codes
        
        Returns:
            int: Number of remaining backup codes
        """
        try:
            hashed_codes = json.loads(hashed_codes_json)
            return len(hashed_codes)
        except:
            return 0

# Create global instance
mfa_manager = MFAManager()
```

**What this file does:**
- Creates TOTP secrets (the shared secret between server and phone app)
- Generates QR codes (what user scans with their phone)
- Verifies 6-digit codes (checks if the code is correct)
- Manages backup codes (for recovery if phone is lost)
- Encrypts secrets before storing (security)

**Save this file and verify:**
```bash
python3 -c "from mfa_manager import mfa_manager; print('✅ mfa_manager.py works')"
```

### STEP 2: Create Database Tables

You need to store MFA data somewhere. You'll add it to the SQLite database.

**Create file:** `/workspace/create_mfa_tables.py`

```python
#!/usr/bin/env python3
"""
Create MFA database tables

This script creates the necessary database tables for MFA.
Run this once to set up the database.
"""

import sqlite3
from pathlib import Path
from config import Config

# Database path
DB_PATH = Config.APPLICATION_DIR / 'stitch.db'

# SQL to create tables
CREATE_USER_MFA_TABLE = """
CREATE TABLE IF NOT EXISTS user_mfa (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    mfa_secret TEXT NOT NULL,
    mfa_enabled INTEGER DEFAULT 0,
    backup_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
"""

CREATE_MFA_AUDIT_TABLE = """
CREATE TABLE IF NOT EXISTS mfa_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER DEFAULT 1,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_user_mfa_username ON user_mfa(username);",
    "CREATE INDEX IF NOT EXISTS idx_mfa_audit_username ON mfa_audit_log(username);",
    "CREATE INDEX IF NOT EXISTS idx_mfa_audit_timestamp ON mfa_audit_log(timestamp);",
]

def create_mfa_tables():
    """Create MFA tables in database"""
    
    # Ensure directory exists
    Config.APPLICATION_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"📁 Database path: {DB_PATH}")
    
    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Create user_mfa table
        print("Creating user_mfa table...")
        cursor.execute(CREATE_USER_MFA_TABLE)
        print("✅ user_mfa table created")
        
        # Create mfa_audit_log table
        print("Creating mfa_audit_log table...")
        cursor.execute(CREATE_MFA_AUDIT_TABLE)
        print("✅ mfa_audit_log table created")
        
        # Create indexes
        print("Creating indexes...")
        for index_sql in CREATE_INDEXES:
            cursor.execute(index_sql)
        print("✅ Indexes created")
        
        # Commit changes
        conn.commit()
        print("\n✅ MFA database tables created successfully!")
        
        # Verify tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%mfa%';")
        tables = cursor.fetchall()
        print("\n📋 MFA tables in database:")
        for table in tables:
            print(f"   - {table[0]}")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        conn.rollback()
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    create_mfa_tables()
```

**Run this script:**
```bash
cd /workspace
python3 create_mfa_tables.py
```

**Expected output:**
```
📁 Database path: /workspace/Application/stitch.db
Creating user_mfa table...
✅ user_mfa table created
Creating mfa_audit_log table...
✅ mfa_audit_log table created
Creating indexes...
✅ Indexes created

✅ MFA database tables created successfully!

📋 MFA tables in database:
   - user_mfa
   - mfa_audit_log
```

**Verify tables created:**
```bash
sqlite3 /workspace/Application/stitch.db "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%mfa%';"
```

Should output:
```
user_mfa
mfa_audit_log
```

### STEP 3: Create Database Helper Functions

Now create functions to save/retrieve MFA data from the database.

**Create file:** `/workspace/mfa_database.py`

```python
#!/usr/bin/env python3
"""
MFA Database Operations

Helper functions for storing and retrieving MFA data
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from config import Config

DB_PATH = Config.APPLICATION_DIR / 'stitch.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def get_user_mfa_status(username):
    """
    Check if user has MFA enabled
    
    Args:
        username (str): Username to check
    
    Returns:
        dict: {
            'exists': bool,
            'enabled': bool,
            'secret': str or None
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT mfa_enabled, mfa_secret FROM user_mfa WHERE username = ?",
        (username,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return {'exists': False, 'enabled': False, 'secret': None}
    
    return {
        'exists': True,
        'enabled': bool(row['mfa_enabled']),
        'secret': row['mfa_secret']
    }

def save_user_mfa(username, encrypted_secret, hashed_backup_codes_json):
    """
    Save MFA configuration for user
    
    Args:
        username (str): Username
        encrypted_secret (str): Encrypted TOTP secret
        hashed_backup_codes_json (str): JSON array of hashed backup codes
    
    Returns:
        bool: Success
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert or replace
        cursor.execute("""
            INSERT OR REPLACE INTO user_mfa 
            (username, mfa_secret, mfa_enabled, backup_codes, updated_at)
            VALUES (?, ?, 1, ?, CURRENT_TIMESTAMP)
        """, (username, encrypted_secret, hashed_backup_codes_json))
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"❌ Error saving MFA: {e}")
        conn.rollback()
        conn.close()
        return False

def get_user_mfa_config(username):
    """
    Get full MFA configuration for user
    
    Args:
        username (str): Username
    
    Returns:
        dict or None: MFA configuration
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM user_mfa WHERE username = ?",
        (username,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return None
    
    return dict(row)

def update_user_backup_codes(username, new_backup_codes_json):
    """
    Update backup codes for user (after one is used)
    
    Args:
        username (str): Username
        new_backup_codes_json (str): JSON array of remaining hashed codes
    
    Returns:
        bool: Success
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE user_mfa 
            SET backup_codes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE username = ?
        """, (new_backup_codes_json, username))
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"❌ Error updating backup codes: {e}")
        conn.rollback()
        conn.close()
        return False

def log_mfa_event(username, action, ip_address, user_agent="", success=True, details=None):
    """
    Log MFA event to audit log
    
    Args:
        username (str): Username
        action (str): Action type ('setup', 'verify_success', 'verify_fail', etc.)
        ip_address (str): IP address
        user_agent (str): User agent string
        success (bool): Whether action succeeded
        details (dict): Additional details
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO mfa_audit_log 
            (username, action, ip_address, user_agent, success, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            action,
            ip_address,
            user_agent,
            1 if success else 0,
            json.dumps(details) if details else None
        ))
        
        conn.commit()
    
    except Exception as e:
        print(f"⚠️  Error logging MFA event: {e}")
        conn.rollback()
    
    finally:
        conn.close()

def disable_user_mfa(username):
    """
    Disable MFA for user (admin function)
    
    Args:
        username (str): Username
    
    Returns:
        bool: Success
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE user_mfa 
            SET mfa_enabled = 0
            WHERE username = ?
        """, (username,))
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"❌ Error disabling MFA: {e}")
        conn.rollback()
        conn.close()
        return False

def delete_user_mfa(username):
    """
    Completely remove MFA configuration for user
    
    Args:
        username (str): Username
    
    Returns:
        bool: Success
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM user_mfa WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"❌ Error deleting MFA: {e}")
        conn.rollback()
        conn.close()
        return False
```

**Save and verify:**
```bash
python3 -c "from mfa_database import get_user_mfa_status; print('✅ mfa_database.py works')"
```

### STEP 4: Create HTML Templates

Now create the web pages users will see.

#### Template 1: MFA Setup Page

**Create file:** `/workspace/templates/mfa_setup.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Set Up Two-Factor Authentication</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .setup-container {
            max-width: 600px;
            width: 100%;
            background: #1a2142;
            border: 1px solid #2d3748;
            border-radius: 1rem;
            padding: 3rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #00d9ff, #667eea);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: #a0aec0;
            font-size: 1rem;
        }

        .step {
            margin-bottom: 2rem;
            padding: 1.5rem;
            background: rgba(0, 217, 255, 0.05);
            border: 1px solid rgba(0, 217, 255, 0.2);
            border-radius: 0.5rem;
        }

        .step h3 {
            color: #00d9ff;
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }

        .step p {
            color: #a0aec0;
            line-height: 1.6;
            margin-bottom: 1rem;
        }

        .qr-code {
            text-align: center;
            padding: 1.5rem;
            background: white;
            border-radius: 0.5rem;
            margin: 1rem 0;
        }

        .qr-code img {
            max-width: 100%;
            height: auto;
        }

        .manual-code {
            background: #0a0e27;
            padding: 1rem;
            border-radius: 0.5rem;
            text-align: center;
            font-family: 'Courier New', monospace;
            font-size: 1.2rem;
            letter-spacing: 2px;
            color: #00d9ff;
            margin: 1rem 0;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #a0aec0;
            font-weight: 500;
        }

        input[type="text"] {
            width: 100%;
            padding: 0.875rem 1rem;
            background: #151b35;
            border: 1px solid #2d3748;
            border-radius: 0.5rem;
            color: #ffffff;
            font-size: 1rem;
            text-align: center;
            letter-spacing: 3px;
            font-family: 'Courier New', monospace;
        }

        input:focus {
            outline: none;
            border-color: #00d9ff;
            box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);
        }

        .btn {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(135deg, #00d9ff, #667eea);
            color: white;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 217, 255, 0.3);
        }

        .alert {
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .alert-error {
            background: rgba(245, 101, 101, 0.15);
            border: 1px solid #f56565;
            color: #f56565;
        }

        .apps-list {
            list-style: none;
            padding: 0;
        }

        .apps-list li {
            padding: 0.5rem 0;
            color: #a0aec0;
        }

        .apps-list li:before {
            content: "✓ ";
            color: #00d9ff;
            font-weight: bold;
            margin-right: 0.5rem;
        }

        @media (max-width: 768px) {
            .setup-container {
                padding: 2rem 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="setup-container">
        <div class="header">
            <h1>🔒 Set Up Two-Factor Authentication</h1>
            <p>Secure your account with an authenticator app</p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="step">
            <h3>Step 1: Install an Authenticator App</h3>
            <p>Download one of these apps on your phone:</p>
            <ul class="apps-list">
                <li>Microsoft Authenticator (iOS/Android)</li>
                <li>Google Authenticator (iOS/Android)</li>
                <li>Authy (iOS/Android)</li>
                <li>1Password (iOS/Android)</li>
                <li>Any TOTP-compatible app</li>
            </ul>
        </div>

        <div class="step">
            <h3>Step 2: Scan This QR Code</h3>
            <p>Open your authenticator app and scan this QR code:</p>
            <div class="qr-code">
                <img src="{{ qr_code }}" alt="QR Code for MFA Setup">
            </div>
            <p style="text-align: center; color: #667eea; font-size: 0.9rem;">
                Or enter this code manually:
            </p>
            <div class="manual-code">{{ secret }}</div>
        </div>

        <div class="step">
            <h3>Step 3: Enter the 6-Digit Code</h3>
            <p>Enter the 6-digit code shown in your authenticator app:</p>
            
            <form method="POST">
                <div class="form-group">
                    <label for="token">Verification Code</label>
                    <input type="text" 
                           id="token" 
                           name="token" 
                           maxlength="6" 
                           pattern="[0-9]{6}"
                           placeholder="000000"
                           required 
                           autofocus
                           autocomplete="off">
                </div>
                
                <button type="submit" class="btn">Verify and Complete Setup</button>
            </form>
        </div>
    </div>

    <script>
        // Auto-submit when 6 digits entered
        document.getElementById('token').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            e.target.value = value;
            
            if (value.length === 6) {
                // Could auto-submit here if desired
                // e.target.form.submit();
            }
        });
    </script>
</body>
</html>
```

#### Template 2: MFA Verification Page

**Create file:** `/workspace/templates/mfa_verify.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .verify-container {
            max-width: 450px;
            width: 100%;
            background: #1a2142;
            border: 1px solid #2d3748;
            border-radius: 1rem;
            padding: 3rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #00d9ff, #667eea);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: #a0aec0;
            font-size: 1rem;
        }

        .alert {
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
            animation: slideIn 0.3s ease;
        }

        .alert-error {
            background: rgba(245, 101, 101, 0.15);
            border: 1px solid #f56565;
            color: #f56565;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #a0aec0;
            font-weight: 500;
        }

        input[type="text"] {
            width: 100%;
            padding: 1rem;
            background: #151b35;
            border: 1px solid #2d3748;
            border-radius: 0.5rem;
            color: #ffffff;
            font-size: 1.5rem;
            text-align: center;
            letter-spacing: 8px;
            font-family: 'Courier New', monospace;
        }

        input:focus {
            outline: none;
            border-color: #00d9ff;
            box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);
        }

        .btn {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(135deg, #00d9ff, #667eea);
            color: white;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 1rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 217, 255, 0.3);
        }

        .backup-link {
            text-align: center;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #2d3748;
        }

        .backup-link a {
            color: #00d9ff;
            text-decoration: none;
            font-size: 0.9rem;
        }

        .backup-link a:hover {
            text-decoration: underline;
        }

        .help-text {
            color: #667eea;
            font-size: 0.9rem;
            text-align: center;
            margin-top: 1rem;
        }

        @media (max-width: 768px) {
            .verify-container {
                padding: 2rem 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="verify-container">
        <div class="header">
            <h1>🔐 Two-Factor Authentication</h1>
            <p>Enter the code from your authenticator app</p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST" id="verifyForm">
            <div class="form-group">
                <label for="token">Verification Code</label>
                <input type="text" 
                       id="token" 
                       name="token" 
                       maxlength="6" 
                       pattern="[0-9]{6}"
                       placeholder="000000"
                       required 
                       autofocus
                       autocomplete="off">
                <p class="help-text">Enter the 6-digit code shown in your app</p>
            </div>
            
            <button type="submit" class="btn">Verify</button>
        </form>

        <div class="backup-link">
            <p style="color: #a0aec0; margin-bottom: 0.5rem;">Lost your phone?</p>
            <a href="#" onclick="showBackupForm(); return false;">Use a backup recovery code instead</a>
        </div>

        <!-- Hidden backup code form -->
        <form method="POST" id="backupForm" style="display: none; margin-top: 2rem;">
            <div class="form-group">
                <label for="backup_token">Backup Recovery Code</label>
                <input type="text" 
                       id="backup_token" 
                       name="token" 
                       maxlength="8"
                       placeholder="XXXXXXXX"
                       autocomplete="off"
                       style="letter-spacing: 3px;">
                <input type="hidden" name="use_backup" value="true">
                <p class="help-text">Enter one of your backup codes</p>
            </div>
            <button type="submit" class="btn">Use Backup Code</button>
            <p style="text-align: center; margin-top: 1rem;">
                <a href="#" onclick="showNormalForm(); return false;" style="color: #00d9ff;">
                    ← Back to authenticator code
                </a>
            </p>
        </form>
    </div>

    <script>
        // Auto-format and submit when 6 digits entered
        document.getElementById('token').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            e.target.value = value;
        });

        // Format backup code to uppercase
        document.getElementById('backup_token').addEventListener('input', function(e) {
            e.target.value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
        });

        function showBackupForm() {
            document.getElementById('verifyForm').style.display = 'none';
            document.getElementById('backupForm').style.display = 'block';
            document.getElementById('backup_token').focus();
        }

        function showNormalForm() {
            document.getElementById('backupForm').style.display = 'none';
            document.getElementById('verifyForm').style.display = 'block';
            document.getElementById('token').focus();
        }
    </script>
</body>
</html>
```

#### Template 3: Backup Codes Display

**Create file:** `/workspace/templates/mfa_backup_codes.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup Recovery Codes</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .backup-container {
            max-width: 600px;
            width: 100%;
            background: #1a2142;
            border: 1px solid #2d3748;
            border-radius: 1rem;
            padding: 3rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #00d9ff, #667eea);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: #a0aec0;
            font-size: 1rem;
        }

        .warning {
            background: rgba(246, 173, 85, 0.15);
            border: 1px solid #f6ad55;
            color: #f6ad55;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
        }

        .warning h3 {
            margin-bottom: 0.5rem;
            font-size: 1.2rem;
        }

        .warning ul {
            margin-left: 1.5rem;
            margin-top: 0.5rem;
        }

        .warning li {
            margin: 0.5rem 0;
        }

        .codes-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin: 2rem 0;
            padding: 1.5rem;
            background: rgba(0, 217, 255, 0.05);
            border: 1px solid rgba(0, 217, 255, 0.2);
            border-radius: 0.5rem;
        }

        .code-item {
            background: #0a0e27;
            padding: 1rem;
            border-radius: 0.5rem;
            text-align: center;
            font-family: 'Courier New', monospace;
            font-size: 1.2rem;
            letter-spacing: 2px;
            color: #00d9ff;
            border: 1px solid #2d3748;
        }

        .btn {
            width: 100%;
            padding: 1rem;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 1rem;
        }

        .btn-primary {
            background: linear-gradient(135deg, #00d9ff, #667eea);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 217, 255, 0.3);
        }

        .btn-secondary {
            background: transparent;
            border: 1px solid #2d3748;
            color: #a0aec0;
        }

        .btn-secondary:hover {
            border-color: #00d9ff;
            color: #00d9ff;
        }

        @media (max-width: 768px) {
            .backup-container {
                padding: 2rem 1.5rem;
            }
            
            .codes-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="backup-container">
        <div class="header">
            <h1>✅ MFA Setup Complete!</h1>
            <p>Save these backup recovery codes</p>
        </div>

        <div class="warning">
            <h3>⚠️ IMPORTANT - Save These Codes Now!</h3>
            <ul>
                <li>These codes will only be shown ONCE</li>
                <li>Each code can only be used ONE TIME</li>
                <li>You'll need these if you lose your phone/authenticator</li>
                <li>Store them somewhere safe (password manager, printed paper, etc.)</li>
            </ul>
        </div>

        <div class="codes-grid">
            {% for code in backup_codes %}
                <div class="code-item">{{ code }}</div>
            {% endfor %}
        </div>

        <button onclick="downloadCodes()" class="btn btn-secondary">
            📥 Download as Text File
        </button>

        <button onclick="printCodes()" class="btn btn-secondary">
            🖨️ Print Codes
        </button>

        <button onclick="window.location.href='/'" class="btn btn-primary">
            Continue to Dashboard
        </button>
    </div>

    <script>
        const backupCodes = {{ backup_codes | tojson }};

        function downloadCodes() {
            const text = 'BACKUP RECOVERY CODES\n' +
                        'Generated: ' + new Date().toLocaleString() + '\n' +
                        '================================\n\n' +
                        backupCodes.join('\n') + '\n\n' +
                        '================================\n' +
                        'KEEP THESE CODES SAFE!\n' +
                        'Each code can only be used once.';
            
            const blob = new Blob([text], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mfa-backup-codes.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }

        function printCodes() {
            window.print();
        }

        // Warn before leaving page
        let saved = false;
        window.addEventListener('beforeunload', function(e) {
            if (!saved) {
                e.preventDefault();
                e.returnValue = '';
                return 'Have you saved your backup codes? They will not be shown again!';
            }
        });

        // Mark as saved when download/print used
        document.querySelectorAll('.btn-secondary').forEach(btn => {
            btn.addEventListener('click', function() {
                saved = true;
            });
        });
    </script>
</body>
</html>
```

**Verify templates created:**
```bash
ls -la /workspace/templates/mfa_*.html
```

Should show:
```
mfa_setup.html
mfa_verify.html
mfa_backup_codes.html
```

### STEP 5: Update web_app_real.py

Now modify the main Flask app to add MFA routes and update the login flow.

**Find and read the login function in `/workspace/web_app_real.py` around line 525.**

**You will REPLACE the entire `/login` route with this:**

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login route - now with MFA support
    
    Flow:
    1. Verify username + password (first factor)
    2. Check if MFA is enabled for this user
    3. If MFA not setup → redirect to /mfa/setup
    4. If MFA enabled → redirect to /mfa/verify
    5. After MFA verification → complete login
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = get_remote_address()
        
        # Validate inputs exist
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html'), 400
        
        # Check if IP is locked out
        if is_login_locked(client_ip):
            remaining_seconds = get_lockout_time_remaining(client_ip)
            remaining_minutes = (remaining_seconds + 59) // 60
            log_debug(f"Login lockout for IP {client_ip} - {remaining_minutes} minutes remaining", "ERROR", "Security")
            flash(f'Too many failed attempts. Please try again in {remaining_minutes} minutes.', 'error')
            return render_template('login.html'), 429
        
        # Verify credentials (FIRST FACTOR)
        if username in USERS and password and check_password_hash(USERS[username], password):
            # Clear failed attempts
            clear_failed_login_attempts(client_ip)
            
            # Import MFA functions
            from mfa_database import get_user_mfa_status
            
            # Check MFA status
            mfa_status = get_user_mfa_status(username)
            
            if not mfa_status['enabled']:
                # MFA not set up - redirect to setup
                session['mfa_setup_username'] = username
                session['mfa_setup_ip'] = client_ip
                session['mfa_setup_time'] = datetime.now().isoformat()
                log_debug(f"User {username} needs MFA setup", "INFO", "MFA")
                return redirect(url_for('mfa_setup'))
            else:
                # MFA enabled - redirect to verification
                session['mfa_verify_username'] = username
                session['mfa_verify_ip'] = client_ip
                session['mfa_verify_time'] = datetime.now().isoformat()
                log_debug(f"User {username} proceeding to MFA verification", "INFO", "MFA")
                return redirect(url_for('mfa_verify'))
        else:
            # Failed login - track attempt
            attempt_count = track_failed_login(client_ip, username)
            
            # Track metrics
            metrics_collector.increment_counter('failed_logins')
            
            # Check if now locked
            if is_login_locked(client_ip):
                remaining_seconds = get_lockout_time_remaining(client_ip)
                remaining_minutes = (remaining_seconds + 59) // 60
                flash(f'Too many failed attempts. Account locked for {remaining_minutes} minutes.', 'error')
                log_debug(f"Failed login triggered lockout for {username} from {client_ip}", "WARNING", "Security")
            else:
                attempts_remaining = MAX_LOGIN_ATTEMPTS - attempt_count
                flash(f'Invalid credentials. {attempts_remaining} attempts remaining.', 'error')
                log_debug(f"Failed login attempt for {username} from {client_ip} (attempt {attempt_count}/{MAX_LOGIN_ATTEMPTS})", "WARNING", "Security")
    
    return render_template('login.html')
```

**Then ADD these new routes after the login route:**

```python
@app.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    """
    MFA setup page for first-time users
    Shows QR code and verifies initial TOTP code
    """
    # Import MFA modules
    from mfa_manager import mfa_manager
    from mfa_database import save_user_mfa, log_mfa_event
    import json
    
    # Check if user is in setup flow
    if 'mfa_setup_username' not in session:
        flash('Invalid MFA setup session', 'error')
        return redirect(url_for('login'))
    
    username = session['mfa_setup_username']
    client_ip = session.get('mfa_setup_ip', get_remote_address())
    
    # Check session timeout (5 minutes)
    if 'mfa_setup_time' in session:
        setup_time = datetime.fromisoformat(session['mfa_setup_time'])
        if (datetime.now() - setup_time).total_seconds() > 300:
            session.pop('mfa_setup_username', None)
            session.pop('mfa_setup_secret', None)
            session.pop('mfa_setup_ip', None)
            session.pop('mfa_setup_time', None)
            flash('MFA setup session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        secret = session.get('mfa_setup_secret')
        
        if not secret or not token:
            flash('Invalid setup request', 'error')
            return redirect(url_for('mfa_setup'))
        
        # Verify the token
        if mfa_manager.verify_token(secret, token):
            # Generate backup codes
            backup_codes = mfa_manager.generate_backup_codes(10)
            backup_codes_hashed = [mfa_manager.hash_backup_code(c) for c in backup_codes]
            
            # Save MFA configuration
            encrypted_secret = mfa_manager.encrypt_secret(secret)
            save_result = save_user_mfa(
                username, 
                encrypted_secret, 
                json.dumps(backup_codes_hashed)
            )
            
            if save_result:
                # Store backup codes in session for display
                session['backup_codes'] = backup_codes
                
                # Clear setup session
                session.pop('mfa_setup_username', None)
                session.pop('mfa_setup_secret', None)
                session.pop('mfa_setup_ip', None)
                session.pop('mfa_setup_time', None)
                
                # Log MFA setup
                log_mfa_event(username, 'setup_complete', client_ip, request.headers.get('User-Agent', ''))
                
                log_debug(f"MFA setup completed for {username}", "INFO", "MFA")
                flash('MFA setup successful! Save your backup codes.', 'success')
                return redirect(url_for('mfa_backup_codes'))
            else:
                flash('Error saving MFA configuration. Please try again.', 'error')
                log_debug(f"MFA setup failed for {username} - database error", "ERROR", "MFA")
        else:
            flash('Invalid verification code. Please try again.', 'error')
            log_mfa_event(username, 'setup_verify_fail', client_ip, request.headers.get('User-Agent', ''), success=False)
    
    # Generate new secret for setup (or reuse existing in session)
    if 'mfa_setup_secret' not in session:
        secret = mfa_manager.generate_secret()
        session['mfa_setup_secret'] = secret
    else:
        secret = session['mfa_setup_secret']
    
    # Generate QR code
    provisioning_uri = mfa_manager.get_provisioning_uri(username, secret)
    qr_code_data = mfa_manager.generate_qr_code(provisioning_uri)
    
    return render_template('mfa_setup.html', 
                         qr_code=qr_code_data,
                         secret=secret,
                         username=username)

@app.route('/mfa/backup-codes')
def mfa_backup_codes():
    """Display backup codes after MFA setup (one-time display)"""
    backup_codes = session.get('backup_codes')
    
    if not backup_codes:
        flash('No backup codes to display', 'error')
        return redirect(url_for('index'))
    
    # Clear from session after retrieval
    session.pop('backup_codes', None)
    
    return render_template('mfa_backup_codes.html', backup_codes=backup_codes)

@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """
    MFA verification page (SECOND FACTOR)
    Verifies TOTP code or backup recovery code
    """
    # Import MFA modules
    from mfa_manager import mfa_manager
    from mfa_database import get_user_mfa_config, update_user_backup_codes, log_mfa_event
    
    # Check if user is in verification flow
    if 'mfa_verify_username' not in session:
        flash('Invalid MFA verification session', 'error')
        return redirect(url_for('login'))
    
    username = session['mfa_verify_username']
    client_ip = session.get('mfa_verify_ip', get_remote_address())
    
    # Check session timeout (5 minutes)
    if 'mfa_verify_time' in session:
        verify_time = datetime.fromisoformat(session['mfa_verify_time'])
        if (datetime.now() - verify_time).total_seconds() > 300:
            session.pop('mfa_verify_username', None)
            session.pop('mfa_verify_ip', None)
            session.pop('mfa_verify_time', None)
            flash('MFA verification session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        use_backup = request.form.get('use_backup', 'false') == 'true'
        
        if not token:
            flash('Verification code required', 'error')
            return render_template('mfa_verify.html')
        
        # Get user's MFA configuration
        mfa_config = get_user_mfa_config(username)
        
        if not mfa_config:
            flash('MFA not configured for this account', 'error')
            log_debug(f"MFA verify failed for {username} - no config", "ERROR", "MFA")
            return redirect(url_for('login'))
        
        # Check if using backup code
        if use_backup:
            is_valid, new_backup_codes = mfa_manager.verify_backup_code(
                token, mfa_config['backup_codes']
            )
            
            if is_valid:
                # Update backup codes (remove used one)
                update_user_backup_codes(username, new_backup_codes)
                
                # Log recovery code usage
                log_mfa_event(username, 'recovery_code_used', client_ip, request.headers.get('User-Agent', ''))
                
                # Complete login
                complete_mfa_login(username, client_ip)
                flash('Login successful. Consider resetting your MFA device.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid recovery code', 'error')
                log_mfa_event(username, 'recovery_code_fail', client_ip, request.headers.get('User-Agent', ''), success=False)
        else:
            # Verify TOTP token
            encrypted_secret = mfa_config['mfa_secret']
            secret = mfa_manager.decrypt_secret(encrypted_secret)
            
            if mfa_manager.verify_token(secret, token):
                # Log successful verification
                log_mfa_event(username, 'verify_success', client_ip, request.headers.get('User-Agent', ''))
                
                # Complete login
                complete_mfa_login(username, client_ip)
                return redirect(url_for('index'))
            else:
                flash('Invalid verification code', 'error')
                log_mfa_event(username, 'verify_fail', client_ip, request.headers.get('User-Agent', ''), success=False)
    
    return render_template('mfa_verify.html')

def complete_mfa_login(username, client_ip):
    """
    Complete login after MFA verification
    Creates session and logs user in
    """
    # Clear MFA verification session
    session.pop('mfa_verify_username', None)
    session.pop('mfa_verify_ip', None)
    session.pop('mfa_verify_time', None)
    
    # Create authenticated session
    session.permanent = True
    session['logged_in'] = True
    session['username'] = username
    session['user'] = username
    session['login_time'] = datetime.now().isoformat()
    
    # Track metrics
    metrics_collector.increment_counter('total_logins')
    
    log_debug(f"✓ User {username} completed MFA login from {client_ip}", "INFO", "Authentication")
```

**Verify the changes:**
```bash
python3 -c "from web_app_real import app; print('✅ web_app_real.py syntax OK')"
```

### STEP 6: Update config.py (Optional)

Add MFA configuration options to `/workspace/config.py`.

**Add this section after line 115:**

```python
    # ============================================================================
    # MFA Configuration
    # ============================================================================
    MFA_REQUIRED = os.getenv('STITCH_MFA_REQUIRED', 'true').lower() in ('true', '1', 'yes')
    MFA_GRACE_PERIOD_DAYS = int(os.getenv('STITCH_MFA_GRACE_PERIOD_DAYS', '7'))
    MFA_BACKUP_CODES_COUNT = int(os.getenv('STITCH_MFA_BACKUP_CODES_COUNT', '10'))
    MFA_ISSUER_NAME = os.getenv('STITCH_MFA_ISSUER_NAME', APP_NAME)
    MFA_SESSION_TIMEOUT_MINUTES = int(os.getenv('STITCH_MFA_SESSION_TIMEOUT_MINUTES', '5'))
```

### STEP 7: Test the Implementation

**Start the Flask application:**

```bash
cd /workspace
python3 web_app_real.py
```

**In another terminal, test MFA:**

1. **Open browser:** `http://localhost:5000/login`

2. **Log in with username and password**

3. **Should redirect to `/mfa/setup`**
   - Verify QR code displays
   - Verify manual secret code shows

4. **Open Microsoft Authenticator app on your phone:**
   - Tap "+" to add account
   - Scan the QR code
   - Or manually enter the secret code

5. **Enter the 6-digit code from the app**
   - Should verify and show backup codes page

6. **Save backup codes**
   - Download or print them
   - Click "Continue to Dashboard"

7. **Should be logged in!**

8. **Log out and log in again:**
   - Enter username + password
   - Should redirect to `/mfa/verify`
   - Enter 6-digit code from app
   - Should log in successfully

### STEP 8: Test Backup Code Recovery

1. **Log in with username + password**
2. **On MFA verification page, click "Lost your device?"**
3. **Enter one of your backup codes**
4. **Should log in successfully**
5. **Try using the same backup code again**
6. **Should fail (codes are one-time use)**

---

## 5. Testing Your Implementation

### Unit Tests

**Create file:** `/workspace/test_mfa.py`

```python
#!/usr/bin/env python3
"""
Unit tests for MFA functionality
"""

import unittest
from mfa_manager import mfa_manager
import time

class TestMFAManager(unittest.TestCase):
    """Test MFA Manager functions"""
    
    def test_generate_secret(self):
        """Test secret generation"""
        secret = mfa_manager.generate_secret()
        self.assertIsInstance(secret, str)
        self.assertTrue(len(secret) >= 16)
        print(f"✅ Generated secret: {secret}")
    
    def test_encrypt_decrypt_secret(self):
        """Test encryption and decryption"""
        secret = "JBSWY3DPEHPK3PXP"
        encrypted = mfa_manager.encrypt_secret(secret)
        decrypted = mfa_manager.decrypt_secret(encrypted)
        self.assertEqual(secret, decrypted)
        print(f"✅ Encryption/decryption works")
    
    def test_verify_token(self):
        """Test TOTP token verification"""
        import pyotp
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        current_token = totp.now()
        
        # Should verify correct token
        self.assertTrue(mfa_manager.verify_token(secret, current_token))
        print(f"✅ Token verification works: {current_token}")
        
        # Should reject incorrect token
        self.assertFalse(mfa_manager.verify_token(secret, "000000"))
        print(f"✅ Invalid token correctly rejected")
    
    def test_backup_codes(self):
        """Test backup code generation and verification"""
        codes = mfa_manager.generate_backup_codes(10)
        self.assertEqual(len(codes), 10)
        
        # Hash codes
        hashed = [mfa_manager.hash_backup_code(c) for c in codes]
        
        # Verify first code
        import json
        is_valid, remaining = mfa_manager.verify_backup_code(codes[0], json.dumps(hashed))
        self.assertTrue(is_valid)
        
        remaining_list = json.loads(remaining)
        self.assertEqual(len(remaining_list), 9)  # One removed
        
        print(f"✅ Backup codes work")
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        secret = "JBSWY3DPEHPK3PXP"
        uri = mfa_manager.get_provisioning_uri("testuser", secret)
        self.assertIn("otpauth://totp", uri)
        
        qr_data = mfa_manager.generate_qr_code(uri)
        self.assertTrue(qr_data.startswith("data:image/png;base64,"))
        
        print(f"✅ QR code generation works")

if __name__ == "__main__":
    print("Running MFA Unit Tests")
    print("=" * 50)
    unittest.main(verbosity=2)
```

**Run tests:**
```bash
python3 test_mfa.py
```

**Expected output:**
```
Running MFA Unit Tests
==================================================
test_backup_codes (__main__.TestMFAManager) ... ✅ Backup codes work
ok
test_encrypt_decrypt_secret (__main__.TestMFAManager) ... ✅ Encryption/decryption works
ok
test_generate_secret (__main__.TestMFAManager) ... ✅ Generated secret: JBSWY3DPEHPK3PXP
ok
test_qr_code_generation (__main__.TestMFAManager) ... ✅ QR code generation works
ok
test_verify_token (__main__.TestMFAManager) ... ✅ Token verification works: 123456
✅ Invalid token correctly rejected
ok

----------------------------------------------------------------------
Ran 5 tests in 0.123s

OK
```

---

## 6. Troubleshooting

### Common Issues

#### Issue 1: "Module not found: pyotp"
**Solution:**
```bash
pip3 install pyotp qrcode pillow cryptography
```

#### Issue 2: "Invalid token" even with correct code
**Problem:** Server time is wrong
**Solution:**
```bash
# Check server time
date

# Install NTP
sudo apt-get install ntp
sudo systemctl start ntp
```

#### Issue 3: Database error on save
**Problem:** Table doesn't exist
**Solution:**
```bash
python3 create_mfa_tables.py
```

#### Issue 4: QR code doesn't display
**Problem:** Pillow not installed
**Solution:**
```bash
pip3 install pillow
```

#### Issue 5: Session expires too quickly
**Problem:** MFA session timeout too short
**Solution:** In `config.py`, increase `MFA_SESSION_TIMEOUT_MINUTES`

---

## 7. Final Checklist

Before declaring success, verify ALL of these:

### Functionality:
- [ ] MFA setup page displays QR code
- [ ] QR code scans correctly on phone
- [ ] Manual secret entry works
- [ ] TOTP code verification works
- [ ] Invalid code shows error
- [ ] Backup codes generate (10 codes)
- [ ] Backup codes download works
- [ ] Backup code verification works
- [ ] Used backup code cannot be reused
- [ ] Login flow requires MFA after setup
- [ ] Logout and re-login requires MFA

### Security:
- [ ] TOTP secrets encrypted in database
- [ ] Backup codes hashed in database
- [ ] MFA session times out after 5 minutes
- [ ] Cannot skip MFA by going directly to /dashboard
- [ ] Failed MFA attempts logged
- [ ] Encryption key file has 0600 permissions (Linux)

### Database:
- [ ] `user_mfa` table exists
- [ ] `mfa_audit_log` table exists
- [ ] Indexes created
- [ ] MFA data saves correctly
- [ ] Backup codes update after use

### User Experience:
- [ ] Clear instructions on setup page
- [ ] Error messages helpful
- [ ] Backup codes display warning
- [ ] Mobile-responsive design
- [ ] Works on iOS and Android

### Code Quality:
- [ ] No syntax errors
- [ ] All imports work
- [ ] Unit tests pass
- [ ] No security warnings

---

## 🎉 Congratulations!

If all checklist items pass, you have successfully implemented MFA!

**What you've accomplished:**
- ✅ Added TOTP-based two-factor authentication
- ✅ Compatible with Microsoft Authenticator, Google Authenticator, etc.
- ✅ Secure secret encryption and storage
- ✅ Backup code recovery system
- ✅ Complete audit logging
- ✅ User-friendly setup and verification pages
- ✅ Significantly improved login security

**Next steps:**
1. Test thoroughly with real users
2. Monitor MFA audit logs
3. Set up alerts for suspicious activity
4. Document MFA process for users
5. Train admins on MFA reset procedures

---

*End of Implementation Guide*
