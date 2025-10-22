# Complete Passwordless Email + MFA Implementation Guide

## 🎯 Purpose

This guide will walk you through implementing a **passwordless authentication system** where users log in using:
1. **Email verification code** (sent to their email)
2. **TOTP code** (from Microsoft Authenticator or similar app)

**NO PASSWORDS.** Just email + authenticator app.

**Primary Email:** brooketogo98@gmail.com

---

## 📋 Table of Contents

1. [Understanding What You're Building](#1-understanding-what-youre-building)
2. [Prerequisites](#2-prerequisites)
3. [Phase 1: Email Infrastructure](#phase-1-email-infrastructure)
4. [Phase 2: Email Authentication](#phase-2-email-authentication)
5. [Phase 3: MFA Integration](#phase-3-mfa-integration)
6. [Phase 4: Migration & Cutover](#phase-4-migration--cutover)
7. [Phase 5: Remove Password Auth](#phase-5-remove-password-auth)
8. [Phase 6: Testing & Hardening](#phase-6-testing--hardening)

---

## 1. Understanding What You're Building

### Current System (INSECURE):
```
User enters: username + password
↓
Server checks password
↓
User logged in ❌ (ONE factor = weak)
```

### What You're Building (SECURE):
```
User enters: email address
↓
Server sends 6-digit code to email
↓
User enters code from email ✅ (First factor: email access)
↓
User enters 6-digit TOTP from authenticator app ✅ (Second factor: phone)
↓
User logged in ✅✅ (TWO factors = strong)
```

### User Experience

**First-Time User:**
```
1. Go to login page
2. Enter: brooketogo98@gmail.com
3. Check email → See code: 742891
4. Enter code: 742891
5. Scan QR code with Microsoft Authenticator
6. App shows: 123456
7. Enter TOTP: 123456
8. Save 10 backup codes
9. ✅ Logged in!
```

**Returning User:**
```
1. Go to login page
2. Enter: brooketogo98@gmail.com
3. Check email → Enter code
4. Open Microsoft Authenticator → Enter TOTP
5. ✅ Logged in!
```

---

## 2. Prerequisites

### Step 2.1: Set Up Gmail App Password

**CRITICAL:** Don't use your real Gmail password for SMTP!

1. **Go to Google Account Settings:**
   - Visit: https://myaccount.google.com/security
   - Sign in as: brooketogo98@gmail.com

2. **Enable 2-Step Verification:**
   - Find "2-Step Verification"
   - Click "Get Started"
   - Follow steps to enable

3. **Create App Password:**
   - After 2FA enabled, go back to Security
   - Find "App passwords"
   - Select "Mail" and "Other (Custom name)"
   - Name it: "Oranolio RAT SMTP"
   - Click "Generate"
   - **COPY THE 16-CHARACTER PASSWORD**
   - Example: `abcd efgh ijkl mnop`

4. **Save Securely:**
   ```bash
   # Add to environment variables
   export STITCH_SMTP_USER="brooketogo98@gmail.com"
   export STITCH_SMTP_PASSWORD="abcdefghijklmnop"  # No spaces!
   ```

### Step 2.2: Install Dependencies

```bash
cd /workspace

# Install email and MFA packages
pip3 install --upgrade pip
pip3 install pyotp==2.9.0 qrcode==7.4.2 pillow==10.1.0 cryptography==41.0.7

# Verify installation
python3 -c "import pyotp, qrcode, smtplib; print('✅ All dependencies installed')"
```

### Step 2.3: Backup Current System

```bash
cd /workspace

# Create comprehensive backup
tar -czf passwordless_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    web_app_real.py \
    config.py \
    templates/ \
    Application/

# Verify backup created
ls -lh passwordless_backup_*.tar.gz
```

---

## PHASE 1: Email Infrastructure

### STEP 1.1: Create Email Manager Module

**Create file:** `/workspace/email_manager.py`

```python
#!/usr/bin/env python3
"""
Email Manager for Passwordless Authentication
Handles email sending, code generation, and verification
"""

import smtplib
import secrets
import hashlib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from config import Config

logger = logging.getLogger(__name__)

class EmailManager:
    """Manage email sending for authentication"""
    
    def __init__(self):
        self.smtp_host = Config.SMTP_HOST
        self.smtp_port = Config.SMTP_PORT
        self.smtp_user = Config.SMTP_USER
        self.smtp_password = Config.SMTP_PASSWORD
        self.smtp_use_tls = Config.SMTP_USE_TLS
        self.from_email = getattr(Config, 'FROM_EMAIL', Config.SMTP_USER)
        self.from_name = getattr(Config, 'FROM_NAME', 'Oranolio RAT Security')
    
    def generate_code(self, length=6):
        """
        Generate cryptographically secure numeric code
        
        Args:
            length (int): Length of code (default: 6)
        
        Returns:
            str: Random numeric code (e.g., "742891")
        """
        code = ''.join([str(secrets.randbelow(10)) for _ in range(length)])
        return code
    
    def hash_code(self, code):
        """
        Hash verification code for storage
        
        Args:
            code (str): Plaintext code
        
        Returns:
            str: SHA-256 hash of code
        """
        return hashlib.sha256(code.encode()).hexdigest()
    
    def send_verification_email(self, to_email, code, ip_address=""):
        """
        Send verification code email
        
        Args:
            to_email (str): Recipient email address
            code (str): 6-digit verification code
            ip_address (str): IP address of request (for security info)
        
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = '🔐 Your Login Code - Oranolio RAT'
            msg['From'] = f'{self.from_name} <{self.from_email}>'
            msg['To'] = to_email
            msg['X-Priority'] = '1'
            msg['X-MSMail-Priority'] = 'High'
            
            # Plain text version
            text = f"""
Hi there,

Your login verification code is:

    {code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Security Info:
- IP Address: {ip_address or 'Unknown'}
- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Never share this code with anyone.

--
Oranolio RAT Security Team
            """
            
            # HTML version
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            color: #ffffff;
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .code-box {{
            background-color: #f8f9fa;
            border: 2px dashed #667eea;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .code {{
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
            letter-spacing: 8px;
            font-family: 'Courier New', monospace;
        }}
        .info {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Your Login Verification Code</h1>
        </div>
        <div class="content">
            <p>Hi there,</p>
            <p>Your login verification code is:</p>
            
            <div class="code-box">
                <div class="code">{code}</div>
            </div>
            
            <p><strong>This code will expire in 10 minutes.</strong></p>
            
            <p>If you didn't request this code, please ignore this email.</p>
            
            <div class="info">
                <strong>Security Information:</strong><br>
                IP Address: {ip_address or 'Unknown'}<br>
                Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
            
            <p style="color: #dc3545;"><strong>⚠️ Never share this code with anyone.</strong></p>
        </div>
        <div class="footer">
            Oranolio RAT Security Team<br>
            This is an automated message. Please do not reply.
        </div>
    </div>
</body>
</html>
            """
            
            # Attach both versions
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"Verification email sent to {to_email}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send verification email to {to_email}: {e}")
            return False
    
    def test_email_connection(self):
        """Test SMTP connection"""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
            return True
        except Exception as e:
            logger.error(f"SMTP connection failed: {e}")
            return False

# Global instance
email_manager = EmailManager()
```

**Save and test:**
```bash
python3 -c "from email_manager import email_manager; print('✅ email_manager.py works')"
```

### STEP 1.2: Create Email Database Tables

**Create file:** `/workspace/create_email_tables.py`

```python
#!/usr/bin/env python3
"""
Create database tables for email authentication
"""

import sqlite3
from pathlib import Path
from config import Config

DB_PATH = Config.APPLICATION_DIR / 'stitch.db'

# SQL for users_email table
CREATE_USERS_EMAIL = """
CREATE TABLE IF NOT EXISTS users_email (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    is_verified INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0
);
"""

# SQL for email_verification_codes table
CREATE_EMAIL_CODES = """
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    ip_address TEXT,
    expires_at TIMESTAMP NOT NULL,
    used INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# SQL for email_auth_audit table
CREATE_EMAIL_AUDIT = """
CREATE TABLE IF NOT EXISTS email_auth_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER DEFAULT 1,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);
"""

# Indexes
CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_email_email ON users_email(email);",
    "CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_verification_codes(email);",
    "CREATE INDEX IF NOT EXISTS idx_email_codes_expires ON email_verification_codes(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_email_audit_email ON email_auth_audit(email);",
    "CREATE INDEX IF NOT EXISTS idx_email_audit_timestamp ON email_auth_audit(timestamp);",
]

def create_email_tables():
    """Create all email authentication tables"""
    
    # Ensure directory exists
    Config.APPLICATION_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"📁 Database: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Create users_email table
        print("Creating users_email table...")
        cursor.execute(CREATE_USERS_EMAIL)
        print("✅ users_email created")
        
        # Create email_verification_codes table
        print("Creating email_verification_codes table...")
        cursor.execute(CREATE_EMAIL_CODES)
        print("✅ email_verification_codes created")
        
        # Create email_auth_audit table
        print("Creating email_auth_audit table...")
        cursor.execute(CREATE_EMAIL_AUDIT)
        print("✅ email_auth_audit created")
        
        # Create indexes
        print("Creating indexes...")
        for index_sql in CREATE_INDEXES:
            cursor.execute(index_sql)
        print("✅ Indexes created")
        
        # Insert primary email
        cursor.execute("""
            INSERT OR IGNORE INTO users_email (email, is_verified, is_active)
            VALUES (?, 1, 1)
        """, ('brooketogo98@gmail.com',))
        print("✅ Primary email added: brooketogo98@gmail.com")
        
        conn.commit()
        print("\n✅ Email authentication tables created successfully!")
        
        # Verify
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%email%';")
        tables = cursor.fetchall()
        print("\n📋 Email tables:")
        for table in tables:
            print(f"   - {table[0]}")
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        conn.rollback()
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    create_email_tables()
```

**Run this:**
```bash
python3 create_email_tables.py
```

**Expected output:**
```
📁 Database: /workspace/Application/stitch.db
Creating users_email table...
✅ users_email created
Creating email_verification_codes table...
✅ email_verification_codes created
Creating email_auth_audit table...
✅ email_auth_audit created
Creating indexes...
✅ Indexes created
✅ Primary email added: brooketogo98@gmail.com

✅ Email authentication tables created successfully!

📋 Email tables:
   - users_email
   - email_verification_codes
   - email_auth_audit
```

### STEP 1.3: Test Email Sending

**Create file:** `/workspace/test_email_sending.py`

```python
#!/usr/bin/env python3
"""Test email sending"""

from email_manager import email_manager
import os

def test_smtp_connection():
    """Test SMTP connection"""
    print("Testing SMTP connection...")
    if email_manager.test_email_connection():
        print("✅ SMTP connection successful")
        return True
    else:
        print("❌ SMTP connection failed")
        print("\nCheck your environment variables:")
        print(f"  STITCH_SMTP_USER: {os.getenv('STITCH_SMTP_USER', 'NOT SET')}")
        print(f"  STITCH_SMTP_PASSWORD: {'SET' if os.getenv('STITCH_SMTP_PASSWORD') else 'NOT SET'}")
        return False

def test_send_email():
    """Send test email"""
    print("\nSending test email to brooketogo98@gmail.com...")
    code = email_manager.generate_code()
    print(f"Generated code: {code}")
    
    success = email_manager.send_verification_email(
        to_email='brooketogo98@gmail.com',
        code=code,
        ip_address='127.0.0.1'
    )
    
    if success:
        print("✅ Test email sent successfully!")
        print(f"\nCheck brooketogo98@gmail.com for code: {code}")
        return True
    else:
        print("❌ Failed to send test email")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("EMAIL SENDING TEST")
    print("=" * 50)
    
    # Test connection
    if not test_smtp_connection():
        exit(1)
    
    # Test sending
    if not test_send_email():
        exit(1)
    
    print("\n✅ All email tests passed!")
```

**Run this:**
```bash
# First, set environment variables
export STITCH_SMTP_USER="brooketogo98@gmail.com"
export STITCH_SMTP_PASSWORD="your-app-password-here"  # From Step 2.1

# Run test
python3 test_email_sending.py
```

**Check your email at brooketogo98@gmail.com!**

---

## PHASE 2: Email Authentication

### STEP 2.1: Create Email Auth Module

**Create file:** `/workspace/email_auth.py`

```python
#!/usr/bin/env python3
"""
Email Authentication Module
Database operations for email-based authentication
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from config import Config
from email_manager import email_manager

DB_PATH = Config.APPLICATION_DIR / 'stitch.db'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_verification_code(email, ip_address=""):
    """
    Generate and store verification code for email
    
    Args:
        email (str): Email address
        ip_address (str): IP address of requester
    
    Returns:
        tuple: (code, expires_at) or (None, None) if failed
    """
    # Generate code
    code = email_manager.generate_code(6)
    code_hash = email_manager.hash_code(code)
    
    # Set expiration (10 minutes)
    expires_at = datetime.now() + timedelta(minutes=10)
    
    # Store in database
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO email_verification_codes 
            (email, code_hash, ip_address, expires_at)
            VALUES (?, ?, ?, ?)
        """, (email, code_hash, ip_address, expires_at))
        
        conn.commit()
        return code, expires_at
    
    except Exception as e:
        print(f"Error creating verification code: {e}")
        conn.rollback()
        return None, None
    
    finally:
        conn.close()

def verify_code(email, code):
    """
    Verify email verification code
    
    Args:
        email (str): Email address
        code (str): Code to verify
    
    Returns:
        bool: True if valid, False otherwise
    """
    code_hash = email_manager.hash_code(code)
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Find valid code
        cursor.execute("""
            SELECT id, expires_at, used, attempts 
            FROM email_verification_codes
            WHERE email = ? AND code_hash = ? AND used = 0
            ORDER BY created_at DESC
            LIMIT 1
        """, (email, code_hash))
        
        row = cursor.fetchone()
        
        if not row:
            return False
        
        # Check expiration
        expires_at = datetime.fromisoformat(row['expires_at'])
        if datetime.now() > expires_at:
            return False
        
        # Check attempts
        if row['attempts'] >= 5:
            return False
        
        # Mark as used
        cursor.execute("""
            UPDATE email_verification_codes 
            SET used = 1
            WHERE id = ?
        """, (row['id'],))
        
        # Update last login
        cursor.execute("""
            UPDATE users_email 
            SET last_login = CURRENT_TIMESTAMP,
                login_count = login_count + 1
            WHERE email = ?
        """, (email,))
        
        conn.commit()
        return True
    
    except Exception as e:
        print(f"Error verifying code: {e}")
        conn.rollback()
        return False
    
    finally:
        conn.close()

def record_failed_attempt(email, code):
    """Record failed verification attempt"""
    code_hash = email_manager.hash_code(code)
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE email_verification_codes
            SET attempts = attempts + 1
            WHERE email = ? AND code_hash = ?
        """, (email, code_hash))
        
        conn.commit()
    
    except Exception as e:
        print(f"Error recording failed attempt: {e}")
        conn.rollback()
    
    finally:
        conn.close()

def log_email_auth_event(email, action, ip_address="", user_agent="", success=True, details=None):
    """Log email authentication event"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO email_auth_audit
            (email, action, ip_address, user_agent, success, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (email, action, ip_address, user_agent, 1 if success else 0, 
              json.dumps(details) if details else None))
        
        conn.commit()
    
    except Exception as e:
        print(f"Error logging event: {e}")
        conn.rollback()
    
    finally:
        conn.close()

def check_rate_limit(email, hours=1, max_codes=3):
    """
    Check if email has exceeded rate limit
    
    Args:
        email (str): Email address
        hours (int): Time window in hours
        max_codes (int): Max codes allowed in time window
    
    Returns:
        bool: True if within limit, False if exceeded
    """
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        since = datetime.now() - timedelta(hours=hours)
        
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE email = ? AND created_at > ?
        """, (email, since))
        
        row = cursor.fetchone()
        count = row['count'] if row else 0
        
        return count < max_codes
    
    finally:
        conn.close()

def email_exists(email):
    """Check if email exists in database"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM users_email WHERE email = ?", (email,))
        return cursor.fetchone() is not None
    
    finally:
        conn.close()

def create_email_user(email):
    """Create new email user"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO users_email (email, is_verified, is_active)
            VALUES (?, 1, 1)
        """, (email,))
        
        conn.commit()
        return True
    
    except Exception as e:
        print(f"Error creating email user: {e}")
        conn.rollback()
        return False
    
    finally:
        conn.close()
```

**Test it:**
```bash
python3 -c "from email_auth import create_verification_code; code, exp = create_verification_code('test@example.com'); print(f'✅ Code: {code}')"
```

### STEP 2.2: Create Email Login Templates

**Create file:** `/workspace/templates/email_login.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Oranolio RAT</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 450px;
            width: 100%;
            padding: 50px 40px;
        }

        .logo {
            text-align: center;
            margin-bottom: 40px;
        }

        .logo h1 {
            font-size: 32px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }

        .logo p {
            color: #666;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }

        input[type="email"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
        }

        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .alert-error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }

        .alert-success {
            background: #efe;
            border: 1px solid #cfc;
            color: #3c3;
        }

        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-top: 30px;
            border-radius: 5px;
        }

        .info-box p {
            font-size: 13px;
            color: #666;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 Oranolio RAT</h1>
            <p>Secure Passwordless Login</p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" 
                       id="email" 
                       name="email" 
                       required 
                       autofocus
                       placeholder="your.email@example.com">
            </div>

            <button type="submit" class="btn">Send Verification Code</button>
        </form>

        <div class="info-box">
            <p><strong>🔒 How it works:</strong></p>
            <p>1. Enter your email address</p>
            <p>2. Check your email for verification code</p>
            <p>3. Enter code + authenticator app code</p>
            <p>4. You're in! No password needed.</p>
        </div>
    </div>
</body>
</html>
```

**Create file:** `/workspace/templates/email_verify.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enter Code - Oranolio RAT</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .verify-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 450px;
            width: 100%;
            padding: 50px 40px;
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo h1 {
            font-size: 28px;
            color: #333;
            margin-bottom: 10px;
        }

        .logo p {
            color: #667eea;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }

        input[type="text"] {
            width: 100%;
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 32px;
            font-family: 'Courier New', monospace;
            text-align: center;
            letter-spacing: 10px;
            transition: all 0.3s ease;
        }

        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .alert-error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }

        .info-box {
            background: #f0f8ff;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-top: 20px;
            border-radius: 5px;
        }

        .info-box p {
            font-size: 13px;
            color: #666;
            margin: 5px 0;
        }

        .resend-link {
            text-align: center;
            margin-top: 20px;
        }

        .resend-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }

        .resend-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="verify-container">
        <div class="logo">
            <h1>📧 Check Your Email</h1>
            <p>Code sent to: <strong>{{ email }}</strong></p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <div class="form-group">
                <label for="code">Enter 6-Digit Code</label>
                <input type="text" 
                       id="code" 
                       name="code" 
                       maxlength="6"
                       pattern="[0-9]{6}"
                       required 
                       autofocus
                       autocomplete="off"
                       placeholder="000000">
            </div>

            <button type="submit" class="btn">Verify Code</button>
        </form>

        <div class="info-box">
            <p><strong>⏱️ Code expires in 10 minutes</strong></p>
            <p>Didn't receive it? Check your spam folder.</p>
        </div>

        <div class="resend-link">
            <a href="/login">← Request new code</a>
        </div>
    </div>

    <script>
        // Auto-format code input
        document.getElementById('code').addEventListener('input', function(e) {
            e.target.value = e.target.value.replace(/\D/g, '');
        });
    </script>
</body>
</html>
```

---

*This guide continues with Phase 3-6 in the full implementation...*

**Due to length limits, I'll create the remaining phases in a separate comprehensive document. The key is proper ordering to avoid breaking things.**

---

## Quick Reference: What You've Created So Far

✅ Phase 1 Complete:
- `email_manager.py` - Email sending
- `create_email_tables.py` - Database schema  
- `test_email_sending.py` - Testing tool
- Email tables in database

✅ Phase 2 In Progress:
- `email_auth.py` - Auth logic
- `templates/email_login.html` - Login page
- `templates/email_verify.html` - Verify page

**Next:** Continue with MFA integration, then migrate from passwords.

---

*This is a partial guide - full version will include all 6 phases with complete code.*
