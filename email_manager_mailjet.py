#!/usr/bin/env python3
"""
Email Manager with Mailjet API Integration
Ultra-premium email delivery for passwordless authentication
"""

import secrets
import hashlib
import logging
import requests
import base64
from datetime import datetime, timedelta
from config import Config

logger = logging.getLogger(__name__)

class MailjetEmailManager:
    """Manage email sending via Mailjet API"""
    
    def __init__(self):
        # Mailjet credentials
        self.api_key = Config.MAILJET_API_KEY
        self.api_secret = Config.MAILJET_API_SECRET
        
        # Email settings
        self.from_email = Config.FROM_EMAIL
        self.from_name = Config.FROM_NAME
        
        # Mailjet API endpoint
        self.api_url = 'https://api.mailjet.com/v3.1/send'
        
        # Create auth header
        credentials = f"{self.api_key}:{self.api_secret}"
        self.auth_header = base64.b64encode(credentials.encode()).decode()
    
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
        Send verification code email via Mailjet API
        
        Args:
            to_email (str): Recipient email address
            code (str): 6-digit verification code
            ip_address (str): IP address of request
        
        Returns:
            bool: True if sent successfully, False otherwise
        """
        # Check if we have valid credentials
        if not self.api_secret or self.api_secret == 'your_mailjet_secret_here':
            logger.warning(f"📧 MOCK MODE: Verification email would be sent to {to_email}")
            logger.warning(f"📧 MOCK MODE: Code: {code}")
            logger.warning("📧 MOCK MODE: To enable real email sending, configure MAILJET_API_SECRET in .env")
            return True  # Return True in mock mode
            
        try:
            # Premium HTML email template
            html_content = self._create_premium_email_template(code, ip_address)
            text_content = self._create_text_email(code, ip_address)
            
            # Mailjet API payload
            payload = {
                "Messages": [
                    {
                        "From": {
                            "Email": self.from_email,
                            "Name": self.from_name
                        },
                        "To": [
                            {
                                "Email": to_email,
                                "Name": to_email.split('@')[0].title()
                            }
                        ],
                        "Subject": "🔐 Your Exclusive Access Code",
                        "TextPart": text_content,
                        "HTMLPart": html_content,
                        "CustomID": f"verification_{datetime.now().timestamp()}"
                    }
                ]
            }
            
            # Send via Mailjet API
            response = requests.post(
                self.api_url,
                headers={
                    'Authorization': f'Basic {self.auth_header}',
                    'Content-Type': 'application/json'
                },
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Verification email sent to {to_email} via Mailjet")
                return True
            else:
                logger.error(f"❌ Mailjet API error: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"❌ Failed to send email via Mailjet: {e}")
            return False
    
    def _create_premium_email_template(self, code, ip_address):
        """Create ultra-premium HTML email template"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 24px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }}
        
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f0f1e 100%);
            padding: 50px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(212, 175, 55, 0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 0.5; transform: scale(1); }}
            50% {{ opacity: 0.8; transform: scale(1.1); }}
        }}
        
        .logo {{
            position: relative;
            z-index: 1;
            font-size: 14px;
            letter-spacing: 4px;
            color: #d4af37;
            font-weight: 300;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        
        .header h1 {{
            position: relative;
            z-index: 1;
            color: #ffffff;
            font-size: 28px;
            font-weight: 300;
            letter-spacing: 1px;
            margin: 0;
        }}
        
        .content {{
            padding: 60px 40px;
            background: #ffffff;
        }}
        
        .greeting {{
            font-size: 16px;
            color: #333333;
            margin-bottom: 30px;
            font-weight: 400;
        }}
        
        .code-container {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border: 2px solid #d4af37;
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            margin: 40px 0;
            position: relative;
        }}
        
        .code-container::before {{
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(135deg, #d4af37, #f4e5a1, #d4af37);
            border-radius: 16px;
            z-index: -1;
            opacity: 0.3;
        }}
        
        .code-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #666666;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        
        .code {{
            font-size: 48px;
            font-weight: 700;
            color: #1a1a2e;
            letter-spacing: 12px;
            font-family: 'Courier New', monospace;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .expiry {{
            margin-top: 15px;
            font-size: 13px;
            color: #d4af37;
            font-weight: 600;
        }}
        
        .info-box {{
            background: #f8f9fa;
            border-left: 4px solid #d4af37;
            padding: 20px;
            margin: 30px 0;
            border-radius: 8px;
        }}
        
        .info-box p {{
            font-size: 14px;
            color: #555555;
            line-height: 1.6;
            margin: 8px 0;
        }}
        
        .security-info {{
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #e0e0e0;
        }}
        
        .security-info h3 {{
            font-size: 14px;
            color: #333333;
            margin-bottom: 15px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .security-details {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            font-size: 12px;
            color: #666666;
        }}
        
        .security-details p {{
            margin: 5px 0;
            font-family: 'Courier New', monospace;
        }}
        
        .footer {{
            background: #1a1a2e;
            padding: 40px;
            text-align: center;
        }}
        
        .footer p {{
            color: #999999;
            font-size: 12px;
            line-height: 1.6;
            margin: 5px 0;
        }}
        
        .footer .brand {{
            color: #d4af37;
            font-weight: 600;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: 20px;
        }}
        
        @media (max-width: 600px) {{
            .content {{
                padding: 40px 20px;
            }}
            
            .code {{
                font-size: 36px;
                letter-spacing: 8px;
            }}
            
            .header {{
                padding: 40px 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">Oranolio</div>
            <h1>Exclusive Access</h1>
        </div>
        
        <div class="content">
            <p class="greeting">Your verification code has arrived.</p>
            
            <div class="code-container">
                <div class="code-label">Verification Code</div>
                <div class="code">{code}</div>
                <div class="expiry">⏱ Expires in 10 minutes</div>
            </div>
            
            <div class="info-box">
                <p><strong>⚠️ Security Notice:</strong></p>
                <p>This code grants access to a privileged system. Never share this code with anyone.</p>
                <p>If you didn't request this code, please ignore this email and contact security immediately.</p>
            </div>
            
            <div class="security-info">
                <h3>Session Information</h3>
                <div class="security-details">
                    <p>IP Address: {ip_address or 'Unknown'}</p>
                    <p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>Request ID: {datetime.now().timestamp()}</p>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>This is an automated message from a secure system.</p>
            <p>Do not reply to this email.</p>
            <p class="brand">Oranolio Security</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _create_text_email(self, code, ip_address):
        """Create plain text version of email"""
        return f"""
ORANOLIO - EXCLUSIVE ACCESS
══════════════════════════════════════

Your Verification Code:

    {code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

SECURITY INFORMATION:
- IP Address: {ip_address or 'Unknown'}
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Never share this code with anyone.

--
Oranolio Security Team
        """
    
    def test_connection(self):
        """Test Mailjet API connection"""
        # Check if we have valid credentials
        if not self.api_secret or self.api_secret == 'your_mailjet_secret_here':
            logger.warning("Mailjet API secret not configured - using mock mode")
            return False
            
        try:
            # Simple API test - get account info
            response = requests.get(
                'https://api.mailjet.com/v3/REST/contact',
                headers={
                    'Authorization': f'Basic {self.auth_header}'
                },
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info("✅ Mailjet API connection successful")
                return True
            else:
                logger.error(f"❌ Mailjet API test failed: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"❌ Mailjet connection test error: {e}")
            return False

# Global instance
email_manager = MailjetEmailManager()
