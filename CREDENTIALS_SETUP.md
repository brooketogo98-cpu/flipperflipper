# Stitch RAT - Credential Configuration Guide

## 🔐 Security First

The Stitch RAT web interface **requires** you to configure your own admin credentials before it will start. This ensures you're not using default/hard-coded credentials that attackers could exploit.

---

## Quick Setup (Recommended Method)

### 1. Copy the Example File

```bash
cp .env.example .env
```

### 2. Edit the .env File

Open `.env` in your text editor and set your credentials:

```bash
# Change these to your own secure values!
STITCH_ADMIN_USER=yourusername
STITCH_ADMIN_PASSWORD=YourVeryStrongPassword123!
```

**Requirements:**
- Username: any alphanumeric username
- Password: minimum 12 characters (enforced by application)

### 3. Start the Application

```bash
python3 web_app_real.py
```

---

## Alternative: Environment Variables

If you prefer not to use a `.env` file, you can set environment variables directly:

### Linux/macOS:

```bash
export STITCH_ADMIN_USER="yourusername"
export STITCH_ADMIN_PASSWORD="YourVeryStrongPassword123!"
python3 web_app_real.py
```

### Windows (Command Prompt):

```cmd
set STITCH_ADMIN_USER=yourusername
set STITCH_ADMIN_PASSWORD=YourVeryStrongPassword123!
python web_app_real.py
```

### Windows (PowerShell):

```powershell
$env:STITCH_ADMIN_USER="yourusername"
$env:STITCH_ADMIN_PASSWORD="YourVeryStrongPassword123!"
python web_app_real.py
```

---

## Password Requirements

✅ **Minimum 12 characters** (enforced)  
✅ **Recommended:** Mix of uppercase, lowercase, numbers, and symbols  
✅ **Don't use:** Dictionary words, common passwords, or personal info  

### Good Password Examples:

- `MyS3cur3P@ssw0rd!2024`
- `Tr0pic@lF!sh#Sw1mming`
- `C0ff33&D0nuts@Midnight`

### Bad Password Examples:

❌ `password123` (too common)  
❌ `stitch2024` (default - never use!)  
❌ `short` (less than 12 characters)  

---

## What Happens if Credentials Aren't Set?

If you try to start the application without configuring credentials, you'll see this error:

```
╔═══════════════════════════════════════════════════════════════════════╗
║                     CREDENTIALS NOT CONFIGURED                        ║
╚═══════════════════════════════════════════════════════════════════════╝

ERROR: Admin credentials must be configured before starting Stitch.

Please set the following environment variables:
  - STITCH_ADMIN_USER     (your admin username)
  - STITCH_ADMIN_PASSWORD (your admin password)
```

The application will **not start** until you configure valid credentials.

---

## Security Best Practices

### 1. Never Commit Credentials

The `.env` file is already in `.gitignore` to prevent accidental commits. Never commit credentials to version control!

### 2. Use Unique Passwords

Don't reuse passwords from other services. Each application should have its own unique password.

### 3. Change Compromised Credentials

If you suspect your credentials have been compromised:

1. Stop the Stitch server
2. Change the password in `.env` or environment variables
3. Restart the server
4. All existing sessions will be invalidated

### 4. Store Securely

- Use a password manager to generate and store your credentials
- Don't write passwords on sticky notes or in plain text files
- Don't share credentials via email or chat

### 5. Production Deployment

For production environments:

- ✅ Use HTTPS (enable `STITCH_ENABLE_HTTPS=True`)
- ✅ Set strong password (20+ characters recommended)
- ✅ Restrict CORS origins (`STITCH_CORS_ORIGINS=https://yourdomain.com`)
- ✅ Enable rate limiting (see Phase 2 improvements)
- ✅ Use firewall rules to restrict access
- ✅ Keep credentials in a secure secrets manager

---

## Troubleshooting

### "Password must be at least 12 characters"

Your password is too short. Choose a longer password for better security.

```bash
# Wrong (only 8 characters)
STITCH_ADMIN_PASSWORD=Pass123!

# Correct (14 characters)
STITCH_ADMIN_PASSWORD=MySecurePass123!
```

### "Credentials not configured"

You haven't set the environment variables. Follow the Quick Setup section above.

### "python-dotenv not installed"

The application will work fine with manual environment variables, but if you want to use `.env` files:

```bash
pip install python-dotenv
```

### Can't log in with my credentials

1. Check that you're using the **exact** username and password you configured
2. Check for typos in your `.env` file
3. Restart the application after changing credentials
4. Check the logs for authentication errors

---

## Additional Configuration

See `.env.example` for all available configuration options including:

- Session timeout
- Server ports
- HTTPS/SSL settings
- CORS configuration
- And more...

---

## Need Help?

- Check `COMPREHENSIVE_AUDIT.md` for security recommendations
- Review `HOW_IT_WORKS.md` for architecture details
- See the main `README.md` for general usage

---

**Remember:** Security starts with strong credentials. Take the time to set them up properly!
