# Stitch RAT - HTTPS/SSL Configuration Guide

## 🔒 Why HTTPS?

**CRITICAL:** Without HTTPS, your admin credentials and all communication with the Stitch interface are transmitted in **clear text** over the network. Anyone monitoring network traffic can:
- Steal your admin password
- Intercept commands sent to targets
- Modify data in transit (man-in-the-middle attacks)

**Always use HTTPS in production environments.**

---

## Prerequisites

**Required:** OpenSSL must be installed for certificate generation.

```bash
# Check if OpenSSL is installed
which openssl

# Install if needed:
# Debian/Ubuntu:
sudo apt-get install openssl

# macOS:
brew install openssl
```

## Quick Setup (Auto-Generated Certificate)

The easiest way to enable HTTPS is with an auto-generated self-signed certificate:

### 1. Enable HTTPS in Environment

```bash
# In .env file:
STITCH_ENABLE_HTTPS=true

# Or via environment variable:
export STITCH_ENABLE_HTTPS=true
```

### 2. Start the Application

```bash
python3 web_app_real.py
```

The application will automatically:
- Generate a self-signed SSL certificate (4096-bit RSA)
- Store it in the `certs/` directory
- Enable HTTPS on port 5000 (or your configured port)
- Use the certificate for encrypted communication

### 3. Access via HTTPS

```
https://localhost:5000
```

**Browser Warning:** You'll see a security warning because self-signed certificates aren't trusted by browsers. This is expected. Click "Advanced" and "Proceed" to continue.

---

## Using Custom Certificates (Production)

For production environments, use certificates from a trusted Certificate Authority (CA):

### Option 1: Let's Encrypt (Free, Recommended)

Let's Encrypt provides free, trusted SSL certificates. Use Certbot to obtain them:

```bash
# Install Certbot
sudo apt-get install certbot

# Generate certificate (interactive)
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in: /etc/letsencrypt/live/yourdomain.com/
```

### Option 2: Commercial CA

Purchase a certificate from a commercial CA (DigiCert, GlobalSign, etc.) and follow their instructions.

### Configure Stitch to Use Custom Certificates

```bash
# In .env file:
STITCH_ENABLE_HTTPS=true
STITCH_SSL_CERT=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
STITCH_SSL_KEY=/etc/letsencrypt/live/yourdomain.com/privkey.pem

# Or via environment variables:
export STITCH_ENABLE_HTTPS=true
export STITCH_SSL_CERT=/path/to/your/cert.pem
export STITCH_SSL_KEY=/path/to/your/key.pem
```

Then start the application:

```bash
python3 web_app_real.py
```

---

## Certificate Types Explained

### Self-Signed Certificates
- **Pros:** Free, instant, no external dependencies
- **Cons:** Browser warnings, not trusted by default, unsuitable for production
- **Use case:** Development, testing, internal networks

### CA-Signed Certificates (Let's Encrypt, Commercial)
- **Pros:** Trusted by browsers, no warnings, professional
- **Cons:** Requires domain name, renewal process
- **Use case:** Production, public-facing deployments

---

## Certificate Management

### Auto-Generated Certificate Location

```
certs/
├── cert.pem    # SSL certificate (4096-bit RSA)
└── key.pem     # Private key
```

**Important:**
- These files are automatically created on first HTTPS startup
- Valid for 365 days
- Stored in the `certs/` directory (excluded from git)
- Reused on subsequent startups

### Regenerating Auto-Generated Certificates

```bash
# Delete existing certificates
rm -rf certs/

# Restart application - new ones will be generated
python3 web_app_real.py
```

### Manual Certificate Generation

Use the included utility:

```bash
python3 ssl_utils.py
```

This generates certificates in the `certs/` directory and provides setup instructions.

---

## Troubleshooting

### "HTTPS requested but SSL setup failed"

**Problem:** HTTPS is enabled but certificates can't be loaded.

**Solutions:**
1. Check file paths in STITCH_SSL_CERT and STITCH_SSL_KEY
2. Ensure certificate files exist and are readable
3. Verify OpenSSL is installed (`which openssl`)
4. Check file permissions on certificate files

### Browser Shows "Your connection is not private"

**Problem:** Self-signed certificate not trusted by browser.

**Solution:** This is expected for self-signed certificates. Options:
1. Click "Advanced" → "Proceed anyway" (development only)
2. Use a CA-signed certificate for production
3. Add the certificate to your browser's trusted list

### "OpenSSL not found"

**Problem:** OpenSSL is not installed.

**Solution:**
```bash
# Debian/Ubuntu
sudo apt-get install openssl

# macOS
brew install openssl

# Verify installation
which openssl
```

### Certificate Expired

**Problem:** Certificate is older than 365 days.

**Solution:**
```bash
# For auto-generated certificates:
rm -rf certs/
python3 web_app_real.py  # Will generate new ones

# For Let's Encrypt:
sudo certbot renew
```

---

## Security Best Practices

### 1. Always Use HTTPS in Production
```bash
STITCH_ENABLE_HTTPS=true
```

### 2. Use Trusted Certificates
Self-signed certificates are for development only. Production requires CA-signed certificates.

### 3. Keep Certificates Secure
- Never commit certificates to version control (already in .gitignore)
- Restrict file permissions: `chmod 600 certs/*.pem`
- Store private keys securely

### 4. Renew Before Expiration
- Let's Encrypt: Auto-renewal via cron job
- Auto-generated: Valid for 365 days
- Commercial: Follow CA renewal process

### 5. Monitor Certificate Status
```bash
# Check certificate expiration
openssl x509 -in certs/cert.pem -noout -dates

# Check certificate details
openssl x509 -in certs/cert.pem -noout -text
```

---

## Configuration Summary

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `STITCH_ENABLE_HTTPS` | No | `false` | Enable HTTPS/SSL support |
| `STITCH_SSL_CERT` | No | Auto-generated | Path to SSL certificate file |
| `STITCH_SSL_KEY` | No | Auto-generated | Path to SSL private key file |
| `STITCH_WEB_PORT` | No | `5000` | Port for web interface |

---

## Production Deployment Checklist

Before deploying to production:

- ✅ `STITCH_ENABLE_HTTPS=true` configured
- ✅ Using CA-signed certificate (not self-signed)
- ✅ Certificate valid for your domain
- ✅ Certificate not expired
- ✅ Private key permissions restricted (`chmod 600`)
- ✅ Firewall allows HTTPS port (443 or your configured port)
- ✅ CORS origins restricted (`STITCH_ALLOWED_ORIGINS`)
- ✅ Strong admin credentials configured
- ✅ Rate limiting enabled (automatic)
- ✅ Debug mode disabled

---

## Example Configurations

### Development (Auto-Generated Certificate)

```bash
# .env
STITCH_ENABLE_HTTPS=true
STITCH_ADMIN_USER=admin
STITCH_ADMIN_PASSWORD=Dev_Password_123!
```

### Production (Let's Encrypt)

```bash
# .env
STITCH_ENABLE_HTTPS=true
STITCH_SSL_CERT=/etc/letsencrypt/live/stitch.yourdomain.com/fullchain.pem
STITCH_SSL_KEY=/etc/letsencrypt/live/stitch.yourdomain.com/privkey.pem
STITCH_ALLOWED_ORIGINS=https://stitch.yourdomain.com
STITCH_ADMIN_USER=admin
STITCH_ADMIN_PASSWORD=VeryStrongProductionPassword123!
STITCH_WEB_PORT=443
```

---

## Need Help?

- Review `CREDENTIALS_SETUP.md` for credential configuration
- Check `COMPREHENSIVE_AUDIT.md` for security recommendations
- See `.env.example` for all configuration options

---

**Remember:** HTTPS is essential for production deployments. Never transmit credentials over unencrypted HTTP in production!
