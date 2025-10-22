# Elite RAT Ubuntu Server Deployment Guide

## 🚀 Complete Production Deployment Guide

This guide provides step-by-step instructions for deploying the Elite RAT web application on Ubuntu Server with enterprise-grade security and reliability.

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu Server 20.04 LTS or newer
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Storage**: Minimum 10GB free space
- **Network**: Internet connection for package installation
- **Access**: Root/sudo privileges

### Supported Ubuntu Versions
- ✅ Ubuntu 22.04 LTS (Jammy) - **Recommended**
- ✅ Ubuntu 20.04 LTS (Focal)
- ✅ Ubuntu 24.04 LTS (Noble)

## 🔧 Quick Deployment (Automated)

### Option 1: One-Command Deployment
```bash
# Run the automated deployment script
sudo python3 /workspace/deploy.py
```

### Option 2: Manual Step-by-Step Deployment
Follow the manual steps below for full control over the deployment process.

## 📖 Manual Deployment Steps

### Step 1: System Preparation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    build-essential libssl-dev libffi-dev nginx supervisor \
    ufw fail2ban sqlite3 curl wget git htop
```

### Step 2: Create Service User
```bash
# Create dedicated service user for security
sudo groupadd --system elite-rat
sudo useradd --system --gid elite-rat --shell /bin/false \
    --home-dir /opt/elite-rat --create-home elite-rat
```

### Step 3: Create Directory Structure
```bash
# Create required directories
sudo mkdir -p /opt/elite-rat
sudo mkdir -p /var/log/elite-rat
sudo mkdir -p /var/lib/elite-rat
sudo mkdir -p /etc/elite-rat
sudo mkdir -p /var/run/elite-rat

# Set proper ownership and permissions
sudo chown elite-rat:elite-rat /opt/elite-rat /var/log/elite-rat /var/lib/elite-rat /var/run/elite-rat
sudo chown root:elite-rat /etc/elite-rat
sudo chmod 750 /var/lib/elite-rat /etc/elite-rat
```

### Step 4: Install Application Files
```bash
# Copy application files to installation directory
sudo cp /workspace/web_app_real.py /opt/elite-rat/
sudo cp /workspace/config.py /opt/elite-rat/
sudo cp /workspace/auth_utils.py /opt/elite-rat/
sudo cp /workspace/web_app_enhancements.py /opt/elite-rat/
sudo cp /workspace/ssl_utils.py /opt/elite-rat/
sudo cp /workspace/requirements_production.txt /opt/elite-rat/

# Copy application directories
sudo cp -r /workspace/Application /opt/elite-rat/
sudo cp -r /workspace/Core /opt/elite-rat/
sudo cp -r /workspace/Configuration /opt/elite-rat/
sudo cp -r /workspace/templates /opt/elite-rat/
sudo cp -r /workspace/static /opt/elite-rat/

# Set ownership
sudo chown -R elite-rat:elite-rat /opt/elite-rat/
```

### Step 5: Setup Python Environment
```bash
# Create virtual environment
sudo -u elite-rat python3 -m venv /opt/elite-rat/venv

# Install Python dependencies
sudo -u elite-rat /opt/elite-rat/venv/bin/pip install --upgrade pip
sudo -u elite-rat /opt/elite-rat/venv/bin/pip install -r /opt/elite-rat/requirements_production.txt
```

### Step 6: Configure Environment
```bash
# Copy production environment template
sudo cp /workspace/.env.production /etc/elite-rat/production.env

# Edit configuration (IMPORTANT!)
sudo nano /etc/elite-rat/production.env
```

**⚠️ CRITICAL: Edit the configuration file and change:**
- `STITCH_ADMIN_PASSWORD` - Set a strong password
- `STITCH_SECRET_KEY` - Generate a random 64-character string
- `STITCH_SSL_CN` - Set your domain name
- Other security settings as needed

### Step 7: Create Systemd Service
```bash
# Create service file
sudo tee /etc/systemd/system/elite-rat.service > /dev/null <<EOF
[Unit]
Description=Elite RAT Web Application
After=network.target
Wants=network.target

[Service]
Type=simple
User=elite-rat
Group=elite-rat
WorkingDirectory=/opt/elite-rat
Environment=PATH=/opt/elite-rat/venv/bin
EnvironmentFile=/etc/elite-rat/production.env
ExecStart=/opt/elite-rat/venv/bin/python web_app_real.py
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/elite-rat /var/lib/elite-rat /opt/elite-rat/Application /opt/elite-rat/uploads /opt/elite-rat/downloads
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable elite-rat
```

### Step 8: Configure Nginx Reverse Proxy
```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/elite-rat > /dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/elite-rat.crt;
    ssl_certificate_key /etc/nginx/ssl/elite-rat.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    location /socket.io/ {
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
EOF

# Enable site and create SSL certificate
sudo ln -sf /etc/nginx/sites-available/elite-rat /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Create SSL directory and certificate
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/elite-rat.key \
    -out /etc/nginx/ssl/elite-rat.crt \
    -subj "/C=US/ST=State/L=City/O=Elite RAT/CN=localhost"

# Test and reload Nginx
sudo nginx -t
sudo systemctl reload nginx
```

### Step 9: Configure Firewall
```bash
# Configure UFW firewall
sudo ufw --force enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 4040/tcp  # C2 Server (be careful!)

# Check status
sudo ufw status
```

### Step 10: Configure Fail2Ban
```bash
# Create custom jail for Elite RAT
sudo tee /etc/fail2ban/jail.d/elite-rat.conf > /dev/null <<EOF
[elite-rat]
enabled = true
port = 80,443
filter = elite-rat
logpath = /var/log/elite-rat/web.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

# Create filter
sudo tee /etc/fail2ban/filter.d/elite-rat.conf > /dev/null <<EOF
[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
            ^.*Suspicious activity from <HOST>.*$
ignoreregex =
EOF

# Restart Fail2Ban
sudo systemctl restart fail2ban
```

### Step 11: Setup Log Rotation
```bash
# Configure log rotation
sudo tee /etc/logrotate.d/elite-rat > /dev/null <<EOF
/var/log/elite-rat/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 elite-rat elite-rat
    postrotate
        systemctl reload elite-rat > /dev/null 2>&1 || true
    endscript
}
EOF
```

## 🚀 Starting the Service

### Using the Management Script
```bash
# Copy management script
sudo cp /workspace/start_production.sh /usr/local/bin/elite-rat-manage
sudo chmod +x /usr/local/bin/elite-rat-manage

# Start the service
sudo elite-rat-manage start

# Check status
sudo elite-rat-manage status

# View logs
sudo elite-rat-manage logs
```

### Manual Service Management
```bash
# Start services
sudo systemctl start nginx
sudo systemctl start elite-rat

# Check status
sudo systemctl status elite-rat

# View logs
sudo journalctl -u elite-rat -f
```

## 🌐 Accessing the Web Interface

Once deployed, access the web interface at:
- **HTTPS**: `https://your-server-ip` (Recommended)
- **HTTP**: `http://your-server-ip` (Redirects to HTTPS)

Default credentials (CHANGE IMMEDIATELY):
- **Username**: admin
- **Password**: (Set in `/etc/elite-rat/production.env`)

## 🔧 Configuration Management

### Environment Variables
Edit `/etc/elite-rat/production.env` to configure:

```bash
# Security Settings
STITCH_ADMIN_USER=admin
STITCH_ADMIN_PASSWORD=YourSecurePassword123!
STITCH_SECRET_KEY=your-64-character-random-string

# Server Settings
STITCH_HOST=127.0.0.1
STITCH_PORT=5000
STITCH_DEBUG=false

# HTTPS Settings
STITCH_ENABLE_HTTPS=true
STITCH_SSL_AUTO_GENERATE=true

# Rate Limiting
STITCH_MAX_LOGIN_ATTEMPTS=3
STITCH_LOGIN_LOCKOUT_MINUTES=30
```

### Applying Configuration Changes
```bash
# After editing configuration
sudo systemctl restart elite-rat
```

## 📊 Monitoring and Maintenance

### Service Status
```bash
# Check service status
sudo systemctl status elite-rat nginx

# Check port usage
sudo netstat -tlnp | grep -E ':(80|443|5000|4040)'

# Check system resources
htop
```

### Log Management
```bash
# View application logs
sudo journalctl -u elite-rat -f

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# View application-specific logs
sudo tail -f /var/log/elite-rat/web.log
```

### Backup and Restore
```bash
# Create backup
sudo elite-rat-manage backup

# Manual backup
sudo tar -czf elite-rat-backup-$(date +%Y%m%d).tar.gz \
    /etc/elite-rat \
    /var/lib/elite-rat \
    /var/log/elite-rat
```

## 🔒 Security Best Practices

### 1. Change Default Credentials
- Set strong admin password (16+ characters)
- Use unique secret keys
- Enable two-factor authentication if available

### 2. Network Security
- Use HTTPS only (disable HTTP in production)
- Configure proper firewall rules
- Use VPN for administrative access
- Restrict C2 port access

### 3. System Security
- Keep Ubuntu updated: `sudo apt update && sudo apt upgrade`
- Monitor failed login attempts
- Use fail2ban for intrusion prevention
- Regular security audits

### 4. Application Security
- Monitor application logs
- Regular backups
- Update dependencies regularly
- Use strong session timeouts

## 🚨 Troubleshooting

### Service Won't Start
```bash
# Check service logs
sudo journalctl -u elite-rat --no-pager -l

# Check configuration
sudo -u elite-rat /opt/elite-rat/venv/bin/python -c "
import sys
sys.path.insert(0, '/opt/elite-rat')
from config import Config
print('Config loaded successfully')
"

# Check permissions
ls -la /opt/elite-rat/
ls -la /etc/elite-rat/
```

### Port Conflicts
```bash
# Check what's using ports
sudo netstat -tlnp | grep -E ':(80|443|5000|4040)'

# Kill conflicting processes
sudo pkill -f web_app_real
```

### SSL Certificate Issues
```bash
# Regenerate SSL certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/elite-rat.key \
    -out /etc/nginx/ssl/elite-rat.crt \
    -subj "/C=US/ST=State/L=City/O=Elite RAT/CN=$(hostname -f)"

# Test Nginx configuration
sudo nginx -t
sudo systemctl reload nginx
```

### Permission Issues
```bash
# Fix ownership
sudo chown -R elite-rat:elite-rat /opt/elite-rat/
sudo chown -R elite-rat:elite-rat /var/log/elite-rat/
sudo chown -R elite-rat:elite-rat /var/lib/elite-rat/

# Fix permissions
sudo chmod 750 /etc/elite-rat/
sudo chmod 640 /etc/elite-rat/production.env
```

## 📈 Performance Optimization

### For High Traffic
```bash
# Install Redis for session storage
sudo apt install redis-server
sudo systemctl enable redis-server

# Configure Nginx worker processes
sudo nano /etc/nginx/nginx.conf
# Set: worker_processes auto;
# Set: worker_connections 1024;

# Use Gunicorn for better performance
sudo -u elite-rat /opt/elite-rat/venv/bin/pip install gunicorn
```

### System Tuning
```bash
# Increase file descriptor limits
echo "elite-rat soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "elite-rat hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 1024" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 🔄 Updates and Maintenance

### Updating the Application
```bash
# Using management script
sudo elite-rat-manage update

# Manual update
sudo systemctl stop elite-rat
# Copy new files to /opt/elite-rat/
sudo systemctl start elite-rat
```

### System Updates
```bash
# Regular system updates
sudo apt update && sudo apt upgrade -y

# Update Python packages
sudo -u elite-rat /opt/elite-rat/venv/bin/pip install --upgrade -r /opt/elite-rat/requirements_production.txt
```

## 📞 Support and Maintenance

### Regular Maintenance Tasks
1. **Weekly**: Check logs for errors
2. **Weekly**: Verify backups
3. **Monthly**: Update system packages
4. **Monthly**: Review security logs
5. **Quarterly**: Security audit

### Emergency Procedures
```bash
# Emergency stop
sudo systemctl stop elite-rat nginx

# Emergency restart
sudo systemctl restart elite-rat nginx

# Emergency backup
sudo elite-rat-manage backup
```

## ✅ Deployment Checklist

- [ ] Ubuntu Server updated
- [ ] System dependencies installed
- [ ] Service user created
- [ ] Application files deployed
- [ ] Python environment configured
- [ ] Configuration file edited with secure passwords
- [ ] Systemd service created and enabled
- [ ] Nginx configured with SSL
- [ ] Firewall configured
- [ ] Fail2Ban configured
- [ ] Log rotation configured
- [ ] Service started successfully
- [ ] Web interface accessible
- [ ] Admin login working
- [ ] SSL certificate valid
- [ ] Logs being written
- [ ] Backup procedure tested

## 🎯 Quick Start Commands

```bash
# Complete automated deployment
sudo python3 /workspace/deploy.py

# Start service
sudo /usr/local/bin/elite-rat-manage start

# Check status
sudo /usr/local/bin/elite-rat-manage status

# View logs
sudo /usr/local/bin/elite-rat-manage logs

# Access web interface
# Open browser to: https://your-server-ip
```

---

**⚠️ SECURITY WARNING**: This application is designed for authorized penetration testing and security research only. Ensure you have proper authorization before deployment and use. Always follow responsible disclosure practices and applicable laws.

**📝 Note**: Replace `your-server-ip` and `your-domain.com` with your actual server details throughout this guide.