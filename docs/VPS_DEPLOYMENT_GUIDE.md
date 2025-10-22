# 🌐 Elite RAT VPS Deployment Guide - Ionos Ubuntu Server

## 🎯 VPS-Specific Deployment for Ionos Hosting

This guide is specifically tailored for deploying Elite RAT on an Ionos VPS with Ubuntu via SSH terminal access.

## 📋 Prerequisites

### VPS Information You'll Need
- **VPS IP Address**: `_________________`
- **SSH Username**: `_________________` (usually `root` or `ubuntu`)
- **SSH Password/Key**: Have your credentials ready
- **Domain Name** (optional): `_________________`

### Local Requirements
- SSH client (Terminal on Mac/Linux, PuTTY on Windows)
- Git installed locally
- Your GitHub credentials

## 🚀 Deployment Options for VPS

### Option 1: Direct Git Clone (RECOMMENDED for VPS)
This is the best approach for a VPS - clone directly on the server.

### Option 2: SCP/SFTP Upload
Upload files manually if Git isn't available.

### Option 3: GitHub Release Package
Create a release package and download on VPS.

## 📖 Step-by-Step VPS Deployment

### Step 1: Connect to Your VPS
```bash
# Connect via SSH (replace with your VPS details)
ssh root@your-vps-ip
# or
ssh ubuntu@your-vps-ip

# If using SSH key:
ssh -i /path/to/your/key.pem ubuntu@your-vps-ip
```

### Step 2: Prepare the VPS System
```bash
# Update system packages
apt update && apt upgrade -y

# Install essential packages
apt install -y git python3 python3-pip python3-venv curl wget nano htop

# Check Python version (should be 3.8+)
python3 --version

# Check available disk space
df -h

# Check memory
free -h
```

### Step 3: Clone Your Repository
```bash
# Navigate to a good location
cd /opt

# Clone your repository (replace with your repo URL)
git clone https://github.com/yourusername/your-repo-name.git elite-rat

# Or if you want to clone to /workspace to match our scripts:
git clone https://github.com/yourusername/your-repo-name.git /workspace

# Navigate to the project
cd /workspace  # or cd /opt/elite-rat
```

### Step 4: Run Automated Deployment
```bash
# Make deployment script executable
chmod +x deploy.py

# Run the automated deployment
python3 deploy.py

# This will handle everything:
# - Install system dependencies
# - Create service user
# - Set up directories
# - Install Python packages
# - Configure Nginx
# - Set up SSL
# - Configure firewall
# - Start services
```

### Step 5: Configure Your Credentials
```bash
# Edit the production configuration
nano /etc/elite-rat/production.env

# Change these critical settings:
STITCH_ADMIN_USER=your_admin_username
STITCH_ADMIN_PASSWORD=YourVerySecurePassword123!
STITCH_SECRET_KEY=generate_a_64_character_random_string_here
STITCH_SSL_CN=your-domain.com  # or your VPS IP
```

### Step 6: Start the Service
```bash
# Start the service
systemctl start elite-rat nginx

# Check status
systemctl status elite-rat
systemctl status nginx

# Enable auto-start on boot
systemctl enable elite-rat nginx

# Check if it's working
curl -I http://localhost:5000
```

### Step 7: Configure Firewall for VPS
```bash
# Configure UFW firewall
ufw --force enable

# Allow SSH (CRITICAL - don't lock yourself out!)
ufw allow 22/tcp

# Allow web traffic
ufw allow 80/tcp
ufw allow 443/tcp

# Allow C2 traffic (be careful with this)
ufw allow 4040/tcp

# Check firewall status
ufw status verbose
```

### Step 8: Test Access
```bash
# Get your VPS public IP
curl ifconfig.me

# Test local access
curl -k https://localhost

# From your local machine, test:
# https://your-vps-ip
```

## 🌐 VPS-Specific Considerations

### Ionos VPS Networking
```bash
# Check network interfaces
ip addr show

# Check if ports are open
netstat -tlnp | grep -E ':(80|443|5000|4040)'

# Test external connectivity
curl -I https://google.com
```

### Domain Configuration (Optional)
If you have a domain pointing to your VPS:

```bash
# Update SSL certificate with your domain
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/elite-rat.key \
    -out /etc/nginx/ssl/elite-rat.crt \
    -subj "/C=US/ST=State/L=City/O=Elite RAT/CN=yourdomain.com"

# Update Nginx configuration
nano /etc/nginx/sites-available/elite-rat
# Change server_name from _ to yourdomain.com

# Reload Nginx
systemctl reload nginx
```

### VPS Resource Monitoring
```bash
# Monitor system resources
htop

# Check disk usage
df -h

# Check memory usage
free -h

# Monitor logs
journalctl -u elite-rat -f
```

## 🔒 VPS Security Hardening

### SSH Security
```bash
# Create a new user (don't use root for everything)
adduser admin
usermod -aG sudo admin

# Disable root SSH login (optional, be careful!)
nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Restart SSH: systemctl restart ssh
```

### Additional Security
```bash
# Install additional security tools
apt install -y fail2ban unattended-upgrades

# Configure automatic security updates
dpkg-reconfigure unattended-upgrades

# Check fail2ban status
systemctl status fail2ban
```

## 📱 Remote Management

### Using the Management Script
```bash
# Copy management script to system path
cp /workspace/start_production.sh /usr/local/bin/elite-rat-manage
chmod +x /usr/local/bin/elite-rat-manage

# Use the management script
elite-rat-manage status
elite-rat-manage start
elite-rat-manage stop
elite-rat-manage logs
elite-rat-manage backup
```

### Remote Monitoring
```bash
# Check service status remotely
ssh root@your-vps-ip "systemctl status elite-rat"

# View logs remotely
ssh root@your-vps-ip "journalctl -u elite-rat -n 50"

# Check system resources remotely
ssh root@your-vps-ip "htop -n 1"
```

## 🚨 Troubleshooting VPS Issues

### Common VPS Problems

#### Port Access Issues
```bash
# Check if Ionos firewall is blocking ports
# You may need to configure firewall in Ionos control panel

# Test port connectivity from outside
# Use online port checker tools

# Check iptables rules
iptables -L
```

#### Memory Issues
```bash
# Check memory usage
free -h

# If low memory, create swap file
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

#### Disk Space Issues
```bash
# Check disk usage
df -h

# Clean up if needed
apt autoremove -y
apt autoclean
journalctl --vacuum-time=7d
```

### Network Connectivity Issues
```bash
# Test DNS resolution
nslookup google.com

# Test internet connectivity
ping -c 4 8.8.8.8

# Check network configuration
ip route show
```

## 🔄 Updates and Maintenance

### Updating the Application
```bash
# SSH to your VPS
ssh root@your-vps-ip

# Navigate to project directory
cd /workspace

# Pull latest changes
git pull origin main

# Run update
elite-rat-manage update

# Or manual update:
systemctl stop elite-rat
pip install -r requirements_production.txt
systemctl start elite-rat
```

### System Maintenance
```bash
# Regular system updates
apt update && apt upgrade -y

# Check service health
elite-rat-manage status

# Create backups
elite-rat-manage backup

# Monitor logs
elite-rat-manage logs
```

## 📊 VPS Performance Optimization

### For Small VPS (1-2GB RAM)
```bash
# Optimize Python for low memory
export PYTHONOPTIMIZE=1

# Use lighter web server if needed
pip install gunicorn
# Update service to use gunicorn instead of built-in server
```

### For Larger VPS (4GB+ RAM)
```bash
# Install Redis for better session management
apt install redis-server
systemctl enable redis-server

# Configure application to use Redis
# Add to production.env:
# REDIS_URL=redis://localhost:6379/0
```

## 🌍 Accessing Your Deployed Application

After successful deployment:

### Web Interface
- **Primary URL**: `https://your-vps-ip`
- **With Domain**: `https://yourdomain.com`
- **Admin Login**: `https://your-vps-ip/login`

### C2 Server
- **C2 Endpoint**: `your-vps-ip:4040`

### SSH Management
- **SSH Access**: `ssh root@your-vps-ip`
- **Service Control**: `elite-rat-manage [command]`

## 📋 VPS Deployment Checklist

- [ ] VPS accessible via SSH
- [ ] System packages updated
- [ ] Git repository cloned
- [ ] Automated deployment completed
- [ ] Credentials configured (changed from defaults)
- [ ] Services started and enabled
- [ ] Firewall configured
- [ ] Web interface accessible externally
- [ ] SSL certificate working
- [ ] Admin login functional
- [ ] C2 port accessible (if needed)
- [ ] Monitoring and logging working
- [ ] Backup procedure tested

## 🎯 Quick VPS Deployment Commands

```bash
# Complete VPS deployment in one session:

# 1. Connect to VPS
ssh root@your-vps-ip

# 2. Install Git and clone
apt update && apt install -y git python3 python3-pip
git clone https://github.com/yourusername/your-repo.git /workspace
cd /workspace

# 3. Deploy
python3 deploy.py

# 4. Configure
nano /etc/elite-rat/production.env
# (Change passwords and keys)

# 5. Start
systemctl start elite-rat nginx

# 6. Test
curl -k https://localhost
```

## 🔗 Next Steps After VPS Deployment

1. **Test thoroughly** - Verify all functionality works
2. **Configure monitoring** - Set up log monitoring
3. **Plan backups** - Schedule regular backups
4. **Document access** - Save all credentials securely
5. **Monitor resources** - Keep an eye on VPS performance
6. **Plan updates** - Schedule regular maintenance

---

**⚠️ VPS Security Reminder**: Your VPS is directly exposed to the internet. Ensure you:
- Use strong passwords
- Keep the system updated
- Monitor access logs
- Use firewall properly
- Consider VPN access for admin functions

**📞 Ionos Support**: If you encounter VPS-specific issues, Ionos support can help with:
- Firewall configuration
- Network connectivity
- Resource limits
- Backup services