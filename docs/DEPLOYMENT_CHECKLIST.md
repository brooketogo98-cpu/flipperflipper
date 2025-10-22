# Elite RAT Ubuntu Deployment Checklist

## 🎯 Pre-Deployment Requirements

### System Requirements ✅
- [ ] Ubuntu Server 20.04 LTS or newer
- [ ] Minimum 2GB RAM (4GB+ recommended)
- [ ] Minimum 10GB free disk space
- [ ] Internet connection available
- [ ] Root/sudo access confirmed
- [ ] Server IP address documented: `_________________`

### Network Requirements ✅
- [ ] Port 22 (SSH) accessible for management
- [ ] Port 80 (HTTP) available for web traffic
- [ ] Port 443 (HTTPS) available for secure web traffic
- [ ] Port 4040 (C2) available for payload connections
- [ ] Firewall rules planned and documented

### Security Preparation ✅
- [ ] Strong admin password generated (16+ characters)
- [ ] Secret key generated (64 random characters)
- [ ] SSL certificate plan (self-signed or proper CA)
- [ ] Domain name configured (if using proper SSL)
- [ ] Backup strategy planned

## 🚀 Deployment Steps

### Phase 1: System Preparation
- [ ] **Step 1.1**: System packages updated (`sudo apt update && sudo apt upgrade -y`)
- [ ] **Step 1.2**: Essential packages installed (python3, nginx, supervisor, etc.)
- [ ] **Step 1.3**: System reboot completed (if kernel updated)
- [ ] **Step 1.4**: Disk space verified (at least 5GB free after updates)

### Phase 2: User and Directory Setup
- [ ] **Step 2.1**: Service group created (`elite-rat`)
- [ ] **Step 2.2**: Service user created (`elite-rat`)
- [ ] **Step 2.3**: Installation directory created (`/opt/elite-rat`)
- [ ] **Step 2.4**: Log directory created (`/var/log/elite-rat`)
- [ ] **Step 2.5**: Data directory created (`/var/lib/elite-rat`)
- [ ] **Step 2.6**: Config directory created (`/etc/elite-rat`)
- [ ] **Step 2.7**: Runtime directory created (`/var/run/elite-rat`)
- [ ] **Step 2.8**: Directory permissions set correctly

### Phase 3: Application Installation
- [ ] **Step 3.1**: Core Python files copied to `/opt/elite-rat/`
- [ ] **Step 3.2**: Application directories copied (`Application/`, `Core/`, etc.)
- [ ] **Step 3.3**: Web assets copied (`templates/`, `static/`)
- [ ] **Step 3.4**: File ownership set to `elite-rat:elite-rat`
- [ ] **Step 3.5**: File permissions set correctly (644 for files, 755 for dirs)

### Phase 4: Python Environment
- [ ] **Step 4.1**: Virtual environment created (`/opt/elite-rat/venv`)
- [ ] **Step 4.2**: Pip upgraded in virtual environment
- [ ] **Step 4.3**: Production requirements installed
- [ ] **Step 4.4**: Dependencies verified (test import)
- [ ] **Step 4.5**: Virtual environment owned by service user

### Phase 5: Configuration
- [ ] **Step 5.1**: Production config template copied
- [ ] **Step 5.2**: Admin username set in config
- [ ] **Step 5.3**: **CRITICAL**: Admin password changed from default
- [ ] **Step 5.4**: **CRITICAL**: Secret key set to random value
- [ ] **Step 5.5**: SSL settings configured
- [ ] **Step 5.6**: Rate limiting configured
- [ ] **Step 5.7**: Logging settings configured
- [ ] **Step 5.8**: Config file permissions set (640, root:elite-rat)

### Phase 6: Service Configuration
- [ ] **Step 6.1**: Systemd service file created
- [ ] **Step 6.2**: Service security settings configured
- [ ] **Step 6.3**: Service enabled for auto-start
- [ ] **Step 6.4**: Service configuration validated

### Phase 7: Web Server Setup
- [ ] **Step 7.1**: Nginx configuration created
- [ ] **Step 7.2**: SSL certificate generated/installed
- [ ] **Step 7.3**: Security headers configured
- [ ] **Step 7.4**: Rate limiting configured
- [ ] **Step 7.5**: Nginx configuration tested (`nginx -t`)
- [ ] **Step 7.6**: Default site disabled
- [ ] **Step 7.7**: Elite RAT site enabled

### Phase 8: Security Configuration
- [ ] **Step 8.1**: UFW firewall enabled
- [ ] **Step 8.2**: SSH access allowed (port 22)
- [ ] **Step 8.3**: HTTP access allowed (port 80)
- [ ] **Step 8.4**: HTTPS access allowed (port 443)
- [ ] **Step 8.5**: C2 port access configured (port 4040)
- [ ] **Step 8.6**: Fail2Ban installed and configured
- [ ] **Step 8.7**: Custom Fail2Ban jail created for Elite RAT
- [ ] **Step 8.8**: Fail2Ban service restarted

### Phase 9: Logging and Monitoring
- [ ] **Step 9.1**: Log rotation configured
- [ ] **Step 9.2**: Log directories have correct permissions
- [ ] **Step 9.3**: Monitoring tools installed (htop, etc.)
- [ ] **Step 9.4**: Log retention policy configured

### Phase 10: Service Startup
- [ ] **Step 10.1**: Nginx service started
- [ ] **Step 10.2**: Elite RAT service started
- [ ] **Step 10.3**: Services enabled for auto-start
- [ ] **Step 10.4**: Service status verified (both running)

## 🧪 Testing and Verification

### Basic Functionality Tests
- [ ] **Test 1**: Web interface accessible via HTTP
- [ ] **Test 2**: HTTP redirects to HTTPS correctly
- [ ] **Test 3**: HTTPS web interface loads without errors
- [ ] **Test 4**: SSL certificate validates (or shows expected self-signed warning)
- [ ] **Test 5**: Admin login page displays correctly
- [ ] **Test 6**: Admin login works with configured credentials
- [ ] **Test 7**: Dashboard loads after successful login
- [ ] **Test 8**: WebSocket connection establishes (real-time updates work)

### Security Tests
- [ ] **Test 9**: Failed login attempts are logged
- [ ] **Test 10**: Rate limiting works (test with multiple failed logins)
- [ ] **Test 11**: Session timeout works correctly
- [ ] **Test 12**: HTTPS enforced (HTTP requests redirect)
- [ ] **Test 13**: Security headers present in responses
- [ ] **Test 14**: Fail2Ban triggers on repeated failed attempts

### System Integration Tests
- [ ] **Test 15**: Service survives system reboot
- [ ] **Test 16**: Logs are being written correctly
- [ ] **Test 17**: Log rotation works
- [ ] **Test 18**: Backup procedure works
- [ ] **Test 19**: Service restart works without issues
- [ ] **Test 20**: Port 4040 is accessible for C2 connections

### Performance Tests
- [ ] **Test 21**: Web interface responds quickly (< 2 seconds)
- [ ] **Test 22**: Multiple concurrent connections work
- [ ] **Test 23**: File upload functionality works
- [ ] **Test 24**: System resources are reasonable (check with `htop`)

## 🔒 Security Verification

### Critical Security Checks
- [ ] **Security 1**: Default passwords have been changed
- [ ] **Security 2**: Secret keys are random and secure
- [ ] **Security 3**: Config file permissions are restrictive (640)
- [ ] **Security 4**: Service runs as non-root user
- [ ] **Security 5**: Firewall is active and configured
- [ ] **Security 6**: Fail2Ban is active and monitoring
- [ ] **Security 7**: HTTPS is enforced
- [ ] **Security 8**: Security headers are present
- [ ] **Security 9**: Unnecessary services are disabled
- [ ] **Security 10**: System is up to date

### Access Control Verification
- [ ] **Access 1**: Only authorized users can access admin interface
- [ ] **Access 2**: Session management works correctly
- [ ] **Access 3**: Rate limiting prevents brute force attacks
- [ ] **Access 4**: Failed login attempts are monitored
- [ ] **Access 5**: File permissions prevent unauthorized access

## 📊 Post-Deployment Tasks

### Documentation
- [ ] **Doc 1**: Server details documented (IP, credentials, etc.)
- [ ] **Doc 2**: Configuration changes documented
- [ ] **Doc 3**: Backup procedures documented
- [ ] **Doc 4**: Monitoring procedures documented
- [ ] **Doc 5**: Emergency procedures documented

### Monitoring Setup
- [ ] **Monitor 1**: Log monitoring configured
- [ ] **Monitor 2**: Service health monitoring setup
- [ ] **Monitor 3**: Disk space monitoring configured
- [ ] **Monitor 4**: Security event monitoring setup
- [ ] **Monitor 5**: Backup verification scheduled

### Maintenance Planning
- [ ] **Maint 1**: Update schedule planned
- [ ] **Maint 2**: Backup schedule configured
- [ ] **Maint 3**: Log review schedule planned
- [ ] **Maint 4**: Security audit schedule planned
- [ ] **Maint 5**: Emergency contact information documented

## 🚨 Troubleshooting Checklist

### If Service Won't Start
- [ ] Check service logs: `sudo journalctl -u elite-rat --no-pager -l`
- [ ] Verify configuration: Test config file loading
- [ ] Check permissions: Ensure all files owned by correct user
- [ ] Verify Python environment: Test virtual environment activation
- [ ] Check port conflicts: Ensure ports 5000 and 4040 are free

### If Web Interface Not Accessible
- [ ] Check Nginx status: `sudo systemctl status nginx`
- [ ] Verify Nginx configuration: `sudo nginx -t`
- [ ] Check firewall: `sudo ufw status`
- [ ] Verify SSL certificate: Check certificate files exist
- [ ] Check port binding: `sudo netstat -tlnp | grep :443`

### If SSL Issues
- [ ] Regenerate certificate if self-signed
- [ ] Check certificate file permissions
- [ ] Verify Nginx SSL configuration
- [ ] Test with HTTP first, then enable HTTPS

## ✅ Final Verification

### Deployment Complete Checklist
- [ ] **All deployment steps completed successfully**
- [ ] **All tests passed**
- [ ] **Security verification completed**
- [ ] **Documentation updated**
- [ ] **Monitoring configured**
- [ ] **Backup tested**
- [ ] **Emergency procedures documented**

### Sign-off
- **Deployed by**: _________________ 
- **Date**: _________________
- **Server IP**: _________________
- **Admin Username**: _________________
- **SSL Certificate Type**: _________________ (Self-signed/CA-issued)
- **Backup Location**: _________________

### Access Information
- **Web Interface**: `https://your-server-ip`
- **Admin Panel**: `https://your-server-ip/login`
- **C2 Port**: `your-server-ip:4040`
- **SSH Access**: `ssh user@your-server-ip`

---

## 🎯 Quick Commands Reference

```bash
# Check service status
sudo systemctl status elite-rat nginx

# View logs
sudo journalctl -u elite-rat -f

# Restart services
sudo systemctl restart elite-rat nginx

# Check firewall
sudo ufw status

# Test configuration
sudo nginx -t

# View system resources
htop

# Check listening ports
sudo netstat -tlnp | grep -E ':(80|443|5000|4040)'
```

**⚠️ IMPORTANT**: Keep this checklist and update it with your specific deployment details. This serves as both a deployment guide and operational documentation.