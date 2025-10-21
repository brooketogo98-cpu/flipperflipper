#!/bin/bash
#############################################################
# VPS SECURITY HARDENING & MONITORING SETUP
# Run after deploy.sh for enhanced security
#############################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Change SSH port for security
secure_ssh() {
    log "Securing SSH configuration..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Change SSH port to 2222 (or any non-standard port)
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
    
    # Disable root login after creating admin user
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (after setting up keys)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Allow the new port in firewall
    ufw allow 2222/tcp comment 'SSH-Custom' > /dev/null 2>&1
    
    log "SSH secured on port 2222"
}

# Install fail2ban for brute force protection
install_fail2ban() {
    log "Installing Fail2ban..."
    
    apt-get install -y fail2ban > /dev/null 2>&1
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    systemctl restart fail2ban
    
    log "Fail2ban configured"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Install monitoring tools
    apt-get install -y htop iftop nethogs vnstat > /dev/null 2>&1
    
    # Create monitoring script
    cat > /opt/elite_rat/monitor.sh << 'EOF'
#!/bin/bash

# Simple monitoring dashboard
while true; do
    clear
    echo "==================================="
    echo "ELITE RAT C2 - SYSTEM MONITOR"
    echo "==================================="
    echo ""
    
    # System info
    echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 ")"}')"
    echo ""
    
    # Network connections
    echo "Active C2 Connections:"
    netstat -tn 2>/dev/null | grep :5555 | grep ESTABLISHED | wc -l
    echo ""
    
    echo "Web Interface Connections:"
    netstat -tn 2>/dev/null | grep :5000 | grep ESTABLISHED | wc -l
    echo ""
    
    # Service status
    echo "Service Status:"
    systemctl is-active elite_rat > /dev/null 2>&1 && echo "✓ Elite RAT: Running" || echo "✗ Elite RAT: Stopped"
    echo ""
    
    # Recent logs
    echo "Recent Activity:"
    journalctl -u elite_rat -n 5 --no-pager 2>/dev/null | tail -5
    
    sleep 5
done
EOF
    
    chmod +x /opt/elite_rat/monitor.sh
    
    log "Monitoring script created"
}

# Create admin user
create_admin_user() {
    log "Creating admin user..."
    
    # Check if elite_admin already exists
    if ! id "elite_admin" &>/dev/null; then
        # Create user
        useradd -m -s /bin/bash elite_admin
        
        # Set password (you should change this)
        echo "elite_admin:EliteAdmin2024!" | chpasswd
        
        # Add to sudo group
        usermod -aG sudo elite_admin
        
        # Create SSH directory
        mkdir -p /home/elite_admin/.ssh
        chmod 700 /home/elite_admin/.ssh
        
        # Copy root's authorized_keys if exists
        if [ -f /root/.ssh/authorized_keys ]; then
            cp /root/.ssh/authorized_keys /home/elite_admin/.ssh/
            chown -R elite_admin:elite_admin /home/elite_admin/.ssh
        fi
        
        log "Admin user 'elite_admin' created"
        log "Default password: EliteAdmin2024! (CHANGE THIS!)"
    else
        log "Admin user already exists"
    fi
}

# Setup backup
setup_backup() {
    log "Setting up automated backups..."
    
    # Create backup directory
    mkdir -p /opt/backups
    
    # Create backup script
    cat > /opt/elite_rat/backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/elite_rat_$DATE.tar.gz"

# Create backup
tar -czf $BACKUP_FILE \
    --exclude='/opt/elite_rat/venv' \
    --exclude='/opt/elite_rat/.git' \
    /opt/elite_rat 2>/dev/null

# Keep only last 7 backups
ls -t $BACKUP_DIR/elite_rat_*.tar.gz | tail -n +8 | xargs rm -f 2>/dev/null

echo "[$(date)] Backup created: $BACKUP_FILE"
EOF
    
    chmod +x /opt/elite_rat/backup.sh
    
    # Add to crontab (daily at 3 AM)
    (crontab -l 2>/dev/null; echo "0 3 * * * /opt/elite_rat/backup.sh >> /var/log/elite_backup.log 2>&1") | crontab -
    
    log "Automated backups configured"
}

# Install additional tools
install_tools() {
    log "Installing additional tools..."
    
    apt-get install -y \
        ncdu \
        tree \
        jq \
        tmux \
        screen \
        nmap \
        tcpdump \
        dnsutils \
        whois \
        > /dev/null 2>&1
    
    log "Tools installed"
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/elite_rat << 'EOF'
/var/log/elite_rat*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl reload elite_rat > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log "Log rotation configured"
}

# Display final info
show_security_info() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}SECURITY HARDENING COMPLETE!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT CHANGES:${NC}"
    echo ""
    echo -e "1. ${RED}SSH Port Changed:${NC} 2222 (was 22)"
    echo -e "   Connect with: ${GREEN}ssh -p 2222 elite_admin@$(curl -s ifconfig.me)${NC}"
    echo ""
    echo -e "2. ${RED}New Admin User:${NC}"
    echo -e "   Username: ${GREEN}elite_admin${NC}"
    echo -e "   Password: ${GREEN}EliteAdmin2024!${NC} ${RED}(CHANGE THIS!)${NC}"
    echo ""
    echo -e "3. ${YELLOW}Security Features:${NC}"
    echo -e "   ✓ Fail2ban (brute force protection)"
    echo -e "   ✓ Automated backups (daily at 3 AM)"
    echo -e "   ✓ Log rotation (7 days)"
    echo -e "   ✓ System monitoring"
    echo ""
    echo -e "4. ${YELLOW}Monitoring Tools:${NC}"
    echo -e "   Live monitor: ${GREEN}/opt/elite_rat/monitor.sh${NC}"
    echo -e "   Network: ${GREEN}iftop${NC}, ${GREEN}nethogs${NC}"
    echo -e "   System: ${GREEN}htop${NC}, ${GREEN}vnstat${NC}"
    echo ""
    echo -e "${RED}⚠️  TODO:${NC}"
    echo -e "   1. Change elite_admin password: ${GREEN}passwd elite_admin${NC}"
    echo -e "   2. Setup SSH keys and disable password auth"
    echo -e "   3. Configure Plesk if needed"
    echo ""
    echo "=========================================="
}

# Main
main() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}VPS SECURITY HARDENING${NC}"
    echo "=========================================="
    echo ""
    
    create_admin_user
    secure_ssh
    install_fail2ban
    setup_monitoring
    setup_backup
    install_tools
    setup_log_rotation
    show_security_info
}

main