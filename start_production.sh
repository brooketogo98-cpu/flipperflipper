#!/bin/bash
# Elite RAT Production Startup Script for Ubuntu Server
# This script provides easy management of the Elite RAT service

set -e

# Configuration
SERVICE_NAME="elite-rat"
INSTALL_DIR="/opt/elite-rat"
CONFIG_FILE="/etc/elite-rat/production.env"
LOG_DIR="/var/log/elite-rat"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_service_exists() {
    if ! systemctl list-units --full -all | grep -Fq "$SERVICE_NAME.service"; then
        print_error "Service $SERVICE_NAME not found. Run deployment script first."
        exit 1
    fi
}

show_status() {
    print_status "Elite RAT Service Status:"
    echo "=========================="
    
    # Service status
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Service is running"
    else
        print_error "Service is not running"
    fi
    
    # Detailed status
    systemctl status $SERVICE_NAME --no-pager -l
    
    echo ""
    print_status "Port Status:"
    echo "============"
    netstat -tlnp | grep -E ':(80|443|5000|4040) ' || echo "No services listening on expected ports"
    
    echo ""
    print_status "Recent Logs:"
    echo "============"
    journalctl -u $SERVICE_NAME --no-pager -n 10
}

start_service() {
    print_status "Starting Elite RAT service..."
    
    # Check configuration
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Check if default passwords are still in use
    if grep -q "CHANGE_THIS" "$CONFIG_FILE"; then
        print_error "Default passwords detected in configuration!"
        print_error "Please edit $CONFIG_FILE and set secure passwords"
        exit 1
    fi
    
    # Start services
    systemctl start nginx
    systemctl start $SERVICE_NAME
    
    # Wait a moment for startup
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Elite RAT started successfully"
        show_access_info
    else
        print_error "Failed to start Elite RAT"
        journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
}

stop_service() {
    print_status "Stopping Elite RAT service..."
    systemctl stop $SERVICE_NAME
    print_success "Elite RAT stopped"
}

restart_service() {
    print_status "Restarting Elite RAT service..."
    systemctl restart nginx
    systemctl restart $SERVICE_NAME
    
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Elite RAT restarted successfully"
    else
        print_error "Failed to restart Elite RAT"
        journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
}

show_logs() {
    print_status "Elite RAT Logs (Press Ctrl+C to exit):"
    echo "======================================"
    journalctl -u $SERVICE_NAME -f
}

show_access_info() {
    echo ""
    print_status "Access Information:"
    echo "=================="
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo "Web Interface URLs:"
    echo "  HTTP:  http://$SERVER_IP"
    echo "  HTTPS: https://$SERVER_IP"
    echo ""
    echo "C2 Server Port: 4040"
    echo ""
    
    # Show admin credentials from config
    if [[ -f "$CONFIG_FILE" ]]; then
        ADMIN_USER=$(grep "STITCH_ADMIN_USER=" "$CONFIG_FILE" | cut -d'=' -f2)
        echo "Admin Username: $ADMIN_USER"
        echo "Admin Password: (check $CONFIG_FILE)"
    fi
    
    echo ""
    print_warning "Security Reminders:"
    echo "- Ensure firewall is properly configured"
    echo "- Use strong passwords"
    echo "- Monitor access logs regularly"
    echo "- Keep system updated"
}

configure_service() {
    print_status "Opening configuration file for editing..."
    
    if command -v nano &> /dev/null; then
        nano "$CONFIG_FILE"
    elif command -v vim &> /dev/null; then
        vim "$CONFIG_FILE"
    else
        print_error "No text editor found. Please edit $CONFIG_FILE manually"
        exit 1
    fi
    
    print_status "Configuration updated. Restart service to apply changes."
}

backup_data() {
    print_status "Creating backup of Elite RAT data..."
    
    BACKUP_DIR="/tmp/elite-rat-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup configuration
    cp -r /etc/elite-rat "$BACKUP_DIR/"
    
    # Backup data
    if [[ -d "/var/lib/elite-rat" ]]; then
        cp -r /var/lib/elite-rat "$BACKUP_DIR/"
    fi
    
    # Backup logs
    cp -r "$LOG_DIR" "$BACKUP_DIR/"
    
    # Create archive
    tar -czf "${BACKUP_DIR}.tar.gz" -C /tmp "$(basename $BACKUP_DIR)"
    rm -rf "$BACKUP_DIR"
    
    print_success "Backup created: ${BACKUP_DIR}.tar.gz"
}

update_service() {
    print_status "Updating Elite RAT service..."
    
    # Stop service
    systemctl stop $SERVICE_NAME
    
    # Backup current installation
    backup_data
    
    # Update from workspace (if available)
    if [[ -d "/workspace" ]]; then
        print_status "Updating from /workspace..."
        
        # Update Python files
        for file in web_app_real.py config.py auth_utils.py web_app_enhancements.py ssl_utils.py; do
            if [[ -f "/workspace/$file" ]]; then
                cp "/workspace/$file" "$INSTALL_DIR/"
                chown elite-rat:elite-rat "$INSTALL_DIR/$file"
                print_status "Updated: $file"
            fi
        done
        
        # Update requirements
        if [[ -f "/workspace/requirements_production.txt" ]]; then
            cp "/workspace/requirements_production.txt" "$INSTALL_DIR/"
            
            # Update Python packages
            sudo -u elite-rat "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements_production.txt"
            print_status "Updated Python packages"
        fi
    else
        print_warning "No /workspace directory found. Manual update required."
    fi
    
    # Restart service
    systemctl start $SERVICE_NAME
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Elite RAT updated successfully"
    else
        print_error "Update failed. Check logs for details."
        exit 1
    fi
}

show_help() {
    echo "Elite RAT Production Management Script"
    echo "====================================="
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     - Start the Elite RAT service"
    echo "  stop      - Stop the Elite RAT service"
    echo "  restart   - Restart the Elite RAT service"
    echo "  status    - Show service status and information"
    echo "  logs      - Show live service logs"
    echo "  config    - Edit configuration file"
    echo "  backup    - Create backup of data and configuration"
    echo "  update    - Update service from workspace"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 start"
    echo "  sudo $0 status"
    echo "  sudo $0 logs"
}

# Main script logic
case "${1:-help}" in
    start)
        check_root
        check_service_exists
        start_service
        ;;
    stop)
        check_root
        check_service_exists
        stop_service
        ;;
    restart)
        check_root
        check_service_exists
        restart_service
        ;;
    status)
        check_service_exists
        show_status
        ;;
    logs)
        check_service_exists
        show_logs
        ;;
    config)
        check_root
        configure_service
        ;;
    backup)
        check_root
        backup_data
        ;;
    update)
        check_root
        check_service_exists
        update_service
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac