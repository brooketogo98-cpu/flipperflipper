#!/bin/bash
#############################################################
# FIX VPS ACCESS - Make Flask app accessible from public IP
#############################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}     FIXING VPS ACCESS FOR FLASK APP${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "YOUR_VPS_IP")
echo -e "\n${GREEN}Public IP detected: ${PUBLIC_IP}${NC}"

# 1. Kill existing Flask processes
echo -e "\n${YELLOW}[1/6] Stopping existing Flask processes...${NC}"
pkill -f "python.*start_server" 2>/dev/null || true
pkill -f "python.*web_app_real" 2>/dev/null || true
pkill -f "flask" 2>/dev/null || true
fuser -k 5000/tcp 2>/dev/null || true
echo -e "${GREEN}✓ Processes stopped${NC}"

# 2. Configure UFW firewall
echo -e "\n${YELLOW}[2/6] Configuring firewall...${NC}"

# Check if UFW is installed and active
if command -v ufw &> /dev/null; then
    # Allow required ports
    sudo ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
    sudo ufw allow 5000/tcp comment 'Flask App' 2>/dev/null || true
    sudo ufw allow 80/tcp comment 'HTTP' 2>/dev/null || true
    sudo ufw allow 443/tcp comment 'HTTPS' 2>/dev/null || true
    
    # Enable UFW if not already
    sudo ufw --force enable 2>/dev/null || true
    
    echo -e "${GREEN}✓ UFW firewall configured${NC}"
    echo "  Allowed ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 5000 (Flask)"
else
    echo -e "${YELLOW}UFW not found, checking iptables...${NC}"
    
    # Use iptables as fallback
    sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
    sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    
    # Save iptables rules
    if command -v netfilter-persistent &> /dev/null; then
        sudo netfilter-persistent save 2>/dev/null || true
    elif [ -f /etc/iptables/rules.v4 ]; then
        sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ iptables configured${NC}"
fi

# 3. Create improved start script
echo -e "\n${YELLOW}[3/6] Creating improved start script...${NC}"

cat > /workspace/start_server_fixed.py << 'EOF'
#!/usr/bin/env python3
"""
Improved Flask server starter with proper host binding
"""

import os
import sys
import time
import socket
import signal
import argparse

def check_port(host='0.0.0.0', port=5000):
    """Check if a port is available"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def kill_existing_server(port=5000):
    """Kill any process using the specified port"""
    import subprocess
    try:
        # Find and kill process using the port
        result = subprocess.run(
            f"lsof -t -i:{port}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                    print(f"Killed existing process {pid} on port {port}")
                except:
                    pass
            time.sleep(2)
    except:
        pass

def main():
    parser = argparse.ArgumentParser(description='Start Flask server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--production', action='store_true', help='Run in production mode')
    args = parser.parse_args()

    # Set environment variables
    os.environ['STITCH_DEBUG'] = 'true' if args.debug else 'false'
    os.environ['STITCH_ADMIN_USER'] = os.environ.get('ADMIN_USER', 'admin')
    os.environ['STITCH_ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD', 'SuperSecurePass123!')
    
    # Add workspace to path
    sys.path.insert(0, '/workspace')
    
    # Check and kill existing server
    if check_port(args.host, args.port):
        print(f"Port {args.port} is in use, stopping existing server...")
        kill_existing_server(args.port)
    
    # Get public IP
    try:
        import urllib.request
        public_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
    except:
        public_ip = args.host
    
    print("="*60)
    print(" ELITE RAT C2 - WEB SERVER ")
    print("="*60)
    print(f"\nStarting server on {args.host}:{args.port}")
    print(f"\nAccess URLs:")
    print(f"  Local:    http://localhost:{args.port}")
    if public_ip != '0.0.0.0':
        print(f"  Public:   http://{public_ip}:{args.port}")
    print(f"\nCredentials:")
    print(f"  Username: {os.environ.get('STITCH_ADMIN_USER', 'admin')}")
    print(f"  Password: {os.environ.get('STITCH_ADMIN_PASSWORD', 'SuperSecurePass123!')}")
    print("="*60)
    
    try:
        from web_app_real import app, socketio
        
        # Configure for production if specified
        if args.production:
            app.config['ENV'] = 'production'
            app.config['DEBUG'] = False
            
        # Try to use socketio.run first (for WebSocket support)
        try:
            socketio.run(
                app,
                host=args.host,
                port=args.port,
                debug=args.debug,
                use_reloader=False,
                log_output=True
            )
        except:
            # Fallback to regular Flask app.run
            print("\nFalling back to Flask's built-in server...")
            app.run(
                host=args.host,
                port=args.port,
                debug=args.debug,
                use_reloader=False
            )
            
    except ImportError as e:
        print(f"\nError: Missing module - {e}")
        print("\nInstalling required modules...")
        os.system("pip install flask flask-socketio flask-cors flask-login flask-limiter flask-wtf email-validator pycryptodome")
        print("\nPlease run the script again after installation completes.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF

chmod +x /workspace/start_server_fixed.py

echo -e "${GREEN}✓ Improved start script created${NC}"

# 4. Test port accessibility
echo -e "\n${YELLOW}[4/6] Testing port accessibility...${NC}"

# Check if port 5000 is open externally
timeout 2 nc -zv $PUBLIC_IP 5000 2>/dev/null && echo -e "${GREEN}✓ Port 5000 is accessible${NC}" || echo -e "${YELLOW}⚠ Port 5000 not yet accessible (will be after starting server)${NC}"

# 5. Create systemd service (optional but recommended)
echo -e "\n${YELLOW}[5/6] Creating systemd service (optional)...${NC}"

sudo tee /etc/systemd/system/flask-app.service > /dev/null << EOF
[Unit]
Description=Flask Elite RAT Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/workspace
Environment="PATH=/usr/bin:/bin:/usr/local/bin"
Environment="ADMIN_USER=admin"
Environment="ADMIN_PASSWORD=SuperSecurePass123!"
ExecStart=/usr/bin/python3 /workspace/start_server_fixed.py --host 0.0.0.0 --port 5000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Systemd service created${NC}"

# 6. Create Nginx config (optional)
echo -e "\n${YELLOW}[6/6] Creating Nginx config (optional)...${NC}"

if command -v nginx &> /dev/null; then
    sudo tee /etc/nginx/sites-available/flask-app > /dev/null << EOF
server {
    listen 80;
    server_name $PUBLIC_IP;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
EOF
    
    echo -e "${GREEN}✓ Nginx config created (not activated)${NC}"
else
    echo -e "${YELLOW}Nginx not installed (optional)${NC}"
fi

# Final instructions
echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}      SETUP COMPLETE!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}🚀 QUICK START:${NC}"
echo -e "${GREEN}python3 /workspace/start_server_fixed.py${NC}"

echo -e "\n${YELLOW}🎯 ADVANCED OPTIONS:${NC}"
echo "python3 /workspace/start_server_fixed.py --help"
echo "python3 /workspace/start_server_fixed.py --port 8080"
echo "python3 /workspace/start_server_fixed.py --production"

echo -e "\n${YELLOW}🔧 SYSTEMD SERVICE (for persistent running):${NC}"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl start flask-app"
echo "sudo systemctl enable flask-app  # Auto-start on boot"
echo "sudo systemctl status flask-app"

echo -e "\n${YELLOW}🌐 NGINX REVERSE PROXY (to use port 80):${NC}"
echo "sudo ln -s /etc/nginx/sites-available/flask-app /etc/nginx/sites-enabled/"
echo "sudo nginx -t"
echo "sudo systemctl restart nginx"

echo -e "\n${YELLOW}📱 ACCESS YOUR APP:${NC}"
echo -e "${GREEN}Direct:${NC} http://$PUBLIC_IP:5000"
if command -v nginx &> /dev/null; then
    echo -e "${GREEN}Via Nginx:${NC} http://$PUBLIC_IP"
fi

echo -e "\n${YELLOW}🔍 TROUBLESHOOTING:${NC}"
echo "Check if server is running:  ps aux | grep python"
echo "Check listening ports:       sudo netstat -tulpn | grep :5000"
echo "Check firewall status:       sudo ufw status"
echo "View logs:                   journalctl -u flask-app -f"
echo "Test locally:                curl http://localhost:5000"

echo -e "\n${BLUE}═══════════════════════════════════════════════${NC}"