/**
 * Process Injection UI
 * Advanced interface for process injection management
 */

class InjectionDashboard {
    constructor() {
        this.processes = [];
        this.techniques = [];
        this.selectedProcess = null;
        this.selectedTechnique = null;
        this.injectionHistory = [];
        this.filters = {
            showSystem: false,
            showCritical: false,
            onlyInjectable: true,
            searchTerm: ''
        };
        
        this.init();
    }
    
    async init() {
        // Check if injection container exists
        if (!document.getElementById('injection-dashboard')) {
            this.createDashboard();
        }
        
        // Load data
        await this.loadTechniques();
        await this.loadProcesses();
        await this.loadHistory();
        
        // Setup event listeners
        this.attachEventListeners();
        
        // Start auto-refresh
        this.startAutoRefresh();
    }
    
    createDashboard() {
        const container = document.getElementById('injection-container') || document.body;
        
        const dashboardHTML = `
            <div id="injection-dashboard" class="injection-dashboard">
                <!-- Header -->
                <div class="injection-header">
                    <h2>⚡ Process Injection Control</h2>
                    <div class="header-actions">
                        <button id="refresh-processes" class="btn btn-secondary">
                            🔄 Refresh
                        </button>
                        <button id="clear-history" class="btn btn-danger">
                            🗑️ Clear History
                        </button>
                    </div>
                </div>
                
                <!-- Main Content -->
                <div class="injection-content">
                    <!-- Left Panel: Process Explorer -->
                    <div class="process-panel">
                        <div class="panel-header">
                            <h3>Process Explorer</h3>
                            <div class="process-stats">
                                <span id="process-count">0 processes</span>
                            </div>
                        </div>
                        
                        <!-- Filters -->
                        <div class="process-filters">
                            <input type="text" id="process-search" 
                                   placeholder="Search processes..." 
                                   class="search-input">
                            
                            <div class="filter-checkboxes">
                                <label class="checkbox-label">
                                    <input type="checkbox" id="filter-system">
                                    <span>Show System</span>
                                </label>
                                <label class="checkbox-label">
                                    <input type="checkbox" id="filter-critical">
                                    <span>Show Critical</span>
                                </label>
                                <label class="checkbox-label">
                                    <input type="checkbox" id="filter-injectable" checked>
                                    <span>Only Injectable</span>
                                </label>
                            </div>
                        </div>
                        
                        <!-- Process Table -->
                        <div class="process-table-container">
                            <table id="process-table" class="process-table">
                                <thead>
                                    <tr>
                                        <th>PID</th>
                                        <th>Process</th>
                                        <th>User</th>
                                        <th>Score</th>
                                        <th>Risk</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="process-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Right Panel: Injection Control -->
                    <div class="injection-panel">
                        <!-- Selected Process Info -->
                        <div class="selected-process-card">
                            <h3>Selected Process</h3>
                            <div id="selected-process-info">
                                <p class="no-selection">No process selected</p>
                            </div>
                        </div>
                        
                        <!-- Injection Configuration -->
                        <div class="injection-config-card">
                            <h3>Injection Configuration</h3>
                            
                            <!-- Technique Selection -->
                            <div class="config-section">
                                <label>Injection Technique:</label>
                                <select id="technique-select" class="form-select">
                                    <option value="">Select technique...</option>
                                </select>
                                <div id="technique-info" class="technique-info"></div>
                            </div>
                            
                            <!-- Payload Configuration -->
                            <div class="config-section">
                                <label>Payload Type:</label>
                                <select id="payload-type" class="form-select">
                                    <option value="default">Default Shellcode</option>
                                    <option value="custom">Custom Payload</option>
                                    <option value="c2">C2 Beacon</option>
                                </select>
                            </div>
                            
                            <!-- Advanced Options -->
                            <div class="config-section">
                                <h4>Advanced Options</h4>
                                <div class="advanced-options">
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="use-stealth" checked>
                                        <span>Stealth Mode</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="cleanup-traces" checked>
                                        <span>Auto-cleanup Traces</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="use-syscalls">
                                        <span>Direct Syscalls</span>
                                    </label>
                                    <label class="checkbox-label">
                                        <input type="checkbox" id="unhook-ntdll">
                                        <span>Unhook NTDLL</span>
                                    </label>
                                </div>
                            </div>
                            
                            <!-- Execute Button -->
                            <div class="execute-section">
                                <button id="execute-injection" class="btn btn-primary btn-large">
                                    ⚡ Execute Injection
                                </button>
                            </div>
                        </div>
                        
                        <!-- Injection History -->
                        <div class="history-card">
                            <h3>Recent Injections</h3>
                            <div id="injection-history" class="injection-history">
                                <!-- Populated dynamically -->
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Status Bar -->
                <div class="injection-status-bar">
                    <div id="status-message">Ready</div>
                    <div id="status-indicator" class="status-indicator"></div>
                </div>
            </div>
        `;
        
        container.innerHTML = dashboardHTML;
        this.addStyles();
    }
    
    addStyles() {
        if (document.getElementById('injection-styles')) return;
        
        const styles = `
            <style id="injection-styles">
                .injection-dashboard {
                    padding: 20px;
                    background: var(--bg-secondary);
                    border-radius: 8px;
                    margin: 20px;
                }
                
                .injection-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid var(--border);
                }
                
                .injection-content {
                    display: grid;
                    grid-template-columns: 2fr 1fr;
                    gap: 20px;
                }
                
                .process-panel, .injection-panel {
                    background: var(--bg-primary);
                    border-radius: 8px;
                    padding: 20px;
                }
                
                .panel-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }
                
                .process-filters {
                    margin-bottom: 15px;
                }
                
                .search-input {
                    width: 100%;
                    padding: 8px 12px;
                    border: 1px solid var(--border);
                    border-radius: 4px;
                    background: var(--bg-secondary);
                    color: var(--text-primary);
                    margin-bottom: 10px;
                }
                
                .filter-checkboxes {
                    display: flex;
                    gap: 15px;
                }
                
                .checkbox-label {
                    display: flex;
                    align-items: center;
                    gap: 5px;
                    cursor: pointer;
                    font-size: 0.9rem;
                }
                
                .process-table-container {
                    max-height: 500px;
                    overflow-y: auto;
                    border: 1px solid var(--border);
                    border-radius: 4px;
                }
                
                .process-table {
                    width: 100%;
                    border-collapse: collapse;
                }
                
                .process-table th {
                    background: var(--bg-secondary);
                    padding: 10px;
                    text-align: left;
                    font-weight: 600;
                    position: sticky;
                    top: 0;
                    z-index: 10;
                }
                
                .process-table td {
                    padding: 8px 10px;
                    border-bottom: 1px solid var(--border);
                }
                
                .process-table tr:hover {
                    background: var(--bg-hover);
                }
                
                .process-table tr.selected {
                    background: var(--primary-dark);
                }
                
                .injection-score {
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 0.85rem;
                    font-weight: 600;
                }
                
                .score-high { background: #4caf50; color: white; }
                .score-medium { background: #ff9800; color: white; }
                .score-low { background: #f44336; color: white; }
                
                .risk-badge {
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 0.85rem;
                }
                
                .risk-very-low { background: #e8f5e9; color: #2e7d32; }
                .risk-low { background: #fff3e0; color: #f57c00; }
                .risk-medium { background: #fce4ec; color: #c2185b; }
                .risk-high { background: #ffebee; color: #c62828; }
                
                .select-btn {
                    padding: 4px 12px;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 0.85rem;
                }
                
                .select-btn:hover {
                    background: var(--primary-dark);
                }
                
                .selected-process-card,
                .injection-config-card,
                .history-card {
                    background: var(--bg-secondary);
                    padding: 15px;
                    border-radius: 6px;
                    margin-bottom: 15px;
                }
                
                .selected-process-card h3,
                .injection-config-card h3,
                .history-card h3 {
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid var(--border);
                }
                
                .no-selection {
                    color: var(--text-secondary);
                    font-style: italic;
                    text-align: center;
                    padding: 20px;
                }
                
                .process-info-grid {
                    display: grid;
                    grid-template-columns: auto 1fr;
                    gap: 8px;
                    font-size: 0.9rem;
                }
                
                .info-label {
                    font-weight: 600;
                    color: var(--text-secondary);
                }
                
                .config-section {
                    margin-bottom: 20px;
                }
                
                .config-section label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 600;
                    font-size: 0.9rem;
                }
                
                .form-select {
                    width: 100%;
                    padding: 8px;
                    border: 1px solid var(--border);
                    border-radius: 4px;
                    background: var(--bg-primary);
                    color: var(--text-primary);
                }
                
                .technique-info {
                    margin-top: 10px;
                    padding: 10px;
                    background: var(--bg-primary);
                    border-radius: 4px;
                    font-size: 0.85rem;
                    color: var(--text-secondary);
                }
                
                .advanced-options {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 10px;
                }
                
                .execute-section {
                    text-align: center;
                    margin-top: 20px;
                }
                
                .btn-large {
                    padding: 12px 30px;
                    font-size: 1.1rem;
                    font-weight: 600;
                }
                
                .injection-history {
                    max-height: 200px;
                    overflow-y: auto;
                }
                
                .history-item {
                    padding: 8px;
                    margin-bottom: 8px;
                    background: var(--bg-primary);
                    border-radius: 4px;
                    font-size: 0.85rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .history-success { border-left: 3px solid #4caf50; }
                .history-failed { border-left: 3px solid #f44336; }
                
                .injection-status-bar {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-top: 20px;
                    padding: 10px;
                    background: var(--bg-primary);
                    border-radius: 4px;
                }
                
                .status-indicator {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    background: #4caf50;
                }
                
                .status-indicator.error {
                    background: #f44336;
                }
                
                .status-indicator.warning {
                    background: #ff9800;
                }
                
                @media (max-width: 1200px) {
                    .injection-content {
                        grid-template-columns: 1fr;
                    }
                }
            </style>
        `;
        
        document.head.insertAdjacentHTML('beforeend', styles);
    }
    
    async loadProcesses() {
        try {
            const params = new URLSearchParams({
                show_system: this.filters.showSystem,
                show_critical: this.filters.showCritical,
                only_injectable: this.filters.onlyInjectable
            });
            
            const response = await fetch(`/api/inject/list-processes?${params}`);
            const data = await response.json();
            
            if (data.success) {
                this.processes = data.processes;
                this.renderProcessTable();
                document.getElementById('process-count').textContent = `${data.count} processes`;
            }
        } catch (error) {
            console.error('Failed to load processes:', error);
            this.showStatus('Failed to load processes', 'error');
        }
    }
    
    async loadTechniques() {
        try {
            const response = await fetch('/api/inject/techniques');
            const data = await response.json();
            
            if (data.success) {
                this.techniques = data.techniques;
                this.renderTechniqueSelect();
            }
        } catch (error) {
            console.error('Failed to load techniques:', error);
        }
    }
    
    async loadHistory() {
        try {
            const response = await fetch('/api/inject/history');
            const data = await response.json();
            
            if (data.success) {
                this.injectionHistory = data.history;
                this.renderHistory();
            }
        } catch (error) {
            console.error('Failed to load history:', error);
        }
    }
    
    renderProcessTable() {
        const tbody = document.getElementById('process-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        // Filter processes based on search
        let filtered = this.processes;
        if (this.filters.searchTerm) {
            const term = this.filters.searchTerm.toLowerCase();
            filtered = this.processes.filter(p => 
                p.name.toLowerCase().includes(term) ||
                p.pid.toString().includes(term) ||
                p.username.toLowerCase().includes(term)
            );
        }
        
        filtered.forEach(process => {
            const row = document.createElement('tr');
            row.dataset.pid = process.pid;
            
            // Score class
            let scoreClass = 'score-low';
            if (process.injection_score >= 70) scoreClass = 'score-high';
            else if (process.injection_score >= 40) scoreClass = 'score-medium';
            
            // Risk class
            const riskClass = `risk-${process.risk_level.toLowerCase().replace(' ', '-')}`;
            
            row.innerHTML = `
                <td>${process.pid}</td>
                <td title="${process.path || 'N/A'}">${process.name}</td>
                <td>${process.username}</td>
                <td><span class="injection-score ${scoreClass}">${process.injection_score}</span></td>
                <td><span class="risk-badge ${riskClass}">${process.risk_level}</span></td>
                <td>
                    <button class="select-btn" onclick="injectionDashboard.selectProcess(${process.pid})">
                        Select
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    renderTechniqueSelect() {
        const select = document.getElementById('technique-select');
        if (!select) return;
        
        select.innerHTML = '<option value="">Select technique...</option>';
        
        this.techniques.forEach(tech => {
            const option = document.createElement('option');
            option.value = tech.id;
            option.textContent = `${tech.name} (${tech.risk} Risk)`;
            select.appendChild(option);
        });
    }
    
    renderHistory() {
        const container = document.getElementById('injection-history');
        if (!container) return;
        
        if (this.injectionHistory.length === 0) {
            container.innerHTML = '<p class="no-selection">No injection history</p>';
            return;
        }
        
        container.innerHTML = '';
        
        this.injectionHistory.slice(-10).reverse().forEach(item => {
            const div = document.createElement('div');
            div.className = `history-item history-${item.success ? 'success' : 'failed'}`;
            
            const time = new Date(item.timestamp * 1000).toLocaleTimeString();
            
            div.innerHTML = `
                <div>
                    <strong>PID ${item.pid}</strong> - ${item.technique}
                    <div style="font-size: 0.75rem; color: var(--text-secondary);">${time}</div>
                </div>
                <div>
                    ${item.success ? '✅' : '❌'}
                </div>
            `;
            
            container.appendChild(div);
        });
    }
    
    selectProcess(pid) {
        this.selectedProcess = this.processes.find(p => p.pid === pid);
        
        if (!this.selectedProcess) {
            this.showStatus('Process not found', 'error');
            return;
        }
        
        // Update UI
        const infoDiv = document.getElementById('selected-process-info');
        if (infoDiv) {
            infoDiv.innerHTML = `
                <div class="process-info-grid">
                    <span class="info-label">PID:</span>
                    <span>${this.selectedProcess.pid}</span>
                    
                    <span class="info-label">Name:</span>
                    <span>${this.selectedProcess.name}</span>
                    
                    <span class="info-label">User:</span>
                    <span>${this.selectedProcess.username}</span>
                    
                    <span class="info-label">Architecture:</span>
                    <span>${this.selectedProcess.arch}</span>
                    
                    <span class="info-label">Threads:</span>
                    <span>${this.selectedProcess.threads}</span>
                    
                    <span class="info-label">Memory:</span>
                    <span>${this.selectedProcess.memory_human}</span>
                    
                    <span class="info-label">Score:</span>
                    <span>${this.selectedProcess.injection_score}</span>
                    
                    <span class="info-label">Recommended:</span>
                    <span>${this.selectedProcess.recommended_technique}</span>
                </div>
            `;
        }
        
        // Highlight selected row
        document.querySelectorAll('.process-table tr').forEach(tr => {
            tr.classList.remove('selected');
        });
        
        const selectedRow = document.querySelector(`tr[data-pid="${pid}"]`);
        if (selectedRow) {
            selectedRow.classList.add('selected');
        }
        
        // Auto-select recommended technique
        const techniqueSelect = document.getElementById('technique-select');
        if (techniqueSelect) {
            const recommended = this.techniques.find(t => 
                t.name === this.selectedProcess.recommended_technique
            );
            if (recommended) {
                techniqueSelect.value = recommended.id;
                this.updateTechniqueInfo();
            }
        }
        
        this.showStatus(`Selected process: ${this.selectedProcess.name} (PID ${pid})`, 'success');
    }
    
    updateTechniqueInfo() {
        const select = document.getElementById('technique-select');
        const infoDiv = document.getElementById('technique-info');
        
        if (!select || !infoDiv) return;
        
        const technique = this.techniques.find(t => t.id === select.value);
        
        if (technique) {
            infoDiv.innerHTML = `
                <strong>${technique.name}</strong><br>
                Risk Level: ${technique.risk}<br>
                ${this.getTechniqueDescription(technique.id)}
            `;
        } else {
            infoDiv.innerHTML = '';
        }
    }
    
    getTechniqueDescription(id) {
        const descriptions = {
            'createremotethread': 'Classic injection using CreateRemoteThread API',
            'setwindowshook': 'Inject via Windows hook procedures',
            'queueuserapc': 'Queue an Asynchronous Procedure Call to target thread',
            'hollowing': 'Replace legitimate process memory with malicious code',
            'manual': 'Manually map DLL without Windows loader',
            'reflective': 'DLL loads itself without external dependencies',
            'ptrace': 'Linux process tracing and manipulation',
            'proc_mem': 'Direct memory writing via /proc/[pid]/mem',
            'ld_preload': 'Library injection via LD_PRELOAD environment variable',
            'dlopen': 'Force library loading with dlopen'
        };
        
        return descriptions[id] || 'Advanced injection technique';
    }
    
    async executeInjection() {
        if (!this.selectedProcess) {
            this.showStatus('Please select a process first', 'error');
            return;
        }
        
        const technique = document.getElementById('technique-select').value;
        if (!technique) {
            this.showStatus('Please select an injection technique', 'error');
            return;
        }
        
        // Gather configuration
        const config = {
            pid: this.selectedProcess.pid,
            technique: technique,
            payload_type: document.getElementById('payload-type').value,
            options: {
                stealth: document.getElementById('use-stealth').checked,
                cleanup: document.getElementById('cleanup-traces').checked,
                syscalls: document.getElementById('use-syscalls').checked,
                unhook: document.getElementById('unhook-ntdll').checked
            }
        };
        
        // Disable button
        const btn = document.getElementById('execute-injection');
        btn.disabled = true;
        btn.textContent = 'Executing...';
        
        this.showStatus('Executing injection...', 'warning');
        
        try {
            const response = await fetch('/api/inject/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showStatus(`Injection successful! ID: ${result.injection_id}`, 'success');
                
                // Add to history
                this.injectionHistory.push({
                    id: result.injection_id,
                    pid: config.pid,
                    technique: technique,
                    timestamp: Date.now() / 1000,
                    success: true
                });
                
                this.renderHistory();
            } else {
                this.showStatus(`Injection failed: ${result.error}`, 'error');
            }
            
        } catch (error) {
            this.showStatus(`Error: ${error.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = '⚡ Execute Injection';
        }
    }
    
    attachEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('refresh-processes');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadProcesses());
        }
        
        // Clear history
        const clearBtn = document.getElementById('clear-history');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.injectionHistory = [];
                this.renderHistory();
                this.showStatus('History cleared', 'success');
            });
        }
        
        // Search
        const searchInput = document.getElementById('process-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filters.searchTerm = e.target.value;
                this.renderProcessTable();
            });
        }
        
        // Filters
        document.getElementById('filter-system')?.addEventListener('change', (e) => {
            this.filters.showSystem = e.target.checked;
            this.loadProcesses();
        });
        
        document.getElementById('filter-critical')?.addEventListener('change', (e) => {
            this.filters.showCritical = e.target.checked;
            this.loadProcesses();
        });
        
        document.getElementById('filter-injectable')?.addEventListener('change', (e) => {
            this.filters.onlyInjectable = e.target.checked;
            this.loadProcesses();
        });
        
        // Technique select
        document.getElementById('technique-select')?.addEventListener('change', () => {
            this.updateTechniqueInfo();
        });
        
        // Execute button
        document.getElementById('execute-injection')?.addEventListener('click', () => {
            this.executeInjection();
        });
    }
    
    showStatus(message, type = 'info') {
        const statusMsg = document.getElementById('status-message');
        const statusIndicator = document.getElementById('status-indicator');
        
        if (statusMsg) {
            statusMsg.textContent = message;
        }
        
        if (statusIndicator) {
            statusIndicator.className = `status-indicator ${type}`;
        }
        
        // Auto-clear after 5 seconds
        setTimeout(() => {
            if (statusMsg && statusMsg.textContent === message) {
                statusMsg.textContent = 'Ready';
                statusIndicator.className = 'status-indicator';
            }
        }, 5000);
    }
    
    startAutoRefresh() {
        // Refresh process list every 30 seconds
        setInterval(() => {
            this.loadProcesses();
        }, 30000);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.injectionDashboard = new InjectionDashboard();
    });
} else {
    window.injectionDashboard = new InjectionDashboard();
}