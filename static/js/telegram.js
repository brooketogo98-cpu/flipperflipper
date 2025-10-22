/**
 * Telegram OSINT Module - Frontend JavaScript
 * For authorized security research only
 */

let scrapedMembers = [];
let massDMRunning = false;
let massDMPaused = false;

/**
 * Save Telegram API configuration
 */
async function saveTelegramConfig() {
    const apiId = document.getElementById('telegram-api-id').value;
    const apiHash = document.getElementById('telegram-api-hash').value;
    const phone = document.getElementById('telegram-phone').value;
    
    if (!apiId || !apiHash || !phone) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/telegram/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                api_id: apiId,
                api_hash: apiHash,
                phone: phone
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('✅ Configuration saved!', 'success');
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

/**
 * Test Telegram authentication
 */
async function testTelegramAuth() {
    showNotification('Testing authentication...', 'info');
    
    try {
        const response = await fetch('/api/telegram/auth', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('✅ Authentication successful!', 'success');
        } else {
            showNotification(`Authentication failed: ${data.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

/**
 * Scrape members from channel/group
 */
async function scrapeMembers() {
    const target = document.getElementById('scrape-target').value;
    const includeAdmins = document.getElementById('scrape-admins').checked;
    const includeBots = document.getElementById('scrape-bots').checked;
    const includeHidden = document.getElementById('scrape-hidden').checked;
    
    if (!target) {
        showNotification('Please enter a target channel', 'error');
        return;
    }
    
    // Show status
    const statusDiv = document.getElementById('scrape-status');
    const progressDiv = document.getElementById('scrape-progress');
    statusDiv.style.display = 'block';
    progressDiv.innerHTML = '🔍 Starting scraper...';
    
    try {
        const response = await fetch('/api/telegram/scrape', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target: target,
                include_admins: includeAdmins,
                include_bots: includeBots,
                aggressive: includeHidden
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            scrapedMembers = data.members;
            displayMembers(data.members);
            progressDiv.innerHTML = `✅ Successfully scraped ${data.count} members!`;
            showNotification(`Scraped ${data.count} members`, 'success');
        } else {
            progressDiv.innerHTML = `❌ Error: ${data.error}`;
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        progressDiv.innerHTML = `❌ Error: ${error.message}`;
        showNotification(`Error: ${error.message}`, 'error');
    }
}

/**
 * Display scraped members in table
 */
function displayMembers(members) {
    const tbody = document.getElementById('members-tbody');
    const countSpan = document.getElementById('member-count');
    
    countSpan.textContent = members.length;
    
    if (members.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; color: #999;">
                    No members found
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = members.map(member => `
        <tr>
            <td>@${member.username || '(no username)'}</td>
            <td>${member.first_name} ${member.last_name}</td>
            <td>${member.id}</td>
            <td>${member.phone || 'N/A'}</td>
            <td>
                <span class="badge ${getStatusBadgeClass(member.status)}">
                    ${member.status}
                </span>
            </td>
            <td>
                <button onclick="sendSingleDM(${member.id})" class="btn-small">
                    Send DM
                </button>
            </td>
        </tr>
    `).join('');
}

/**
 * Get badge class for status
 */
function getStatusBadgeClass(status) {
    switch(status) {
        case 'Online': return 'badge-success';
        case 'Recently': return 'badge-info';
        case 'Offline': return 'badge-secondary';
        default: return 'badge-default';
    }
}

/**
 * Export members to CSV
 */
async function exportMembers() {
    if (scrapedMembers.length === 0) {
        showNotification('No members to export', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/telegram/export', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({format: 'csv'})
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`✅ Exported to ${data.filename}`, 'success');
            
            // Download file
            window.location.href = `/api/download/${data.filename}`;
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

/**
 * Start mass DM campaign
 */
async function startMassDM() {
    if (scrapedMembers.length === 0) {
        showNotification('No members loaded. Scrape first!', 'error');
        return;
    }
    
    const message = document.getElementById('mass-message').value;
    const delay = parseInt(document.getElementById('message-delay').value);
    const limit = parseInt(document.getElementById('message-limit').value);
    const randomize = document.getElementById('randomize-delay').checked;
    const skipSent = document.getElementById('skip-sent').checked;
    
    if (!message) {
        showNotification('Please enter a message', 'error');
        return;
    }
    
    // Confirm action
    const confirmed = confirm(
        `⚠️ WARNING: You are about to send ${Math.min(scrapedMembers.length, limit)} messages.\n\n` +
        `This may result in:\n` +
        `• Your Telegram account being banned\n` +
        `• Legal consequences if unauthorized\n` +
        `• Spam reports\n\n` +
        `Are you SURE you want to continue?`
    );
    
    if (!confirmed) {
        return;
    }
    
    // Show status
    const statusDiv = document.getElementById('mass-dm-status');
    const progressDiv = document.getElementById('dm-progress');
    const statsDiv = document.getElementById('dm-stats');
    
    statusDiv.style.display = 'block';
    progressDiv.innerHTML = '🚀 Starting mass DM campaign...';
    massDMRunning = true;
    
    try {
        const response = await fetch('/api/telegram/mass-dm', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                message: message,
                delay: delay,
                max_messages: limit,
                randomize_delay: randomize,
                skip_sent: skipSent
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const stats = data.stats;
            progressDiv.innerHTML = '✅ Mass DM campaign complete!';
            statsDiv.innerHTML = `
                <strong>Results:</strong><br>
                ✅ Success: ${stats.success}<br>
                ❌ Failed: ${stats.failed}<br>
                ⏭️ Skipped: ${stats.skipped}<br>
                ⚠️ Flood waits: ${stats.flood_wait}
            `;
            showNotification(`Campaign complete! Sent ${stats.success} messages`, 'success');
        } else {
            progressDiv.innerHTML = `❌ Error: ${data.error}`;
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        progressDiv.innerHTML = `❌ Error: ${error.message}`;
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        massDMRunning = false;
    }
}

/**
 * Pause mass DM
 */
function pauseMassDM() {
    massDMPaused = !massDMPaused;
    const button = event.target;
    
    if (massDMPaused) {
        button.textContent = '▶️ Resume';
        showNotification('Mass DM paused', 'info');
    } else {
        button.textContent = '⏸️ Pause';
        showNotification('Mass DM resumed', 'info');
    }
}

/**
 * Stop mass DM
 */
function stopMassDM() {
    massDMRunning = false;
    showNotification('Mass DM stopped', 'info');
    
    const statusDiv = document.getElementById('mass-dm-status');
    const progressDiv = document.getElementById('dm-progress');
    progressDiv.innerHTML = '⏹️ Stopped by user';
}

/**
 * Send DM to single user
 */
async function sendSingleDM(userId) {
    const message = prompt('Enter message to send:');
    if (!message) return;
    
    showNotification(`Sending DM to user ${userId}...`, 'info');
    
    // Implementation would go here
    showNotification('Single DM feature coming soon', 'info');
}

/**
 * Show notification
 */
function showNotification(message, type) {
    // Use existing notification system or create alert
    if (typeof addLog === 'function') {
        addLog(message, type);
    } else {
        console.log(`[${type}] ${message}`);
        alert(message);
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('✈️ Telegram OSINT module loaded');
});
