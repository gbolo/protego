// Global state
let users = [];
let acls = {};
let metrics = {};
let currentUserId = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    loadAllData();
    loadMetrics();
    loadConfig();
    setupACLToggle();
});

// Tab switching
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update button states
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-tab') === tabName) {
            btn.classList.add('active');
        }
    });

    // Update content visibility
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// ACL Allow All toggle
function setupACLToggle() {
    const aclAllowAll = document.getElementById('acl_allow_all');
    const allowedHostsGroup = document.getElementById('allowed-hosts-group');
    
    aclAllowAll.addEventListener('change', (e) => {
        if (e.target.checked) {
            allowedHostsGroup.style.display = 'none';
        } else {
            allowedHostsGroup.style.display = 'block';
        }
    });
}

// Load users from API
async function loadUsers() {
    try {
        const response = await fetch('/api/v1/user');
        const data = await response.json();
        users = Array.isArray(data) ? data : (data.users || []);
        // Don't display yet - wait for ACLs to load too
    } catch (error) {
        console.error('Error loading users:', error);
        alert('Failed to load users');
    }
}

// Load ACLs from API
async function loadACLs() {
    try {
        const response = await fetch('/api/v1/acl');
        const data = await response.json();
        acls = data || {};
    } catch (error) {
        console.error('Error loading ACLs:', error);
    }
}

// Load both users and ACLs, then display
async function loadAllData() {
    await Promise.all([loadUsers(), loadACLs(), loadMetrics()]);
    displayUsers();
    updateDashboard();
}

// Display users in table
function displayUsers() {
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '';

    users.forEach(user => {
        // Count total IPs including those from ACL
        const totalIPs = getTotalIPsForUser(user);
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${user.id}</code></td>
            <td>${user.description || '-'}</td>
            <td>
                <span class="badge ${user.enabled ? 'badge-success' : 'badge-danger'}">
                    ${user.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </td>
            <td>
                <span class="badge ${user.acl_allow_all ? 'badge-info' : 'badge-warning'}">
                    ${user.acl_allow_all ? 'Allow All' : 'Restricted'}
                </span>
            </td>
            <td>${(user.acl_allowed_hosts || []).join(', ') || '-'}</td>
            <td>
                <button class="btn btn-sm btn-manage" onclick="showIPModal('${user.id}')">
                    📋 Manage <span class="ip-count">${totalIPs}</span>
                </button>
            </td>
            <td class="actions">
                <button class="btn btn-sm btn-edit" onclick="editUser('${user.id}')">✏️ Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.id}')">🗑️ Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Get total IPs for a user (manual + ACL)
function getTotalIPsForUser(user) {
    const allIPs = new Set(user.ips || []);
    
    // Add IPs from ACLs that belong to this user
    Object.keys(acls).forEach(ip => {
        const acl = acls[ip];
        // Check if this ACL matches the user's ACL settings
        if (user.acl_allowed_hosts && acl.allowed_hosts) {
            const aclHosts = acl.allowed_hosts.sort().join(',');
            const userHosts = user.acl_allowed_hosts.sort().join(',');
            if (aclHosts === userHosts) {
                allIPs.add(ip);
            }
        }
    });
    
    return allIPs.size;
}

// Update dashboard statistics
function updateDashboard() {
    const totalUsers = users.length;
    const enabledUsers = users.filter(u => u.enabled).length;
    const totalIPs = users.reduce((sum, u) => sum + (u.ips || []).length, 0);

    document.getElementById('stat-total-users').textContent = totalUsers;
    document.getElementById('stat-enabled-users').textContent = enabledUsers;
    document.getElementById('stat-total-ips').textContent = totalIPs;

    // Display IP addresses with their associated users
    displayIPAddresses();
}

// Display all IP addresses with their associated users
function displayIPAddresses() {
    const tbody = document.getElementById('ip-tbody');
    tbody.innerHTML = '';

    // Collect all IPs from both user.ips and ACLs
    const ipList = [];
    const processedIPs = new Set();
    
    // First, add IPs from user.ips field (manually added via UI)
    users.forEach(user => {
        if (user.ips && user.ips.length > 0) {
            user.ips.forEach(ip => {
                processedIPs.add(ip);
                ipList.push({
                    ip: ip,
                    userId: user.id,
                    description: user.description || '-',
                    enabled: user.enabled,
                    aclAllowAll: user.acl_allow_all,
                    allowedHosts: user.acl_allowed_hosts || [],
                    source: 'manual'
                });
            });
        }
    });
    
    // Then, add IPs from ACLs (added via /challenge endpoint)
    Object.keys(acls).forEach(ip => {
        if (!processedIPs.has(ip)) {
            const acl = acls[ip];
            // Try to find the user by checking if they have this IP in their ACL settings
            let matchedUser = null;
            users.forEach(user => {
                // Check if ACL allowed_hosts matches user's allowed_hosts
                if (acl.allowed_hosts && user.acl_allowed_hosts) {
                    const aclHosts = acl.allowed_hosts.sort().join(',');
                    const userHosts = user.acl_allowed_hosts.sort().join(',');
                    if (aclHosts === userHosts) {
                        matchedUser = user;
                    }
                }
            });
            
            ipList.push({
                ip: ip,
                userId: matchedUser ? matchedUser.id : 'Unknown',
                description: matchedUser ? (matchedUser.description || '-') : 'Via Challenge',
                enabled: matchedUser ? matchedUser.enabled : true,
                aclAllowAll: acl.allow_all || false,
                allowedHosts: acl.allowed_hosts || [],
                source: 'challenge'
            });
        }
    });

    // Sort by IP address
    ipList.sort((a, b) => {
        // Simple IP comparison (works for IPv4)
        const aParts = a.ip.split('.').map(Number);
        const bParts = b.ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            if (aParts[i] !== bParts[i]) {
                return aParts[i] - bParts[i];
            }
        }
        return 0;
    });

    if (ipList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-secondary); font-style: italic;">No authorized IP addresses</td></tr>';
        return;
    }

    ipList.forEach(item => {
        const metricsData = metrics[item.ip];
        const totalHits = metricsData ? metricsData.total_requests : 0;
        const hasMetrics = metricsData && totalHits > 0;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <code style="font-size: 1em; ${hasMetrics ? 'cursor: pointer; color: var(--primary-color); text-decoration: underline;' : ''}" 
                      ${hasMetrics ? `onclick="showIPMetricsModal('${item.ip}')"` : ''}>
                    ${item.ip}
                </code>
            </td>
            <td><code>${item.userId}</code></td>
            <td>${item.description}</td>
            <td>
                <span class="badge ${item.enabled ? 'badge-success' : 'badge-danger'}">
                    ${item.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </td>
            <td>
                <span class="badge ${item.aclAllowAll ? 'badge-info' : 'badge-warning'}">
                    ${item.aclAllowAll ? 'Allow All' : 'Restricted'}
                </span>
            </td>
            <td>${item.allowedHosts.join(', ') || '-'}</td>
            <td>
                ${hasMetrics ? `<span class="badge badge-info" style="cursor: pointer;" onclick="showIPMetricsModal('${item.ip}')">${totalHits}</span>` : '<span style="color: var(--text-secondary);">0</span>'}
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Show add user modal
function showAddUserModal() {
    document.getElementById('modal-title').textContent = 'Add User';
    document.getElementById('user-form').reset();
    document.getElementById('user-id').value = '';
    document.getElementById('enabled').checked = true;
    document.getElementById('user-modal').style.display = 'block';
}

// Edit user
function editUser(userId) {
    const user = users.find(u => u.id === userId);
    if (!user) return;

    document.getElementById('modal-title').textContent = 'Edit User';
    document.getElementById('user-id').value = user.id;
    document.getElementById('description').value = user.description || '';
    document.getElementById('secret').value = ''; // Never show existing secret
    document.getElementById('enabled').checked = user.enabled;
    document.getElementById('acl_allow_all').checked = user.acl_allow_all;
    document.getElementById('acl_allowed_hosts').value = (user.acl_allowed_hosts || []).join(', ');
    document.getElementById('dns_names').value = (user.dns_names || []).join(', ');
    document.getElementById('ttl_minutes').value = user.ttl_minutes || '';

    // Toggle allowed hosts visibility
    if (user.acl_allow_all) {
        document.getElementById('allowed-hosts-group').style.display = 'none';
    } else {
        document.getElementById('allowed-hosts-group').style.display = 'block';
    }

    document.getElementById('user-modal').style.display = 'block';
}

// Close user modal
function closeUserModal() {
    document.getElementById('user-modal').style.display = 'none';
}

// Save user (add or update)
async function saveUser(event) {
    event.preventDefault();

    const userId = document.getElementById('user-id').value;
    const secret = document.getElementById('secret').value;
    const description = document.getElementById('description').value;
    const enabled = document.getElementById('enabled').checked;
    const aclAllowAll = document.getElementById('acl_allow_all').checked;
    const aclAllowedHosts = document.getElementById('acl_allowed_hosts').value
        .split(',')
        .map(h => h.trim())
        .filter(h => h);
    const dnsNames = document.getElementById('dns_names').value
        .split(',')
        .map(n => n.trim())
        .filter(n => n);
    const ttlMinutes = parseInt(document.getElementById('ttl_minutes').value) || 0;

    const userData = {
        description,
        enabled: true, // Always create enabled users
        acl_allow_all: aclAllowAll,
        acl_allowed_hosts: aclAllowedHosts,
        dns_names: dnsNames,
        ttl_minutes: ttlMinutes
    };

    // Only add secret if provided
    if (secret) {
        userData.secret = secret;
    }

    try {
        let response;
        if (userId) {
            // Update existing user
            response = await fetch(`/api/v1/user/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        } else {
            // Create new user
            if (!secret) {
                alert('Secret is required for new users');
                return;
            }
            response = await fetch('/api/v1/user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        }

        if (response.ok) {
            closeUserModal();
            loadAllData();
        } else {
            const error = await response.json();
            alert(`Error: ${error.error || 'Failed to save user'}`);
        }
    } catch (error) {
        console.error('Error saving user:', error);
        alert('Failed to save user');
    }
}

// Delete user
async function deleteUser(userId) {
    if (!confirm(`Are you sure you want to delete user ${userId}?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/user/${userId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadAllData();
        } else {
            const error = await response.json();
            alert(`Error: ${error.error || 'Failed to delete user'}`);
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        alert('Failed to delete user');
    }
}

// Show IP management modal
function showIPModal(userId) {
    currentUserId = userId;
    const user = users.find(u => u.id === userId);
    if (!user) return;

    document.getElementById('ip-modal-user-id').textContent = userId;
    
    // Collect all IPs for this user from both sources
    const allIPs = new Set(user.ips || []);
    
    // Add IPs from ACLs that belong to this user
    Object.keys(acls).forEach(ip => {
        const acl = acls[ip];
        // Check if this ACL matches the user's ACL settings
        if (user.acl_allowed_hosts && acl.allowed_hosts) {
            const aclHosts = acl.allowed_hosts.sort().join(',');
            const userHosts = user.acl_allowed_hosts.sort().join(',');
            if (aclHosts === userHosts) {
                allIPs.add(ip);
            }
        } else if (user.acl_allow_all && acl.allow_all) {
            // Both allow all - might belong to this user, but we can't be certain
            // For now, we'll be conservative and not include it unless we can match
        }
    });
    
    displayIPs(Array.from(allIPs), userId);
    document.getElementById('ip-modal').style.display = 'block';
}

// Close IP modal
function closeIPModal() {
    document.getElementById('ip-modal').style.display = 'none';
    currentUserId = null;
}

// Display IPs in list
function displayIPs(ips, userId) {
    const ipList = document.getElementById('ip-list');
    ipList.innerHTML = '';

    if (ips.length === 0) {
        ipList.innerHTML = '<li class="no-ips">No IPs configured</li>';
        return;
    }

    const user = users.find(u => u.id === userId);
    const manualIPs = new Set(user?.ips || []);

    ips.forEach(ip => {
        const isManual = manualIPs.has(ip);
        const isInACL = acls.hasOwnProperty(ip);
        
        let sourceLabel = '';
        if (isManual && isInACL) {
            sourceLabel = '<span class="badge badge-info" style="font-size: 0.7em; margin-left: 8px;">Manual + ACL</span>';
        } else if (isManual) {
            sourceLabel = '<span class="badge badge-success" style="font-size: 0.7em; margin-left: 8px;">Manual</span>';
        } else if (isInACL) {
            sourceLabel = '<span class="badge badge-warning" style="font-size: 0.7em; margin-left: 8px;">Via Challenge</span>';
        }
        
        const li = document.createElement('li');
        li.innerHTML = `
            <span>
                ${ip}
                ${sourceLabel}
            </span>
            <button class="btn btn-sm btn-danger" onclick="removeIP('${ip}')">Remove</button>
        `;
        ipList.appendChild(li);
    });
}

// Add IP
async function addIP() {
    const ipInput = document.getElementById('new-ip');
    const ip = ipInput.value.trim();

    if (!ip) {
        alert('Please enter an IP address');
        return;
    }

    try {
        const response = await fetch(`/api/v1/user/${currentUserId}/ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        if (response.ok) {
            ipInput.value = '';
            const updatedUser = await response.json();
            // Update user in local state
            const userIndex = users.findIndex(u => u.id === currentUserId);
            if (userIndex !== -1) {
                users[userIndex] = updatedUser;
            }
            displayIPs(updatedUser.ips || [], currentUserId);
            displayUsers();
            updateDashboard();
        } else {
            const error = await response.json();
            alert(`Error: ${error.error || 'Failed to add IP'}`);
        }
    } catch (error) {
        console.error('Error adding IP:', error);
        alert('Failed to add IP');
    }
}

// Remove IP
async function removeIP(ip) {
    const isInACL = acls.hasOwnProperty(ip);
    
    let confirmMsg = `Remove IP ${ip}?`;
    if (isInACL) {
        confirmMsg = `Remove IP ${ip}?\n\nNote: This IP was authorized via /challenge endpoint. Removing it from the user will also remove it from the ACL system.`;
    }
    
    if (!confirm(confirmMsg)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/user/${currentUserId}/ip`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        if (response.ok) {
            const updatedUser = await response.json();
            // Update user in local state
            const userIndex = users.findIndex(u => u.id === currentUserId);
            if (userIndex !== -1) {
                users[userIndex] = updatedUser;
            }
            
            // Also remove from ACL if it exists
            if (isInACL) {
                await fetch(`/api/v1/acl/${ip}`, { method: 'DELETE' }).catch(err => {
                    console.warn('Could not remove from ACL:', err);
                });
                // Reload ACLs to update local state
                await loadACLs();
            }
            
            // Reload all data to update counts and lists
            await loadAllData();
            // Reload the IP list for this modal
            showIPModal(currentUserId);
        } else {
            const error = await response.json();
            alert(`Error: ${error.error || 'Failed to remove IP'}`);
        }
    } catch (error) {
        console.error('Error removing IP:', error);
        alert('Failed to remove IP');
    }
}

// Load metrics from API
async function loadMetrics() {
    try {
        const response = await fetch('/api/v1/metrics');
        const data = await response.json();
        metrics = data || {};
        displayMetrics();
    } catch (error) {
        console.error('Error loading metrics:', error);
    }
}

// Display metrics in table
function displayMetrics() {
    const tbody = document.getElementById('metrics-tbody');
    tbody.innerHTML = '';

    const metricsList = Object.entries(metrics).map(([ip, data]) => ({
        ip,
        ...data
    }));

    // Sort by total requests (descending)
    metricsList.sort((a, b) => b.total_requests - a.total_requests);

    if (metricsList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 40px; color: var(--text-secondary); font-style: italic;">No authorization metrics yet</td></tr>';
        return;
    }

    metricsList.forEach(item => {
        // Format FQDN access as a list
        const fqdnList = Object.entries(item.fqdn_access || {})
            .map(([fqdn, count]) => `${fqdn} (${count})`)
            .join(', ');

        // Format last seen time
        const lastSeen = new Date(item.last_seen).toLocaleString();

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code style="font-size: 1em;">${item.ip}</code></td>
            <td><span class="badge badge-info">${item.total_requests}</span></td>
            <td style="font-size: 0.9em;">${fqdnList || '-'}</td>
            <td style="font-size: 0.85em; color: var(--text-secondary);">${lastSeen}</td>
        `;
        tbody.appendChild(row);
    });
}

// Load configuration
async function loadConfig() {
    try {
        const response = await fetch('/api/v1/config');
        const config = await response.json();
        displayConfig(config);
    } catch (error) {
        console.error('Error loading config:', error);
        document.getElementById('config-display').innerHTML = '<p class="error">Failed to load configuration</p>';
    }
}

// Display configuration
function displayConfig(config) {
    const configDisplay = document.getElementById('config-display');
    configDisplay.innerHTML = `
        <div class="config-grid">
            <div class="config-item">
                <div class="config-label">Log Level</div>
                <div class="config-value">${config.log_level}</div>
            </div>
            <div class="config-item">
                <div class="config-label">Log Encoding</div>
                <div class="config-value">${config.log_encoding}</div>
            </div>
            <div class="config-item">
                <div class="config-label">Server Address</div>
                <div class="config-value">${config.server_bind_address}:${config.server_bind_port}</div>
            </div>
            <div class="config-item">
                <div class="config-label">TLS Enabled</div>
                <div class="config-value">
                    <span class="badge ${config.server_tls_enabled ? 'badge-success' : 'badge-warning'}">
                        ${config.server_tls_enabled ? 'Yes' : 'No'}
                    </span>
                </div>
            </div>
            <div class="config-item">
                <div class="config-label">Database Provider</div>
                <div class="config-value">${config.db_provider}</div>
            </div>
            ${config.db_provider === 'bolt' ? `
            <div class="config-item">
                <div class="config-label">Database File</div>
                <div class="config-value"><code>${config.db_bolt_file}</code></div>
            </div>
            ` : ''}
        </div>
    `;
}

// Show IP metrics modal
function showIPMetricsModal(ip) {
    const metricsData = metrics[ip];
    if (!metricsData) return;

    document.getElementById('metrics-modal-ip').textContent = ip;
    document.getElementById('metrics-total').textContent = metricsData.total_requests;
    
    // Format last seen
    const lastSeen = new Date(metricsData.last_seen).toLocaleString();
    document.getElementById('metrics-last-seen').textContent = lastSeen;

    // Display FQDN breakdown
    const tbody = document.getElementById('fqdn-metrics-tbody');
    tbody.innerHTML = '';

    const fqdnList = Object.entries(metricsData.fqdn_access || {})
        .sort((a, b) => b[1] - a[1]); // Sort by count descending

    if (fqdnList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; padding: 20px; color: var(--text-secondary);">No FQDN access data</td></tr>';
    } else {
        fqdnList.forEach(([fqdn, count]) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code>${fqdn}</code></td>
                <td><span class="badge badge-info">${count}</span></td>
            `;
            tbody.appendChild(row);
        });
    }

    document.getElementById('ip-metrics-modal').style.display = 'block';
}

// Close IP metrics modal
function closeIPMetricsModal() {
    document.getElementById('ip-metrics-modal').style.display = 'none';
}

// Close modals when clicking outside
window.onclick = function(event) {
    const userModal = document.getElementById('user-modal');
    const ipModal = document.getElementById('ip-modal');
    const metricsModal = document.getElementById('ip-metrics-modal');
    
    if (event.target === userModal) {
        closeUserModal();
    }
    if (event.target === ipModal) {
        closeIPModal();
    }
    if (event.target === metricsModal) {
        closeIPMetricsModal();
    }
}

