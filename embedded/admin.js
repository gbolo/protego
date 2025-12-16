// Global state
let adminSecret = '';
let currentACLEdit = null;
let currentUserEdit = null;
let allACLs = [];
let allUsers = [];
let aclsLoaded = false;
let usersLoaded = false;

// API Base URL
const API_BASE = '/api/v1';

// ============================================================================
// Authentication
// ============================================================================

function authenticate() {
  const secret = $('#admin-secret').val();
  if (!secret) {
    showAuthError('Please enter admin secret');
    return;
  }
  
  adminSecret = secret;
  
  // Test authentication by calling get all users
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/user`,
    headers: { 'Admin-Secret': adminSecret },
    success: function() {
      $('#auth-section').hide();
      $('#dashboard-section').show();
      
      // Initialize stats with zeros
      updateStats();
      
      // Load data
      loadACLs();
      loadUsers();
    },
    error: function() {
      showAuthError('Authentication failed. Please check your admin secret.');
      adminSecret = '';
    }
  });
}

function showAuthError(message) {
  const errorDiv = $('#auth-error');
  errorDiv.text(message);
  errorDiv.show();
}

// ============================================================================
// Tab Management
// ============================================================================

function initTabs() {
  $('.tab').on('click', function() {
    const tab = $(this).data('tab');
    
    // Update active tab
    $('.tab').removeClass('active');
    $(this).addClass('active');
    
    // Show corresponding content
    $('.content-section').removeClass('active');
    $(`#${tab}-content`).addClass('active');
  });
}

// ============================================================================
// Stats Update
// ============================================================================

function updateStats() {
  console.log('Updating stats - ACLs:', allACLs.length, 'Users:', allUsers.length);
  
  // Update ACL count
  $('#totalACLs').text(allACLs.length || 0);
  
  // Update user counts
  $('#totalUsers').text(allUsers.length || 0);
  
  const enabledCount = allUsers.filter(u => u && u.enabled).length;
  const disabledCount = allUsers.length - enabledCount;
  
  $('#enabledUsers').text(enabledCount);
  $('#disabledUsers').text(disabledCount);
}

// ============================================================================
// Notifications
// ============================================================================

function showNotification(message, type = 'success') {
  const notification = $('#global-notification');
  notification.removeClass('message-success message-error message-info');
  notification.addClass(`message-${type}`);
  notification.text(message);
  notification.show();
  
  // Auto-hide after 5 seconds
  setTimeout(() => {
    notification.hide();
  }, 5000);
}

// ============================================================================
// Refresh All Data
// ============================================================================

function refreshAll() {
  loadACLs();
  loadUsers();
}

// ============================================================================
// ACL Management
// ============================================================================

function loadACLs() {
  $('#acl-loading').show();
  $('#acls-container').hide().empty();
  aclsLoaded = false;
  
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/acl`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      console.log('ACLs loaded:', data);
      $('#acl-loading').hide();
      $('#acls-container').show();
      allACLs = Array.isArray(data) ? data : [];
      aclsLoaded = true;
      renderACLs(allACLs);
      updateStats();
      updateLastUpdated('acl-last-updated');
    },
    error: function(xhr) {
      console.error('Failed to load ACLs:', xhr);
      $('#acl-loading').hide();
      $('#acls-container').show();
      allACLs = [];
      aclsLoaded = true;
      $('#acls-container').html(`
        <div class="message message-error">
          Failed to load ACLs: ${xhr.responseJSON?.error || 'Unknown error'}
        </div>
      `);
      updateStats();
    }
  });
}

function renderACLs(acls) {
  const container = $('#acls-container');
  container.empty();
  
  console.log('Rendering ACLs:', acls, 'Length:', acls ? acls.length : 'null');
  
  if (!Array.isArray(acls) || acls.length === 0) {
    console.log('Showing empty state for ACLs');
    container.html(`
      <div class="empty-state">
        <div class="empty-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
            <path d="M9 12h6M12 9v6"/>
          </svg>
        </div>
        <h3>No ACLs Yet</h3>
        <p>Access Control Lists manage IP-based permissions.</p>
        <p class="hint">Click the "Add ACL" button above to create your first one.</p>
      </div>
    `);
    return;
  }
  
  // Sort ACLs: by expiration (longest first), then by access, then by IP
  const sortedAcls = [...acls].sort((a, b) => {
    // First, sort by expiration (longest first)
    const aExpiry = a.ttl ? new Date(a.ttl).getTime() : Infinity;
    const bExpiry = b.ttl ? new Date(b.ttl).getTime() : Infinity;
    
    if (aExpiry !== bExpiry) {
      return bExpiry - aExpiry; // Longer expiration (or Infinity) comes first
    }
    
    // Second, sort by access (Everything before Limited)
    if (a.allow_all !== b.allow_all) {
      return b.allow_all - a.allow_all; // true (1) comes before false (0)
    }
    
    // Finally, sort by IP address
    return a.ip_address.localeCompare(b.ip_address, undefined, { numeric: true });
  });
  
  // Add header row
  container.append(`
    <div class="acl-header">
      <div>IP Address</div>
      <div>Access</div>
      <div>Allowed Hosts</div>
      <div>User IDs</div>
      <div>Expires</div>
    </div>
  `);
  
  sortedAcls.forEach(acl => {
    const allowAllTag = acl.allow_all 
      ? '<span class="tag tag-success">Everything</span>' 
      : '<span class="tag tag-secondary">Limited</span>';
    
    const hostsHTML = acl.allowed_hosts && acl.allowed_hosts.length > 0
      ? `<div class="tag-list">${acl.allowed_hosts.map(h => `<span class="tag tag-info">${escapeHtml(h)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">—</span>';
    
    // Create user tags with tooltips showing description
    const userIdsHTML = acl.user_ids && acl.user_ids.length > 0
      ? `<div class="tag-list">${acl.user_ids.map(userId => {
          // Find user in allUsers to get description
          const user = allUsers.find(u => u.id === userId);
          const description = user && user.description ? escapeHtml(user.description) : 'No description';
          
          return `<span class="tag tag-warning user-tag-with-tooltip" data-user-id="${escapeHtml(userId)}">
            ${escapeHtml(userId)}
            <span class="user-tag-tooltip">${description}</span>
          </span>`;
        }).join('')}</div>`
      : '<span class="tag tag-secondary">—</span>';
    
    const ttlHTML = acl.ttl 
      ? formatTTL(acl.ttl)
      : '<span class="tag tag-secondary">∞ Never</span>';
    
    // Determine risk level for allow_all ACLs
    let riskClass = '';
    if (acl.allow_all) {
      if (!acl.ttl) {
        // No expiration - highest risk
        riskClass = 'risk-high';
      } else {
        const now = new Date();
        const expiry = new Date(acl.ttl);
        const daysUntilExpiry = (expiry - now) / (1000 * 60 * 60 * 24);
        
        if (daysUntilExpiry > 30) {
          // More than 30 days - high risk
          riskClass = 'risk-high';
        } else if (daysUntilExpiry > 0) {
          // Less than 30 days but not expired - medium risk
          riskClass = 'risk-medium';
        }
      }
    }
    
    const row = $(`
      <div class="acl-row ${riskClass}" data-ip="${escapeHtml(acl.ip_address)}">
        <div class="acl-ip clickable-ip">${escapeHtml(acl.ip_address)}</div>
        <div class="acl-access">${allowAllTag}</div>
        <div class="acl-hosts">${hostsHTML}</div>
        <div class="acl-users">${userIdsHTML}</div>
        <div class="acl-ttl">${ttlHTML}</div>
      </div>
    `);
    
    container.append(row);
  });
  
  // Bind click event to entire row
  $('.acl-row').on('click', function(e) {
    // Don't trigger if clicking on a user tag (they have their own tooltip behavior)
    if ($(e.target).closest('.user-tag-with-tooltip').length > 0) {
      return;
    }
    
    const ip = $(this).data('ip');
    editACL(ip);
  });
}

function populateUserDropdown() {
  const select = $('#acl-user-ids');
  select.empty();
  
  if (!allUsers || allUsers.length === 0) {
    select.append('<option value="" disabled>No users available</option>');
    return;
  }
  
  // Filter out disabled users and add them to the dropdown
  const enabledUsers = allUsers.filter(user => !user.disabled);
  
  if (enabledUsers.length === 0) {
    select.append('<option value="" disabled>No enabled users available</option>');
    return;
  }
  
  enabledUsers.forEach(user => {
    const description = user.description ? ` - ${user.description}` : '';
    select.append(`<option value="${escapeHtml(user.id)}">${escapeHtml(user.id)}${escapeHtml(description)}</option>`);
  });
}

function openACLModal(isEdit = false, acl = null) {
  currentACLEdit = acl;
  
  // Populate user dropdown
  populateUserDropdown();
  
  if (isEdit && acl) {
    $('#acl-modal-title').text('Edit ACL');
    $('#acl-ip').val(acl.ip_address).prop('disabled', true);
    $('#acl-allow-all').prop('checked', acl.allow_all);
    $('#acl-allowed-hosts').val(acl.allowed_hosts ? acl.allowed_hosts.join(', ') : '');
    
    // Set selected users in the multi-select
    const userIds = acl.user_ids || [];
    $('#acl-user-ids').val(userIds);
    
    $('#acl-ttl').val(acl.ttl || '');
    
    // Show delete button when editing
    $('#delete-acl-btn').show();
  } else {
    $('#acl-modal-title').text('Add ACL');
    $('#acl-ip').val('').prop('disabled', false);
    $('#acl-allow-all').prop('checked', false);
    $('#acl-allowed-hosts').val('');
    $('#acl-user-ids').val([]);
    $('#acl-ttl').val('');
    
    // Hide delete button when adding
    $('#delete-acl-btn').hide();
  }
  
  $('#acl-modal').show();
}

function closeACLModal() {
  $('#acl-modal').hide();
  currentACLEdit = null;
}

function saveACL() {
  const ip = $('#acl-ip').val().trim();
  const allowAll = $('#acl-allow-all').is(':checked');
  const allowedHostsStr = $('#acl-allowed-hosts').val().trim();
  const selectedUserIds = $('#acl-user-ids').val(); // This returns an array from multi-select
  const ttl = $('#acl-ttl').val().trim();
  
  if (!ip) {
    showNotification('IP address is required', 'error');
    return;
  }
  
  const allowedHosts = allowedHostsStr 
    ? allowedHostsStr.split(',').map(h => h.trim()).filter(h => h)
    : [];
  
  // selectedUserIds is already an array from the multi-select, or null if nothing selected
  const userIds = selectedUserIds && selectedUserIds.length > 0 ? selectedUserIds : [];
  
  const aclData = {
    allow_all: allowAll,
    allowed_hosts: allowedHosts,
    user_ids: userIds
  };
  
  if (ttl) {
    aclData.ttl = ttl;
  }
  
  const isEdit = currentACLEdit !== null;
  const method = isEdit ? 'PUT' : 'POST';
  const url = `${API_BASE}/acl/${ip}`;
  
  $.ajax({
    type: method,
    url: url,
    headers: { 
      'Admin-Secret': adminSecret,
      'Content-Type': 'application/json'
    },
    data: JSON.stringify(aclData),
    success: function() {
      showNotification(`ACL ${isEdit ? 'updated' : 'created'} successfully`, 'success');
      closeACLModal();
      refreshAll();
    },
    error: function(xhr) {
      showNotification(`Failed to ${isEdit ? 'update' : 'create'} ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

function editACL(ip) {
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/acl/${ip}`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(acl) {
      openACLModal(true, acl);
    },
    error: function(xhr) {
      showNotification(`Failed to load ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

function deleteACL(ip) {
  if (!confirm(`Are you sure you want to delete ACL for IP ${ip}?`)) {
    return;
  }
  
  $.ajax({
    type: 'DELETE',
    url: `${API_BASE}/acl/${ip}`,
    headers: { 'Admin-Secret': adminSecret },
    success: function() {
      showNotification('ACL deleted successfully', 'success');
      closeACLModal();
      refreshAll();
    },
    error: function(xhr) {
      showNotification(`Failed to delete ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

// ============================================================================
// User Management
// ============================================================================

function loadUsers() {
  $('#user-loading').show();
  $('#users-container').hide().empty();
  usersLoaded = false;
  
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/user`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      console.log('Users loaded:', data);
      $('#user-loading').hide();
      $('#users-container').show();
      allUsers = Array.isArray(data) ? data : [];
      usersLoaded = true;
      renderUsers(allUsers);
      updateStats();
      updateLastUpdated('user-last-updated');
    },
    error: function(xhr) {
      console.error('Failed to load Users:', xhr);
      $('#user-loading').hide();
      $('#users-container').show();
      allUsers = [];
      usersLoaded = true;
      $('#users-container').html(`
        <div class="message message-error">
          Failed to load users: ${xhr.responseJSON?.error || 'Unknown error'}
        </div>
      `);
      updateStats();
    }
  });
}

function renderUsers(users) {
  const container = $('#users-container');
  container.empty();
  
  console.log('Rendering Users:', users, 'Length:', users ? users.length : 'null');
  
  if (!Array.isArray(users) || users.length === 0) {
    console.log('Showing empty state for Users');
    container.html(`
      <div class="empty-state">
        <div class="empty-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
            <line x1="12" y1="11" x2="12" y2="14"/>
            <line x1="10.5" y1="12.5" x2="13.5" y2="12.5"/>
          </svg>
        </div>
        <h3>No Users Yet</h3>
        <p>Users can authenticate to gain access.</p>
        <p class="hint">Click the "Add User" button above to create your first one.</p>
      </div>
    `);
    return;
  }
  
  users.forEach(user => {
    const enabledTag = user.enabled
      ? '<span class="tag tag-success">Enabled</span>'
      : '<span class="tag tag-danger">Disabled</span>';
    
    const allowAllTag = user.acl_allow_all 
      ? '<span class="tag tag-success">Yes</span>' 
      : '<span class="tag tag-secondary">No</span>';
    
    const hostsHTML = user.acl_allowed_hosts && user.acl_allowed_hosts.length > 0
      ? `<div class="tag-list">${user.acl_allowed_hosts.map(h => `<span class="tag tag-info">${escapeHtml(h)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">None</span>';
    
    const dnsHTML = user.dns_names && user.dns_names.length > 0
      ? `<div class="tag-list">${user.dns_names.map(d => `<span class="tag tag-warning">${escapeHtml(d)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">None</span>';
    
    // Find IPs from ACLs that have this user
    const userIPs = allACLs
      .filter(acl => acl.user_ids && acl.user_ids.includes(user.id))
      .map(acl => acl.ip_address);
    
    const ipsHTML = userIPs.length > 0
      ? `<div class="tag-list">${userIPs.map(ip => `<span class="tag tag-primary">${escapeHtml(ip)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">No active IPs</span>';
    
    const card = $(`
      <div class="item-card">
        <div class="item-header">
          <div class="item-title">
            <div class="item-name"><code>${escapeHtml(user.id)}</code></div>
            <div class="item-subtitle">${escapeHtml(user.description || 'No description')}</div>
          </div>
          ${enabledTag}
        </div>
        
        <div class="item-details">
          <div class="item-detail">
            <div class="detail-label">Active IP Addresses</div>
            <div class="detail-value">${ipsHTML}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">ACL Allow All</div>
            <div class="detail-value">${allowAllTag}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">ACL Allowed Hosts</div>
            <div class="detail-value">${hostsHTML}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">DNS Names</div>
            <div class="detail-value">${dnsHTML}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">TTL Minutes</div>
            <div class="detail-value"><span class="tag tag-info">${user.ttl_minutes || 0}</span></div>
          </div>
        </div>
        
        <div class="item-actions">
          <button class="btn btn-primary edit-user-btn" data-id="${user.id}">
            <i class="fi fi-rr-edit"></i>
            <span>Edit</span>
          </button>
          <button class="btn btn-danger delete-user-btn" data-id="${user.id}">
            <i class="fi fi-rr-trash"></i>
            <span>Delete</span>
          </button>
        </div>
      </div>
    `);
    
    container.append(card);
  });
  
  // Bind edit buttons
  $('.edit-user-btn').on('click', function() {
    const id = $(this).data('id');
    editUser(id);
  });
  
  // Bind delete buttons
  $('.delete-user-btn').on('click', function() {
    const id = $(this).data('id');
    deleteUser(id);
  });
}

function openUserModal(isEdit = false, user = null) {
  currentUserEdit = user;
  
  if (isEdit && user) {
    $('#user-modal-title').text('Edit User');
    $('#user-secret-field').hide();
    $('#user-enabled').prop('checked', user.enabled);
    $('#user-description').val(user.description || '');
    $('#user-acl-allow-all').prop('checked', user.acl_allow_all);
    $('#user-acl-allowed-hosts').val(user.acl_allowed_hosts ? user.acl_allowed_hosts.join(', ') : '');
    $('#user-dns-names').val(user.dns_names ? user.dns_names.join(', ') : '');
    $('#user-ttl-minutes').val(user.ttl_minutes || '');
  } else {
    $('#user-modal-title').text('Add User');
    $('#user-secret-field').show();
    $('#user-secret').val('');
    $('#user-enabled').prop('checked', true);
    $('#user-description').val('');
    $('#user-acl-allow-all').prop('checked', false);
    $('#user-acl-allowed-hosts').val('');
    $('#user-dns-names').val('');
    $('#user-ttl-minutes').val('');
  }
  
  $('#user-modal').show();
}

function closeUserModal() {
  $('#user-modal').hide();
  currentUserEdit = null;
}

function saveUser() {
  const secret = $('#user-secret').val().trim();
  const enabled = $('#user-enabled').is(':checked');
  const description = $('#user-description').val().trim();
  const aclAllowAll = $('#user-acl-allow-all').is(':checked');
  const aclAllowedHostsStr = $('#user-acl-allowed-hosts').val().trim();
  const dnsNamesStr = $('#user-dns-names').val().trim();
  const ttlMinutes = parseInt($('#user-ttl-minutes').val()) || 0;
  
  const isEdit = currentUserEdit !== null;
  
  if (!isEdit && !secret) {
    showNotification('Secret is required for new users', 'error');
    return;
  }
  
  const aclAllowedHosts = aclAllowedHostsStr
    ? aclAllowedHostsStr.split(',').map(h => h.trim()).filter(h => h)
    : [];
  
  const dnsNames = dnsNamesStr
    ? dnsNamesStr.split(',').map(d => d.trim()).filter(d => d)
    : [];
  
  const userData = {
    enabled: enabled,
    description: description,
    acl_allow_all: aclAllowAll,
    acl_allowed_hosts: aclAllowedHosts,
    dns_names: dnsNames,
    ttl_minutes: ttlMinutes
  };
  
  // Add secret only for new users
  if (!isEdit) {
    userData.secret = secret;
  }
  
  const method = isEdit ? 'PUT' : 'POST';
  const url = isEdit ? `${API_BASE}/user/${currentUserEdit.id}` : `${API_BASE}/user`;
  
  $.ajax({
    type: method,
    url: url,
    headers: { 
      'Admin-Secret': adminSecret,
      'Content-Type': 'application/json'
    },
    data: JSON.stringify(userData),
    success: function() {
      showNotification(`User ${isEdit ? 'updated' : 'created'} successfully`, 'success');
      closeUserModal();
      refreshAll();
    },
    error: function(xhr) {
      showNotification(`Failed to ${isEdit ? 'update' : 'create'} user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

function editUser(id) {
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/user/${id}`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(user) {
      openUserModal(true, user);
    },
    error: function(xhr) {
      showNotification(`Failed to load user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

function deleteUser(id) {
  if (!confirm(`Are you sure you want to delete user ${id}?`)) {
    return;
  }
  
  $.ajax({
    type: 'DELETE',
    url: `${API_BASE}/user/${id}`,
    headers: { 'Admin-Secret': adminSecret },
    success: function() {
      showNotification('User deleted successfully', 'success');
      refreshAll();
    },
    error: function(xhr) {
      showNotification(`Failed to delete user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'error');
    }
  });
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatDate(date) {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatDateShort(date) {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

function formatTTL(ttlDate) {
  const now = new Date();
  const expiry = new Date(ttlDate);
  const diffMs = expiry - now;
  
  // If expired
  if (diffMs < 0) {
    return '<span class="tag tag-danger">Expired</span>';
  }
  
  // Convert to hours
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  
  // Less than 24 hours - show human readable
  if (hours < 24) {
    if (hours === 0) {
      if (minutes === 0) {
        return '<span class="tag tag-danger">< 1 min</span>';
      }
      return `<span class="tag tag-warning">${minutes} min${minutes !== 1 ? 's' : ''}</span>`;
    }
    if (minutes > 0) {
      return `<span class="tag tag-warning">${hours}h ${minutes}m</span>`;
    }
    return `<span class="tag tag-warning">${hours} hour${hours !== 1 ? 's' : ''}</span>`;
  }
  
  // More than 24 hours - show short date
  return `<span class="tag tag-info">${formatDateShort(expiry)}</span>`;
}

function updateLastUpdated(elementId) {
  const now = new Date();
  $(`#${elementId}`).text(`Last updated: ${formatDate(now)}`);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================================
// Filtering
// ============================================================================

function applyACLFilters() {
  const ipFilter = $('#filter-acl-ip').val().toLowerCase().trim();
  const userFilter = $('#filter-acl-user').val().toLowerCase().trim();
  const statusFilter = $('#filter-acl-status').val();
  
  const now = new Date();
  
  const filtered = allACLs.filter(acl => {
    // IP filter
    if (ipFilter && !acl.ip_address.toLowerCase().includes(ipFilter)) {
      return false;
    }
    
    // User ID filter
    if (userFilter) {
      const hasMatchingUser = acl.user_ids && acl.user_ids.some(uid => 
        uid.toLowerCase().includes(userFilter)
      );
      if (!hasMatchingUser) {
        return false;
      }
    }
    
    // Status filter
    if (statusFilter && acl.ttl) {
      const expiry = new Date(acl.ttl);
      const isExpired = expiry < now;
      
      if (statusFilter === 'active' && isExpired) {
        return false;
      }
      if (statusFilter === 'expired' && !isExpired) {
        return false;
      }
    } else if (statusFilter === 'expired') {
      // If there's no TTL, it never expires, so filter it out when looking for expired ones
      return false;
    }
    
    return true;
  });
  
  renderACLs(filtered);
}

function applyUserFilters() {
  const idFilter = $('#filter-user-id').val().toLowerCase().trim();
  const descFilter = $('#filter-user-desc').val().toLowerCase().trim();
  const hasIpsFilter = $('#filter-user-has-ips').val();
  
  const filtered = allUsers.filter(user => {
    // User ID filter
    if (idFilter && !user.id.toLowerCase().includes(idFilter)) {
      return false;
    }
    
    // Description filter
    if (descFilter && !user.description.toLowerCase().includes(descFilter)) {
      return false;
    }
    
    // Has IPs filter
    if (hasIpsFilter) {
      const userIPs = allACLs.filter(acl => acl.user_id === user.id);
      const hasActiveIPs = userIPs.length > 0;
      
      if (hasIpsFilter === 'yes' && !hasActiveIPs) {
        return false;
      }
      if (hasIpsFilter === 'no' && hasActiveIPs) {
        return false;
      }
    }
    
    return true;
  });
  
  renderUsers(filtered);
}

function clearACLFilters() {
  $('#filter-acl-ip').val('');
  $('#filter-acl-user').val('');
  $('#filter-acl-status').val('');
  applyACLFilters();
}

function clearUserFilters() {
  $('#filter-user-id').val('');
  $('#filter-user-desc').val('');
  $('#filter-user-has-ips').val('');
  applyUserFilters();
}

// ============================================================================
// Version Info
// ============================================================================

function loadVersion() {
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/version`,
    success: function(data) {
      if (data && data.version) {
        $('#version-info').text(`Version ${data.version} (${data.build_ref || 'dev'})`);
      }
    },
    error: function() {
      $('#version-info').text('Version info unavailable');
    }
  });
}

// ============================================================================
// Initialization
// ============================================================================

$(document).ready(function() {
  // Load version info
  loadVersion();
  
  // Auth section
  $('#auth-button').on('click', authenticate);
  $('#admin-secret').on('keyup', function(e) {
    if (e.keyCode === 13) {
      authenticate();
    }
  });
  
  // Initialize tabs
  initTabs();
  
  // ACL buttons
  $('#add-acl-btn').on('click', () => openACLModal(false));
  $('#refresh-acls-btn').on('click', refreshAll);
  $('#save-acl-btn').on('click', saveACL);
  $('#delete-acl-btn').on('click', function() {
    if (currentACLEdit && currentACLEdit.ip_address) {
      deleteACL(currentACLEdit.ip_address);
    }
  });
  
  // ACL filters
  $('#filter-acl-ip').on('input', applyACLFilters);
  $('#filter-acl-user').on('input', applyACLFilters);
  $('#filter-acl-status').on('change', applyACLFilters);
  $('#clear-acl-filters').on('click', clearACLFilters);
  
  // User buttons
  $('#add-user-btn').on('click', () => openUserModal(false));
  $('#refresh-users-btn').on('click', refreshAll);
  $('#save-user-btn').on('click', saveUser);
  
  // User filters
  $('#filter-user-id').on('input', applyUserFilters);
  $('#filter-user-desc').on('input', applyUserFilters);
  $('#filter-user-has-ips').on('change', applyUserFilters);
  $('#clear-user-filters').on('click', clearUserFilters);
  
  // Close modal on background click
  $('.modal').on('click', function(e) {
    if (e.target === this) {
      $(this).hide();
    }
  });
  
  // User tag tooltip handlers (event delegation for dynamic content)
  $(document).on('click', '.user-tag-with-tooltip', function(e) {
    e.stopPropagation();
    console.log('User tag clicked!');
    const tooltip = $(this).find('.user-tag-tooltip');
    console.log('Tooltip element:', tooltip, 'Has show class:', tooltip.hasClass('show'));
    
    // Hide all other tooltips
    $('.user-tag-tooltip').not(tooltip).removeClass('show');
    
    // Toggle this tooltip
    tooltip.toggleClass('show');
    console.log('After toggle, has show class:', tooltip.hasClass('show'));
  });
  
  // Hide tooltips when clicking outside
  $(document).on('click', function(e) {
    if (!$(e.target).closest('.user-tag-with-tooltip').length) {
      $('.user-tag-tooltip').removeClass('show');
    }
  });
});
