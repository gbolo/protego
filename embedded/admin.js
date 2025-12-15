// Global state
let adminSecret = '';
let currentACLEdit = null;
let currentUserEdit = null;
let allACLs = [];
let allUsers = [];

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
  $('#totalACLs').text(allACLs.length);
  $('#totalUsers').text(allUsers.length);
  
  const enabledCount = allUsers.filter(u => u.enabled).length;
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
// ACL Management
// ============================================================================

function loadACLs() {
  $('#acl-loading').show();
  $('#acls-container').empty();
  
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/acl`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      allACLs = data || [];
      renderACLs(allACLs);
      updateStats();
      updateLastUpdated('acl-last-updated');
      $('#acl-loading').hide();
    },
    error: function(xhr) {
      $('#acl-loading').hide();
      $('#acls-container').html(`
        <div class="message message-error">
          Failed to load ACLs: ${xhr.responseJSON?.error || 'Unknown error'}
        </div>
      `);
    }
  });
}

function renderACLs(acls) {
  const container = $('#acls-container');
  container.empty();
  
  if (!acls || acls.length === 0) {
    container.html(`
      <div class="message message-info">
        <i class="fi fi-rr-info"></i>
        <span>No ACLs found. Click "Add ACL" to create one.</span>
      </div>
    `);
    return;
  }
  
  acls.forEach(acl => {
    const allowAllTag = acl.allow_all 
      ? '<span class="tag tag-success">Yes</span>' 
      : '<span class="tag tag-secondary">No</span>';
    
    const hostsHTML = acl.allowed_hosts && acl.allowed_hosts.length > 0
      ? `<div class="tag-list">${acl.allowed_hosts.map(h => `<span class="tag tag-info">${escapeHtml(h)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">None</span>';
    
    const userIdsHTML = acl.user_ids && acl.user_ids.length > 0
      ? `<div class="tag-list">${acl.user_ids.map(u => `<span class="tag tag-warning">${escapeHtml(u)}</span>`).join('')}</div>`
      : '<span class="tag tag-secondary">None</span>';
    
    const ttlHTML = acl.ttl 
      ? `<span class="tag tag-info">${formatDate(new Date(acl.ttl))}</span>`
      : '<span class="tag tag-secondary">Never</span>';
    
    const card = $(`
      <div class="item-card">
        <div class="item-header">
          <div class="item-title">
            <div class="item-name">${escapeHtml(acl.ip_address)}</div>
            <div class="item-subtitle">IP Access Control</div>
          </div>
        </div>
        
        <div class="item-details">
          <div class="item-detail">
            <div class="detail-label">Allow All</div>
            <div class="detail-value">${allowAllTag}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">Allowed Hosts</div>
            <div class="detail-value">${hostsHTML}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">User IDs</div>
            <div class="detail-value">${userIdsHTML}</div>
          </div>
          <div class="item-detail">
            <div class="detail-label">TTL Expiration</div>
            <div class="detail-value">${ttlHTML}</div>
          </div>
        </div>
        
        <div class="item-actions">
          <button class="btn btn-primary edit-acl-btn" data-ip="${acl.ip_address}">
            <i class="fi fi-rr-edit"></i>
            <span>Edit</span>
          </button>
          <button class="btn btn-danger delete-acl-btn" data-ip="${acl.ip_address}">
            <i class="fi fi-rr-trash"></i>
            <span>Delete</span>
          </button>
        </div>
      </div>
    `);
    
    container.append(card);
  });
  
  // Bind edit buttons
  $('.edit-acl-btn').on('click', function() {
    const ip = $(this).data('ip');
    editACL(ip);
  });
  
  // Bind delete buttons
  $('.delete-acl-btn').on('click', function() {
    const ip = $(this).data('ip');
    deleteACL(ip);
  });
}

function openACLModal(isEdit = false, acl = null) {
  currentACLEdit = acl;
  
  if (isEdit && acl) {
    $('#acl-modal-title').text('Edit ACL');
    $('#acl-ip').val(acl.ip_address).prop('disabled', true);
    $('#acl-allow-all').prop('checked', acl.allow_all);
    $('#acl-allowed-hosts').val(acl.allowed_hosts ? acl.allowed_hosts.join(', ') : '');
    $('#acl-user-ids').val(acl.user_ids ? acl.user_ids.join(', ') : '');
    $('#acl-ttl').val(acl.ttl || '');
  } else {
    $('#acl-modal-title').text('Add ACL');
    $('#acl-ip').val('').prop('disabled', false);
    $('#acl-allow-all').prop('checked', false);
    $('#acl-allowed-hosts').val('');
    $('#acl-user-ids').val('');
    $('#acl-ttl').val('');
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
  const userIdsStr = $('#acl-user-ids').val().trim();
  const ttl = $('#acl-ttl').val().trim();
  
  if (!ip) {
    showNotification('IP address is required', 'error');
    return;
  }
  
  const allowedHosts = allowedHostsStr 
    ? allowedHostsStr.split(',').map(h => h.trim()).filter(h => h)
    : [];
  
  const userIds = userIdsStr
    ? userIdsStr.split(',').map(u => u.trim()).filter(u => u)
    : [];
  
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
      loadACLs();
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
      loadACLs();
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
  $('#users-container').empty();
  
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/user`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      allUsers = data || [];
      renderUsers(allUsers);
      updateStats();
      updateLastUpdated('user-last-updated');
      $('#user-loading').hide();
    },
    error: function(xhr) {
      $('#user-loading').hide();
      $('#users-container').html(`
        <div class="message message-error">
          Failed to load users: ${xhr.responseJSON?.error || 'Unknown error'}
        </div>
      `);
    }
  });
}

function renderUsers(users) {
  const container = $('#users-container');
  container.empty();
  
  if (!users || users.length === 0) {
    container.html(`
      <div class="message message-info">
        <i class="fi fi-rr-info"></i>
        <span>No users found. Click "Add User" to create one.</span>
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
      loadUsers();
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
      loadUsers();
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
// Initialization
// ============================================================================

$(document).ready(function() {
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
  $('#refresh-acls-btn').on('click', loadACLs);
  $('#save-acl-btn').on('click', saveACL);
  
  // User buttons
  $('#add-user-btn').on('click', () => openUserModal(false));
  $('#refresh-users-btn').on('click', loadUsers);
  $('#save-user-btn').on('click', saveUser);
  
  // Close modal on background click
  $('.modal').on('click', function(e) {
    if (e.target === this) {
      $(this).hide();
    }
  });
});
