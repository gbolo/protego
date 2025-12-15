// Global state
let adminSecret = '';
let currentACLEdit = null;
let currentUserEdit = null;

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
  errorDiv.find('button.delete').off('click').on('click', function() {
    errorDiv.addClass('is-hidden');
  });
  errorDiv.text(message);
  errorDiv.removeClass('is-hidden');
}

// ============================================================================
// Tab Management
// ============================================================================

function initTabs() {
  $('.tabs li').on('click', function() {
    const tab = $(this).data('tab');
    
    // Update active tab
    $('.tabs li').removeClass('is-active');
    $(this).addClass('is-active');
    
    // Show corresponding content
    $('.content-section').removeClass('is-active');
    $(`#${tab}-content`).addClass('is-active');
  });
}

// ============================================================================
// Notifications
// ============================================================================

function showNotification(message, type = 'success') {
  const notification = $('#global-notification');
  notification.removeClass('is-success is-danger is-warning is-info');
  notification.addClass(`is-${type}`);
  $('#notification-message').text(message);
  notification.removeClass('is-hidden');
  
  // Auto-hide after 5 seconds
  setTimeout(() => {
    notification.addClass('is-hidden');
  }, 5000);
}

function initNotificationClose() {
  $('#global-notification .delete').on('click', function() {
    $('#global-notification').addClass('is-hidden');
  });
}

// ============================================================================
// ACL Management
// ============================================================================

function loadACLs() {
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/acl`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      renderACLs(data);
    },
    error: function(xhr) {
      $('#acls-table-body').html(`
        <tr>
          <td colspan="6" class="has-text-centered has-text-danger">
            Failed to load ACLs: ${xhr.responseJSON?.error || 'Unknown error'}
          </td>
        </tr>
      `);
    }
  });
}

function renderACLs(acls) {
  const tbody = $('#acls-table-body');
  
  if (!acls || acls.length === 0) {
    tbody.html(`
      <tr>
        <td colspan="6" class="has-text-centered has-text-grey-light">
          No ACLs found. Click "Add ACL" to create one.
        </td>
      </tr>
    `);
    return;
  }
  
  tbody.empty();
  acls.forEach(acl => {
    const allowAllBadge = acl.allow_all 
      ? '<span class="tag is-success">Yes</span>' 
      : '<span class="tag">No</span>';
    
    const hosts = acl.allowed_hosts && acl.allowed_hosts.length > 0
      ? `<div class="tag-list">${acl.allowed_hosts.map(h => `<span class="tag is-info">${h}</span>`).join('')}</div>`
      : '<span class="has-text-grey-light">None</span>';
    
    const userIds = acl.user_ids && acl.user_ids.length > 0
      ? `<div class="tag-list">${acl.user_ids.map(u => `<span class="tag is-warning">${u}</span>`).join('')}</div>`
      : '<span class="has-text-grey-light">None</span>';
    
    const ttl = acl.ttl 
      ? `<span class="tag is-light">${new Date(acl.ttl).toLocaleString()}</span>`
      : '<span class="has-text-grey-light">Never</span>';
    
    tbody.append(`
      <tr>
        <td><strong>${acl.ip_address}</strong></td>
        <td>${allowAllBadge}</td>
        <td>${hosts}</td>
        <td>${userIds}</td>
        <td>${ttl}</td>
        <td>
          <div class="buttons">
            <button class="button is-small is-info edit-acl-btn" data-ip="${acl.ip_address}">
              <span class="icon is-small"><i class="fas fa-edit"></i></span>
            </button>
            <button class="button is-small is-danger delete-acl-btn" data-ip="${acl.ip_address}">
              <span class="icon is-small"><i class="fas fa-trash"></i></span>
            </button>
          </div>
        </td>
      </tr>
    `);
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
  
  $('#acl-modal').addClass('is-active');
}

function closeACLModal() {
  $('#acl-modal').removeClass('is-active');
  currentACLEdit = null;
}

function saveACL() {
  const ip = $('#acl-ip').val().trim();
  const allowAll = $('#acl-allow-all').is(':checked');
  const allowedHostsStr = $('#acl-allowed-hosts').val().trim();
  const userIdsStr = $('#acl-user-ids').val().trim();
  const ttl = $('#acl-ttl').val().trim();
  
  if (!ip) {
    showNotification('IP address is required', 'danger');
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
      showNotification(`Failed to ${isEdit ? 'update' : 'create'} ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
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
      showNotification(`Failed to load ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
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
      showNotification(`Failed to delete ACL: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
    }
  });
}

// ============================================================================
// User Management
// ============================================================================

function loadUsers() {
  $.ajax({
    type: 'GET',
    url: `${API_BASE}/user`,
    headers: { 'Admin-Secret': adminSecret },
    success: function(data) {
      renderUsers(data);
    },
    error: function(xhr) {
      $('#users-table-body').html(`
        <tr>
          <td colspan="7" class="has-text-centered has-text-danger">
            Failed to load users: ${xhr.responseJSON?.error || 'Unknown error'}
          </td>
        </tr>
      `);
    }
  });
}

function renderUsers(users) {
  const tbody = $('#users-table-body');
  
  if (!users || users.length === 0) {
    tbody.html(`
      <tr>
        <td colspan="7" class="has-text-centered has-text-grey-light">
          No users found. Click "Add User" to create one.
        </td>
      </tr>
    `);
    return;
  }
  
  tbody.empty();
  users.forEach(user => {
    const enabledBadge = user.enabled
      ? '<span class="tag is-success">Yes</span>'
      : '<span class="tag is-danger">No</span>';
    
    const allowAllBadge = user.acl_allow_all 
      ? '<span class="tag is-success">Yes</span>' 
      : '<span class="tag">No</span>';
    
    const hosts = user.acl_allowed_hosts && user.acl_allowed_hosts.length > 0
      ? `<div class="tag-list">${user.acl_allowed_hosts.map(h => `<span class="tag is-info">${h}</span>`).join('')}</div>`
      : '<span class="has-text-grey-light">None</span>';
    
    tbody.append(`
      <tr>
        <td><code>${user.id}</code></td>
        <td>${enabledBadge}</td>
        <td>${user.description || '<span class="has-text-grey-light">N/A</span>'}</td>
        <td>${allowAllBadge}</td>
        <td>${hosts}</td>
        <td>${user.ttl_minutes || 0}</td>
        <td>
          <div class="buttons">
            <button class="button is-small is-info edit-user-btn" data-id="${user.id}">
              <span class="icon is-small"><i class="fas fa-edit"></i></span>
            </button>
            <button class="button is-small is-danger delete-user-btn" data-id="${user.id}">
              <span class="icon is-small"><i class="fas fa-trash"></i></span>
            </button>
          </div>
        </td>
      </tr>
    `);
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
    $('#user-secret').val('').prop('disabled', true).closest('.field').hide();
    $('#user-enabled').prop('checked', user.enabled);
    $('#user-description').val(user.description || '');
    $('#user-acl-allow-all').prop('checked', user.acl_allow_all);
    $('#user-acl-allowed-hosts').val(user.acl_allowed_hosts ? user.acl_allowed_hosts.join(', ') : '');
    $('#user-dns-names').val(user.dns_names ? user.dns_names.join(', ') : '');
    $('#user-ttl-minutes').val(user.ttl_minutes || '');
  } else {
    $('#user-modal-title').text('Add User');
    $('#user-secret').val('').prop('disabled', false).closest('.field').show();
    $('#user-enabled').prop('checked', true);
    $('#user-description').val('');
    $('#user-acl-allow-all').prop('checked', false);
    $('#user-acl-allowed-hosts').val('');
    $('#user-dns-names').val('');
    $('#user-ttl-minutes').val('');
  }
  
  $('#user-modal').addClass('is-active');
}

function closeUserModal() {
  $('#user-modal').removeClass('is-active');
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
    showNotification('Secret is required for new users', 'danger');
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
      showNotification(`Failed to ${isEdit ? 'update' : 'create'} user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
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
      showNotification(`Failed to load user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
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
      showNotification(`Failed to delete user: ${xhr.responseJSON?.error || 'Unknown error'}`, 'danger');
    }
  });
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
  
  // Initialize notifications
  initNotificationClose();
  
  // ACL buttons
  $('#add-acl-btn').on('click', () => openACLModal(false));
  $('#refresh-acls-btn').on('click', loadACLs);
  $('#save-acl-btn').on('click', saveACL);
  
  // User buttons
  $('#add-user-btn').on('click', () => openUserModal(false));
  $('#refresh-users-btn').on('click', loadUsers);
  $('#save-user-btn').on('click', saveUser);
  
  // Modal close buttons
  $('.modal .delete, .cancel-modal').on('click', function() {
    $(this).closest('.modal').removeClass('is-active');
  });
  
  // Close modal on background click
  $('.modal-background').on('click', function() {
    $(this).closest('.modal').removeClass('is-active');
  });
});

