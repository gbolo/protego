package dataprovider

import (
	"encoding/json"
	"testing"
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		description string
		wantErr     bool
	}{
		{
			name:        "Valid user",
			secret:      "validSecret123",
			description: "Test User",
			wantErr:     false,
		},
		{
			name:        "Secret too short",
			secret:      "short",
			description: "Test User",
			wantErr:     true,
		},
		{
			name:        "Minimum length secret",
			secret:      "123456",
			description: "Test User",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.secret, tt.description)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if user == nil {
					t.Error("Expected user to be created")
					return
				}
				if user.Description != tt.description {
					t.Errorf("Expected description %s, got %s", tt.description, user.Description)
				}
				if user.ID == "" {
					t.Error("Expected user ID to be generated")
				}
				if user.Secret == "" {
					t.Error("Expected secret to be hashed")
				}
				if !user.Enabled {
					t.Error("Expected user to be enabled by default")
				}
			}
		})
	}
}

func TestUser_CheckHost(t *testing.T) {
	user := &User{
		ACLAllowedHosts: []string{"example.com", "test.example.com", "api.example.com"},
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		{
			name: "Exact match",
			host: "example.com",
			want: true,
		},
		{
			name: "Subdomain match",
			host: "test.example.com",
			want: true,
		},
		{
			name: "Case insensitive match",
			host: "EXAMPLE.COM",
			want: true,
		},
		{
			name: "No match",
			host: "notallowed.com",
			want: false,
		},
		{
			name: "Partial match should fail",
			host: "xample.com",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.CheckHost(tt.host); got != tt.want {
				t.Errorf("User.CheckHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_AddHost(t *testing.T) {
	user := &User{
		ACLAllowedHosts: []string{},
	}

	// Add valid host
	err := user.AddHost("example.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(user.ACLAllowedHosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(user.ACLAllowedHosts))
	}

	// Add duplicate host (should not add)
	err = user.AddHost("example.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(user.ACLAllowedHosts) != 1 {
		t.Errorf("Expected 1 host after duplicate, got %d", len(user.ACLAllowedHosts))
	}

	// Add invalid host
	err = user.AddHost("invalid host with spaces")
	if err == nil {
		t.Error("Expected error for invalid host")
	}
}

func TestUser_RemoveHost(t *testing.T) {
	user := &User{
		ACLAllowedHosts: []string{"example.com", "test.com", "api.com"},
	}

	// Remove existing host
	user.RemoveHost("test.com")
	if len(user.ACLAllowedHosts) != 2 {
		t.Errorf("Expected 2 hosts after removal, got %d", len(user.ACLAllowedHosts))
	}
	if user.CheckHost("test.com") {
		t.Error("Host should have been removed")
	}

	// Remove non-existent host (should not error)
	user.RemoveHost("notexist.com")
	if len(user.ACLAllowedHosts) != 2 {
		t.Errorf("Expected 2 hosts after removing non-existent, got %d", len(user.ACLAllowedHosts))
	}
}

func TestUser_CheckIp(t *testing.T) {
	user := &User{
		IPs: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
	}

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "Exact match",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "Case insensitive match",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "No match",
			ip:   "1.2.3.4",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := user.CheckIp(tt.ip); got != tt.want {
				t.Errorf("User.CheckIp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_AddIp(t *testing.T) {
	user := &User{
		IPs: []string{},
	}

	// Add valid IP
	err := user.AddIp("192.168.1.1")
	if err != nil {
		t.Errorf("AddIp() error = %v", err)
	}
	if len(user.IPs) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(user.IPs))
	}

	// Add duplicate IP (should not add)
	err = user.AddIp("192.168.1.1")
	if err != nil {
		t.Errorf("AddIp() error = %v", err)
	}
	if len(user.IPs) != 1 {
		t.Errorf("Expected 1 IP after duplicate, got %d", len(user.IPs))
	}

	// Add invalid IP
	err = user.AddIp("not.an.ip.address")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestUser_RemoveIp(t *testing.T) {
	user := &User{
		IPs: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
	}

	// Remove existing IP
	user.RemoveIp("10.0.0.1")
	if len(user.IPs) != 2 {
		t.Errorf("Expected 2 IPs after removal, got %d", len(user.IPs))
	}
	if user.CheckIp("10.0.0.1") {
		t.Error("IP should have been removed")
	}

	// Remove non-existent IP (should not error)
	user.RemoveIp("1.2.3.4")
	if len(user.IPs) != 2 {
		t.Errorf("Expected 2 IPs after removing non-existent, got %d", len(user.IPs))
	}
}

func TestUser_SetAclAllowAll(t *testing.T) {
	user := &User{
		ACLAllowAll: false,
	}

	user.SetAclAllowAll(true)
	if !user.ACLAllowAll {
		t.Error("Expected ACLAllowAll to be true")
	}

	user.SetAclAllowAll(false)
	if user.ACLAllowAll {
		t.Error("Expected ACLAllowAll to be false")
	}
}

func TestUser_Encode(t *testing.T) {
	user := &User{
		Enabled:         true,
		Description:     "Test User",
		ID:              "testid123",
		Secret:          "hashed_secret",
		ACLAllowAll:     true,
		ACLAllowedHosts: []string{"example.com"},
		DNSNames:        []string{"home.dyndns.org"},
		TTLMinutes:      60,
		IPs:             []string{"192.168.1.1"},
	}

	encoded := user.Encode()
	if len(encoded) == 0 {
		t.Error("Expected encoded data")
	}

	// Verify it's valid JSON
	var decoded User
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Errorf("Failed to decode user: %v", err)
	}

	if decoded.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, decoded.ID)
	}
	if decoded.Description != user.Description {
		t.Errorf("Expected description %s, got %s", user.Description, decoded.Description)
	}
}

func TestDecodeUser(t *testing.T) {
	validJSON := []byte(`{
		"enabled": true,
		"description": "Test User",
		"secret": "validSecret123",
		"acl_allow_all": true,
		"acl_allowed_hosts": ["example.com"],
		"dns_names": ["home.dyndns.org"],
		"ttl_minutes": 60
	}`)

	user, err := DecodeUser(validJSON)
	if err != nil {
		t.Fatalf("DecodeUser() error = %v", err)
	}

	if user == nil {
		t.Fatal("Expected user to be created")
	}

	if user.Description != "Test User" {
		t.Errorf("Expected description 'Test User', got '%s'", user.Description)
	}

	if !user.ACLAllowAll {
		t.Error("Expected ACLAllowAll to be true")
	}

	if len(user.ACLAllowedHosts) != 1 || user.ACLAllowedHosts[0] != "example.com" {
		t.Error("Expected ACLAllowedHosts to contain 'example.com'")
	}

	if user.TTLMinutes != 60 {
		t.Errorf("Expected TTLMinutes 60, got %d", user.TTLMinutes)
	}

	// Test invalid JSON
	invalidJSON := []byte(`{"secret": "short"}`)
	user, err = DecodeUser(invalidJSON)
	if err == nil {
		t.Error("Expected error for short secret")
	}
}
