package dataprovider

import (
	"encoding/json"
	"testing"
	"time"
)

func TestACL_CheckHost(t *testing.T) {
	acl := &ACL{
		AllowedHosts: []string{"example.com", "test.example.com", "api.example.com"},
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
			name: "Mixed case match",
			host: "Test.Example.COM",
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
		{
			name: "Empty host",
			host: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acl.CheckHost(tt.host); got != tt.want {
				t.Errorf("ACL.CheckHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACL_AddHost(t *testing.T) {
	acl := &ACL{
		AllowedHosts: []string{},
	}

	// Add valid host
	err := acl.AddHost("example.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(acl.AllowedHosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(acl.AllowedHosts))
	}
	if acl.AllowedHosts[0] != "example.com" {
		t.Errorf("Expected host 'example.com', got '%s'", acl.AllowedHosts[0])
	}

	// Add duplicate host (should not add)
	err = acl.AddHost("example.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(acl.AllowedHosts) != 1 {
		t.Errorf("Expected 1 host after duplicate, got %d", len(acl.AllowedHosts))
	}

	// Add host with different case (should not add duplicate)
	err = acl.AddHost("EXAMPLE.COM")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(acl.AllowedHosts) != 1 {
		t.Errorf("Expected 1 host after case-insensitive duplicate, got %d", len(acl.AllowedHosts))
	}

	// Add another valid host
	err = acl.AddHost("test.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}
	if len(acl.AllowedHosts) != 2 {
		t.Errorf("Expected 2 hosts, got %d", len(acl.AllowedHosts))
	}

	// Add invalid host
	err = acl.AddHost("invalid host with spaces")
	if err == nil {
		t.Error("Expected error for invalid host")
	}
	if len(acl.AllowedHosts) != 2 {
		t.Errorf("Expected 2 hosts after invalid add, got %d", len(acl.AllowedHosts))
	}

	// Add invalid host with special characters
	err = acl.AddHost("invalid!@#$.com")
	if err == nil {
		t.Error("Expected error for invalid host with special characters")
	}
}

func TestACL_RemoveHost(t *testing.T) {
	acl := &ACL{
		AllowedHosts: []string{"example.com", "test.com", "api.com"},
	}

	// Remove existing host
	acl.RemoveHost("test.com")
	if len(acl.AllowedHosts) != 2 {
		t.Errorf("Expected 2 hosts after removal, got %d", len(acl.AllowedHosts))
	}
	if acl.CheckHost("test.com") {
		t.Error("Host should have been removed")
	}

	// Verify remaining hosts are intact
	if !acl.CheckHost("example.com") {
		t.Error("example.com should still be present")
	}
	if !acl.CheckHost("api.com") {
		t.Error("api.com should still be present")
	}

	// Remove with different case
	acl.RemoveHost("EXAMPLE.COM")
	if len(acl.AllowedHosts) != 1 {
		t.Errorf("Expected 1 host after case-insensitive removal, got %d", len(acl.AllowedHosts))
	}
	if acl.CheckHost("example.com") {
		t.Error("Host should have been removed (case insensitive)")
	}

	// Remove non-existent host (should not error or change list)
	acl.RemoveHost("notexist.com")
	if len(acl.AllowedHosts) != 1 {
		t.Errorf("Expected 1 host after removing non-existent, got %d", len(acl.AllowedHosts))
	}
}

func TestACL_SetAllowAll(t *testing.T) {
	acl := &ACL{
		AllowAll: false,
	}

	acl.SetAllowAll(true)
	if !acl.AllowAll {
		t.Error("Expected AllowAll to be true")
	}

	acl.SetAllowAll(false)
	if acl.AllowAll {
		t.Error("Expected AllowAll to be false")
	}
}

func TestACL_IsExpired(t *testing.T) {
	tests := []struct {
		name string
		ttl  *time.Time
		want bool
	}{
		{
			name: "No TTL set",
			ttl:  nil,
			want: false,
		},
		{
			name: "Future TTL",
			ttl:  timePtr(time.Now().Add(1 * time.Hour)),
			want: false,
		},
		{
			name: "Past TTL",
			ttl:  timePtr(time.Now().Add(-1 * time.Hour)),
			want: true,
		},
		{
			name: "Just expired",
			ttl:  timePtr(time.Now().Add(-1 * time.Second)),
			want: true,
		},
		{
			name: "Far future TTL",
			ttl:  timePtr(time.Now().Add(24 * time.Hour)),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := &ACL{
				TTL: tt.ttl,
			}
			if got := acl.IsExpired(); got != tt.want {
				t.Errorf("ACL.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACL_Encode(t *testing.T) {
	ttl := time.Now().Add(1 * time.Hour)
	acl := &ACL{
		AllowAll:     true,
		AllowedHosts: []string{"example.com", "test.com"},
		TTL:          &ttl,
	}

	encoded := acl.Encode()
	if len(encoded) == 0 {
		t.Error("Expected encoded data")
	}

	// Verify it's valid JSON
	var decoded ACL
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Errorf("Failed to decode ACL: %v", err)
	}

	if decoded.AllowAll != acl.AllowAll {
		t.Errorf("Expected AllowAll %v, got %v", acl.AllowAll, decoded.AllowAll)
	}

	if len(decoded.AllowedHosts) != len(acl.AllowedHosts) {
		t.Errorf("Expected %d hosts, got %d", len(acl.AllowedHosts), len(decoded.AllowedHosts))
	}

	if decoded.TTL == nil {
		t.Error("Expected TTL to be set")
	}
}

func TestACL_EmptyHostList(t *testing.T) {
	acl := &ACL{
		AllowAll:     false,
		AllowedHosts: []string{},
	}

	// Should not match any host when list is empty
	if acl.CheckHost("example.com") {
		t.Error("Empty host list should not match any host")
	}

	// Adding a host should work
	err := acl.AddHost("example.com")
	if err != nil {
		t.Errorf("AddHost() error = %v", err)
	}

	if !acl.CheckHost("example.com") {
		t.Error("Host should match after adding")
	}
}

func TestACL_AllowAllOverride(t *testing.T) {
	acl := &ACL{
		AllowAll:     true,
		AllowedHosts: []string{"example.com"},
	}

	// When AllowAll is true, the AllowedHosts list is typically ignored
	// but CheckHost still works for the list
	if !acl.CheckHost("example.com") {
		t.Error("Host in list should still match")
	}

	// Note: The actual authorization logic in handlers checks AllowAll first
	// This test just verifies the CheckHost method behavior
}

// Helper function to create a time pointer
func timePtr(t time.Time) *time.Time {
	return &t
}

