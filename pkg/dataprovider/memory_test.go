package dataprovider

import (
	"testing"
	"time"
)

func TestMemoryProvider_InitializeDatabase(t *testing.T) {
	provider, err := NewMemoryProvider()
	if err != nil {
		t.Fatalf("NewMemoryProvider() error = %v", err)
	}

	if provider.users == nil {
		t.Error("Expected users map to be initialized")
	}

	if provider.acls == nil {
		t.Error("Expected acls map to be initialized")
	}
}

func TestMemoryProvider_CheckAvailability(t *testing.T) {
	provider, _ := NewMemoryProvider()

	err := provider.CheckAvailability()
	if err != nil {
		t.Errorf("CheckAvailability() error = %v", err)
	}
}

func TestMemoryProvider_AddUser(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Test User")

	err := provider.AddUser(user)
	if err != nil {
		t.Errorf("AddUser() error = %v", err)
	}

	// Verify user was added
	retrieved, err := provider.GetUser(user.ID)
	if err != nil {
		t.Errorf("GetUser() error = %v", err)
	}
	if retrieved == nil {
		t.Error("Expected user to be retrieved")
	}
	if retrieved.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, retrieved.ID)
	}
}

func TestMemoryProvider_AddUser_Duplicate(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Test User")

	// Add user first time
	err := provider.AddUser(user)
	if err != nil {
		t.Errorf("AddUser() error = %v", err)
	}

	// Try to add same user again
	err = provider.AddUser(user)
	if err != ErrUserExists {
		t.Errorf("Expected ErrUserExists, got %v", err)
	}
}

func TestMemoryProvider_GetUser(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Test User")
	provider.AddUser(user)

	// Get existing user
	retrieved, err := provider.GetUser(user.ID)
	if err != nil {
		t.Errorf("GetUser() error = %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected user to be retrieved")
	}
	if retrieved.Description != "Test User" {
		t.Errorf("Expected description 'Test User', got '%s'", retrieved.Description)
	}

	// Get non-existent user
	retrieved, err = provider.GetUser("nonexistent")
	if err != nil {
		t.Errorf("GetUser() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent user")
	}
}

func TestMemoryProvider_UpdateUser(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Original Description")
	user.ACLAllowAll = false
	provider.AddUser(user)

	// Update user
	user.Description = "Updated Description"
	user.ACLAllowAll = true
	user.ACLAllowedHosts = []string{"example.com"}

	err := provider.UpdateUser(user)
	if err != nil {
		t.Errorf("UpdateUser() error = %v", err)
	}

	// Verify update
	retrieved, _ := provider.GetUser(user.ID)
	if retrieved.Description != "Updated Description" {
		t.Errorf("Expected description 'Updated Description', got '%s'", retrieved.Description)
	}
	if !retrieved.ACLAllowAll {
		t.Error("Expected ACLAllowAll to be true")
	}
	if len(retrieved.ACLAllowedHosts) != 1 {
		t.Errorf("Expected 1 allowed host, got %d", len(retrieved.ACLAllowedHosts))
	}
}

func TestMemoryProvider_UpdateUser_NonExistent(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Test User")

	err := provider.UpdateUser(user)
	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestMemoryProvider_RemoveUser(t *testing.T) {
	provider, _ := NewMemoryProvider()

	user, _ := NewUser("testsecret123", "Test User")
	provider.AddUser(user)

	// Remove user
	err := provider.RemoveUser(user)
	if err != nil {
		t.Errorf("RemoveUser() error = %v", err)
	}

	// Verify removal
	retrieved, _ := provider.GetUser(user.ID)
	if retrieved != nil {
		t.Error("Expected user to be removed")
	}
}

func TestMemoryProvider_GetAllUsers(t *testing.T) {
	provider, _ := NewMemoryProvider()

	// Empty list
	users, err := provider.GetAllUsers()
	if err != nil {
		t.Errorf("GetAllUsers() error = %v", err)
	}
	if len(users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(users))
	}

	// Add multiple users
	for i := 0; i < 3; i++ {
		user, _ := NewUser("secret"+string(rune(i+48)), "User "+string(rune(i+48)))
		provider.AddUser(user)
	}

	users, err = provider.GetAllUsers()
	if err != nil {
		t.Errorf("GetAllUsers() error = %v", err)
	}
	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}
}

func TestMemoryProvider_AddIp(t *testing.T) {
	provider, _ := NewMemoryProvider()

	testIP := "192.168.1.1"
	acl := &ACL{
		AllowAll:     true,
		AllowedHosts: []string{"example.com"},
	}

	err := provider.AddIp(testIP, acl)
	if err != nil {
		t.Errorf("AddIp() error = %v", err)
	}

	// Verify IP was added
	retrieved, err := provider.GetACL(testIP)
	if err != nil {
		t.Errorf("GetACL() error = %v", err)
	}
	if retrieved == nil {
		t.Error("Expected ACL to be retrieved")
	}
	if !retrieved.AllowAll {
		t.Error("Expected AllowAll to be true")
	}
}

func TestMemoryProvider_AddIp_Invalid(t *testing.T) {
	provider, _ := NewMemoryProvider()

	acl := &ACL{
		AllowAll: true,
	}

	err := provider.AddIp("not.an.ip", acl)
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestMemoryProvider_GetACL(t *testing.T) {
	provider, _ := NewMemoryProvider()

	testIP := "192.168.1.1"
	acl := &ACL{
		AllowAll:     false,
		AllowedHosts: []string{"example.com"},
	}
	provider.AddIp(testIP, acl)

	// Get existing ACL
	retrieved, err := provider.GetACL(testIP)
	if err != nil {
		t.Errorf("GetACL() error = %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected ACL to be retrieved")
	}
	if retrieved.AllowAll {
		t.Error("Expected AllowAll to be false")
	}
	if len(retrieved.AllowedHosts) != 1 {
		t.Errorf("Expected 1 allowed host, got %d", len(retrieved.AllowedHosts))
	}

	// Get non-existent ACL
	retrieved, err = provider.GetACL("10.0.0.1")
	if err != nil {
		t.Errorf("GetACL() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent ACL")
	}
}

func TestMemoryProvider_GetACL_Expired(t *testing.T) {
	provider, _ := NewMemoryProvider()

	testIP := "192.168.1.1"
	expiredTime := time.Now().Add(-1 * time.Hour)
	acl := &ACL{
		AllowAll: true,
		TTL:      &expiredTime,
	}
	provider.AddIp(testIP, acl)

	// Get expired ACL (should be removed and return nil)
	retrieved, err := provider.GetACL(testIP)
	if err != nil {
		t.Errorf("GetACL() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for expired ACL")
	}

	// Verify it was removed from the map
	provider.lock.Lock()
	_, exists := provider.acls[testIP]
	provider.lock.Unlock()
	if exists {
		t.Error("Expected expired ACL to be removed from map")
	}
}

func TestMemoryProvider_UpdateACL(t *testing.T) {
	provider, _ := NewMemoryProvider()

	testIP := "192.168.1.1"
	acl := &ACL{
		AllowAll:     false,
		AllowedHosts: []string{"example.com"},
	}
	provider.AddIp(testIP, acl)

	// Update ACL
	newACL := &ACL{
		AllowAll:     true,
		AllowedHosts: []string{"example.com", "test.com"},
	}
	err := provider.UpdateACL(testIP, newACL)
	if err != nil {
		t.Errorf("UpdateACL() error = %v", err)
	}

	// Verify update
	retrieved, _ := provider.GetACL(testIP)
	if !retrieved.AllowAll {
		t.Error("Expected AllowAll to be true")
	}
	if len(retrieved.AllowedHosts) != 2 {
		t.Errorf("Expected 2 allowed hosts, got %d", len(retrieved.AllowedHosts))
	}
}

func TestMemoryProvider_UpdateACL_NonExistent(t *testing.T) {
	provider, _ := NewMemoryProvider()

	acl := &ACL{
		AllowAll: true,
	}

	err := provider.UpdateACL("192.168.1.1", acl)
	if err == nil {
		t.Error("Expected error for non-existent ACL")
	}
}

func TestMemoryProvider_RemoveIp(t *testing.T) {
	provider, _ := NewMemoryProvider()

	testIP := "192.168.1.1"
	acl := &ACL{
		AllowAll: true,
	}
	provider.AddIp(testIP, acl)

	// Remove IP
	err := provider.RemoveIp(testIP)
	if err != nil {
		t.Errorf("RemoveIp() error = %v", err)
	}

	// Verify removal
	retrieved, _ := provider.GetACL(testIP)
	if retrieved != nil {
		t.Error("Expected ACL to be removed")
	}
}

func TestMemoryProvider_Concurrency(t *testing.T) {
	provider, _ := NewMemoryProvider()

	// Test concurrent access
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			user, _ := NewUser("secret"+string(rune(id+48)), "User")
			provider.AddUser(user)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all users were added
	users, _ := provider.GetAllUsers()
	if len(users) != 10 {
		t.Errorf("Expected 10 users after concurrent writes, got %d", len(users))
	}
}
