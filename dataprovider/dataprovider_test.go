package dataprovider

import (
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// -----------------------------------------------------------------------------
// Bolt temp file tracking + TestMain cleanup
// -----------------------------------------------------------------------------

var (
	boltTempFiles   []string
	boltTempFilesMu sync.Mutex
)

func registerBoltTempFile(path string) {
	boltTempFilesMu.Lock()
	boltTempFiles = append(boltTempFiles, path)
	boltTempFilesMu.Unlock()
}

func TestMain(m *testing.M) {
	code := m.Run()

	// Cleanup Bolt temp files even if tests/benchmarks failed
	boltTempFilesMu.Lock()
	for _, f := range boltTempFiles {
		log.Debugf("removing temp file %s", f)
		_ = os.Remove(f)
	}
	boltTempFilesMu.Unlock()

	os.Exit(code)
}

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

// newTestProvider returns a fresh Provider for the given implementation name.
// impl must be "memory" or "bolt".
func newTestProvider(t *testing.T, impl string) Provider {
	t.Helper()

	var p Provider

	switch impl {
	case "memory":
		mp, err := NewMemoryProvider()
		if err != nil {
			t.Fatalf("NewMemoryProvider: %v", err)
		}
		p = &mp

	case "bolt":
		// Create a temp file for Bolt; each test gets its own DB.
		tmp, err := os.CreateTemp("", "protego-bolt-test-*.db")
		if err != nil {
			t.Fatalf("error creating temp bolt file: %v", err)
		}
		log.Debugf("created temp file: %s", tmp.Name())
		// Close the file; Bolt will open it itself.
		_ = tmp.Close()

		registerBoltTempFile(tmp.Name())

		// Configure viper to point Bolt at the temp file.
		viper.Set("db.bolt.file", tmp.Name())

		bp, err := NewBoltProvider()
		if err != nil {
			t.Fatalf("NewBoltProvider: %v", err)
		}
		p = &bp

	default:
		t.Fatalf("unknown provider implementation: %q", impl)
	}

	if err := p.InitializeDatabase(); err != nil {
		t.Fatalf("InitializeDatabase(%s): %v", impl, err)
	}
	if err := p.CheckAvailability(); err != nil {
		t.Fatalf("CheckAvailability(%s): %v", impl, err)
	}

	// If the concrete provider has a Close() method, call it after the test.
	if closer, ok := p.(interface{ Close() error }); ok {
		t.Cleanup(func() {
			_ = closer.Close()
		})
	}

	return p
}

func newTestUser(id string) *User {
	return &User{
		Enabled:         true,
		Description:     "test user " + id,
		ID:              id,
		Secret:          "supersecret",
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{"git.example.com", "wiki.example.com"},
		DNSNames:        []string{"myhome.no-ip.info"},
		TTLMinutes:      60,
		IPs:             []string{"1.1.1.1"},
	}
}

func newTestACL() *ACL {
	ttl := time.Now().Add(1 * time.Hour)
	return &ACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com", "wiki.example.com"},
		TTL:          &ttl,
	}
}

func equalACL(a, b *ACL) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	if a.AllowAll != b.AllowAll {
		return false
	}
	if !reflect.DeepEqual(a.AllowedHosts, b.AllowedHosts) {
		return false
	}

	// Compare TTL using time.Equal, ignoring monotonic bits.
	if (a.TTL == nil) != (b.TTL == nil) {
		return false
	}
	if a.TTL != nil && !a.TTL.Equal(*b.TTL) {
		return false
	}

	return true
}

var providerImpls = []string{"memory", "bolt"}

// -----------------------------------------------------------------------------
// User CRUD tests
// -----------------------------------------------------------------------------

func TestProvider_UserCRUD(t *testing.T) {
	for _, impl := range providerImpls {
		t.Run(impl, func(t *testing.T) {
			p := newTestProvider(t, impl)

			// Create
			u := newTestUser("user-1")
			if err := p.AddUser(u); err != nil {
				t.Fatalf("AddUser: %v", err)
			}

			// Read
			got, err := p.GetUser(u.ID)
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if !reflect.DeepEqual(u, got) {
				t.Fatalf("GetUser mismatch:\nwant: %+v\n got: %+v", u, got)
			}

			// Update
			u.Description = "updated description"
			u.Enabled = false
			u.IPs = append(u.IPs, "2.2.2.2")

			if updateErr := p.UpdateUser(u); updateErr != nil {
				t.Fatalf("UpdateUser: %v", updateErr)
			}

			got2, err2 := p.GetUser(u.ID)
			if err2 != nil {
				t.Fatalf("GetUser after update: %v", err2)
			}
			if !reflect.DeepEqual(u, got2) {
				t.Fatalf("GetUser after update mismatch:\nwant: %+v\n got: %+v", u, got2)
			}

			// GetAllUsers should contain at least this user
			all, err3 := p.GetAllUsers()
			if err3 != nil {
				t.Fatalf("GetAllUsers: %v", err3)
			}
			found := false
			for _, usr := range all {
				if usr.ID == u.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("GetAllUsers: expected to find user %q in result", u.ID)
			}

			// Delete
			if deleteErr := p.RemoveUser(u); deleteErr != nil {
				t.Fatalf("RemoveUser: %v", deleteErr)
			}

			deletedUser, getErr := p.GetUser(u.ID)
			if getErr != nil || deletedUser != nil {
				t.Fatalf("GetUser after RemoveUser: expected both user and err to be nil: %v %v", deletedUser, getErr)
			}
		})
	}
}

func TestProvider_AddUser_DuplicateID(t *testing.T) {
	for _, impl := range providerImpls {
		t.Run(impl, func(t *testing.T) {
			p := newTestProvider(t, impl)

			u1 := newTestUser("dup-id")
			u2 := newTestUser("dup-id")

			if err := p.AddUser(u1); err != nil {
				t.Fatalf("first AddUser: %v", err)
			}
			if err := p.AddUser(u2); err == nil {
				t.Fatalf("second AddUser with same ID should fail")
			}
		})
	}
}

// -----------------------------------------------------------------------------
// ACL CRUD tests
// -----------------------------------------------------------------------------

func TestProvider_ACLCRUD(t *testing.T) {
	for _, impl := range providerImpls {
		t.Run(impl, func(t *testing.T) {
			p := newTestProvider(t, impl)

			ip := "10.0.0.1"
			acl := newTestACL()

			// Create
			if err := p.AddIp(ip, acl); err != nil {
				t.Fatalf("AddIp: %v", err)
			}

			// Read
			got, err := p.GetACL(ip)
			if err != nil {
				t.Fatalf("GetACL: %v", err)
			}
			if !equalACL(acl, got) {
				t.Fatalf("GetACL mismatch:\nwant: %+v\n got: %+v", acl, got)
			}

			// Update
			acl.AllowAll = true
			acl.AllowedHosts = []string{"example.com"}

			if updateErr := p.UpdateACL(ip, acl); updateErr != nil {
				t.Fatalf("UpdateACL: %v", updateErr)
			}

			got2, err2 := p.GetACL(ip)
			if err2 != nil {
				t.Fatalf("GetACL after update: %v", err2)
			}
			if !equalACL(acl, got2) {
				t.Fatalf("GetACL after update mismatch:\nwant: %+v\n got: %+v", acl, got2)
			}

			// GetAllACLs should contain this IP
			all, err3 := p.GetAllACLs()
			if err3 != nil {
				t.Fatalf("GetAllACLs: %v", err3)
			}
			gotACL, ok := all[ip]
			if !ok {
				t.Fatalf("GetAllACLs: expected ACL for IP %q", ip)
			}
			if !equalACL(acl, gotACL) {
				t.Fatalf("GetAllACLs[IP] mismatch:\nwant: %+v\n got: %+v", acl, gotACL)
			}

			// Delete
			if err := p.RemoveIp(ip); err != nil {
				t.Fatalf("RemoveIp: %v", err)
			}
			if a, err := p.GetACL(ip); err != nil || a != nil {
				t.Fatalf("GetACL after RemoveIp: expected expect both acl to be nil: %v %v", a, err)
			}
		})
	}
}

func TestProvider_AddIp_Duplicate(t *testing.T) {
	for _, impl := range providerImpls {
		t.Run(impl, func(t *testing.T) {
			p := newTestProvider(t, impl)

			ip := "10.0.0.2"
			acl1 := newTestACL()
			acl2 := newTestACL()

			newTTL := time.Now().Add(3 * time.Hour)
			acl2.TTL = &newTTL

			if err := p.AddIp(ip, acl1); err != nil {
				t.Fatalf("first AddIp: %v", err)
			}
			if err := p.AddIp(ip, acl2); err != nil {
				t.Fatalf("second AddIp for same IP should not fail")
			}

			got2, err := p.GetACL(ip)
			if err != nil {
				t.Fatalf("failed to get acl: %v", err)
			}
			if !equalACL(acl2, got2) {
				t.Fatalf("GetACL after update mismatch:\nwant: %+v\n got: %+v", acl2, got2)
			}
		})
	}
}
