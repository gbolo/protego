package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gbolo/protego/dataprovider"
	"github.com/gbolo/protego/pkg/fiberapp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// -----------------------------------------------------------------------------
// Test setup helpers
// -----------------------------------------------------------------------------

// setupTestFiberApp sets up a fresh Fiber app with in-memory data provider
func setupTestFiberApp(t *testing.T) interface {
	Test(*http.Request, ...int) (*http.Response, error)
} {
	t.Helper()

	// Clean Viper between tests
	viper.Reset()
	viper.Set("admin.secret", "test-admin-secret")

	// Fresh memory provider
	mp, err := dataprovider.NewMemoryProvider()
	if err != nil {
		t.Fatalf("NewMemoryProvider: %v", err)
	}
	if err := mp.InitializeDatabase(); err != nil {
		t.Fatalf("InitializeDatabase: %v", err)
	}
	if err := mp.CheckAvailability(); err != nil {
		t.Fatalf("CheckAvailability: %v", err)
	}
	dataProvider = &mp

	// Initialize ddnsProvider
	ddnsProvider = dataprovider.NewDdnsProvider()

	// Create Fiber app
	app := fiberapp.GetFiberApp("Protego-Test")
	setupFiberRoutes(app)

	return app
}

// -----------------------------------------------------------------------------
// /version
// -----------------------------------------------------------------------------

func TestFiberHandlerVersion(t *testing.T) {
	app := setupTestFiberApp(t)

	req, _ := http.NewRequest("GET", "/api/v1/version", nil)
	res, err := app.Test(req, -1)

	assert.Nil(t, err)
	assert.Equal(t, 200, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	var v version
	err = json.Unmarshal(body, &v)
	assert.Nil(t, err)
	assert.NotEmpty(t, v.Version)
	assert.NotEmpty(t, v.BuildRef)
}

// -----------------------------------------------------------------------------
// User CRUD
// -----------------------------------------------------------------------------

func TestFiberHandlerUserCRUD(t *testing.T) {
	app := setupTestFiberApp(t)

	// Test data
	var userId string // Will be set from response
	createReqBody := addUser{
		Enabled:         true,
		Description:     "Test User",
		Secret:          "supersecret",
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{"git.example.com"},
		DNSNames:        []string{},
		TTLMinutes:      60,
	}

	// 1. Add user
	t.Run("AddUser", func(t *testing.T) {
		createBytes, _ := json.Marshal(createReqBody)
		req, _ := http.NewRequest("POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 201, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		assert.Nil(t, err)
		assert.NotEmpty(t, user.ID)
		userId = user.ID // Store for subsequent tests
		assert.Equal(t, "Test User", user.Description)
		assert.True(t, user.Enabled)
	})

	// 2. Get user
	t.Run("GetUser", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/user/"+userId, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		assert.Nil(t, err)
		assert.Equal(t, userId, user.ID)
	})

	// 3. Update user
	t.Run("UpdateUser", func(t *testing.T) {
		updateReqBody := modifyUser{
			Enabled:         false,
			Description:     "Updated User",
			ACLAllowAll:     true,
			ACLAllowedHosts: []string{},
			DNSNames:        []string{},
			TTLMinutes:      120,
		}
		updateBytes, _ := json.Marshal(updateReqBody)
		req, _ := http.NewRequest("PUT", "/api/v1/user/"+userId, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		assert.Nil(t, err)
		assert.Equal(t, "Updated User", user.Description)
		assert.False(t, user.Enabled)
		assert.True(t, user.ACLAllowAll)
	})

	// 4. Get all users
	t.Run("GetAllUsers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var users []getUser
		err = json.Unmarshal(body, &users)
		assert.Nil(t, err)
		assert.GreaterOrEqual(t, len(users), 1)
	})

	// 5. Delete user
	t.Run("DeleteUser", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/v1/user/"+userId, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	// 6. Verify user is deleted
	t.Run("GetDeletedUser", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/user/"+userId, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 404, res.StatusCode)
	})
}

func TestFiberHandlerUserUnauthorized(t *testing.T) {
	app := setupTestFiberApp(t)

	tests := []struct {
		description string
		route       string
		method      string
		body        any
	}{
		{
			description: "add user without admin secret",
			route:       "/api/v1/user",
			method:      "POST",
			body:        addUser{Secret: "secret"},
		},
		{
			description: "get user without admin secret",
			route:       "/api/v1/user/testuser",
			method:      "GET",
			body:        nil,
		},
		{
			description: "update user without admin secret",
			route:       "/api/v1/user/testuser",
			method:      "PUT",
			body:        modifyUser{},
		},
		{
			description: "delete user without admin secret",
			route:       "/api/v1/user/testuser",
			method:      "DELETE",
			body:        nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			var reqBody []byte
			if test.body != nil {
				reqBody, _ = json.Marshal(test.body)
			}

			req, _ := http.NewRequest(test.method, test.route, bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			// Not setting Admin-Secret header

			res, err := app.Test(req, -1)
			assert.Nil(t, err)
			assert.Equal(t, 401, res.StatusCode)
		})
	}
}

// -----------------------------------------------------------------------------
// ACL CRUD
// -----------------------------------------------------------------------------

func TestFiberHandlerACLCRUD(t *testing.T) {
	app := setupTestFiberApp(t)

	// Test data
	testIP := "192.168.1.100"
	ttl := "2025-12-31T23:59:59Z"
	createReqBody := addACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com", "wiki.example.com"},
		UserIDs:      []string{"user1", "user2"},
		TTL:          &ttl,
	}

	// 1. Add ACL
	t.Run("AddACL", func(t *testing.T) {
		createBytes, _ := json.Marshal(createReqBody)
		req, _ := http.NewRequest("POST", "/api/v1/acl/"+testIP, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 201, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		assert.Nil(t, err)
		assert.Equal(t, testIP, acl.IPAddress)
		assert.False(t, acl.AllowAll)
		assert.Equal(t, 2, len(acl.AllowedHosts))
	})

	// 2. Get ACL
	t.Run("GetACL", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/acl/"+testIP, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		assert.Nil(t, err)
		assert.Equal(t, testIP, acl.IPAddress)
	})

	// 3. Update ACL
	t.Run("UpdateACL", func(t *testing.T) {
		updateReqBody := modifyACL{
			AllowAll:     true,
			AllowedHosts: []string{},
			UserIDs:      []string{"user1"},
			TTL:          nil,
		}
		updateBytes, _ := json.Marshal(updateReqBody)
		req, _ := http.NewRequest("PUT", "/api/v1/acl/"+testIP, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		assert.Nil(t, err)
		assert.True(t, acl.AllowAll)
		assert.Equal(t, 1, len(acl.UserIDs))
	})

	// 4. Get all ACLs
	t.Run("GetAllACLs", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/acl", nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acls []getACL
		err = json.Unmarshal(body, &acls)
		assert.Nil(t, err)
		assert.GreaterOrEqual(t, len(acls), 1)
	})

	// 5. Delete ACL
	t.Run("DeleteACL", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/v1/acl/"+testIP, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	// 6. Verify ACL is deleted
	t.Run("GetDeletedACL", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/acl/"+testIP, nil)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 404, res.StatusCode)
	})
}

func TestFiberHandlerACLInvalidIP(t *testing.T) {
	app := setupTestFiberApp(t)

	t.Run("invalid IP format", func(t *testing.T) {
		createReqBody := addACL{AllowAll: true}
		createBytes, _ := json.Marshal(createReqBody)

		req, _ := http.NewRequest("POST", "/api/v1/acl/not-an-ip", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 400, res.StatusCode)
	})
}

func TestFiberHandlerACLGetAllEmpty(t *testing.T) {
	app := setupTestFiberApp(t)

	req, _ := http.NewRequest("GET", "/api/v1/acl", nil)
	req.Header.Set("Admin-Secret", "test-admin-secret")

	res, err := app.Test(req, -1)
	assert.Nil(t, err)
	assert.Equal(t, 200, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	var acls []getACL
	err = json.Unmarshal(body, &acls)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(acls))
}

// -----------------------------------------------------------------------------
// Route Tests
// -----------------------------------------------------------------------------

func TestFiberRoutes(t *testing.T) {
	app := setupTestFiberApp(t)

	tests := []struct {
		description  string
		route        string
		method       string
		expectedCode int
	}{
		{
			description:  "get version",
			route:        "/api/v1/version",
			method:       "GET",
			expectedCode: 200,
		},
		{
			description:  "non existing route",
			route:        "/api/v1/i-dont-exist",
			method:       "GET",
			expectedCode: 404,
		},
		{
			description:  "admin page exists",
			route:        "/admin",
			method:       "GET",
			expectedCode: 200,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, test.route, nil)
			res, err := app.Test(req, -1)

			assert.Nil(t, err)
			assert.Equal(t, test.expectedCode, res.StatusCode)
		})
	}
}

// -----------------------------------------------------------------------------
// Challenge endpoint with ACL merging
// -----------------------------------------------------------------------------

func TestFiberHandlerChallenge_MergeACLsForSameIP(t *testing.T) {
	app := setupTestFiberApp(t)

	const (
		userSecret1 = "secret-user-1"
		userSecret2 = "secret-user-2"
		clientIP    = "203.0.113.20"
		host1       = "git.example.com"
		host2       = "wiki.example.com"
	)

	// --- Create first user with shorter TTL ---
	t.Run("Create first user", func(t *testing.T) {
		reqBody1 := addUser{
			Enabled:         true,
			Description:     "First User",
			Secret:          userSecret1,
			ACLAllowAll:     false,
			ACLAllowedHosts: []string{host1},
			TTLMinutes:      60, // shorter TTL
		}
		b1, _ := json.Marshal(reqBody1)

		req, _ := http.NewRequest("POST", "/api/v1/user", bytes.NewReader(b1))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 201, res.StatusCode)
	})

	// --- First challenge with user1 ---
	var firstTTL *time.Time
	t.Run("First challenge creates ACL for user1", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/challenge", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-Secret", userSecret1)

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 202, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var chResp challengeResponse
		err = json.Unmarshal(body, &chResp)
		assert.Nil(t, err)
		assert.Equal(t, clientIP, chResp.IpAddress)
		assert.Equal(t, 1, len(chResp.ACL.AllowedHosts))
		assert.Equal(t, host1, chResp.ACL.AllowedHosts[0])
		assert.NotNil(t, chResp.ACL.TTL)
		firstTTL = chResp.ACL.TTL
	})

	// --- Create second user with longer TTL and AllowAll=true ---
	t.Run("Create second user", func(t *testing.T) {
		reqBody2 := addUser{
			Enabled:         true,
			Description:     "Second User",
			Secret:          userSecret2,
			ACLAllowAll:     true, // this should win
			ACLAllowedHosts: []string{host2},
			TTLMinutes:      120, // longer TTL
		}
		b2, _ := json.Marshal(reqBody2)

		req, _ := http.NewRequest("POST", "/api/v1/user", bytes.NewReader(b2))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 201, res.StatusCode)
	})

	// --- Second challenge with SAME IP but user2's secret ---
	t.Run("Second challenge merges ACLs", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/challenge", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-Secret", userSecret2)

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 202, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var chResp challengeResponse
		err = json.Unmarshal(body, &chResp)
		assert.Nil(t, err)

		// --- Assert merged ACL properties ---

		// AllowAll: true should win
		assert.True(t, chResp.ACL.AllowAll, "merged ACL should have AllowAll=true")

		// AllowedHosts: union of host1 and host2
		assert.GreaterOrEqual(t, len(chResp.ACL.AllowedHosts), 2, "merged ACL should have at least 2 hosts")
		hostSet := make(map[string]struct{})
		for _, h := range chResp.ACL.AllowedHosts {
			hostSet[h] = struct{}{}
		}
		_, hasHost1 := hostSet[host1]
		_, hasHost2 := hostSet[host2]
		assert.True(t, hasHost1, "merged ACL should contain host1")
		assert.True(t, hasHost2, "merged ACL should contain host2")

		// TTL: greater of the two should win (or at least not be earlier)
		assert.NotNil(t, chResp.ACL.TTL, "merged ACL should have TTL")
		assert.False(t, chResp.ACL.TTL.Before(*firstTTL), "merged ACL TTL should be >= first TTL")
	})

	// --- Verify authorization works for both hosts ---
	t.Run("Authorize host1 after merge", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/authorize", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = host1

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode, "should authorize host1 after ACL merge")
	})

	t.Run("Authorize host2 after merge", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/authorize", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = host2

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode, "should authorize host2 after ACL merge")
	})

	// --- Verify AllowAll works ---
	t.Run("Authorize any host with AllowAll", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/authorize", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = "random.example.com"

		res, err := app.Test(req, -1)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode, "should authorize any host when AllowAll=true")
	})
}
