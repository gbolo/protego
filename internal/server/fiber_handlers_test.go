package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/gbolo/protego/pkg/fiberapp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Initialize ddnsProvider with data provider reference
	ddnsProvider = dataprovider.NewDdnsProvider(dataProvider)

	// Create Fiber app
	app := fiberapp.GetFiberApp("Protego-Test")
	setupFiberRoutes(app)

	return app
}

// -----------------------------------------------------------------------------
// /version
// -----------------------------------------------------------------------------

func TestFiberHandlerVersion(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/version", http.NoBody)
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, 200, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	var v version
	err = json.Unmarshal(body, &v)
	require.NoError(t, err)
	assert.NotEmpty(t, v.Version)
	assert.NotEmpty(t, v.BuildRef)
}

// -----------------------------------------------------------------------------
// User CRUD
// -----------------------------------------------------------------------------

func TestFiberHandlerUserCRUD(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	// Test data
	userId := "testuser" // Use a defined user ID
	createReqBody := addUser{
		ID:              userId,
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
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		require.NoError(t, err)
		assert.Equal(t, userId, user.ID)
		assert.Equal(t, "Test User", user.Description)
		assert.True(t, user.Enabled)
	})

	// 2. Get user
	t.Run("GetUser", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/user/"+userId, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		require.NoError(t, err)
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
		req, _ := http.NewRequestWithContext(t.Context(), "PUT", "/api/v1/user/"+userId, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		require.NoError(t, err)
		assert.Equal(t, "Updated User", user.Description)
		assert.False(t, user.Enabled)
		assert.True(t, user.ACLAllowAll)
	})

	// 4. Get all users
	t.Run("GetAllUsers", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/user", http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var users []getUser
		err = json.Unmarshal(body, &users)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(users), 1)
	})

	// 5. Delete user
	t.Run("DeleteUser", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "DELETE", "/api/v1/user/"+userId, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// 6. Verify user is deleted
	t.Run("GetDeletedUser", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/user/"+userId, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 404, res.StatusCode)
	})
}

func TestFiberHandlerUserUnauthorized(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

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
			body:        addUser{ID: "test", Secret: "secret"},
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

			req, _ := http.NewRequestWithContext(t.Context(), test.method, test.route, bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			// Not setting Admin-Secret header

			res, err := app.Test(req, -1)
			require.NoError(t, err)
			defer res.Body.Close()
			assert.Equal(t, 401, res.StatusCode)
		})
	}
}

// -----------------------------------------------------------------------------
// ACL CRUD
// -----------------------------------------------------------------------------

func TestFiberHandlerACLCRUD(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

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
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+testIP, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		require.NoError(t, err)
		assert.Equal(t, testIP, acl.IPAddress)
		assert.False(t, acl.AllowAll)
		assert.Len(t, acl.AllowedHosts, 2)
	})

	// 2. Get ACL
	t.Run("GetACL", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+testIP, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		require.NoError(t, err)
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
		req, _ := http.NewRequestWithContext(t.Context(), "PUT", "/api/v1/acl/"+testIP, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		require.NoError(t, err)
		assert.True(t, acl.AllowAll)
		assert.Len(t, acl.UserIDs, 1)
	})

	// 4. Get all ACLs
	t.Run("GetAllACLs", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl", http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var acls []getACL
		err = json.Unmarshal(body, &acls)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(acls), 1)
	})

	// 5. Delete ACL
	t.Run("DeleteACL", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "DELETE", "/api/v1/acl/"+testIP, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// 6. Verify ACL is deleted
	t.Run("GetDeletedACL", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+testIP, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 404, res.StatusCode)
	})
}

func TestFiberHandlerACLInvalidIP(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	t.Run("invalid IP format", func(t *testing.T) {
		createReqBody := addACL{AllowAll: true}
		createBytes, _ := json.Marshal(createReqBody)

		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/not-an-ip", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 400, res.StatusCode)
	})
}

func TestFiberHandlerACLGetAllEmpty(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl", http.NoBody)
	req.Header.Set("Admin-Secret", "test-admin-secret")

	res, err := app.Test(req, -1)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, 200, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	var acls []getACL
	err = json.Unmarshal(body, &acls)
	require.NoError(t, err)
	assert.Empty(t, acls)
}

// -----------------------------------------------------------------------------
// Route Tests
// -----------------------------------------------------------------------------

func TestFiberRoutes(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

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
			req, _ := http.NewRequestWithContext(t.Context(), test.method, test.route, http.NoBody)
			res, err := app.Test(req, -1)
			require.NoError(t, err)
			defer res.Body.Close()

			assert.Equal(t, test.expectedCode, res.StatusCode)
		})
	}
}

// -----------------------------------------------------------------------------
// Challenge endpoint with ACL merging
// -----------------------------------------------------------------------------

func TestFiberHandlerChallenge_MergeACLsForSameIP(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		userId1     = "user1"
		userId2     = "user2"
		userSecret1 = "secret-user-1"
		userSecret2 = "secret-user-2"
		clientIP    = "203.0.113.20"
		host1       = "git.example.com"
		host2       = "wiki.example.com"
	)

	// --- Create first user with shorter TTL ---
	t.Run("Create first user", func(t *testing.T) {
		reqBody1 := addUser{
			ID:              userId1,
			Enabled:         true,
			Description:     "First User",
			Secret:          userSecret1,
			ACLAllowAll:     false,
			ACLAllowedHosts: []string{host1},
			TTLMinutes:      60, // shorter TTL
		}
		b1, _ := json.Marshal(reqBody1)

		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(b1))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()

		if res.StatusCode != 201 {
			body, _ := io.ReadAll(res.Body)
			t.Logf("Error creating user: %s", string(body))
		}
		assert.Equal(t, 201, res.StatusCode)
	})

	// --- First challenge with user1 ---
	var firstTTL *time.Time
	t.Run("First challenge creates ACL for user1", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/challenge", http.NoBody)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-ID", userId1)
		req.Header.Set("User-Secret", userSecret1)

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 202, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var chResp challengeResponse
		err = json.Unmarshal(body, &chResp)
		require.NoError(t, err)
		assert.Equal(t, clientIP, chResp.IpAddress)
		assert.Len(t, chResp.AllowedHosts, 1)
		assert.Equal(t, host1, chResp.AllowedHosts[0])
		assert.NotNil(t, chResp.TTL)
		firstTTL = chResp.TTL
	})

	// --- Create second user with longer TTL and AllowAll=true ---
	t.Run("Create second user", func(t *testing.T) {
		reqBody2 := addUser{
			ID:              userId2,
			Enabled:         true,
			Description:     "Second User",
			Secret:          userSecret2,
			ACLAllowAll:     true, // this should win
			ACLAllowedHosts: []string{host2},
			TTLMinutes:      120, // longer TTL
		}
		b2, _ := json.Marshal(reqBody2)

		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(b2))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// --- Second challenge with SAME IP but user2's secret ---
	t.Run("Second challenge merges ACLs", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/challenge", http.NoBody)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-ID", userId2)
		req.Header.Set("User-Secret", userSecret2)

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 202, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var chResp challengeResponse
		err = json.Unmarshal(body, &chResp)
		require.NoError(t, err)

		// --- Assert merged ACL properties ---

		// AllowAll: true should win
		assert.True(t, chResp.AllowAll, "merged ACL should have AllowAll=true")

		// AllowedHosts: union of host1 and host2
		assert.GreaterOrEqual(t, len(chResp.AllowedHosts), 2, "merged ACL should have at least 2 hosts")
		hostSet := make(map[string]struct{})
		for _, h := range chResp.AllowedHosts {
			hostSet[h] = struct{}{}
		}
		_, hasHost1 := hostSet[host1]
		_, hasHost2 := hostSet[host2]
		assert.True(t, hasHost1, "merged ACL should contain host1")
		assert.True(t, hasHost2, "merged ACL should contain host2")

		// TTL: greater of the two should win (or at least not be earlier)
		assert.NotNil(t, chResp.TTL, "merged ACL should have TTL")
		assert.False(t, chResp.TTL.Before(*firstTTL), "merged ACL TTL should be >= first TTL")
	})

	// --- Verify authorization works for both hosts ---
	t.Run("Authorize host1 after merge", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/authorize", http.NoBody)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = host1

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "should authorize host1 after ACL merge")
	})

	t.Run("Authorize host2 after merge", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/authorize", http.NoBody)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = host2

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "should authorize host2 after ACL merge")
	})

	// --- Verify AllowAll works ---
	t.Run("Authorize any host with AllowAll", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/authorize", http.NoBody)
		req.Header.Set("X-Real-IP", clientIP)
		req.Host = "random.example.com"

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "should authorize any host when AllowAll=true")
	})
}

// -----------------------------------------------------------------------------
// Max TTL Validation Tests
// -----------------------------------------------------------------------------

func TestFiberHandlerMaxTTL(t *testing.T) {
	// Common test constants
	const (
		maxTTLConfigured   = 100
		maxTTLUnlimited    = 0
		testUserID         = "testuser3"
		testUserUnlimited  = "testuser-unlimited"
		testUserLarge      = "testuser-large"
		testSecret         = "supersecret"
		testDescription    = "Test User"
		updatedDescription = "Updated User"
	)

	// Common endpoints
	var (
		userEndpoint    = "/api/v1/user"
		userIDEndpoint  = "/api/v1/user/" + testUserID
		aclBaseEndpoint = "/api/v1/acl/"
	)

	// Common error messages
	var (
		errTTLExceeded  = "TTL has exceeded max allowed value"
		errTTLRequired  = "TTL is required and cannot be"
		errTTLUnlimited = "TTL is required and cannot be unlimited"
	)

	// Helper to create user request body
	createUserBody := func(id string, ttl int) addUser {
		return addUser{
			ID:          id,
			Enabled:     true,
			Description: testDescription,
			Secret:      testSecret,
			TTLMinutes:  ttl,
		}
	}

	// Helper to create ACL request body with TTL
	createACLBody := func(minutesFromNow int) addACL {
		futureTime := time.Now().Add(time.Duration(minutesFromNow) * time.Minute).Format(time.RFC3339)
		return addACL{
			AllowAll:     true,
			AllowedHosts: []string{},
			TTL:          &futureTime,
		}
	}

	tests := []struct {
		name              string
		maxTTL            int
		method            string
		endpoint          string
		requestBody       any
		expectedStatus    int
		expectedErrorMsg  string
		validateResponse  func(*testing.T, []byte)
		setupPrerequisite func(*testing.T, interface {
			Test(*http.Request, ...int) (*http.Response, error)
		})
	}{
		// User tests with max TTL = 100
		{
			name:             "Add user with TTL exceeding max",
			maxTTL:           maxTTLConfigured,
			method:           "POST",
			endpoint:         userEndpoint,
			requestBody:      createUserBody("testuser1", 200),
			expectedStatus:   400,
			expectedErrorMsg: errTTLExceeded,
		},
		{
			name:             "Add user with TTL = 0 when max is configured",
			maxTTL:           maxTTLConfigured,
			method:           "POST",
			endpoint:         userEndpoint,
			requestBody:      createUserBody("testuser2", 0),
			expectedStatus:   400,
			expectedErrorMsg: errTTLRequired,
		},
		{
			name:           "Add user with valid TTL when max is configured",
			maxTTL:         maxTTLConfigured,
			method:         "POST",
			endpoint:       userEndpoint,
			requestBody:    createUserBody(testUserID, 50),
			expectedStatus: 201,
			validateResponse: func(t *testing.T, body []byte) {
				var user getUser
				err := json.Unmarshal(body, &user)
				require.NoError(t, err)
				assert.Equal(t, testUserID, user.ID)
				assert.Equal(t, 50, user.TTLMinutes)
			},
		},
		{
			name:     "Update user with TTL exceeding max",
			maxTTL:   maxTTLConfigured,
			method:   "PUT",
			endpoint: userIDEndpoint,
			requestBody: modifyUser{
				Enabled:     true,
				Description: updatedDescription,
				TTLMinutes:  150,
			},
			expectedStatus:   400,
			expectedErrorMsg: errTTLExceeded,
			setupPrerequisite: func(t *testing.T, app interface {
				Test(*http.Request, ...int) (*http.Response, error)
			}) {
				reqBody := createUserBody(testUserID, 50)
				createBytes, _ := json.Marshal(reqBody)
				req, _ := http.NewRequestWithContext(t.Context(), "POST", userEndpoint, bytes.NewReader(createBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Admin-Secret", "test-admin-secret")
				res, _ := app.Test(req, -1)
				res.Body.Close()
			},
		},
		{
			name:     "Update user with valid TTL",
			maxTTL:   maxTTLConfigured,
			method:   "PUT",
			endpoint: userIDEndpoint,
			requestBody: modifyUser{
				Enabled:     true,
				Description: updatedDescription,
				TTLMinutes:  75,
			},
			expectedStatus: 200,
			validateResponse: func(t *testing.T, body []byte) {
				var user getUser
				err := json.Unmarshal(body, &user)
				require.NoError(t, err)
				assert.Equal(t, 75, user.TTLMinutes)
			},
			setupPrerequisite: func(t *testing.T, app interface {
				Test(*http.Request, ...int) (*http.Response, error)
			}) {
				reqBody := createUserBody(testUserID, 50)
				createBytes, _ := json.Marshal(reqBody)
				req, _ := http.NewRequestWithContext(t.Context(), "POST", userEndpoint, bytes.NewReader(createBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Admin-Secret", "test-admin-secret")
				res, _ := app.Test(req, -1)
				res.Body.Close()
			},
		},
		// ACL tests with max TTL = 100
		{
			name:     "Add ACL without TTL when max is configured",
			maxTTL:   maxTTLConfigured,
			method:   "POST",
			endpoint: aclBaseEndpoint + "192.168.50.100",
			requestBody: addACL{
				AllowAll:     true,
				AllowedHosts: []string{},
			},
			expectedStatus:   400,
			expectedErrorMsg: errTTLUnlimited,
		},
		{
			name:             "Add ACL with TTL exceeding max",
			maxTTL:           maxTTLConfigured,
			method:           "POST",
			endpoint:         aclBaseEndpoint + "192.168.50.200",
			requestBody:      createACLBody(200),
			expectedStatus:   400,
			expectedErrorMsg: errTTLExceeded,
		},
		{
			name:           "Add ACL with valid TTL when max is configured",
			maxTTL:         maxTTLConfigured,
			method:         "POST",
			endpoint:       aclBaseEndpoint + "192.168.50.150",
			requestBody:    createACLBody(50),
			expectedStatus: 201,
			validateResponse: func(t *testing.T, body []byte) {
				var acl getACL
				err := json.Unmarshal(body, &acl)
				require.NoError(t, err)
				assert.NotNil(t, acl.TTL)
			},
		},
		{
			name:     "Update ACL without TTL when max is configured",
			maxTTL:   maxTTLConfigured,
			method:   "PUT",
			endpoint: aclBaseEndpoint + "192.168.50.151",
			requestBody: modifyACL{
				AllowAll:     false,
				AllowedHosts: []string{"example.com"},
			},
			expectedStatus:   400,
			expectedErrorMsg: errTTLUnlimited,
			setupPrerequisite: func(t *testing.T, app interface {
				Test(*http.Request, ...int) (*http.Response, error)
			}) {
				reqBody := createACLBody(50)
				createBytes, _ := json.Marshal(reqBody)
				req, _ := http.NewRequestWithContext(t.Context(), "POST", aclBaseEndpoint+"192.168.50.151", bytes.NewReader(createBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Admin-Secret", "test-admin-secret")
				res, _ := app.Test(req, -1)
				res.Body.Close()
			},
		},
		{
			name:     "Update ACL with TTL exceeding max",
			maxTTL:   maxTTLConfigured,
			method:   "PUT",
			endpoint: aclBaseEndpoint + "192.168.50.152",
			requestBody: func() modifyACL {
				futureTime := time.Now().Add(180 * time.Minute).Format(time.RFC3339)
				return modifyACL{
					AllowAll:     false,
					AllowedHosts: []string{"example.com"},
					TTL:          &futureTime,
				}
			}(),
			expectedStatus:   400,
			expectedErrorMsg: errTTLExceeded,
			setupPrerequisite: func(t *testing.T, app interface {
				Test(*http.Request, ...int) (*http.Response, error)
			}) {
				reqBody := createACLBody(50)
				createBytes, _ := json.Marshal(reqBody)
				req, _ := http.NewRequestWithContext(t.Context(), "POST", aclBaseEndpoint+"192.168.50.152", bytes.NewReader(createBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Admin-Secret", "test-admin-secret")
				res, _ := app.Test(req, -1)
				res.Body.Close()
			},
		},
		{
			name:     "Update ACL with valid TTL",
			maxTTL:   maxTTLConfigured,
			method:   "PUT",
			endpoint: aclBaseEndpoint + "192.168.50.153",
			requestBody: func() modifyACL {
				futureTime := time.Now().Add(80 * time.Minute).Format(time.RFC3339)
				return modifyACL{
					AllowAll:     false,
					AllowedHosts: []string{"example.com"},
					TTL:          &futureTime,
				}
			}(),
			expectedStatus: 200,
			validateResponse: func(t *testing.T, body []byte) {
				var acl getACL
				err := json.Unmarshal(body, &acl)
				require.NoError(t, err)
				assert.NotNil(t, acl.TTL)
			},
			setupPrerequisite: func(t *testing.T, app interface {
				Test(*http.Request, ...int) (*http.Response, error)
			}) {
				reqBody := createACLBody(50)
				createBytes, _ := json.Marshal(reqBody)
				req, _ := http.NewRequestWithContext(t.Context(), "POST", aclBaseEndpoint+"192.168.50.153", bytes.NewReader(createBytes))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Admin-Secret", "test-admin-secret")
				res, _ := app.Test(req, -1)
				res.Body.Close()
			},
		},
		// Tests with max TTL = 0 (unlimited allowed)
		{
			name:           "Add user with TTL = 0 when unlimited is allowed",
			maxTTL:         maxTTLUnlimited,
			method:         "POST",
			endpoint:       userEndpoint,
			requestBody:    createUserBody(testUserUnlimited, 0),
			expectedStatus: 201,
			validateResponse: func(t *testing.T, body []byte) {
				var user getUser
				err := json.Unmarshal(body, &user)
				require.NoError(t, err)
				assert.Equal(t, testUserUnlimited, user.ID)
				assert.Equal(t, 0, user.TTLMinutes)
			},
		},
		{
			name:     "Add ACL without TTL when unlimited is allowed",
			maxTTL:   maxTTLUnlimited,
			method:   "POST",
			endpoint: aclBaseEndpoint + "192.168.60.100",
			requestBody: addACL{
				AllowAll:     true,
				AllowedHosts: []string{},
			},
			expectedStatus: 201,
			validateResponse: func(t *testing.T, body []byte) {
				var acl getACL
				err := json.Unmarshal(body, &acl)
				require.NoError(t, err)
				assert.Nil(t, acl.TTL)
			},
		},
		{
			name:           "Add user with very large TTL when unlimited is allowed",
			maxTTL:         maxTTLUnlimited,
			method:         "POST",
			endpoint:       userEndpoint,
			requestBody:    createUserBody(testUserLarge, 999999),
			expectedStatus: 201,
			validateResponse: func(t *testing.T, body []byte) {
				var user getUser
				err := json.Unmarshal(body, &user)
				require.NoError(t, err)
				assert.Equal(t, testUserLarge, user.ID)
				assert.Equal(t, 999999, user.TTLMinutes)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response
			viper.Set("ttl.max", tt.maxTTL)

			// Run setup if needed
			if tt.setupPrerequisite != nil {
				tt.setupPrerequisite(t, app)
			}

			// Create request
			reqBytes, _ := json.Marshal(tt.requestBody)
			req, _ := http.NewRequestWithContext(t.Context(), tt.method, tt.endpoint, bytes.NewReader(reqBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Admin-Secret", "test-admin-secret")

			// Execute request
			res, err := app.Test(req, -1)
			require.NoError(t, err)
			defer res.Body.Close()

			// Validate status code
			assert.Equal(t, tt.expectedStatus, res.StatusCode)

			// Read response body
			body, _ := io.ReadAll(res.Body)

			// Validate error message if expected
			if tt.expectedErrorMsg != "" {
				var errResp errorResponse
				err = json.Unmarshal(body, &errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Error, tt.expectedErrorMsg)
			}

			// Custom validation if provided
			if tt.validateResponse != nil {
				tt.validateResponse(t, body)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// User Disable ACL Cleanup Tests
// -----------------------------------------------------------------------------

func TestFiberHandlerUserDisable_RemovesACLs(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		testUserID   = "testuser-disable"
		otherUserID  = "otheruser"
		testSecret   = "supersecret"
		ipOnlyUser   = "10.0.0.1"
		ipSharedUser = "10.0.0.2"
	)

	// Create test user
	t.Run("Create user", func(t *testing.T) {
		reqBody := addUser{
			ID:          testUserID,
			Enabled:     true,
			Description: "Test User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create other user
	t.Run("Create other user", func(t *testing.T) {
		reqBody := addUser{
			ID:          otherUserID,
			Enabled:     true,
			Description: "Other User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create ACL with only testUser
	t.Run("Create ACL with only test user", func(t *testing.T) {
		ttl := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		reqBody := addACL{
			AllowAll:     false,
			AllowedHosts: []string{"example.com"},
			UserIDs:      []string{testUserID},
			TTL:          &ttl,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+ipOnlyUser, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create ACL with both users
	t.Run("Create ACL with both users", func(t *testing.T) {
		ttl := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		reqBody := addACL{
			AllowAll:     false,
			AllowedHosts: []string{"example.com"},
			UserIDs:      []string{testUserID, otherUserID},
			TTL:          &ttl,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+ipSharedUser, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Verify ACLs exist before disabling user
	t.Run("Verify ACLs exist before disable", func(t *testing.T) {
		// Check ACL with only test user
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipOnlyUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")
		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		// Check ACL with both users
		req2, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipSharedUser, http.NoBody)
		req2.Header.Set("Admin-Secret", "test-admin-secret")
		res2, err := app.Test(req2, -1)
		require.NoError(t, err)
		defer res2.Body.Close()
		assert.Equal(t, 200, res2.StatusCode)
	})

	// Disable the user
	t.Run("Disable user", func(t *testing.T) {
		reqBody := modifyUser{
			Enabled:     false,
			Description: "Disabled User",
			TTLMinutes:  60,
		}
		updateBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "PUT", "/api/v1/user/"+testUserID, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// Verify ACL with only test user is removed
	t.Run("Verify ACL with only user is removed", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipOnlyUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 404, res.StatusCode, "ACL with only disabled user should be removed")
	})

	// Verify ACL with both users still exists but without test user
	t.Run("Verify shared ACL exists without disabled user", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipSharedUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "Shared ACL should still exist")

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		require.NoError(t, err)

		// Verify disabled user is not in the ACL
		assert.NotContains(t, acl.UserIDs, testUserID, "Disabled user should be removed from shared ACL")
		// Verify other user is still in the ACL
		assert.Contains(t, acl.UserIDs, otherUserID, "Other user should remain in shared ACL")
		assert.Len(t, acl.UserIDs, 1, "ACL should have exactly one user remaining")
	})
}

func TestFiberHandlerUserDisable_NoACLs(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		testUserID = "testuser-no-acls"
		testSecret = "supersecret"
	)

	// Create user
	t.Run("Create user", func(t *testing.T) {
		reqBody := addUser{
			ID:          testUserID,
			Enabled:     true,
			Description: "Test User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Disable user without any ACLs - should succeed without errors
	t.Run("Disable user with no ACLs", func(t *testing.T) {
		reqBody := modifyUser{
			Enabled:     false,
			Description: "Disabled User",
			TTLMinutes:  60,
		}
		updateBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "PUT", "/api/v1/user/"+testUserID, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		body, _ := io.ReadAll(res.Body)
		var user getUser
		err = json.Unmarshal(body, &user)
		require.NoError(t, err)
		assert.False(t, user.Enabled)
	})
}

func TestFiberHandlerUserDisable_AlreadyDisabled(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		testUserID = "testuser-already-disabled"
		testSecret = "supersecret"
		testIP     = "10.0.0.10"
	)

	// Create disabled user
	t.Run("Create disabled user", func(t *testing.T) {
		reqBody := addUser{
			ID:          testUserID,
			Enabled:     false,
			Description: "Test User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create ACL with disabled user
	t.Run("Create ACL", func(t *testing.T) {
		ttl := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		reqBody := addACL{
			AllowAll:     false,
			AllowedHosts: []string{"example.com"},
			UserIDs:      []string{testUserID},
			TTL:          &ttl,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+testIP, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Update user (still disabled) - ACL should NOT be removed since user wasn't being disabled
	t.Run("Update disabled user", func(t *testing.T) {
		reqBody := modifyUser{
			Enabled:     false,
			Description: "Still Disabled User",
			TTLMinutes:  90,
		}
		updateBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "PUT", "/api/v1/user/"+testUserID, bytes.NewReader(updateBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// ACL should still exist since user was already disabled
	t.Run("Verify ACL still exists", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+testIP, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "ACL should still exist when updating already-disabled user")
	})
}

// -----------------------------------------------------------------------------
// User Delete ACL Cleanup Tests
// -----------------------------------------------------------------------------

func TestFiberHandlerUserDelete_RemovesACLs(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		testUserID   = "testuser-delete"
		otherUserID  = "otheruser-delete"
		testSecret   = "supersecret"
		ipOnlyUser   = "10.0.0.11"
		ipSharedUser = "10.0.0.12"
	)

	// Create test user
	t.Run("Create user", func(t *testing.T) {
		reqBody := addUser{
			ID:          testUserID,
			Enabled:     true,
			Description: "Test User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create other user
	t.Run("Create other user", func(t *testing.T) {
		reqBody := addUser{
			ID:          otherUserID,
			Enabled:     true,
			Description: "Other User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create ACL with only testUser
	t.Run("Create ACL with only test user", func(t *testing.T) {
		ttl := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		reqBody := addACL{
			AllowAll:     false,
			AllowedHosts: []string{"example.com"},
			UserIDs:      []string{testUserID},
			TTL:          &ttl,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+ipOnlyUser, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Create ACL with both users
	t.Run("Create ACL with both users", func(t *testing.T) {
		ttl := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		reqBody := addACL{
			AllowAll:     false,
			AllowedHosts: []string{"example.com"},
			UserIDs:      []string{testUserID, otherUserID},
			TTL:          &ttl,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/acl/"+ipSharedUser, bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Verify ACLs exist before deleting user
	t.Run("Verify ACLs exist before delete", func(t *testing.T) {
		// Check ACL with only test user
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipOnlyUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")
		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)

		// Check ACL with both users
		req2, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipSharedUser, http.NoBody)
		req2.Header.Set("Admin-Secret", "test-admin-secret")
		res2, err := app.Test(req2, -1)
		require.NoError(t, err)
		defer res2.Body.Close()
		assert.Equal(t, 200, res2.StatusCode)
	})

	// Delete the user
	t.Run("Delete user", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "DELETE", "/api/v1/user/"+testUserID, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// Verify ACL with only deleted user is removed
	t.Run("Verify ACL with only user is removed", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipOnlyUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 404, res.StatusCode, "ACL with only deleted user should be removed")
	})

	// Verify ACL with both users still exists but without deleted user
	t.Run("Verify shared ACL exists without deleted user", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/acl/"+ipSharedUser, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode, "Shared ACL should still exist")

		body, _ := io.ReadAll(res.Body)
		var acl getACL
		err = json.Unmarshal(body, &acl)
		require.NoError(t, err)

		// Verify deleted user is not in the ACL
		assert.NotContains(t, acl.UserIDs, testUserID, "Deleted user should be removed from shared ACL")
		// Verify other user is still in the ACL
		assert.Contains(t, acl.UserIDs, otherUserID, "Other user should remain in shared ACL")
		assert.Len(t, acl.UserIDs, 1, "ACL should have exactly one user remaining")
	})
}

func TestFiberHandlerUserDelete_NoACLs(t *testing.T) {
	app := setupTestFiberApp(t) //nolint:bodyclose // False positive: setupTestFiberApp doesn't return response

	const (
		testUserID = "testuser-delete-no-acls"
		testSecret = "supersecret"
	)

	// Create user
	t.Run("Create user", func(t *testing.T) {
		reqBody := addUser{
			ID:          testUserID,
			Enabled:     true,
			Description: "Test User",
			Secret:      testSecret,
			TTLMinutes:  60,
		}
		createBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "/api/v1/user", bytes.NewReader(createBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 201, res.StatusCode)
	})

	// Delete user without any ACLs - should succeed without errors
	t.Run("Delete user with no ACLs", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "DELETE", "/api/v1/user/"+testUserID, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 200, res.StatusCode)
	})

	// Verify user is actually deleted
	t.Run("Verify user is deleted", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "/api/v1/user/"+testUserID, http.NoBody)
		req.Header.Set("Admin-Secret", "test-admin-secret")

		res, err := app.Test(req, -1)
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, 404, res.StatusCode, "Deleted user should not be found")
	})
}
