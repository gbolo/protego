package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gbolo/protego/dataprovider"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

// --- test helpers ---

// sets up a fresh in-memory data provider and a clean config
func setupTestAPI(t *testing.T) {
	t.Helper()

	// clean viper between tests
	viper.Reset()
	// require an admin secret, so we test that header handling works
	viper.Set("admin.secret", "test-admin-secret")

	// fresh memory provider for each test
	mp, err := dataprovider.NewMemoryProvider()
	if err != nil {
		t.Fatalf("NewMemoryProvider: %v", err)
	}
	// override the global dataProvider used by handlers.go
	dataProvider = &mp

	// IMPORTANT: we deliberately do *not* use DNS features in these tests,
	// so we don't need to touch ddnsProvider at all.
	// As long as we don't set DNSNames on users, ddnsProvider won't be used.
}

// small helper to decode JSON into a target struct and fail on error
func decodeJSON(t *testing.T, body *bytes.Buffer, out interface{}) {
	t.Helper()
	if err := json.Unmarshal(body.Bytes(), out); err != nil {
		t.Fatalf("json.Unmarshal: %v (body=%q)", err, body.String())
	}
}

// --- tests ---

// Basic sanity check for /version (handlerVersion)
func TestHandlerVersion(t *testing.T) {
	// handlerVersion doesn't depend on dataProvider, so no setup needed
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rr := httptest.NewRecorder()

	handlerVersion(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handlerVersion status = %d, want %d", rr.Code, http.StatusOK)
	}

	var v version
	decodeJSON(t, rr.Body, &v)

	if v.Version == "" {
		t.Fatalf("expected non-empty Version, got: %#v", v)
	}
	if v.BuildRef == "" {
		t.Fatalf("expected non-empty BuildRef, got: %#v", v)
	}
}

// Happy-path test for:
//
//	POST /user  -> handlerUserAdd
//	GET  /user/{id} -> handlerUserGet
func TestHandlerUserAddAndGet(t *testing.T) {
	setupTestAPI(t)

	// --- POST /user (handlerUserAdd) ---

	reqBody := addUser{
		Enabled:         true,
		Description:     "Test User",
		Secret:          "supersecret",
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{"git.example.com"},
		// DNSNames intentionally empty to avoid ddnsProvider usage
		TTLMinutes: 60,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("json.Marshal addUser: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Admin-Secret", "test-admin-secret")

	rr := httptest.NewRecorder()
	handlerUserAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handlerUserAdd status = %d, want %d; body=%q",
			rr.Code, http.StatusOK, rr.Body.String())
	}

	var created getUser
	decodeJSON(t, rr.Body, &created)

	if created.ID == "" {
		t.Fatalf("expected created user to have ID, got: %#v", created)
	}
	if created.Description != reqBody.Description {
		t.Fatalf("Description mismatch: got %q want %q",
			created.Description, reqBody.Description)
	}
	if created.Enabled != reqBody.Enabled {
		t.Fatalf("Enabled mismatch: got %v want %v",
			created.Enabled, reqBody.Enabled)
	}

	// --- GET /user/{id} (handlerUserGet) ---

	getReq := httptest.NewRequest(http.MethodGet, "/user/"+created.ID, nil)
	getReq.Header.Set("Admin-Secret", "test-admin-secret")

	// mux.Vars() is used in handlerUserGet, so we must set them
	getReq = mux.SetURLVars(getReq, map[string]string{
		"user-id": created.ID,
	})

	getRR := httptest.NewRecorder()
	handlerUserGet(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("handlerUserGet status = %d, want %d; body=%q",
			getRR.Code, http.StatusOK, getRR.Body.String())
	}

	var fetched getUser
	decodeJSON(t, getRR.Body, &fetched)

	if fetched.ID != created.ID {
		t.Fatalf("ID mismatch: got %q want %q", fetched.ID, created.ID)
	}
	if fetched.Description != created.Description {
		t.Fatalf("Description mismatch: got %q want %q",
			fetched.Description, created.Description)
	}
}

// Tests:
//
//	POST /user           -> create a user
//	POST /challenge      -> grant ACL to X-Real-IP using user secret
//	GET  /authorize      -> check that IP+Host is allowed
func TestHandlerChallengeAndAuthorize(t *testing.T) {
	setupTestAPI(t)

	const (
		userSecret = "supersecret"
		clientIP   = "203.0.113.10"
		host       = "git.example.com"
	)

	// --- create a user via POST /user first ---

	reqBody := addUser{
		Enabled:         true,
		Description:     "Challenge User",
		Secret:          userSecret,
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{host},
		TTLMinutes:      60,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("json.Marshal addUser: %v", err)
	}

	addReq := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(b))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Admin-Secret", "test-admin-secret")

	addRR := httptest.NewRecorder()
	handlerUserAdd(addRR, addReq)

	if addRR.Code != http.StatusOK {
		t.Fatalf("handlerUserAdd status = %d, want %d; body=%q",
			addRR.Code, http.StatusOK, addRR.Body.String())
	}

	var created getUser
	decodeJSON(t, addRR.Body, &created)

	// --- POST /challenge with X-Real-IP and User-Secret ---

	chReq := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	chReq.Header.Set("X-Real-IP", clientIP)
	chReq.Header.Set("User-Secret", userSecret)

	chRR := httptest.NewRecorder()
	handlerChallenge(chRR, chReq)

	if chRR.Code != http.StatusAccepted {
		t.Fatalf("handlerChallenge status = %d, want %d; body=%q",
			chRR.Code, http.StatusAccepted, chRR.Body.String())
	}

	var chResp challengeResponse
	decodeJSON(t, chRR.Body, &chResp)

	if chResp.Message == "" {
		t.Fatalf("expected non-empty Message in challengeResponse, got: %#v", chResp)
	}
	if chResp.UserId != created.ID {
		t.Fatalf("UserId mismatch: got %q want %q", chResp.UserId, created.ID)
	}
	if chResp.IpAddress != clientIP {
		t.Fatalf("IpAddress mismatch: got %q want %q", chResp.IpAddress, clientIP)
	}
	if chResp.ACL.AllowAll != reqBody.ACLAllowAll {
		t.Fatalf("ACL.AllowAll mismatch: got %v want %v",
			chResp.ACL.AllowAll, reqBody.ACLAllowAll)
	}
	if len(chResp.ACL.AllowedHosts) != 1 || chResp.ACL.AllowedHosts[0] != host {
		t.Fatalf("ACL.AllowedHosts mismatch: got %v want [%q]",
			chResp.ACL.AllowedHosts, host)
	}

	// --- GET /authorize for that IP+Host should be allowed ---

	authReq := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	authReq.Header.Set("X-Real-IP", clientIP)
	authReq.Host = host

	authRR := httptest.NewRecorder()
	handlerAuthorize(authRR, authReq)

	if authRR.Code != http.StatusOK {
		t.Fatalf("handlerAuthorize status = %d, want %d; body=%q",
			authRR.Code, http.StatusOK, authRR.Body.String())
	}

	// and if we change Host to something not in the ACL, it should be 401
	authReq2 := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	authReq2.Header.Set("X-Real-IP", clientIP)
	authReq2.Host = "other.example.com"

	authRR2 := httptest.NewRecorder()
	handlerAuthorize(authRR2, authReq2)

	if authRR2.Code != http.StatusUnauthorized {
		t.Fatalf("handlerAuthorize (bad host) status = %d, want %d",
			authRR2.Code, http.StatusUnauthorized)
	}
}

// Simple negative test: missing/incorrect Admin-Secret should be 401 on /user
func TestHandlerUserAdd_UnauthorizedWithoutAdminSecret(t *testing.T) {
	setupTestAPI(t)

	reqBody := addUser{
		Enabled:     true,
		Description: "No Admin",
		Secret:      "supersecret",
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("json.Marshal addUser: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// NOTE: no Admin-Secret header set

	rr := httptest.NewRecorder()
	handlerUserAdd(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("handlerUserAdd (no Admin-Secret) status = %d, want %d; body=%q",
			rr.Code, http.StatusUnauthorized, rr.Body.String())
	}

	var errResp errorResponse
	decodeJSON(t, rr.Body, &errResp)
	if errResp.Error == "" {
		t.Fatalf("expected error message in errorResponse, got: %#v", errResp)
	}
}
