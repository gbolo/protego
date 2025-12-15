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

// -----------------------------------------------------------------------------
// Test setup helpers
// -----------------------------------------------------------------------------

// sets up a fresh in-memory data provider and ddnsProvider + clean config
func setupTestAPI(t *testing.T) {
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

	// Initialize ddnsProvider so handlerUserAdd/Update/Delete can call ProcessUser()
	ddnsProvider = dataprovider.NewDdnsProvider()
}

// small helper to decode JSON into a target struct and fail on error
func decodeJSON(t *testing.T, body *bytes.Buffer, out interface{}) {
	t.Helper()
	if err := json.Unmarshal(body.Bytes(), out); err != nil {
		t.Fatalf("json.Unmarshal: %v (body=%q)", err, body.String())
	}
}

// -----------------------------------------------------------------------------
// /version
// -----------------------------------------------------------------------------

func TestHandlerVersion(t *testing.T) {
	// handlerVersion does not depend on dataProvider, so no full setup needed
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

// -----------------------------------------------------------------------------
// User CRUD: Add → Get → Update → Get → GetAll → Delete → Get (fail)
// -----------------------------------------------------------------------------

func TestHandlerUserCRUD(t *testing.T) {
	setupTestAPI(t)

	// ---------- 1. Add user via POST /user ----------

	createReqBody := addUser{
		Enabled:         true,
		Description:     "Test User",
		Secret:          "supersecret", // required by dataprovider.DecodeUser
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{"git.example.com"},
		// DNSNames intentionally empty to avoid real DNS lookups
		TTLMinutes: 60,
	}

	createBytes, err := json.Marshal(createReqBody)
	if err != nil {
		t.Fatalf("json.Marshal addUser: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Admin-Secret", "test-admin-secret")

	createRR := httptest.NewRecorder()
	handlerUserAdd(createRR, createReq)

	if createRR.Code != http.StatusOK {
		t.Fatalf("handlerUserAdd status = %d, want %d; body=%q",
			createRR.Code, http.StatusOK, createRR.Body.String())
	}

	var created getUser
	decodeJSON(t, createRR.Body, &created)

	if created.ID == "" {
		t.Fatalf("expected created user to have ID, got: %#v", created)
	}
	if created.Description != createReqBody.Description {
		t.Fatalf("Description mismatch: got %q want %q",
			created.Description, createReqBody.Description)
	}
	if created.Enabled != createReqBody.Enabled {
		t.Fatalf("Enabled mismatch: got %v want %v",
			created.Enabled, createReqBody.Enabled)
	}

	userID := created.ID

	// ---------- 2. Get user via GET /user/{user-id} ----------

	getReq := httptest.NewRequest(http.MethodGet, "/user/"+userID, nil)
	getReq.Header.Set("Admin-Secret", "test-admin-secret")
	getReq = mux.SetURLVars(getReq, map[string]string{"user-id": userID})

	getRR := httptest.NewRecorder()
	handlerUserGet(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("handlerUserGet status = %d, want %d; body=%q",
			getRR.Code, http.StatusOK, getRR.Body.String())
	}

	var fetched getUser
	decodeJSON(t, getRR.Body, &fetched)

	if fetched.ID != userID {
		t.Fatalf("GET /user/{id}: ID mismatch: got %q want %q", fetched.ID, userID)
	}

	// ---------- 3. Update user via PUT /user/{user-id} ----------

	updateReqBody := addUser{
		Enabled:         false,
		Description:     "Updated User",
		Secret:          "supersecret", // must match original secret so ID matches
		ACLAllowAll:     true,
		ACLAllowedHosts: []string{"git.example.com", "wiki.example.com"},
		TTLMinutes:      120,
	}
	updateBytes, err := json.Marshal(updateReqBody)
	if err != nil {
		t.Fatalf("json.Marshal update addUser: %v", err)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/user/"+userID, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Admin-Secret", "test-admin-secret")
	updateReq = mux.SetURLVars(updateReq, map[string]string{"user-id": userID})

	updateRR := httptest.NewRecorder()
	handlerUserUpdate(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Fatalf("handlerUserUpdate status = %d, want %d; body=%q",
			updateRR.Code, http.StatusOK, updateRR.Body.String())
	}

	var updated getUser
	decodeJSON(t, updateRR.Body, &updated)

	if updated.ID != userID {
		t.Fatalf("Update: ID changed: got %q want %q", updated.ID, userID)
	}
	if updated.Description != updateReqBody.Description {
		t.Fatalf("Update: Description mismatch: got %q want %q",
			updated.Description, updateReqBody.Description)
	}
	if updated.Enabled != updateReqBody.Enabled {
		t.Fatalf("Update: Enabled mismatch: got %v want %v",
			updated.Enabled, updateReqBody.Enabled)
	}
	if updated.ACLAllowAll != updateReqBody.ACLAllowAll {
		t.Fatalf("Update: ACLAllowAll mismatch: got %v want %v",
			updated.ACLAllowAll, updateReqBody.ACLAllowAll)
	}
	if len(updated.ACLAllowedHosts) != len(updateReqBody.ACLAllowedHosts) {
		t.Fatalf("Update: ACLAllowedHosts length mismatch: got %v want %v",
			updated.ACLAllowedHosts, updateReqBody.ACLAllowedHosts)
	}

	// ---------- 4. GetAll users via GET /user ----------

	getAllReq := httptest.NewRequest(http.MethodGet, "/user", nil)
	getAllReq.Header.Set("Admin-Secret", "test-admin-secret")

	getAllRR := httptest.NewRecorder()
	handlerUserGetAll(getAllRR, getAllReq)

	if getAllRR.Code != http.StatusOK {
		t.Fatalf("handlerUserGetAll status = %d, want %d; body=%q",
			getAllRR.Code, http.StatusOK, getAllRR.Body.String())
	}

	var all []getUser
	decodeJSON(t, getAllRR.Body, &all)

	found := false
	for _, u := range all {
		if u.ID == userID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("GetAll: expected to find user %q in list, got: %#v", userID, all)
	}

	// ---------- 5. Delete user via DELETE /user/{user-id} ----------

	delReq := httptest.NewRequest(http.MethodDelete, "/user/"+userID, nil)
	delReq.Header.Set("Admin-Secret", "test-admin-secret")
	delReq = mux.SetURLVars(delReq, map[string]string{"user-id": userID})

	delRR := httptest.NewRecorder()
	handlerUserDelete(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("handlerUserDelete status = %d, want %d; body=%q",
			delRR.Code, http.StatusOK, delRR.Body.String())
	}

	// ---------- 6. Get after delete should fail with 400 ----------

	getAfterDelReq := httptest.NewRequest(http.MethodGet, "/user/"+userID, nil)
	getAfterDelReq.Header.Set("Admin-Secret", "test-admin-secret")
	getAfterDelReq = mux.SetURLVars(getAfterDelReq, map[string]string{"user-id": userID})

	getAfterDelRR := httptest.NewRecorder()
	handlerUserGet(getAfterDelRR, getAfterDelReq)

	if getAfterDelRR.Code != http.StatusBadRequest {
		t.Fatalf("GET /user/{id} after delete: status = %d, want %d; body=%q",
			getAfterDelRR.Code, http.StatusBadRequest, getAfterDelRR.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Challenge + Authorize flow
// -----------------------------------------------------------------------------

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

	if chResp.IpAddress != clientIP {
		t.Fatalf("challengeResponse IpAddress mismatch: got %q want %q",
			chResp.IpAddress, clientIP)
	}
	if len(chResp.ACL.AllowedHosts) == 0 || chResp.ACL.AllowedHosts[0] != host {
		t.Fatalf("challengeResponse ACL.AllowedHosts mismatch: got %v want [%q]",
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

	// --- And if we change Host to something not in the ACL, it should be 401 ---

	authReq2 := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	authReq2.Header.Set("X-Real-IP", clientIP)
	authReq2.Host = "other.example.com"

	authRR2 := httptest.NewRecorder()
	handlerAuthorize(authRR2, authReq2)

	if authRR2.Code != http.StatusUnauthorized {
		t.Fatalf("handlerAuthorize (bad host) status = %d, want %d; body=%q",
			authRR2.Code, http.StatusUnauthorized, authRR2.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Negative test: missing Admin-Secret on /user
// -----------------------------------------------------------------------------

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
	// NOTE: no Admin-Secret header

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
