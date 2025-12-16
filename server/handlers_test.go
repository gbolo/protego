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
func decodeJSON(t *testing.T, body *bytes.Buffer, out any) {
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

func TestHandlerChallenge_MergeACLsForSameIP(t *testing.T) {
	setupTestAPI(t)

	const (
		userSecret1 = "secret-user-1"
		userSecret2 = "secret-user-2"
		clientIP    = "203.0.113.20"
		host1       = "git.example.com"
		host2       = "wiki.example.com"
	)

	// --- create first user via POST /user ---
	reqBody1 := addUser{
		Enabled:         true,
		Description:     "First User",
		Secret:          userSecret1,
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{host1},
		TTLMinutes:      60, // shorter TTL
	}
	b1, err := json.Marshal(reqBody1)
	if err != nil {
		t.Fatalf("json.Marshal addUser1: %v", err)
	}

	addReq1 := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(b1))
	addReq1.Header.Set("Content-Type", "application/json")
	addReq1.Header.Set("Admin-Secret", "test-admin-secret")

	addRR1 := httptest.NewRecorder()
	handlerUserAdd(addRR1, addReq1)

	if addRR1.Code != http.StatusOK {
		t.Fatalf("handlerUserAdd (user1) status = %d, want %d; body=%q",
			addRR1.Code, http.StatusOK, addRR1.Body.String())
	}

	var created1 getUser
	decodeJSON(t, addRR1.Body, &created1)

	// --- first POST /challenge with user1 ---
	chReq1 := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	chReq1.Header.Set("X-Real-IP", clientIP)
	chReq1.Header.Set("User-Secret", userSecret1)

	chRR1 := httptest.NewRecorder()
	handlerChallenge(chRR1, chReq1)

	if chRR1.Code != http.StatusAccepted {
		t.Fatalf("handlerChallenge (user1) status = %d, want %d; body=%q",
			chRR1.Code, http.StatusAccepted, chRR1.Body.String())
	}

	var chResp1 challengeResponse
	decodeJSON(t, chRR1.Body, &chResp1)

	if chResp1.IpAddress != clientIP {
		t.Fatalf("challengeResponse1 IpAddress mismatch: got %q want %q",
			chResp1.IpAddress, clientIP)
	}
	if len(chResp1.ACL.AllowedHosts) != 1 || chResp1.ACL.AllowedHosts[0] != host1 {
		t.Fatalf("challengeResponse1 ACL.AllowedHosts mismatch: got %v want [%q]",
			chResp1.ACL.AllowedHosts, host1)
	}
	if chResp1.ACL.TTL == nil {
		t.Fatalf("challengeResponse1 TTL should not be nil")
	}
	firstTTL := *chResp1.ACL.TTL

	// --- create second user with different ACL + longer TTL + AllowAll=true ---
	reqBody2 := addUser{
		Enabled:         true,
		Description:     "Second User",
		Secret:          userSecret2,
		ACLAllowAll:     true, // this should win
		ACLAllowedHosts: []string{host2},
		TTLMinutes:      120, // longer TTL
	}
	b2, err := json.Marshal(reqBody2)
	if err != nil {
		t.Fatalf("json.Marshal addUser2: %v", err)
	}

	addReq2 := httptest.NewRequest(http.MethodPost, "/user", bytes.NewReader(b2))
	addReq2.Header.Set("Content-Type", "application/json")
	addReq2.Header.Set("Admin-Secret", "test-admin-secret")

	addRR2 := httptest.NewRecorder()
	handlerUserAdd(addRR2, addReq2)

	if addRR2.Code != http.StatusOK {
		t.Fatalf("handlerUserAdd (user2) status = %d, want %d; body=%q",
			addRR2.Code, http.StatusOK, addRR2.Body.String())
	}

	var created2 getUser
	decodeJSON(t, addRR2.Body, &created2)

	// --- second POST /challenge with SAME IP but user2's secret ---
	chReq2 := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	chReq2.Header.Set("X-Real-IP", clientIP)
	chReq2.Header.Set("User-Secret", userSecret2)

	chRR2 := httptest.NewRecorder()
	handlerChallenge(chRR2, chReq2)

	if chRR2.Code != http.StatusAccepted {
		t.Fatalf("handlerChallenge (user2) status = %d, want %d; body=%q",
			chRR2.Code, http.StatusAccepted, chRR2.Body.String())
	}

	var chResp2 challengeResponse
	decodeJSON(t, chRR2.Body, &chResp2)

	// --- Assert merged ACL properties ---

	// AllowAll: true should win
	if !chResp2.ACL.AllowAll {
		t.Fatalf("merged ACL AllowAll = false, want true")
	}

	// AllowedHosts: union of host1 and host2
	hostSet := make(map[string]struct{})
	for _, h := range chResp2.ACL.AllowedHosts {
		hostSet[h] = struct{}{}
	}
	if _, ok := hostSet[host1]; !ok {
		t.Fatalf("merged ACL.AllowedHosts missing %q: %v", host1, chResp2.ACL.AllowedHosts)
	}
	if _, ok := hostSet[host2]; !ok {
		t.Fatalf("merged ACL.AllowedHosts missing %q: %v", host2, chResp2.ACL.AllowedHosts)
	}

	// TTL: greater of the two should win (so it must not be earlier than firstTTL)
	if chResp2.ACL.TTL == nil {
		t.Fatalf("merged ACL TTL should not be nil")
	}
	if chResp2.ACL.TTL.Before(firstTTL) {
		t.Fatalf("merged ACL TTL %v is before first TTL %v (expected >=)",
			chResp2.ACL.TTL, firstTTL)
	}

	// --- Authorization with merged ACL: both hosts should now be allowed ---

	// host1
	authReq1 := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	authReq1.Header.Set("X-Real-IP", clientIP)
	authReq1.Host = host1

	authRR1 := httptest.NewRecorder()
	handlerAuthorize(authRR1, authReq1)

	if authRR1.Code != http.StatusOK {
		t.Fatalf("handlerAuthorize (host1) status = %d, want %d; body=%q",
			authRR1.Code, http.StatusOK, authRR1.Body.String())
	}

	// host2
	authReq2 := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	authReq2.Header.Set("X-Real-IP", clientIP)
	authReq2.Host = host2

	authRR2 := httptest.NewRecorder()
	handlerAuthorize(authRR2, authReq2)

	if authRR2.Code != http.StatusOK {
		t.Fatalf("handlerAuthorize (host2) status = %d, want %d; body=%q",
			authRR2.Code, http.StatusOK, authRR2.Body.String())
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

// -----------------------------------------------------------------------------
// ACL CRUD: Add → Get → Update → Get → GetAll → Delete → Get (fail)
// -----------------------------------------------------------------------------

func TestHandlerACLCRUD(t *testing.T) {
	setupTestAPI(t)

	const testIP = "192.168.1.100"

	// ---------- 1. Add ACL via POST /acl/{ip} ----------

	ttlStr := "2025-12-31T23:59:59Z"
	createReqBody := addACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com", "wiki.example.com"},
		TTL:          &ttlStr,
		UserIDs:      []string{"user1", "user2"},
	}

	createBytes, err := json.Marshal(createReqBody)
	if err != nil {
		t.Fatalf("json.Marshal addACL: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/acl/"+testIP, bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Admin-Secret", "test-admin-secret")
	createReq = mux.SetURLVars(createReq, map[string]string{"ip": testIP})

	createRR := httptest.NewRecorder()
	handlerACLAdd(createRR, createReq)

	if createRR.Code != http.StatusOK {
		t.Fatalf("handlerACLAdd status = %d, want %d; body=%q",
			createRR.Code, http.StatusOK, createRR.Body.String())
	}

	var created getACL
	decodeJSON(t, createRR.Body, &created)

	if created.IPAddress != testIP {
		t.Fatalf("expected created ACL to have IPAddress %q, got: %q", testIP, created.IPAddress)
	}
	if created.AllowAll != createReqBody.AllowAll {
		t.Fatalf("AllowAll mismatch: got %v want %v",
			created.AllowAll, createReqBody.AllowAll)
	}
	if len(created.AllowedHosts) != len(createReqBody.AllowedHosts) {
		t.Fatalf("AllowedHosts length mismatch: got %d want %d",
			len(created.AllowedHosts), len(createReqBody.AllowedHosts))
	}
	if len(created.UserIDs) != len(createReqBody.UserIDs) {
		t.Fatalf("UserIDs length mismatch: got %d want %d",
			len(created.UserIDs), len(createReqBody.UserIDs))
	}

	// ---------- 2. Get ACL via GET /acl/{ip} ----------

	getReq := httptest.NewRequest(http.MethodGet, "/acl/"+testIP, nil)
	getReq.Header.Set("Admin-Secret", "test-admin-secret")
	getReq = mux.SetURLVars(getReq, map[string]string{"ip": testIP})

	getRR := httptest.NewRecorder()
	handlerACLGet(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("handlerACLGet status = %d, want %d; body=%q",
			getRR.Code, http.StatusOK, getRR.Body.String())
	}

	var fetched getACL
	decodeJSON(t, getRR.Body, &fetched)

	if fetched.IPAddress != testIP {
		t.Fatalf("GET /acl/{ip}: IPAddress mismatch: got %q want %q", fetched.IPAddress, testIP)
	}
	if fetched.AllowAll != createReqBody.AllowAll {
		t.Fatalf("GET /acl/{ip}: AllowAll mismatch: got %v want %v",
			fetched.AllowAll, createReqBody.AllowAll)
	}

	// ---------- 3. Update ACL via PUT /acl/{ip} ----------

	ttlStr2 := "2026-01-01T00:00:00Z"
	updateReqBody := modifyACL{
		AllowAll:     true,
		AllowedHosts: []string{"git.example.com", "wiki.example.com", "app.example.com"},
		TTL:          &ttlStr2,
		UserIDs:      []string{"user1", "user2", "user3"},
	}
	updateBytes, err := json.Marshal(updateReqBody)
	if err != nil {
		t.Fatalf("json.Marshal modifyACL: %v", err)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/acl/"+testIP, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Admin-Secret", "test-admin-secret")
	updateReq = mux.SetURLVars(updateReq, map[string]string{"ip": testIP})

	updateRR := httptest.NewRecorder()
	handlerACLUpdate(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Fatalf("handlerACLUpdate status = %d, want %d; body=%q",
			updateRR.Code, http.StatusOK, updateRR.Body.String())
	}

	var updated getACL
	decodeJSON(t, updateRR.Body, &updated)

	if updated.IPAddress != testIP {
		t.Fatalf("Update: IPAddress changed: got %q want %q", updated.IPAddress, testIP)
	}
	if updated.AllowAll != updateReqBody.AllowAll {
		t.Fatalf("Update: AllowAll mismatch: got %v want %v",
			updated.AllowAll, updateReqBody.AllowAll)
	}
	if len(updated.AllowedHosts) != len(updateReqBody.AllowedHosts) {
		t.Fatalf("Update: AllowedHosts length mismatch: got %d want %d",
			len(updated.AllowedHosts), len(updateReqBody.AllowedHosts))
	}
	if len(updated.UserIDs) != len(updateReqBody.UserIDs) {
		t.Fatalf("Update: UserIDs length mismatch: got %d want %d",
			len(updated.UserIDs), len(updateReqBody.UserIDs))
	}

	// ---------- 4. GetAll ACLs via GET /acl ----------

	getAllReq := httptest.NewRequest(http.MethodGet, "/acl", nil)
	getAllReq.Header.Set("Admin-Secret", "test-admin-secret")

	getAllRR := httptest.NewRecorder()
	handlerACLGetAll(getAllRR, getAllReq)

	if getAllRR.Code != http.StatusOK {
		t.Fatalf("handlerACLGetAll status = %d, want %d; body=%q",
			getAllRR.Code, http.StatusOK, getAllRR.Body.String())
	}

	var all []getACL
	decodeJSON(t, getAllRR.Body, &all)

	found := false
	for _, acl := range all {
		if acl.IPAddress == testIP {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("GetAll: expected to find ACL for IP %q in list, got: %#v", testIP, all)
	}

	// ---------- 5. Delete ACL via DELETE /acl/{ip} ----------

	delReq := httptest.NewRequest(http.MethodDelete, "/acl/"+testIP, nil)
	delReq.Header.Set("Admin-Secret", "test-admin-secret")
	delReq = mux.SetURLVars(delReq, map[string]string{"ip": testIP})

	delRR := httptest.NewRecorder()
	handlerACLDelete(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("handlerACLDelete status = %d, want %d; body=%q",
			delRR.Code, http.StatusOK, delRR.Body.String())
	}

	// ---------- 6. Get after delete should fail with 404 ----------

	getAfterDelReq := httptest.NewRequest(http.MethodGet, "/acl/"+testIP, nil)
	getAfterDelReq.Header.Set("Admin-Secret", "test-admin-secret")
	getAfterDelReq = mux.SetURLVars(getAfterDelReq, map[string]string{"ip": testIP})

	getAfterDelRR := httptest.NewRecorder()
	handlerACLGet(getAfterDelRR, getAfterDelReq)

	if getAfterDelRR.Code != http.StatusNotFound {
		t.Fatalf("GET /acl/{ip} after delete: status = %d, want %d; body=%q",
			getAfterDelRR.Code, http.StatusNotFound, getAfterDelRR.Body.String())
	}
}

// -----------------------------------------------------------------------------
// ACL negative tests
// -----------------------------------------------------------------------------

func TestHandlerACLAdd_InvalidIP(t *testing.T) {
	setupTestAPI(t)

	const invalidIP = "not-an-ip"

	createReqBody := addACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com"},
	}

	createBytes, err := json.Marshal(createReqBody)
	if err != nil {
		t.Fatalf("json.Marshal addACL: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/acl/"+invalidIP, bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Admin-Secret", "test-admin-secret")
	createReq = mux.SetURLVars(createReq, map[string]string{"ip": invalidIP})

	createRR := httptest.NewRecorder()
	handlerACLAdd(createRR, createReq)

	if createRR.Code != http.StatusBadRequest {
		t.Fatalf("handlerACLAdd (invalid IP) status = %d, want %d; body=%q",
			createRR.Code, http.StatusBadRequest, createRR.Body.String())
	}

	var errResp errorResponse
	decodeJSON(t, createRR.Body, &errResp)
	if errResp.Error == "" {
		t.Fatalf("expected error message in errorResponse, got: %#v", errResp)
	}
}

func TestHandlerACLAdd_InvalidTTL(t *testing.T) {
	setupTestAPI(t)

	const testIP = "192.168.1.101"
	invalidTTL := "not-a-date"

	createReqBody := addACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com"},
		TTL:          &invalidTTL,
	}

	createBytes, err := json.Marshal(createReqBody)
	if err != nil {
		t.Fatalf("json.Marshal addACL: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/acl/"+testIP, bytes.NewReader(createBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Admin-Secret", "test-admin-secret")
	createReq = mux.SetURLVars(createReq, map[string]string{"ip": testIP})

	createRR := httptest.NewRecorder()
	handlerACLAdd(createRR, createReq)

	if createRR.Code != http.StatusBadRequest {
		t.Fatalf("handlerACLAdd (invalid TTL) status = %d, want %d; body=%q",
			createRR.Code, http.StatusBadRequest, createRR.Body.String())
	}

	var errResp errorResponse
	decodeJSON(t, createRR.Body, &errResp)
	if errResp.Error == "" {
		t.Fatalf("expected error message in errorResponse, got: %#v", errResp)
	}
}

func TestHandlerACL_UnauthorizedWithoutAdminSecret(t *testing.T) {
	setupTestAPI(t)

	const testIP = "192.168.1.102"

	createReqBody := addACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com"},
	}

	b, err := json.Marshal(createReqBody)
	if err != nil {
		t.Fatalf("json.Marshal addACL: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/acl/"+testIP, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"ip": testIP})
	// NOTE: no Admin-Secret header

	rr := httptest.NewRecorder()
	handlerACLAdd(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("handlerACLAdd (no Admin-Secret) status = %d, want %d; body=%q",
			rr.Code, http.StatusUnauthorized, rr.Body.String())
	}

	var errResp errorResponse
	decodeJSON(t, rr.Body, &errResp)
	if errResp.Error == "" {
		t.Fatalf("expected error message in errorResponse, got: %#v", errResp)
	}
}

func TestHandlerACLUpdate_NotFound(t *testing.T) {
	setupTestAPI(t)

	const testIP = "192.168.1.103"

	updateReqBody := modifyACL{
		AllowAll:     true,
		AllowedHosts: []string{"git.example.com"},
	}

	updateBytes, err := json.Marshal(updateReqBody)
	if err != nil {
		t.Fatalf("json.Marshal modifyACL: %v", err)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/acl/"+testIP, bytes.NewReader(updateBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Admin-Secret", "test-admin-secret")
	updateReq = mux.SetURLVars(updateReq, map[string]string{"ip": testIP})

	updateRR := httptest.NewRecorder()
	handlerACLUpdate(updateRR, updateReq)

	if updateRR.Code != http.StatusNotFound {
		t.Fatalf("handlerACLUpdate (non-existent ACL) status = %d, want %d; body=%q",
			updateRR.Code, http.StatusNotFound, updateRR.Body.String())
	}

	var errResp errorResponse
	decodeJSON(t, updateRR.Body, &errResp)
	if errResp.Error == "" {
		t.Fatalf("expected error message in errorResponse, got: %#v", errResp)
	}
}

func TestHandlerACLGetAll_Empty(t *testing.T) {
	setupTestAPI(t)

	// Don't add any ACLs, just try to get all

	getAllReq := httptest.NewRequest(http.MethodGet, "/acl", nil)
	getAllReq.Header.Set("Admin-Secret", "test-admin-secret")

	getAllRR := httptest.NewRecorder()
	handlerACLGetAll(getAllRR, getAllReq)

	if getAllRR.Code != http.StatusOK {
		t.Fatalf("handlerACLGetAll status = %d, want %d; body=%q",
			getAllRR.Code, http.StatusOK, getAllRR.Body.String())
	}

	// Should return empty array (no newline for empty arrays)
	if getAllRR.Body.String() != "[]" {
		t.Fatalf("expected empty array, got: %q", getAllRR.Body.String())
	}
}
