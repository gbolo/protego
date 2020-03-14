package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	validate "github.com/asaskevich/govalidator"
	"github.com/gbolo/protego/dataprovider"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type errorResponse struct {
	Error string `json:"error"`
}

type challengeResponse struct {
	Message   string `json:"message"`
	UserId    string `json:"user_id"`
	IpAddress string `json:"ip_address"`
	dataprovider.ACL
}

// returns version information
func handlerVersion(w http.ResponseWriter, req *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]string{"version": "v1"})
}

// this endpoint determines whether or not the client is allowed to access the resource
func handlerAuthorize(w http.ResponseWriter, req *http.Request) {
	// determine the client's real IP.
	// the proxy MUST set the http header X-Real-IP.
	// *NOTE* for security reasons, the proxy should set this itself and ignore any value the client may have passed
	// TODO: maybe add support for X-Forwarded-For list
	clientIP := req.Header.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		w.WriteHeader(http.StatusUnauthorized)
		// additional logging for debug
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return
	}

	// lookup this client ip. Deny access if we don't have it
	acl, err := dataProvider.GetACL(clientIP)
	if err != nil || acl == nil {
		log.Debugf("client (%s) is unknown", clientIP)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// the client IP is in our database, now check what hosts it can access
	if acl.AllowAll {
		log.Debugf("client (%s) has ALLOW_ALL privileges", clientIP)
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Debugf("client host acl: %v", acl.AllowedHosts)
	if acl.CheckHost(req.Host) {
		log.Debugf("client (%s) ALLOWED access to host %s", clientIP, req.Host)
		w.WriteHeader(http.StatusOK)
		return
	}

	// by default we deny everything
	log.Debugf("client (%s) DENIED access to host %s", clientIP, req.Host)
	w.WriteHeader(http.StatusUnauthorized)
}

func handlerChallenge(w http.ResponseWriter, req *http.Request) {
	// determine the actualUser's real IP.
	// the proxy MUST set the http header X-Real-IP.
	// *NOTE* for security reasons, the proxy should set this itself and ignore any value the actualUser may have passed
	// TODO: maybe add support for X-Forwarded-For list
	clientIP := req.Header.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		writeJSONResponse(w, http.StatusServiceUnavailable, errorResponse{"Unable to properly determine actualUser's IP"})
		// additional logging for debug
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return
	}

	// now we check if the actualUser provided a secret
	clientSecret := req.Header.Get("CLIENT-SECRET")
	user, err := dataprovider.NewUser(clientSecret, "")
	if err == dataprovider.ErrSecretLength {
		log.Infof("actualUser %s was denied due to challenge failure", clientIP)
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"CLIENT-SECRET is incorrect"})
		return
	}

	// check if this actualUser exists
	actualUser, err := dataProvider.GetUser(user.ID)
	if actualUser == nil || err != nil {
		log.Infof("user %s was denied due to incorrect secret", clientIP)
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"unable to find actualUser"})
		return
	}

	// deny the actualUser if it is disabled
	if !actualUser.Enabled {
		log.Infof("actualUser %s was denied due to being disabled", clientIP)
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"this actualUser is currently disabled"})
		return
	}

	// add this actualUser's IP to whitelist
	acl := dataprovider.ACL{
		AllowAll:     actualUser.ACLAllowAll,
		AllowedHosts: actualUser.ACLAllowedHosts,
	}
	if actualUser.TTLMinutes > 0 {
		ttl := time.Now().Add(time.Duration(actualUser.TTLMinutes) * time.Minute)
		acl.TTL = &ttl
		log.Infof("set user IP TTL to: %v", ttl)
	}
	err = dataProvider.AddIp(clientIP, &acl)
	if err != nil {
		log.Errorf("unable to add ACL to DB: %s", err)
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse{"there was an error handling this request"})
		return
	}

	// successful response
	apiResponse := challengeResponse{
		Message:   "access has been granted",
		UserId:    actualUser.ID,
		IpAddress: clientIP,
	}
	apiResponse.ACL = acl
	writeJSONResponse(w, http.StatusAccepted, apiResponse)
}

func handlerClientAdd(w http.ResponseWriter, req *http.Request) {
	// validate authorization header if enabled
	if viper.GetString("admin.secret") != "" && req.Header.Get("ADMIN-SECRET") != viper.GetString("admin.secret") {
		log.Warningf("admin credentials rejected")
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"admin credentials rejected"})
		return
	}

	// try to read the body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		apiResponse := errorResponse{"Bad request. Cannot read request body."}
		writeJSONResponse(w, http.StatusBadRequest, apiResponse)
		return
	}

	// try to unmarshal the body into a valid user
	user, err := dataprovider.DecodeUser(body)
	if err != nil || user == nil {
		log.Errorf("unable to decode user: %v", err)
		apiResponse := errorResponse{"Bad request: " + err.Error()}
		writeJSONResponse(w, http.StatusBadRequest, apiResponse)
		return
	}

	// add the user to the backend now
	err = dataProvider.AddUser(user)
	switch {
	case err == dataprovider.ErrUserExists:
		log.Errorf("couldn't add new user: %v", err)
		apiResponse := errorResponse{fmt.Sprintf("Client already exists (ID: %s). Try Modifying it", user.ID)}
		writeJSONResponse(w, http.StatusConflict, apiResponse)
		return
	case err != nil:
		log.Errorf("couldn't add new user: %v", err)
		apiResponse := errorResponse{"Could not add user"}
		writeJSONResponse(w, http.StatusInternalServerError, apiResponse)
		return
	}
	// user has been added
	log.Infof("new user has been added: %s", user.ID)
	writeJSONResponse(w, http.StatusOK, map[string]string{"user-ID": user.ID})
}

func handlerClientModify(w http.ResponseWriter, req *http.Request) {
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	if viper.GetString("admin.secret") != "" && req.Header.Get("ADMIN-SECRET") != viper.GetString("admin.secret") {
		log.Warningf("admin credentials rejected")
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"admin credentials rejected"})
		return
	}

	// get vars from request to determine if user id was specified
	vars := mux.Vars(req)
	userId := vars["user-id"]
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warningf("user was not found: %s", userId)
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"user was not found"})
		return
	}

	// try to read the body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		apiResponse := errorResponse{"Bad request. Cannot read request body."}
		writeJSONResponse(w, http.StatusBadRequest, apiResponse)
		return
	}

	// try to unmarshal the body into a valid user
	modifiedUser, err := dataprovider.DecodeUser(body)
	if err != nil || user == nil {
		log.Errorf("unable to decode user: %v", err)
		apiResponse := errorResponse{"Bad request: " + err.Error()}
		writeJSONResponse(w, http.StatusBadRequest, apiResponse)
		return
	}

	// add the user to the backend now
	err = dataProvider.UpdateUser(modifiedUser)
	if err != nil {
		log.Errorf("could not update user: %v", err)
		apiResponse := errorResponse{"Could not update user"}
		writeJSONResponse(w, http.StatusInternalServerError, apiResponse)
		return
	}

	// user has been updated
	log.Infof("new user has been updated: %s", user.ID)
	writeJSONResponse(w, http.StatusOK, map[string]string{"user-ID": user.ID})
}

func handlerGetUser(w http.ResponseWriter, req *http.Request) {
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	if viper.GetString("admin.secret") != "" && req.Header.Get("ADMIN-SECRET") != viper.GetString("admin.secret") {
		log.Warningf("admin credentials rejected")
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"admin credentials rejected"})
		return
	}

	// get vars from request to determine if user id was specified
	vars := mux.Vars(req)
	userId := vars["user-id"]
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warningf("user was not found: %s", userId)
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"user was not found"})
		return
	}
	// redact the user secret hash
	user.Secret = "_REDACTED_"
	writeJSONResponse(w, http.StatusOK, user)
}

func handlerClientDelete(w http.ResponseWriter, req *http.Request) {
	// validate authorization header if enabled
	if viper.GetString("admin.secret") != "" && req.Header.Get("ADMIN-SECRET") != viper.GetString("admin.secret") {
		log.Warningf("admin credentials rejected")
		writeJSONResponse(w, http.StatusUnauthorized, errorResponse{"admin credentials rejected"})
		return
	}

	// get vars from request to determine if environment id was specified
	vars := mux.Vars(req)
	userId := vars["user-id"]
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warningf("user was not found: %s", userId)
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"user was not found"})
		return
	}

	err = dataProvider.RemoveUser(user)
	if err != nil {
		log.Warningf("unable to remove client %s: %v", userId, err)
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse{"unable to remove client"})
		return
	}
	// user has been removed
	log.Infof("user has been removed: %s", userId)
	writeJSONResponse(w, http.StatusOK, map[string]string{"User-ID": userId})
}

// wrapper for json responses
func writeJSONResponse(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.MarshalIndent(body, "", "  ")
	w.Write(append(b, []byte("\n")...))
}