package server

import (
	"errors"
	"time"

	validate "github.com/asaskevich/govalidator"
	"github.com/gbolo/protego/dataprovider"
	"github.com/gbolo/protego/internal/meta"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

// fiberHandlerVersion godoc
// @Summary Version information
// @Description Returns version information about this server
// @Tags Information
// @Produce  json
// @Success 200 {object} version
// @Router /version [get]
func fiberHandlerVersion(c *fiber.Ctx) error {
	return c.JSON(version{meta.Version, meta.CommitSHA})
}

// fiberHandlerAuthorize godoc
// @Summary NGINX auth_request destination
// @Description Configure NGINX auth_request to this endpoint
// @Tags Authorization
// @Param X-Real-IP header string true "IP address of the user"
// @Param Host header string false "the host (FQDN) the user is making a request to"
// @Success 200 "access granted"
// @Failure 401 "unauthorized - user IP is unknown or not permitted to access this host"
// @Router /authorize [get]
func fiberHandlerAuthorize(c *fiber.Ctx) error {
	clientIP := c.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// lookup this client ip
	acl, err := dataProvider.GetACL(clientIP)
	if err != nil {
		log.Warningf("error during dataProvider.GetACL: %v", err)
	}
	// check the dynamic DNS provider if acl is nil
	if acl == nil {
		acl = ddnsProvider.GetACL(clientIP)
	}
	// if neither provider can find the IP it's blocked
	if acl == nil {
		log.Debugf("client (%s) is unknown", clientIP)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// the client IP is in our database, now check what hosts it can access
	if acl.AllowAll {
		log.Debugf("client (%s) has ALLOW_ALL privileges", clientIP)
		return c.SendStatus(fiber.StatusOK)
	}
	log.Debugf("client host acl: %v", acl.AllowedHosts)
	if acl.CheckHost(c.Hostname()) {
		log.Debugf("client (%s) ALLOWED access to host %s", clientIP, c.Hostname())
		return c.SendStatus(fiber.StatusOK)
	}

	// by default we deny everything
	log.Debugf("client (%s) DENIED access to host %s", clientIP, c.Hostname())
	return c.SendStatus(fiber.StatusUnauthorized)
}

// fiberHandlerChallenge godoc
// @Summary Challenge used to authorize an IP address for access
// @Description A user must successfully POST to this URL in order for their IP address to be granted access
// @Tags Authorization
// @Produce  json
// @Param X-Real-IP header string true "IP address of the user"
// @Param User-Secret header string true "Secret that was given to/by the user"
// @Success 200 "challenge was accepted: the value of X-Real-IP has been granted an ACL" {object} challengeResponse
// @Failure 400 "bad request: X-Real-IP is not set" {object} errorResponse
// @Failure 401 "unauthorized: the user secret is incorrect or the user is disabled" {object} errorResponse
// @Failure 500 "server could not process the request" {object} errorResponse
// @Router /challenge [post]
func fiberHandlerChallenge(c *fiber.Ctx) error {
	clientIP := c.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"Unable to properly determine user's IP address"})
	}

	clientSecret := c.Get("User-Secret")
	user, err := dataprovider.NewUser(clientSecret, "")
	if errors.Is(err, dataprovider.ErrSecretLength) {
		log.Infof("user %s was denied due to challenge failure", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"User-Secret is incorrect"})
	}

	// check if this user exists
	actualUser, err := dataProvider.GetUser(user.ID)
	if actualUser == nil || err != nil {
		log.Infof("user %s was denied due to incorrect secret", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unable to find user"})
	}

	// deny the user if it is disabled
	if !actualUser.Enabled {
		log.Infof("user %s was denied due to being disabled", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"this user is currently disabled"})
	}

	// add this user's IP to whitelist
	newAcl := dataprovider.ACL{
		AllowAll:     actualUser.ACLAllowAll,
		AllowedHosts: actualUser.ACLAllowedHosts,
		UserIDs:      []string{actualUser.ID},
	}
	if actualUser.TTLMinutes > 0 {
		ttl := time.Now().Add(time.Duration(actualUser.TTLMinutes) * time.Minute)
		newAcl.TTL = &ttl
		log.Infof("set user IP (%s) TTL to: %v", clientIP, ttl)
	}

	// check if an acl already exists for this IP
	existingAcl, err := dataProvider.GetACL(clientIP)
	if err != nil {
		log.Errorf("unable to get ACL from DB: %s", err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"there was an error handling this request"})
	}

	// log a warning if we will be merging a different user ACLs together
	if existingAcl != nil && !existingAcl.CheckUserId(user.ID) {
		log.Warningf("other user(s) %v already have an ACL for client IP: %s. Will need to merge ACls", existingAcl.UserIDs, clientIP)
	}

	acl := dataprovider.MergeACL(&newAcl, existingAcl)
	err = dataProvider.AddIp(clientIP, acl)
	if err != nil {
		log.Errorf("unable to add ACL to DB: %s", err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"there was an error handling this request"})
	}

	// successful response
	log.Infof("user %s with IP (%s) has been added to ACL", user.ID, clientIP)
	apiResponse := challengeResponse{
		Message:   "access has been granted",
		UserId:    actualUser.ID,
		IpAddress: clientIP,
	}
	apiResponse.ACL = *acl
	return c.Status(fiber.StatusAccepted).JSON(apiResponse)
}

// fiberHandlerUserAdd godoc
// @Summary Add a new user
// @Description Creates a new user with the provided configuration. User ID is automatically generated from the secret.
// @Tags User Management
// @Accept json
// @Produce json
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Param user body addUser true "User configuration"
// @Success 201 {object} getUser
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /user [post]
func fiberHandlerUserAdd(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	var req addUser
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	// Validate required fields
	if req.Secret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"secret is required"})
	}

	// Create user - ID is automatically generated from secret
	user, err := dataprovider.NewUser(req.Secret, req.Description)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{err.Error()})
	}

	// Set user properties
	user.Enabled = req.Enabled
	user.ACLAllowAll = req.ACLAllowAll
	user.ACLAllowedHosts = req.ACLAllowedHosts
	user.DNSNames = req.DNSNames
	user.TTLMinutes = req.TTLMinutes

	// Add user to provider
	if err := dataProvider.AddUser(user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("user added: %s", user.ID)

	// Process user for DDNS if DNS names are provided
	if len(user.DNSNames) > 0 {
		ddnsProvider.ProcessUser(user)
	}

	return c.Status(fiber.StatusCreated).JSON(getUserConvert(user))
}

// fiberHandlerUserUpdate godoc
// @Summary Update an existing user
// @Description Updates user configuration
// @Tags User Management
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Param user body modifyUser true "User configuration"
// @Success 200 {object} getUser
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /user/{id} [put]
func fiberHandlerUserUpdate(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user ID is required"})
	}

	var req modifyUser
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	// Get existing user
	existingUser, err := dataProvider.GetUser(id)
	if err != nil || existingUser == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"user not found"})
	}

	// Update user properties
	existingUser.Enabled = req.Enabled
	existingUser.Description = req.Description
	existingUser.ACLAllowAll = req.ACLAllowAll
	existingUser.ACLAllowedHosts = req.ACLAllowedHosts
	existingUser.DNSNames = req.DNSNames
	existingUser.TTLMinutes = req.TTLMinutes

	// Update user in provider
	if err := dataProvider.UpdateUser(existingUser); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("user updated: %s", existingUser.ID)
	return c.JSON(getUserConvert(existingUser))
}

// fiberHandlerUserGet godoc
// @Summary Get user details
// @Description Returns details for a specific user
// @Tags User Management
// @Produce json
// @Param id path string true "User ID"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {object} getUser
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Router /user/{id} [get]
func fiberHandlerUserGet(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user ID is required"})
	}

	user, err := dataProvider.GetUser(id)
	if err != nil || user == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"user not found"})
	}

	return c.JSON(getUserConvert(user))
}

// fiberHandlerUserGetAll godoc
// @Summary Get all users
// @Description Returns a list of all users
// @Tags User Management
// @Produce json
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {array} getUser
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /user [get]
func fiberHandlerUserGetAll(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	users, err := dataProvider.GetAllUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	return c.JSON(getAllUsersConvert(users))
}

// fiberHandlerUserDelete godoc
// @Summary Delete a user
// @Description Deletes a user from the system
// @Tags User Management
// @Param id path string true "User ID"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {object} successResponse
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /user/{id} [delete]
func fiberHandlerUserDelete(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user ID is required"})
	}

	// Check if user exists
	user, err := dataProvider.GetUser(id)
	if err != nil || user == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"user not found"})
	}

	// Delete user
	if err := dataProvider.RemoveUser(user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("user deleted: %s", id)
	return c.JSON(getUserConvert(user))
}

// fiberHandlerACLAdd godoc
// @Summary Add a new ACL
// @Description Creates a new ACL for an IP address
// @Tags ACL Management
// @Accept json
// @Produce json
// @Param ip path string true "IP Address"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Param acl body addACL true "ACL configuration"
// @Success 201 {object} getACL
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /acl/{ip} [post]
func fiberHandlerACLAdd(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	ip := c.Params("ip")
	if !validate.IsIP(ip) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid IP address"})
	}

	var req addACL
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	// Create ACL
	acl := dataprovider.ACL{
		AllowAll:     req.AllowAll,
		AllowedHosts: req.AllowedHosts,
		UserIDs:      req.UserIDs,
	}

	// Parse TTL if provided
	if req.TTL != nil && *req.TTL != "" {
		ttl, err := time.Parse(time.RFC3339, *req.TTL)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid TTL format, use RFC3339"})
		}
		acl.TTL = &ttl
	}

	// Add ACL to provider
	if err := dataProvider.AddIp(ip, &acl); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("ACL added for IP: %s", ip)
	return c.Status(fiber.StatusCreated).JSON(getACLConvert(ip, &acl))
}

// fiberHandlerACLUpdate godoc
// @Summary Update an existing ACL
// @Description Updates ACL configuration for an IP address
// @Tags ACL Management
// @Accept json
// @Produce json
// @Param ip path string true "IP Address"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Param acl body modifyACL true "ACL configuration"
// @Success 200 {object} getACL
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /acl/{ip} [put]
func fiberHandlerACLUpdate(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	ip := c.Params("ip")
	if !validate.IsIP(ip) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid IP address"})
	}

	var req modifyACL
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	// Check if ACL exists
	existingACL, err := dataProvider.GetACL(ip)
	if err != nil || existingACL == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"ACL not found"})
	}

	// Update ACL properties
	existingACL.AllowAll = req.AllowAll
	existingACL.AllowedHosts = req.AllowedHosts
	existingACL.UserIDs = req.UserIDs

	// Parse TTL if provided
	if req.TTL != nil && *req.TTL != "" {
		ttl, err := time.Parse(time.RFC3339, *req.TTL)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid TTL format, use RFC3339"})
		}
		existingACL.TTL = &ttl
	} else {
		existingACL.TTL = nil
	}

	// Update ACL in provider
	if err := dataProvider.AddIp(ip, existingACL); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("ACL updated for IP: %s", ip)
	return c.JSON(getACLConvert(ip, existingACL))
}

// fiberHandlerACLGet godoc
// @Summary Get ACL details
// @Description Returns ACL details for a specific IP address
// @Tags ACL Management
// @Produce json
// @Param ip path string true "IP Address"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {object} getACL
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Router /acl/{ip} [get]
func fiberHandlerACLGet(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	ip := c.Params("ip")
	if !validate.IsIP(ip) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid IP address"})
	}

	acl, err := dataProvider.GetACL(ip)
	if err != nil || acl == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"ACL not found"})
	}

	return c.JSON(getACLConvert(ip, acl))
}

// fiberHandlerACLGetAll godoc
// @Summary Get all ACLs
// @Description Returns a list of all ACLs
// @Tags ACL Management
// @Produce json
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {array} getACL
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /acl [get]
func fiberHandlerACLGetAll(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	acls, err := dataProvider.GetAllACLs()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	return c.JSON(getAllACLsConvert(acls))
}

// fiberHandlerACLDelete godoc
// @Summary Delete an ACL
// @Description Deletes an ACL for a specific IP address
// @Tags ACL Management
// @Param ip path string true "IP Address"
// @Param Admin-Secret header string true "Admin secret for authentication"
// @Success 200 {object} successResponse
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 404 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /acl/{ip} [delete]
func fiberHandlerACLDelete(c *fiber.Ctx) error {
	// Check admin secret
	if !checkAdminSecret(c.Get("Admin-Secret")) {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unauthorized"})
	}

	ip := c.Params("ip")
	if !validate.IsIP(ip) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid IP address"})
	}

	// Check if ACL exists
	acl, err := dataProvider.GetACL(ip)
	if err != nil || acl == nil {
		return c.Status(fiber.StatusNotFound).JSON(errorResponse{"ACL not found"})
	}

	// Delete ACL
	if err := dataProvider.RemoveIp(ip); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{err.Error()})
	}

	log.Infof("ACL deleted for IP: %s", ip)
	return c.JSON(getACLConvert(ip, acl))
}

// checkAdminSecret verifies the admin secret
func checkAdminSecret(providedSecret string) bool {
	configuredSecret := viper.GetString("admin.secret")
	return configuredSecret != "" && providedSecret == configuredSecret
}
