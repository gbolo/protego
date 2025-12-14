package server

import (
	"fmt"
	"sync"
	"time"

	validate "github.com/asaskevich/govalidator"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/gbolo/protego/pkg/log"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

// AuthMetrics tracks authorization metrics per IP
type AuthMetrics struct {
	TotalRequests int            `json:"total_requests"`
	FQDNAccess    map[string]int `json:"fqdn_access"`
	LastSeen      time.Time      `json:"last_seen"`
}

var (
	authMetrics     = make(map[string]*AuthMetrics)
	authMetricsLock sync.RWMutex
)

// @title Protego - REST API
// @version 1.0
// @description Swagger API for Protego - https://github.com/gbolo/protego
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.email gbolo@linuxctl.com
// @license.name MIT
// @license.url https://github.com/gbolo/protego/blob/master/LICENSE
// @BasePath /api/v1

// handlerVersion godoc
// @Summary Version information
// @Description Retrieve the version information of this Protego server
// @Tags Version
// @Produce  json
// @Success 200 {object} version
// @Router /version [get]
func handlerVersion(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version{"v0.1-alpha", "git-30b8019"})
}

// handlerAuthorize godoc
// @Summary NGINX auth_request destination
// @Description Configure NGINX auth_request to this endpoint
// @Tags Authorization
// @Param X-Real-IP header string true "IP address of the user"
// @Param Host header string false "the host (FQDN) the user is making a request to"
// @Success 200 "access granted"
// @Failure 401 "unauthorized - user IP is unknown or not permitted to access this host"
// @Router /authorize [get]
// this endpoint determines whether or not the client is allowed to access the resource
func handlerAuthorize(c *fiber.Ctx) error {
	// determine the client's real IP.
	// the proxy MUST set the http header X-Real-IP.
	// *NOTE* for security reasons, the proxy should set this itself and ignore any value the client may have passed
	// TODO: maybe add support for X-Forwarded-For list
	clientIP := c.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		// additional logging for debug
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// lookup this client ip. Deny access if we don't have it
	acl, err := dataProvider.GetACL(clientIP)
	if err != nil {
		log.Warnf("error during dataProvider.GetACL: %v", err)
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
	hostname := c.Hostname()
	if acl.CheckHost(hostname) {
		log.Debugf("client (%s) ALLOWED access to host %s", clientIP, hostname)

		// Track metrics
		trackAuthMetrics(clientIP, hostname, true)

		return c.SendStatus(fiber.StatusOK)
	}

	// by default we deny everything
	log.Debugf("client (%s) DENIED access to host %s", clientIP, hostname)

	// Track denied attempts too
	trackAuthMetrics(clientIP, hostname, false)

	return c.SendStatus(fiber.StatusUnauthorized)
}

// handlerChallenge godoc
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
func handlerChallenge(c *fiber.Ctx) error {
	// determine the actualUser's real IP.
	// the proxy MUST set the http header X-Real-IP.
	// *NOTE* for security reasons, the proxy should set this itself and ignore any value the client may have passed
	// TODO: maybe add support for X-Forwarded-For list
	clientIP := c.Get("X-Real-IP")
	if !validate.IsIP(clientIP) {
		log.Errorf("X-Real-IP is either set incorrectly or missing! DENYING ACCESS")
		// additional logging for debug
		log.Debugf("X-Real-IP is of length %d with value: %s", len(clientIP), clientIP)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"Unable to properly determine user's IP address"})
	}

	// now we check if the actualUser provided a secret
	clientSecret := c.Get("User-Secret")
	user, err := dataprovider.NewUser(clientSecret, "")
	if err == dataprovider.ErrSecretLength {
		log.Infof("user %s was denied due to challenge failure", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"User-Secret is incorrect"})
	}

	// check if this actualUser exists
	actualUser, err := dataProvider.GetUser(user.ID)
	if actualUser == nil || err != nil {
		log.Infof("user %s was denied due to incorrect secret", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"unable to find user"})
	}

	// deny the actualUser if it is disabled
	if !actualUser.Enabled {
		log.Infof("user %s was denied due to being disabled", clientIP)
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"this user is currently disabled"})
	}

	// add this actualUser's IP to whitelist
	acl := dataprovider.ACL{
		AllowAll:     actualUser.ACLAllowAll,
		AllowedHosts: actualUser.ACLAllowedHosts,
	}
	if actualUser.TTLMinutes > 0 {
		ttl := time.Now().Add(time.Duration(actualUser.TTLMinutes) * time.Minute)
		acl.TTL = &ttl
		log.Infof("set user IP (%s) TTL to: %v", clientIP, ttl)
	}
	err = dataProvider.AddIp(clientIP, &acl)
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
	apiResponse.ACL = acl
	return c.Status(fiber.StatusAccepted).JSON(apiResponse)
}

// handlerUserAdd godoc
// @Summary Add a new User
// @Description add by json user
// @Tags User
// @Accept  json
// @Produce  json
// @Param Admin-Secret header string true "Admin Secret"
// @Param user body server.addUser true "Add User"
// @Success 200 {object} server.getUser
// @Router /user [post]
func handlerUserAdd(c *fiber.Ctx) error {
	// TODO: re-enable authentication when webui supports it
	// validate authorization header if enabled
	//if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
	//	log.Warnf("admin credentials rejected")
	//	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	//}

	// try to read the body
	body := c.Body()

	// try to unmarshal the body into a valid user
	user, err := dataprovider.DecodeUser(body)
	if err != nil || user == nil {
		log.Errorf("unable to decode user: %v", err)
		apiResponse := errorResponse{"Bad request: " + err.Error()}
		return c.Status(fiber.StatusBadRequest).JSON(apiResponse)
	}

	// add the user to the backend now
	err = dataProvider.AddUser(user)
	switch {
	case err == dataprovider.ErrUserExists:
		log.Errorf("couldn't add new user: %v", err)
		apiResponse := errorResponse{fmt.Sprintf("Client already exists (ID: %s). Try Modifying it", user.ID)}
		return c.Status(fiber.StatusConflict).JSON(apiResponse)
	case err != nil:
		log.Errorf("couldn't add new user: %v", err)
		apiResponse := errorResponse{"Could not add user"}
		return c.Status(fiber.StatusInternalServerError).JSON(apiResponse)
	}
	// add this user to dynamic DNS provider
	ddnsProvider.ProcessUser(user)

	// user has been added
	log.Infof("new user has been added: %s", user.ID)
	return c.Status(fiber.StatusOK).JSON(getUserConvert(user))
}

// handlerUserUpdate godoc
// @Summary Update an existing User
// @Description update by json user
// @Tags User
// @Accept  json
// @Produce  json
// @Param Admin-Secret header string true "Admin Secret"
// @Param user body server.modifyUser true "Update User"
// @Success 200 {object} server.getUser
// @Router /user/{id} [put]
func handlerUserUpdate(c *fiber.Ctx) error {
	// TODO: re-enable authentication when webui supports it
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	//if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
	//	log.Warnf("admin credentials rejected")
	//	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	//}

	// get vars from request to determine if user id was specified
	userId := c.Params("userId")
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warnf("user was not found: %s", userId)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user was not found"})
	}

	// try to read the body
	body := c.Body()

	// try to unmarshal the body into a valid user
	modifiedUser, err := dataprovider.DecodeUser(body)
	if err != nil || user == nil {
		log.Errorf("unable to decode user: %v", err)
		apiResponse := errorResponse{"Bad request: " + err.Error()}
		return c.Status(fiber.StatusBadRequest).JSON(apiResponse)
	}

	// add the user to the backend now
	err = dataProvider.UpdateUser(modifiedUser)
	if err != nil {
		log.Errorf("could not update user: %v", err)
		apiResponse := errorResponse{"Could not update user"}
		return c.Status(fiber.StatusInternalServerError).JSON(apiResponse)
	}
	// add this user to dynamic DNS provider
	ddnsProvider.ProcessUser(modifiedUser)

	// user has been updated
	log.Infof("user has been updated: %s", user.ID)
	return c.Status(fiber.StatusOK).JSON(getUserConvert(modifiedUser))
}

// handlerUserGet godoc
// @Summary Retrieve a User based on provided ID
// @Description get User by ID
// @Tags User
// @Produce json
// @Param Admin-Secret header string true "Admin Secret"
// @Param id path string true "User ID"
// @Success 200 {object} server.getUser
// @Router /user/{id} [get]
func handlerUserGet(c *fiber.Ctx) error {
	// TODO: re-enable authentication when webui supports it
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	//if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
	//	log.Warnf("admin credentials rejected")
	//	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	//}

	// get vars from request to determine if user id was specified
	userId := c.Params("userId")
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warnf("user was not found: %s", userId)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user was not found"})
	}
	return c.Status(fiber.StatusOK).JSON(getUserConvert(user))
}

// handlerUserGetAll godoc
// @Summary Retrieve all Users
// @Description get all Users
// @Tags User
// @Produce json
// @Param Admin-Secret header string true "Admin Secret"
// @Success 200 {array} server.getUser
// @Router /user [get]
func handlerUserGetAll(c *fiber.Ctx) error {
	// TODO: re-enable authentication when webui supports it
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	//if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
	//	log.Warnf("admin credentials rejected")
	//	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	//}

	users, err := dataProvider.GetAllUsers()
	if err != nil {
		log.Warnf("could not get all users: %v", err)
		return c.Status(fiber.StatusServiceUnavailable).JSON(errorResponse{"could not retrieve all users"})
	}
	// Fiber handles empty slices properly
	if len(users) == 0 {
		return c.Status(fiber.StatusOK).JSON([]getUser{})
	}
	return c.Status(fiber.StatusOK).JSON(getAllUsersConvert(users))
}

// handlerUserDelete godoc
// @Summary Remove a User based on provided ID
// @Description remove a User by ID
// @Tags User
// @Produce json
// @Param Admin-Secret header string true "Admin Secret"
// @Param id path string true "User ID"
// @Success 200 {object} server.getUser
// @Router /user/{id} [delete]
func handlerUserDelete(c *fiber.Ctx) error {
	// TODO: re-enable authentication when webui supports it
	// validate authorization header if enabled
	//if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
	//	log.Warnf("admin credentials rejected")
	//	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	//}

	// get vars from request to determine if environment id was specified
	userId := c.Params("userId")
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warnf("user was not found: %s", userId)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user was not found"})
	}

	err = dataProvider.RemoveUser(user)
	if err != nil {
		log.Warnf("unable to remove client %s: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"unable to remove client"})
	}
	// user has been removed
	log.Infof("user has been removed: %s", userId)
	return c.Status(fiber.StatusOK).JSON(getUserConvert(user))
}

// handlerUserIPAdd godoc
// @Summary Add IP to user
// @Description Add an IP address to a user's ACL
// @Tags User
// @Accept json
// @Produce json
// @Param Admin-Secret header string false "Admin Secret"
// @Param id path string true "User ID"
// @Param ip body server.ipRequest true "IP address to add"
// @Success 200 {object} server.getUser
// @Router /user/{id}/ip [post]
func handlerUserIPAdd(c *fiber.Ctx) error {
	userId := c.Params("userId")
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warnf("user was not found: %s", userId)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user was not found"})
	}

	var req ipRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	if req.IP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"ip is required"})
	}

	// Validate IP format
	if !validate.IsIPv4(req.IP) && !validate.IsIPv6(req.IP) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid IP address format"})
	}

	// Add IP
	user.AddIp(req.IP)

	// Update user
	err = dataProvider.UpdateUser(user)
	if err != nil {
		log.Warnf("unable to update user %s: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"unable to update user"})
	}

	// Fetch the updated user to ensure we have the latest state
	user, err = dataProvider.GetUser(userId)
	if err != nil || user == nil {
		log.Warnf("unable to fetch updated user %s: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"unable to fetch updated user"})
	}

	log.Infof("IP added to user %s: %s", userId, req.IP)
	return c.Status(fiber.StatusOK).JSON(getUserConvert(user))
}

// handlerUserIPRemove godoc
// @Summary Remove IP from user
// @Description Remove an IP address from a user's ACL
// @Tags User
// @Accept json
// @Produce json
// @Param Admin-Secret header string false "Admin Secret"
// @Param id path string true "User ID"
// @Param ip body server.ipRequest true "IP address to remove"
// @Success 200 {object} server.getUser
// @Router /user/{id}/ip [delete]
func handlerUserIPRemove(c *fiber.Ctx) error {
	userId := c.Params("userId")
	user, err := dataProvider.GetUser(userId)
	if user == nil || err != nil {
		log.Warnf("user was not found: %s", userId)
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"user was not found"})
	}

	var req ipRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"invalid request body"})
	}

	if req.IP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"ip is required"})
	}

	// Remove IP
	user.RemoveIp(req.IP)

	// Update user
	err = dataProvider.UpdateUser(user)
	if err != nil {
		log.Warnf("unable to update user %s: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"unable to update user"})
	}

	// Fetch the updated user to ensure we have the latest state
	user, err = dataProvider.GetUser(userId)
	if err != nil || user == nil {
		log.Warnf("unable to fetch updated user %s: %v", userId, err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"unable to fetch updated user"})
	}

	log.Infof("IP removed from user %s: %s", userId, req.IP)
	return c.Status(fiber.StatusOK).JSON(getUserConvert(user))
}

// handlerConfig godoc
// @Summary Get configuration
// @Description Get current server configuration (non-sensitive values)
// @Tags Config
// @Produce json
// @Success 200 {object} server.configResponse
// @Router /config [get]
func handlerConfig(c *fiber.Ctx) error {
	config := configResponse{
		LogLevel:          viper.GetString("log.level"),
		LogEncoding:       viper.GetString("log.encoding"),
		ServerBindAddress: viper.GetString("server.bind_address"),
		ServerBindPort:    viper.GetString("server.bind_port"),
		ServerTLSEnabled:  viper.GetBool("server.tls.enabled"),
		DBProvider:        viper.GetString("db.provider"),
		DBBoltFile:        viper.GetString("db.bolt.file"),
	}
	return c.Status(fiber.StatusOK).JSON(config)
}

// handlerACLs godoc
// @Summary Get all ACLs
// @Description Get all authorized IP addresses with their ACLs
// @Tags ACL
// @Produce json
// @Success 200 {object} map[string]dataprovider.ACL
// @Router /acl [get]
func handlerACLs(c *fiber.Ctx) error {
	acls, err := dataProvider.GetAllACLs()
	if err != nil {
		log.Errorw("failed to get all ACLs", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"failed to retrieve ACLs"})
	}
	return c.Status(fiber.StatusOK).JSON(acls)
}

// handlerACLDelete godoc
// @Summary Delete an ACL
// @Description Remove an IP address from the ACL system
// @Tags ACL
// @Param ip path string true "IP Address"
// @Success 200 {object} map[string]string
// @Router /acl/{ip} [delete]
func handlerACLDelete(c *fiber.Ctx) error {
	ip := c.Params("ip")

	if ip == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{"ip is required"})
	}

	err := dataProvider.RemoveIp(ip)
	if err != nil {
		log.Warnw("failed to remove IP from ACL", "ip", ip, "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{"failed to remove IP from ACL"})
	}

	log.Infof("IP removed from ACL: %s", ip)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "IP removed from ACL", "ip": ip})
}

// trackAuthMetrics tracks authorization metrics per IP and FQDN
func trackAuthMetrics(ip, fqdn string, allowed bool) {
	authMetricsLock.Lock()
	defer authMetricsLock.Unlock()

	metrics, exists := authMetrics[ip]
	if !exists {
		metrics = &AuthMetrics{
			FQDNAccess: make(map[string]int),
		}
		authMetrics[ip] = metrics
	}

	metrics.TotalRequests++
	metrics.LastSeen = time.Now()

	if allowed {
		metrics.FQDNAccess[fqdn]++
	}
}

// handlerMetrics godoc
// @Summary Get authorization metrics
// @Description Get authorization request metrics per IP and FQDN
// @Tags Metrics
// @Produce json
// @Success 200 {object} map[string]AuthMetrics
// @Router /metrics [get]
func handlerMetrics(c *fiber.Ctx) error {
	authMetricsLock.RLock()
	defer authMetricsLock.RUnlock()

	// Create a copy to avoid holding the lock during JSON marshaling
	metricsCopy := make(map[string]*AuthMetrics)
	for ip, metrics := range authMetrics {
		fqdnCopy := make(map[string]int)
		for fqdn, count := range metrics.FQDNAccess {
			fqdnCopy[fqdn] = count
		}
		metricsCopy[ip] = &AuthMetrics{
			TotalRequests: metrics.TotalRequests,
			FQDNAccess:    fqdnCopy,
			LastSeen:      metrics.LastSeen,
		}
	}

	return c.Status(fiber.StatusOK).JSON(metricsCopy)
}
