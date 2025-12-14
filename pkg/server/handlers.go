package server

import (
	"fmt"
	"time"

	validate "github.com/asaskevich/govalidator"
	"github.com/gbolo/protego/pkg/dataprovider"
	"github.com/gbolo/protego/pkg/log"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
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
	if acl.CheckHost(c.Hostname()) {
		log.Debugf("client (%s) ALLOWED access to host %s", clientIP, c.Hostname())
		return c.SendStatus(fiber.StatusOK)
	}

	// by default we deny everything
	log.Debugf("client (%s) DENIED access to host %s", clientIP, c.Hostname())
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
	// validate authorization header if enabled
	if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
		log.Warnf("admin credentials rejected")
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	}

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
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
		log.Warnf("admin credentials rejected")
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	}

	// get vars from request to determine if user id was specified
	userId := c.Params("user-id")
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
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
		log.Warnf("admin credentials rejected")
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	}

	// get vars from request to determine if user id was specified
	userId := c.Params("user-id")
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
	// validate authorization header if enabled
	// TODO: the user should also be able to modify itself
	if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
		log.Warnf("admin credentials rejected")
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	}

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
	// validate authorization header if enabled
	if viper.GetString("admin.secret") != "" && c.Get("Admin-Secret") != viper.GetString("admin.secret") {
		log.Warnf("admin credentials rejected")
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{"admin credentials rejected"})
	}

	// get vars from request to determine if environment id was specified
	userId := c.Params("user-id")
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
