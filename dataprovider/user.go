package dataprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	validate "github.com/asaskevich/govalidator"
)

var (
	// min length of a secret
	minSecretLength = 6
	// error generated when min length of a secret is not met
	ErrSecretLength = fmt.Errorf("secret does not contain enough characters (minimum is %d)", minSecretLength)
	// error generated when attempting to add a user that already exists
	ErrUserExists = fmt.Errorf("user already exists")
	// error generated when attempting to modify a user that does not exist
	ErrUserNotFound = fmt.Errorf("user was not found")
)

// User represents a user/client which is registered by the admin.
// a User is identified by a secret (which is hashed into an ID).
// a User can have multiple IPs associated with it.
// when a User has one or more DNSNames, all of them get placed in the
// IP database with unlimited TTL. A backend process will clean out old IPs when
// it notices that the DNS names resolves differently.
type User struct {
	// Determines if this User is enabled
	Enabled         bool     `json:"enabled" example:"true"`
	// A brief description of this User
	Description     string   `json:"description" example:"Cloud Strife"`
	// A unique identifier for this User
	ID              string   `json:"id" example:"5e8848"`
	// This secret is used as a challenge to whitelist a User's IP
	Secret          string   `json:"secret,omitempty" example:"supersecret"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll     bool     `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames        []string `json:"dns_names" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes      int      `json:"ttl_minutes" example:"60"`
	// Keeps track of IPs associated with this User
	IPs             []string `json:"ip_addresses" example:"1.1.1.1,1.1.1.2"`
}

// NewUser returns a User with safe defaults
func NewUser(secret, description string) (u *User, err error) {
	if len(secret) < minSecretLength {
		return nil, ErrSecretLength
	}
	secretHash, err := hashSecret(secret)
	if err != nil {
		return nil, err
	}
	u = &User{
		// Enabled is not used for... just set to true
		Enabled:         true,
		Description:     description,
		ID:              generateIdFromSecret(secret),
		Secret:          secretHash,
		ACLAllowAll:     false,
		ACLAllowedHosts: nil,
		DNSNames:        nil,
		IPs:             nil,
		TTLMinutes:      0,
	}
	return
}

func DecodeUser(data []byte) (u *User, err error) {
	tempUser := User{}
	if err = json.Unmarshal(data, &tempUser); err != nil {
		return
	}
	// check if the secret is valid
	u, err = NewUser(tempUser.Secret, tempUser.Description)
	if err != nil {
		u = nil
		return
	}
	// provided user looks valid, construct the allowed fields now
	// TODO: do some validation here, since this data is untrusted
	u.ACLAllowAll = tempUser.ACLAllowAll
	u.ACLAllowedHosts = tempUser.ACLAllowedHosts
	u.TTLMinutes = tempUser.TTLMinutes
	u.DNSNames = tempUser.DNSNames
	u.Enabled = tempUser.Enabled
	return
}

// Encode this object for storage to db
func (u *User) Encode() (encoded []byte) {
	// ignore errors for this call, since I don't think it's really possible here...
	encoded, _ = json.Marshal(u)
	return
}

// CheckHost checks if a host is in the list (case insensitive)
func (u *User) CheckHost(host string) bool {
	for _, allowedHost := range u.ACLAllowedHosts {
		if strings.EqualFold(allowedHost, host) {
			return true
		}
	}
	return false
}

// AddHost adds a new host to the ACL so that the user can access it
func (u *User) AddHost(host string) (err error) {
	if !u.CheckHost(host) {
		if validate.IsDNSName(host) {
			u.ACLAllowedHosts = append(u.ACLAllowedHosts, strings.ToLower(host))
		} else {
			err = fmt.Errorf("validation error for DNS name: %s", host)
		}
	}
	return
}

// RemoveHost removes a host from the ACL
func (u *User) RemoveHost(host string) {
	if u.CheckHost(host) {
		for index, allowedHost := range u.ACLAllowedHosts {
			if strings.EqualFold(allowedHost, host) {
				u.ACLAllowedHosts = append(u.ACLAllowedHosts[:index], u.ACLAllowedHosts[index+1:]...)
				return
			}
		}
	}
}

// SetAclAllowAll sets the value for ACLAllowAll
func (u *User) SetAclAllowAll(allowAll bool) {
	u.ACLAllowAll = allowAll
}

// CheckIp checks if an IP belongs to this user
func (u *User) CheckIp(ip string) bool {
	for _, thisIp := range u.IPs {
		if strings.EqualFold(thisIp, ip) {
			return true
		}
	}
	return false
}

// AddIp adds an IP that has been associated with this user
func (u *User) AddIp(ip string) (err error) {
	if !u.CheckIp(ip) {
		if validate.IsIP(ip) {
			u.IPs = append(u.IPs, strings.ToLower(ip))
		} else {
			err = fmt.Errorf("validation error for IP Address: %s", ip)
		}
	}
	return
}

// RemoveIp removes an IP that has been associated with this user
func (u *User) RemoveIp(ip string) {
	if u.CheckIp(ip) {
		for index, thisIp := range u.IPs {
			if strings.EqualFold(thisIp, ip) {
				u.ACLAllowedHosts = append(u.IPs[:index], u.IPs[index+1:]...)
				return
			}
		}
	}
}
