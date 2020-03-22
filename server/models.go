package server

import "github.com/gbolo/protego/dataprovider"

type addUser struct {
	// Determines if this User is enabled
	Enabled         bool     `json:"enabled" example:"true"`
	// A brief description of this User
	Description     string   `json:"description" example:"Cloud Strife"`
	// This secret is used as a challenge to whitelist a User's IP
	Secret          string   `json:"secret" example:"supersecret"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll     bool     `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames        []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes      int      `json:"ttl_minutes,omitempty" example:"60"`
}

type modifyUser struct {
	// Determines if this User is enabled
	Enabled         bool     `json:"enabled" example:"true"`
	// A brief description of this User
	Description     string   `json:"description" example:"Cloud Strife"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll     bool     `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames        []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes      int      `json:"ttl_minutes,omitempty" example:"60"`
}

type getUser struct {
	// A unique identifier for this User
	ID              string   `json:"id" example:"5e8848"`
	// Determines if this User is enabled
	Enabled         bool     `json:"enabled" example:"true"`
	// A brief description of this User
	Description     string   `json:"description" example:"Cloud Strife"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll     bool     `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames        []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes      int      `json:"ttl_minutes,omitempty" example:"60"`
}

type version struct {
	Version string `json:"version" example:"v1.0"`
	BuildRef string  `json:"build_ref" example:"git-30b8019"`
}

type challengeResponse struct {
	Message   string `json:"message"`
	UserId    string `json:"user_id"`
	IpAddress string `json:"ip_address"`
	dataprovider.ACL
}

type errorResponse struct {
	Error string `json:"error"`
}

func getUserConvert(user *dataprovider.User) getUser {
	return getUser{
		ID:              user.ID,
		Enabled:         user.Enabled,
		Description:     user.Description,
		ACLAllowAll:     user.ACLAllowAll,
		ACLAllowedHosts: user.ACLAllowedHosts,
		DNSNames:        user.DNSNames,
		TTLMinutes:      user.TTLMinutes,
	}
}

func getAllUsersConvert(users []dataprovider.User) (getUsers []getUser) {
	for _, user := range users {
		getUsers = append (getUsers, getUser{
			ID:              user.ID,
			Enabled:         user.Enabled,
			Description:     user.Description,
			ACLAllowAll:     user.ACLAllowAll,
			ACLAllowedHosts: user.ACLAllowedHosts,
			DNSNames:        user.DNSNames,
			TTLMinutes:      user.TTLMinutes,
		})
	}
	return
}