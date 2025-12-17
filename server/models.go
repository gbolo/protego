package server

import "github.com/gbolo/protego/dataprovider"

type addUser struct {
	// A unique identifier for this User (4-64 characters)
	ID string `json:"id" example:"cloud" valid:"stringlength(4|64)"`
	// Determines if this User is enabled
	Enabled bool `json:"enabled" example:"true"`
	// A brief description of this User
	Description string `json:"description" example:"Cloud Strife"`
	// This secret is used as a challenge to whitelist a User's IP
	Secret string `json:"secret" example:"supersecret"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll bool `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes int `json:"ttl_minutes,omitempty" example:"60"`
}

type modifyUser struct {
	// Determines if this User is enabled
	Enabled bool `json:"enabled" example:"true"`
	// A brief description of this User
	Description string `json:"description" example:"Cloud Strife"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll bool `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes int `json:"ttl_minutes,omitempty" example:"60"`
}

type getUser struct {
	// A unique identifier for this User (4-64 characters)
	ID string `json:"id" example:"cloud"`
	// Determines if this User is enabled
	Enabled bool `json:"enabled" example:"true"`
	// A brief description of this User
	Description string `json:"description" example:"Cloud Strife"`
	// Determines if this User is allowed to access ALL resources
	ACLAllowAll bool `json:"acl_allow_all" example:"false"`
	// A list of hosts (FQDN) this User is allowed to access
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// A list of DNS names that resolve this User's IPs which get whitelisted automatically without a challenge.
	DNSNames []string `json:"dns_names,omitempty" example:"myhome.no-ip.info"`
	// Represents the number of minutes this User's IP is whitelisted for after a successful challenge
	TTLMinutes int `json:"ttl_minutes,omitempty" example:"60"`
}

type version struct {
	Version  string `json:"version" example:"v1.0"`
	BuildRef string `json:"build_ref" example:"git-30b8019"`
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

type addACL struct {
	// when true, client is allowed to access everything
	AllowAll bool `json:"allow_all" example:"false"`
	// represents a list of host headers the client is allowed to access
	AllowedHosts []string `json:"allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// after this date, the ACL is no longer valid (RFC3339 format)
	TTL *string `json:"ttl,omitempty" example:"2025-12-31T23:59:59Z"`
	// Users associated with this ACL
	UserIDs []string `json:"user_ids,omitempty" example:"5e8848,a3f129"`
}

type modifyACL struct {
	// when true, client is allowed to access everything
	AllowAll bool `json:"allow_all" example:"false"`
	// represents a list of host headers the client is allowed to access
	AllowedHosts []string `json:"allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// after this date, the ACL is no longer valid (RFC3339 format)
	TTL *string `json:"ttl,omitempty" example:"2025-12-31T23:59:59Z"`
	// Users associated with this ACL
	UserIDs []string `json:"user_ids,omitempty" example:"5e8848,a3f129"`
}

type getACL struct {
	// IP address this ACL applies to
	IPAddress string `json:"ip_address" example:"192.168.1.100"`
	// when true, client is allowed to access everything
	AllowAll bool `json:"allow_all" example:"false"`
	// represents a list of host headers the client is allowed to access
	AllowedHosts []string `json:"allowed_hosts,omitempty" example:"git.example.com,wiki.example.com"`
	// after this date, the ACL is no longer valid (RFC3339 format)
	TTL *string `json:"ttl,omitempty" example:"2025-12-31T23:59:59Z"`
	// Users associated with this ACL
	UserIDs []string `json:"user_ids,omitempty" example:"5e8848,a3f129"`
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
	getUsers = make([]getUser, 0, len(users))
	for i := range users {
		getUsers = append(getUsers, getUser{
			ID:              users[i].ID,
			Enabled:         users[i].Enabled,
			Description:     users[i].Description,
			ACLAllowAll:     users[i].ACLAllowAll,
			ACLAllowedHosts: users[i].ACLAllowedHosts,
			DNSNames:        users[i].DNSNames,
			TTLMinutes:      users[i].TTLMinutes,
		})
	}
	return
}

func getACLConvert(ipAddress string, acl *dataprovider.ACL) getACL {
	result := getACL{
		IPAddress:    ipAddress,
		AllowAll:     acl.AllowAll,
		AllowedHosts: acl.AllowedHosts,
		UserIDs:      acl.UserIDs,
	}
	if acl.TTL != nil {
		ttlStr := acl.TTL.Format("2006-01-02T15:04:05Z07:00")
		result.TTL = &ttlStr
	}
	return result
}

func getAllACLsConvert(acls map[string]*dataprovider.ACL) (getACLs []getACL) {
	// Pre-allocate slice
	getACLs = make([]getACL, 0, len(acls))

	// Directly iterate - map iteration is safe in Go
	for ip, acl := range acls {
		if acl != nil {
			getACLs = append(getACLs, getACLConvert(ip, acl))
		}
	}
	return
}
