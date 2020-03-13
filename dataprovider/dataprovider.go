package dataprovider

import "github.com/gbolo/protego/config"

var log = config.GetLogger()

// Provider interface that data providers must implement.
type Provider interface {
	InitializeDatabase() error
	CheckAvailability() error

	// used for IP authorization
	AddIp(ip string, acl *ACL) error
	RemoveIp(ip string) error
	GetACL(ip string) (*ACL, error)
	UpdateACL(ip string, acl *ACL) error

	// user management
	AddUser(u *User) error
	RemoveUser(u *User) error
	GetUser(id string) (*User, error)
	UpdateUser(u *User) error

	// only needs a real implementation if provider does not
	// natively support TTL
	//MaintananceTTL() error
}
