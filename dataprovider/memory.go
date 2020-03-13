package dataprovider

import (
	"fmt"
	"sync"

	validate "github.com/asaskevich/govalidator"
)

// MemoryProvider implements Provider in memory
// NOT SAFE TO USE OUTSIDE OF TESTING
type MemoryProvider struct {
	users map[string]User
	acls  map[string]ACL
	lock  *sync.Mutex
}

func NewMemoryProvider() (p MemoryProvider, err error) {
	err = p.InitializeDatabase()
	return
}

func (p *MemoryProvider) InitializeDatabase() (err error) {
	p.users = make(map[string]User)
	p.acls = make(map[string]ACL)
	p.lock = new(sync.Mutex)
	log.Infof("Memory provider has been Initialized")
	return nil
}

func (p *MemoryProvider) CheckAvailability() error {
	return nil
}

func (p *MemoryProvider) AddIp(ip string, acl *ACL) error {
	if !validate.IsIP(ip) {
		return fmt.Errorf("validation error for IP: %s", ip)
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.acls[ip] = *acl
	return nil
}

func (p *MemoryProvider) RemoveIp(ip string) error {
	if !validate.IsIP(ip) {
		return fmt.Errorf("validation error for IP: %s", ip)
	}
	// remove the acl
	p.lock.Lock()
	defer p.lock.Unlock()
	if _, ok := p.acls[ip]; ok {
		delete(p.acls, ip)
	}
	return nil
}

func (p *MemoryProvider) GetACL(ip string) (acl *ACL, err error) {
	if !validate.IsIP(ip) {
		return nil, fmt.Errorf("validation error for IP: %s", ip)
	}
	// retrieve the acl
	p.lock.Lock()
	defer p.lock.Unlock()
	if aclFound, ok := p.acls[ip]; ok {
		acl = &aclFound
	}
	return
}

func (p *MemoryProvider) UpdateACL(ip string, acl *ACL) error {
	if !validate.IsIP(ip) {
		return fmt.Errorf("validation error for IP: %s", ip)
	}
	// get existing acl
	ea, _ := p.GetACL(ip)
	if ea == nil {
		return fmt.Errorf("no ACL found for IP: %s", ip)
	}
	// simply overwrite this ACL
	return p.AddIp(ip, acl)
}

func (p *MemoryProvider) AddUser(u *User) error {
	// validate the user object
	if u == nil || len(u.ID) < 6 {
		return fmt.Errorf("validation error for User: %v", u)
	}
	// check if user already exists
	eu, _ := p.GetUser(u.ID)
	if eu != nil {
		return ErrUserExists
	}
	// add the user, since its a new user
	p.lock.Lock()
	defer p.lock.Unlock()
	p.users[u.ID] = *u
	return nil
}

func (p *MemoryProvider) RemoveUser(u *User) error {
	// validate the user object
	if u == nil || len(u.ID) < 6 {
		return fmt.Errorf("validation error for User: %v", u)
	}
	// remove the user
	p.lock.Lock()
	defer p.lock.Unlock()
	if _, ok := p.users[u.ID]; ok {
		delete(p.users, u.ID)
	}
	return nil
}

func (p *MemoryProvider) GetUser(id string) (user *User, err error) {
	// validate the user id
	if len(id) < 6 {
		return nil, fmt.Errorf("user id is invalid: %s", id)
	}
	// retrieve the user
	p.lock.Lock()
	defer p.lock.Unlock()
	if userFound, ok := p.users[id]; ok {
		user = &userFound
	}
	return
}

func (p *MemoryProvider) UpdateUser(u *User) error {
	// validate the user object
	if u == nil || len(u.ID) < 6 {
		return fmt.Errorf("validation error for User: %v", u)
	}
	// check if user already exists
	eu, _ := p.GetUser(u.ID)
	if eu == nil {
		return ErrUserNotFound
	}
	// overwrite the existing user, but keep associated IPs
	u.IPs = eu.IPs
	p.lock.Lock()
	defer p.lock.Unlock()
	p.users[u.ID] = *u
	return nil
}
