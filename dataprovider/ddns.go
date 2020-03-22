package dataprovider

import (
	"net"
	"sync"
	"time"

	validate "github.com/asaskevich/govalidator"
)

type DdnsProvider struct {
	fqdns      map[string]ACL
	acls       map[string]ACL
	lock       *sync.Mutex // TODO: use RWMutex
	stopSignal chan bool
}

func NewDdnsProvider() (p DdnsProvider) {
	p = DdnsProvider{
		fqdns:      make(map[string]ACL),
		acls:       make(map[string]ACL),
		lock:       new(sync.Mutex),
		stopSignal: make(chan bool),
	}
	go p.daemonize()
	log.Debug("ddns provider has been initialized")
	return
}

func (p *DdnsProvider) ProcessUsers(users []User) {
	log.Debugf("processing %d user(s)", len(users))
	for _, user := range users {
		p.ProcessUser(&user)
	}
}

func (p *DdnsProvider) ProcessUser(user *User) {
	if len(user.DNSNames) == 0 {
		return
	}
	log.Debugf("user %s has %d DNS Names", user.ID, len(user.DNSNames))
	p.lock.Lock()
	for _, fqdn := range user.DNSNames {
		if validate.IsDNSName(fqdn) {
			p.fqdns[fqdn] = ACL{
				AllowAll:     user.ACLAllowAll,
				AllowedHosts: user.ACLAllowedHosts,
			}
		}
	}
	p.lock.Unlock()
	p.updateACLs()
}

func (p *DdnsProvider) DeleteUser(user *User) {
	if len(user.DNSNames) == 0 {
		return
	}
	p.lock.Lock()
	for _, fqdn := range user.DNSNames {
		if _, ok := p.fqdns[fqdn]; ok {
			delete(p.fqdns, fqdn)
		}
	}
	p.lock.Unlock()
	p.updateACLs()
}

func (p *DdnsProvider) GetACL(ip string) (acl *ACL) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if aclFound, ok := p.acls[ip]; ok {
		acl = &aclFound
	}
	return
}

func (p *DdnsProvider) updateACLs() {
	if len(p.fqdns) == 0 {
		return
	}
	acls := make(map[string]ACL)
	for fqdn, acl := range p.fqdns {
		ips, err := net.LookupIP(fqdn)
		if err != nil {
			log.Errorf("unable to perform a DNS lookup for %s: %v", fqdn, err)
		}
		if len(ips) > 0 {
			// we ONLY use the first IP address, and ignore everything else
			if len(ips) > 1 {
				log.Warningf("the following dns lookup (%s) resulted in more than one (%d) IPs. Only using the first one %s", fqdn, len(ips), ips[0])
			}
			acls[ips[0].String()] = acl
		}
	}
	log.Debugf("adding %d ACLs", len(acls))
	p.lock.Lock()
	p.acls = acls
	p.lock.Unlock()
}

// daemonize is a blocking loop which periodically updates ACLs. Only exits if shutdown signal is received
func (p *DdnsProvider) daemonize() {
	// for now, hard code this interval
	updateInterval := 120
	t := time.Tick(time.Duration(updateInterval) * time.Minute)
	log.Infof("interval of periodic updates for DNS based ACLs is set to %d minute(s)", updateInterval)

	for {
		select {
		case <-t:
			p.updateACLs()
			log.Debugf("periodic update for DNS based ACLs completed")
		case <-p.stopSignal:
			log.Warning("stop signal received, DNS based ACLs will stop being updated.")
			return
		}
	}
}
