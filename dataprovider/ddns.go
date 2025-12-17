package dataprovider

import (
	"context"
	"net"
	"sync"
	"time"

	validate "github.com/asaskevich/govalidator"
)

type DdnsProvider struct {
	fqdns        map[string]ACL  // Map of FQDN -> ACL config
	acls         map[string]ACL  // Map of resolved IP -> ACL
	users        map[string]User // Cache of users with DNS names
	lock         *sync.Mutex     // TODO: use RWMutex
	stopSignal   chan bool
	dataProvider Provider // Reference to main data provider for syncing
}

func NewDdnsProvider(provider Provider) (p DdnsProvider) {
	p = DdnsProvider{
		fqdns:        make(map[string]ACL),
		acls:         make(map[string]ACL),
		users:        make(map[string]User),
		lock:         new(sync.Mutex),
		stopSignal:   make(chan bool),
		dataProvider: provider,
	}
	go p.daemonize()
	log.Debug("ddns provider has been initialized")
	return
}

// SyncAllUsers fetches all users from data provider and rebuilds FQDN mappings
func (p *DdnsProvider) SyncAllUsers() error {
	if p.dataProvider == nil {
		return nil
	}

	users, err := p.dataProvider.GetAllUsers()
	if err != nil {
		log.Errorf("failed to get users from data provider: %v", err)
		return err
	}

	return p.syncUsers(users)
}

// SyncUser notifies the DDNS provider that a user was added or updated
func (p *DdnsProvider) SyncUser(userID string) error {
	if p.dataProvider == nil {
		return nil
	}

	user, err := p.dataProvider.GetUser(userID)
	if err != nil || user == nil {
		log.Errorf("failed to get user %s from data provider: %v", userID, err)
		return err
	}

	p.lock.Lock()

	// Check if this is a new user or if DNS names changed
	oldUser, existed := p.users[userID]
	hasChanges := false

	if !existed {
		hasChanges = len(user.DNSNames) > 0
		log.Debugf("new user %s with %d DNS names", userID, len(user.DNSNames))
	} else {
		// Check if DNS names changed
		hasChanges = !stringSlicesEqual(oldUser.DNSNames, user.DNSNames) ||
			oldUser.ACLAllowAll != user.ACLAllowAll ||
			!stringSlicesEqual(oldUser.ACLAllowedHosts, user.ACLAllowedHosts)

		if hasChanges {
			log.Infof("user %s DNS config changed, resyncing", userID)

			// Find DNS names that were removed
			removedDNSNames := findRemovedStrings(oldUser.DNSNames, user.DNSNames)

			// Remove old FQDNs from tracking
			for _, fqdn := range oldUser.DNSNames {
				delete(p.fqdns, fqdn)
			}

			// Unlock before calling cleanupDNSACLs to avoid deadlock
			p.lock.Unlock()

			// Clean up ACLs for removed DNS names
			if len(removedDNSNames) > 0 {
				log.Infof("user %s removed %d DNS names, cleaning up ACLs", userID, len(removedDNSNames))
				p.cleanupDNSACLs(userID, removedDNSNames)
			}

			// Re-acquire lock
			p.lock.Lock()
		}
	}

	// Update user cache
	if len(user.DNSNames) > 0 {
		p.users[userID] = *user

		// Add new FQDNs
		for _, fqdn := range user.DNSNames {
			if validate.IsDNSName(fqdn) {
				p.fqdns[fqdn] = ACL{
					AllowAll:     user.ACLAllowAll,
					AllowedHosts: user.ACLAllowedHosts,
					UserIDs:      []string{user.ID},
				}
			}
		}
	} else {
		// User has no DNS names, remove from cache
		delete(p.users, userID)
	}

	p.lock.Unlock()

	// Only update ACLs if something changed
	if hasChanges {
		p.updateACLs()
	}

	return nil
}

// RemoveUser notifies the DDNS provider that a user was deleted
func (p *DdnsProvider) RemoveUser(userID string) {
	p.lock.Lock()
	user, existed := p.users[userID]
	if !existed {
		p.lock.Unlock()
		return
	}

	log.Infof("removing user %s from DDNS provider", userID)

	// Get the DNS names before removing the user
	dnsNames := make([]string, len(user.DNSNames))
	copy(dnsNames, user.DNSNames)

	// Remove all FQDNs for this user
	for _, fqdn := range user.DNSNames {
		delete(p.fqdns, fqdn)
	}

	delete(p.users, userID)
	p.lock.Unlock()

	// Clean up ACLs for the removed DNS names
	p.cleanupDNSACLs(userID, dnsNames)

	// Trigger ACL update
	go p.updateACLs()
}

// RemoveDNSNames removes specific DNS names from a user and cleans up associated ACLs
func (p *DdnsProvider) RemoveDNSNames(userID string, dnsNames []string) {
	if len(dnsNames) == 0 {
		return
	}

	p.lock.Lock()
	// Remove the FQDNs from tracking
	for _, fqdn := range dnsNames {
		delete(p.fqdns, fqdn)
	}
	p.lock.Unlock()

	log.Infof("removing %d DNS names for user %s", len(dnsNames), userID)

	// Clean up ACLs for the removed DNS names
	p.cleanupDNSACLs(userID, dnsNames)
}

// cleanupDNSACLs resolves DNS names and removes/updates ACLs appropriately
func (p *DdnsProvider) cleanupDNSACLs(userID string, dnsNames []string) {
	if p.dataProvider == nil || len(dnsNames) == 0 {
		return
	}

	resolver := &net.Resolver{}
	ctx := context.Background()
	processedIPs := make(map[string]bool)

	for _, fqdn := range dnsNames {
		if !validate.IsDNSName(fqdn) {
			continue
		}

		addrs, err := resolver.LookupIPAddr(ctx, fqdn)
		if err != nil {
			log.Debugf("unable to resolve DNS name %s during cleanup: %v", fqdn, err)
			continue
		}

		for _, addr := range addrs {
			ip := addr.IP.String()

			// Skip if we already processed this IP
			if processedIPs[ip] {
				continue
			}
			processedIPs[ip] = true

			// Get the current ACL from data provider
			existingACL, err := p.dataProvider.GetACL(ip)
			if err != nil || existingACL == nil {
				continue
			}

			// Check if this user is the only one in the ACL
			if len(existingACL.UserIDs) == 1 && existingACL.UserIDs[0] == userID {
				// This user is the only one, remove the entire ACL
				if err := p.dataProvider.RemoveIp(ip); err != nil {
					log.Errorf("failed to remove ACL for IP %s: %v", ip, err)
				} else {
					log.Infof("removed ACL for IP %s (was only used by user %s via FQDN %s)", ip, userID, fqdn)
				}
			} else if existingACL.CheckUserId(userID) {
				// Multiple users, just remove this user from the ACL
				existingACL.RemoveUserId(userID)
				if err := p.dataProvider.UpdateACL(ip, existingACL); err != nil {
					log.Errorf("failed to update ACL for IP %s: %v", ip, err)
				} else {
					log.Infof("removed user %s from ACL for IP %s (other users still using it)", userID, ip)
				}
			}
		}
	}
}

// syncUsers rebuilds the FQDN map from a list of users
func (p *DdnsProvider) syncUsers(users []User) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	// Clear existing mappings
	p.fqdns = make(map[string]ACL)
	p.users = make(map[string]User)

	usersWithDNS := 0
	totalFQDNs := 0

	for _, user := range users {
		if len(user.DNSNames) == 0 {
			continue
		}

		usersWithDNS++
		p.users[user.ID] = user

		for _, fqdn := range user.DNSNames {
			if validate.IsDNSName(fqdn) {
				p.fqdns[fqdn] = ACL{
					AllowAll:     user.ACLAllowAll,
					AllowedHosts: user.ACLAllowedHosts,
					UserIDs:      []string{user.ID},
				}
				totalFQDNs++
			}
		}
	}

	log.Infof("synced %d users with %d total DNS names", usersWithDNS, totalFQDNs)

	// Trigger ACL resolution
	go p.updateACLs()

	return nil
}

// Helper function to compare string slices
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool)
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

// Helper function to find strings in 'old' that are not in 'new'
func findRemovedStrings(old, new []string) []string {
	newSet := make(map[string]bool)
	for _, s := range new {
		newSet[s] = true
	}

	removed := []string{}
	for _, s := range old {
		if !newSet[s] {
			removed = append(removed, s)
		}
	}
	return removed
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
	resolver := &net.Resolver{}
	ctx := context.Background()

	// DDNS ACLs always have a 4-hour TTL
	ddnsTTL := time.Now().Add(4 * time.Hour)

	for fqdn, aclBase := range p.fqdns {
		addrs, err := resolver.LookupIPAddr(ctx, fqdn)
		if err != nil {
			log.Errorf("unable to perform a DNS lookup for %s: %v", fqdn, err)
			continue
		}

		if len(addrs) == 0 {
			log.Warningf("DNS lookup for %s returned no addresses", fqdn)
			continue
		}

		// Process ALL resolved IP addresses
		if len(addrs) > 1 {
			log.Infof("DNS lookup for %s returned %d IPs, processing all of them", fqdn, len(addrs))
		}

		for _, addr := range addrs {
			ip := addr.IP.String()

			// Create ACL with 4-hour TTL
			acl := ACL{
				AllowAll:     aclBase.AllowAll,
				AllowedHosts: aclBase.AllowedHosts,
				UserIDs:      aclBase.UserIDs,
				TTL:          &ddnsTTL,
			}
			acls[ip] = acl

			// Sync to the main data provider
			if p.dataProvider != nil {
				// Check if ACL already exists in data provider
				existingACL, _ := p.dataProvider.GetACL(ip)
				if existingACL != nil {
					// Merge with existing ACL (in case it was added via challenge)
					mergedACL := MergeACL(&acl, existingACL)
					if err := p.dataProvider.AddIp(ip, mergedACL); err != nil {
						log.Errorf("failed to sync DDNS ACL to data provider for IP %s: %v", ip, err)
					} else {
						log.Debugf("synced DDNS ACL to data provider for IP %s (FQDN: %s)", ip, fqdn)
					}
				} else {
					// Add new ACL with 4-hour TTL
					if err := p.dataProvider.AddIp(ip, &acl); err != nil {
						log.Errorf("failed to add DDNS ACL to data provider for IP %s: %v", ip, err)
					} else {
						log.Infof("added DDNS ACL to data provider for IP %s (FQDN: %s, TTL: 4h)", ip, fqdn)
					}
				}
			}
		}
	}
	log.Infof("resolved %d DNS names to %d total IPs", len(p.fqdns), len(acls))
	p.lock.Lock()
	p.acls = acls
	p.lock.Unlock()
}

// daemonize is a blocking loop which periodically updates ACLs. Only exits if shutdown signal is received
func (p *DdnsProvider) daemonize() {
	// for now, hard code this interval
	updateInterval := 1
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
