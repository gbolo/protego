package dataprovider

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	validate "github.com/asaskevich/govalidator"
)

// ACL represents what an IP address is able to access
type ACL struct {
	// when true, client is allowed to access everything
	AllowAll bool `json:"allow_all"`
	// represents a list of host headers the client is allowed to access
	AllowedHosts []string `json:"allowed_hosts"`
	// after this date, the ACL is no longer valid
	TTL *time.Time `json:"ttl"`
	// Users associated with this ACL
	UserIDs []string `json:"user_ids"`
}

// encodes this struct for storage to db
func (a *ACL) Encode() []byte {
	// ignore errors since its not really possible here...
	enc, _ := json.Marshal(a)
	return enc
}

// sets the bool value for allowAll
func (a *ACL) SetAllowAll(allowAll bool) {
	a.AllowAll = allowAll
}

// check if a host is in the list (case insensitive)
func (a *ACL) CheckHost(host string) bool {
	for _, allowedHost := range a.AllowedHosts {
		if strings.EqualFold(allowedHost, host) {
			return true
		}
	}
	return false
}

func (a *ACL) AddHost(host string) (err error) {
	if !a.CheckHost(host) {
		if validate.IsDNSName(host) {
			a.AllowedHosts = append(a.AllowedHosts, strings.ToLower(host))
		} else {
			err = fmt.Errorf("validation error for DNS name: %s", host)
		}
	}
	return
}

func (a *ACL) RemoveHost(host string) {
	if a.CheckHost(host) {
		for index, allowedHost := range a.AllowedHosts {
			if strings.EqualFold(allowedHost, host) {
				a.AllowedHosts = append(a.AllowedHosts[:index], a.AllowedHosts[index+1:]...)
				return
			}
		}
	}
}

func (a *ACL) IsExpired() (expired bool) {
	if a.TTL != nil {
		if a.TTL.Before(time.Now()) {
			expired = true
		}
	}
	return
}

func (a *ACL) CheckUserId(id string) bool {
	for _, userIds := range a.UserIDs {
		if strings.EqualFold(userIds, id) {
			return true
		}
	}
	return false
}

func (a *ACL) AddUserId(id string) (err error) {
	if !a.CheckUserId(id) {
		a.UserIDs = append(a.UserIDs, id)
	}
	return
}

func (a *ACL) RemoveUserId(id string) {
	if a.CheckUserId(id) {
		for index, userId := range a.UserIDs {
			if strings.EqualFold(userId, id) {
				a.UserIDs = append(a.UserIDs[:index], a.UserIDs[index+1:]...)
				return
			}
		}
	}
}

// MergeACL merges two ACLs into a new ACL.
//   - AllowedHosts and UserIDs are combined (deduplicated).
//   - AllowAll is true if either ACL has AllowAll == true.
//   - TTL is the "greater" (later) of the two. If one is nil and the other is not,
//     nil is treated as "no expiration" and wins.
func MergeACL(a, b *ACL) *ACL {
	// Handle nils defensively
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return cloneACL(b)
	}
	if b == nil {
		return cloneACL(a)
	}

	out := &ACL{}

	// AllowAll: "enabled true should win"
	out.AllowAll = a.AllowAll || b.AllowAll

	// TTL: greater (later) wins; nil means "no expiration" and wins
	out.TTL = mergeTTL(a.TTL, b.TTL)

	// AllowedHosts: combine + dedupe
	out.AllowedHosts = mergeStringSlices(a.AllowedHosts, b.AllowedHosts)

	// UserIDs: combine + dedupe
	out.UserIDs = mergeStringSlices(a.UserIDs, b.UserIDs)

	return out
}

func mergeTTL(t1, t2 *time.Time) *time.Time {
	// Both nil → nil
	if t1 == nil && t2 == nil {
		return nil
	}
	// One nil, one non-nil → nil wins (no expiration)
	if t1 == nil && t2 != nil {
		return nil
	}
	if t1 != nil && t2 == nil {
		return nil
	}

	// Both non-nil → pick the later one
	if t1.After(*t2) {
		t := *t1
		return &t
	}
	t := *t2
	return &t
}

func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func cloneACL(src *ACL) *ACL {
	if src == nil {
		return nil
	}

	var ttlCopy *time.Time
	if src.TTL != nil {
		t := *src.TTL
		ttlCopy = &t
	}

	hostsCopy := make([]string, len(src.AllowedHosts))
	copy(hostsCopy, src.AllowedHosts)

	usersCopy := make([]string, len(src.UserIDs))
	copy(usersCopy, src.UserIDs)

	return &ACL{
		AllowAll:     src.AllowAll,
		AllowedHosts: hostsCopy,
		TTL:          ttlCopy,
		UserIDs:      usersCopy,
	}
}
