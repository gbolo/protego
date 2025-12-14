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