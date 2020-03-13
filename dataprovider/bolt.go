package dataprovider

import (
	"encoding/json"
	"fmt"
	"time"

	validate "github.com/asaskevich/govalidator"
	"github.com/boltdb/bolt"
	"github.com/spf13/viper"
)

var (
	userBucket = []byte("user")
	aclBucket  = []byte("acl")
)

// BoltProvider implements Provider for bolt key/value store
type BoltProvider struct {
	dbHandle *bolt.DB
}

func NewBoltProvider() (p BoltProvider, err error) {
	err = p.InitializeDatabase()
	return
}

func (p *BoltProvider) InitializeDatabase() (err error) {
	boltDbFile := viper.GetString("db.bolt.file")
	p.dbHandle, err = bolt.Open(boltDbFile, 0600, &bolt.Options{
		NoGrowSync: false,
		//FreelistType: bolt.FreelistArrayType,
		Timeout: 5 * time.Second})
	if err == nil {
		log.Infof("bolt key/value store handle created")
		err = p.dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(userBucket)
			return e
		})
		if err != nil {
			log.Errorf("error creating user bucket: %v", err)
			return err
		}
		err = p.dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(aclBucket)
			return e
		})
		if err != nil {
			log.Errorf("error creating acl bucket: %v", err)
			return err
		}
	} else {
		log.Errorf("error creating bolt key/value store handle: %v", err)
	}
	return err
}

func (p *BoltProvider) CheckAvailability() error {
	return nil
}

func (p *BoltProvider) AddIp(ip string, acl *ACL) error {
	if !validate.IsIP(ip) {
		return fmt.Errorf("validation error for IP: %s", ip)
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket(aclBucket).Put([]byte(ip), acl.Encode())
		return e
	})
}

func (p *BoltProvider) RemoveIp(ip string) error {
	if !validate.IsIP(ip) {
		return fmt.Errorf("validation error for IP: %s", ip)
	}
	// remove the acl
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket(aclBucket).Delete([]byte(ip))
		return e
	})
}

func (p *BoltProvider) GetACL(ip string) (acl *ACL, err error) {
	if !validate.IsIP(ip) {
		return nil, fmt.Errorf("validation error for IP: %s", ip)
	}
	// retrieve the acl
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		var aclBytes []byte
		aclBytes = tx.Bucket(aclBucket).Get([]byte(ip))
		if len(aclBytes) > 1 {
			// serialize aclBytes into acl
			return json.Unmarshal(aclBytes, &acl)
		}
		return nil
	})
	// check expiration
	if acl != nil && acl.IsExpired() {
		log.Infof("user IP (%s) TTL has expired. Removing from database", ip)
		err = p.RemoveIp(ip)
		acl = nil
	}
	return
}

func (p *BoltProvider) UpdateACL(ip string, acl *ACL) error {
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

func (p *BoltProvider) AddUser(u *User) error {
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
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket(userBucket).Put([]byte(u.ID), u.Encode())
		return e
	})
}

func (p *BoltProvider) RemoveUser(u *User) error {
	// validate the user object
	if u == nil || len(u.ID) < 6 {
		return fmt.Errorf("validation error for User: %v", u)
	}
	// remove the user
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket(userBucket).Delete([]byte(u.ID))
		return e
	})
}

func (p *BoltProvider) GetUser(id string) (user *User, err error) {
	// validate the user id
	if len(id) < 6 {
		return nil, fmt.Errorf("user id is invalid: %s", id)
	}
	// retrieve the user
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		var userBytes []byte
		userBytes = tx.Bucket(userBucket).Get([]byte(id))
		if len(userBytes) > 1 {
			// serialize userBytes into user
			return json.Unmarshal(userBytes, &user)
		}
		return nil
	})
	return
}

func (p *BoltProvider) UpdateUser(u *User) error {
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
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket(userBucket).Put([]byte(u.ID), u.Encode())
		return e
	})
}
