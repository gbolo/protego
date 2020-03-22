
URL="http://127.0.0.1:8080/api/v1/user"

# using httpie
# http --print=Hhb PUT ${URL} ADMIN-SECRET:supersecret <<< '{"Enabled":true,"Description":"this is a test","ID":"5e8848","secret":"password","ACL":{"allow_all":false,"allowed_hosts":["git.fqdn","emby.fqdn","tor.fqdn"]},"ValidDuration":60000000000}'

# type User struct {
# 	Enabled         bool     `json:"enabled"`
# 	Description     string   `json:"description"`
# 	ID              string   `json:"id"`
# 	Secret          string   `json:"secret,omitempty"`
# 	ACLAllowAll     bool     `json:"acl_allow_all"`
# 	ACLAllowedHosts []string `json:"acl_allowed_hosts"`
# 	DNSNames        []string `json:"dns_names"`
# 	IPs             []string `json:"ip_addresses"`
# 	TTLMinutes      int      `json:"ttl_minutes"`
# }


http --print=HhBb GET ${URL} ADMIN-SECRET:supersecret
