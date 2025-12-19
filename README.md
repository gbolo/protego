# Protego

> "You wouldn't believe how many people, even people who work at the Ministry, can't do a decent Shield Charm."
> -- George Weasley regarding the shield charm

## Summary

Protego is a lightweight, self-hosted REST API service that provides transparent IP-based access control for your HTTP services. It's designed to allow **external individuals** (friends, family, remote workers) that you've granted access to easily whitelist their own IP addresses through simple challenges (username/password), enabling them to access your private services without requiring VPN or complex authentication. Since the IP address is whitelisted, this means that other devices also on the same network (such as TVs, or other mobile devices) can now access those services as well without having to do the same challenge.

**How it works:**
1. You grant access by creating users with credentials and specifying which services they can access (via host headers)
2. Users visit a challenge page and authenticate with their username/password
3. Protego creates a temporary ACL entry for their current IP address with a configurable TTL (time-to-live)
4. The user can now access the permitted services for the duration of the TTL
5. ACLs automatically expire, requiring periodic re-authentication

**Key capabilities:**
- **Self-Service IP Whitelisting**: Users whitelist their own IPs through simple username/password challenges
- **Full Featured Admin UI**: Administrators can manage users and ACLs easily from the admin ui
- **Time-Based ACLs**: All IP whitelists expire based on configurable TTLs (enforced maximum limits)
- **Host-Based Restrictions**: Control which specific services (host headers) each user can access
- **Dynamic DNS Support**: Automatically whitelist IPs from users' dynamic DNS names
- **nginx Integration**: Works seamlessly with nginx's `auth_request` module
- **RESTful API**: Fully documented API with embedded Swagger UI for administration
- **Flexible Storage**: Multiple backend options (memory, BoltDB, or implement your own)


## Getting Started

### Step 1: Configure Your Reverse Proxy

Protego works with reverse proxies that support forward authentication. Choose one of the following:

#### nginx

Uses the `auth_request` module (built-in). Add this configuration to protect your services:

```nginx
server {
    listen 443 ssl http2;
    server_name app-to-protect.example.com;
    ...
    
    location / {
        # Protego authorization
        auth_request /auth;
        # Pass through to your backend
        proxy_pass http://backend:8080;
    }

    # Internal auth endpoint
    location = /auth {
        internal;
        proxy_pass http://protego:8080/api/v1/authorize;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr; # protego currently uses X-Real-IP to determine the real client IP
    }
}

# Challenge UI (for users to whitelist their IP)
server {
    listen 443 ssl http2;
    server_name protego.example.com;

    # Your SSL configuration...

    location / {
        proxy_pass http://protego:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Traefik

Uses the [ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/). Set the `address` to `http://protego:8080/api/v1/authorize`.

#### Caddy

Uses the [forward_auth directive](https://caddyserver.com/docs/caddyfile/directives/forward_auth). Set the URI to `http://protego:8080/api/v1/authorize`.

---

### Step 2: Deploy Protego

#### Option A: Using Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/gbolo/protego/releases):

```bash
# Download and extract (example for Linux amd64)
wget -O ./protego https://github.com/gbolo/protego/releases/download/v2.0.0/protego_2.0.0_linux_amd64
chmod +x ./protego

# Run with default settings (config via environment or defaults)
./protego

# Run with custom config file (or copy from the sample config)
./protego -config /path/to/protego.yaml

# Show version
./protego -version
```

#### Option B: Using Docker

```bash
# Run with default configuration
docker run -p 8080:8080 gbolo/protego:latest

# Run with custom config
docker run -p 8080:8080 \
  -v $(pwd)/config:/config \
  gbolo/protego:latest \
  -config /config/protego.yaml
```

Once running, access:
- **API**: http://localhost:8080/api/v1
- **Swagger UI**: http://localhost:8080/swagger
- **Admin UI**: http://localhost:8080/admin
- **Challenge UI**: http://localhost:8080

---

### Step 3: Create Users

#### Option A: Using the Admin UI (Recommended)

Navigate to the **[Admin UI](http://localhost:8080/admin)** and create users through the web interface.
![Add User UI](https://github.com/gbolo/protego/raw/master/docs/diagrams/screenshot_protego_add_user.png)


#### Option B: Using the API

```bash
curl -X POST http://localhost:8080/api/v1/user \
  -H "Admin-Secret: your-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice",
    "enabled": true,
    "description": "Alice Smith",
    "secret": "alice-secret-password",
    "acl_allow_all": false,
    "acl_allowed_hosts": ["app-to-protect.example.com"],
    "ttl_minutes": 43200
  }'
```

---

### Step 4: Users Whitelist Their IPs

Share the your challenge page (e.g., `https://auth.example.com`) with the user and provide them credentiald. The user can then visit the challenge page, enter their credentials, and their IP will be whitelisted for the configured TTL duration.

![Challenge UI](https://github.com/gbolo/protego/raw/master/docs/diagrams/screenshot_protego_challenge_ui.png)


Once the user has successfully been whitelisted they may access the protect site, in this example it's `https://app-to-protect.example.com`. Without being whitelisted they would have gotten a 403 response.

The administrator can also see if they have been whitelisted successfully or not from the admin UI.

![ACLs UI](https://github.com/gbolo/protego/raw/master/docs/diagrams/screenshot_protego_acls_ui.png)

---

## How It Works

![Protego Authorization Flow](https://github.com/gbolo/protego/raw/master/docs/diagrams/protego_authorize_flow.png)

### Authorization Flow

1. Client makes request to your reverse proxy
2. Reverse proxy forwards request details to Protego's `/api/v1/authorize` endpoint
3. Protego checks if the client IP has a valid ACL
4. Reverse proxy allows/denies the request based on Protego's response

### Authorization Logic

Protego authorizes requests based on:
- **IP Address**: Is the client IP in an active (non-expired) ACL?
- **Host Header**: Does the user's ACL allow access to the requested host?
- **TTL**: Has the IP's whitelist entry expired?

### Challenge Flow

1. User visits the challenge page (e.g., `https://auth.yourdomain.com`)
2. User enters their username and secret
3. Protego creates an ACL entry for their current IP with configured TTL
4. User can now access protected services for the TTL duration

## Configuration

### Configuration File

Protego uses a YAML configuration file. By default, it looks for `protego.yaml` in the current directory, or you can specify a path with the `-config` flag.

**Example configuration:**

```yaml
# Server settings
server:
  bind_address: "0.0.0.0"
  bind_port: "8080"
  enable_profiler: false  # Enable pprof endpoints (/debug/pprof)
  enable_tls: false
  tls_cert_file: ""
  tls_key_file: ""

# Logging
log:
  level: "info"  # Options: debug, info, warning, error

# Database provider
db:
  provider: "memory"  # Options: memory, bolt
  bolt_db_path: "./protego.db"

# Admin API authentication
admin:
  secret: "change-me-to-a-secure-secret"

# Time-to-live settings
ttl:
  max: 129600  # Maximum TTL in minutes (90 days). Set to 0 for unlimited.
  ddns_update_interval: 1  # Interval in minutes to update DDNS-based ACLs
```

### Configuration via Environment Variables

All configuration options can be set via environment variables using the `PROTEGO_` prefix:

```bash
export PROTEGO_SERVER_BIND_PORT="9090"
export PROTEGO_LOG_LEVEL="debug"
export PROTEGO_ADMIN_SECRET="my-secure-secret"
export PROTEGO_TTL_MAX="43200"  # 30 days
export PROTEGO_DB_PROVIDER="bolt"
export PROTEGO_DB_BOLT_DB_PATH="/data/protego.db"
```

### Configuration Options Reference

#### Server

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server.bind_address` | string | `0.0.0.0` | IP address to bind to |
| `server.bind_port` | string | `8080` | Port to listen on |
| `server.enable_profiler` | bool | `false` | Enable pprof profiling endpoints |
| `server.enable_tls` | bool | `false` | Enable TLS/HTTPS |
| `server.tls_cert_file` | string | - | Path to TLS certificate file |
| `server.tls_key_file` | string | - | Path to TLS private key file |

#### Logging

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log.level` | string | `info` | Log level: `debug`, `info`, `warning`, `error` |

#### Database

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `db.provider` | string | `memory` | Database backend: `memory`, `bolt` |
| `db.bolt_db_path` | string | `./protego.db` | Path to BoltDB file (when using bolt provider) |

#### Admin

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `admin.secret` | string | - | **Required**. Secret for admin API authentication |

#### TTL (Time-to-Live)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ttl.max` | int | `0` | Maximum TTL in minutes. `0` = unlimited |
| `ttl.ddns_update_interval` | int | `1` | Interval in minutes to refresh DDNS-based ACLs |


## Data Providers

Protego supports multiple backend storage options through the `Provider` interface. You can implement your own by satisfying the [Provider interface](https://pkg.go.dev/github.com/gbolo/protego/pkg/dataprovider#Provider).

### Built-in Providers

#### Bolt Provider
- **Best for**: Production, single-instance deployments
- **Pros**: Persistent, embedded, no external dependencies
- **Cons**: Single-writer, not suitable for HA deployments

```yaml
db:
  provider: "bolt"
  bolt_db_path: "/data/protego.db"
```

#### Memory Provider
- **Best for**: Testing, development, small deployments
- **Pros**: Fast, no dependencies
- **Cons**: Data lost on restart, not suitable for HA deployments

```yaml
db:
  provider: "memory"
```

### Implementing Custom Providers

See the [dataprovider package documentation](https://pkg.go.dev/github.com/gbolo/protego/pkg/dataprovider) for the interface requirements.

