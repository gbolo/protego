# Protego

> "You wouldn't believe how many people, even people who work at the Ministry, can't do a decent Shield Charm."
> -- George Weasley regarding the shield charm

Protego is a self-hosted REST API service, intended to be used in conjunction with
nginx's `auth_request` module, with the goal of providing transparent IP based ACLs to your existing HTTP service(s).

## Features
- 🔐 Support for multiple users with secret-based authentication
- 🌐 Support for whitelisting one or more domains per user
- 🔄 Support for whitelisting a user's dynamic DNS name(s)
- 📚 API is fully documented and testable via embedded swagger endpoint
- 🎨 Embedded Web UI for user challenges
- 🔌 Support for multiple dataprovider backends (you can write your own via an [interface](https://godoc.org/github.com/gbolo/protego/pkg/dataprovider#Provider))
- ⚡ Built with GoFiber v2 for high performance
- 📊 Structured logging with Uber Zap (console/JSON formats)
- ✅ Comprehensive unit tests with 33% coverage
- 🐳 Docker support

## Building & Running
Requirements: `go version 1.13+`

### Using Makefile (Recommended)
```bash
# clone repo
git clone https://github.com/gbolo/protego.git
cd protego

# build from source
make build

# run the server
make run

# run with development mode (live reload assets)
make run-dev

# run tests
make test

# run tests with coverage
make test-coverage

# see all available commands
make help
```

### Manual Build
```bash
# build from source
go build -o bin/protego

# run the Protego server
./bin/protego -config testdata/sampleconfig/protego.yaml

# swagger is available at http://127.0.0.1:8080/swagger
```

## How it Works

![diagram1](https://github.com/gbolo/protego/raw/master/docs/diagrams/protego_authorize_flow.png "Diagram 1")

Let's say you had a a few home services that you would like to share with some people, and you did the right thing by using nginx to reverse proxy these requests already, you would need to do the following:

1. Deploy `protego` and make it accessible to nginx.
2. Modify your nginx server block config(s) to leverage `auth_request` module. For example:
  ```
  location / {
      auth_request /auth;
      ...
  }

  location = /auth {
    internal;
    proxy_pass http://protego.fqdn:8080/api/v1/authorize;
    proxy_pass_request_body off;
    proxy_set_header   Content-Length       "";
    proxy_set_header   Host                 $http_host;
    proxy_set_header   X-Real-IP            $remote_addr;
  }
  ```
3. Use the API to add as many users as you would like.
4. (optional) Expose the Protego challenge web UI for users who do not have a dynamic DNS or would like to access your services from random IPs (like a mobile phone network)
![challenge](https://github.com/gbolo/protego/raw/master/docs/diagrams/screenshot_protego_challenge_ui.png "challenge UI")

## Configuration

Protego uses YAML configuration with environment variable overrides. See `testdata/sampleconfig/protego.yaml` for a complete example.

### Logger Configuration

```yaml
log:
  level: debug              # debug, info, warn, error, fatal
  encoding: console         # console (colored) or json (structured)
  enable_color: true        # Enable ANSI colors
```

Environment variable override:
```bash
export PROTEGO_LOG_LEVEL=info
export PROTEGO_LOG_ENCODING=json
```

### Server Configuration

```yaml
server:
  bind_address: 0.0.0.0
  bind_port: 8080
  access_log: false         # Enable Fiber access logging
  compression: false        # Enable gzip compression
  enable_profiler: false    # Enable /debug/metrics endpoint
```

### Database Configuration

```yaml
db:
  provider: bolt            # bolt or memory
  bolt:
    file: ./data/protego.db
```

##  Example Deployment
**TODO: Coming Soon...**

## Monitoring & Profiling

### Metrics Dashboard

Enable the metrics dashboard via configuration:
```yaml
server:
  enable_profiler: true
```

Then access the metrics UI at: `http://127.0.0.1:8080/debug/metrics`

### Memory and Performance Profiling

```bash
# Enable profiler
export PROTEGO_SERVER_ENABLE_PROFILER=true

# Available endpoints:
# - /debug/metrics - Fiber metrics dashboard
# - /debug/pprof   - Go pprof profiling

# Visual memory stats - https://github.com/dche423/temi
temi -url http://127.0.0.1:8080/debug/vars
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
make test-server
make test-dataprovider
```

See [TESTING.md](TESTING.md) for detailed testing documentation.

## Documentation

- [TESTING.md](TESTING.md) - Testing guide and coverage
- [LOGGER_REFACTORING.md](LOGGER_REFACTORING.md) - Logger configuration and usage
- API Documentation - Available at `/swagger` when server is running
