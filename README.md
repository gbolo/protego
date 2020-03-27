# Protego

> "You wouldn't believe how many people, even people who work at the Ministry, can't do a decent Shield Charm."
> -- George Weasley regarding the shield charm

Protego is a self-hosted REST API service, intended to be used in conjunction with
nginx's `auth_request` module, with the goal of providing transparent IP based ACLs to your existing HTTP service(s).

## Features
- Support for multiple users
- Support for whitelisting one or more domains per user
- Support for whitelisting a user's dynamic DNS name(s)
- API is fully documented and testable via embedded swagger endpoint
- Embedded Web UI for user challenges
- Support for multiple dataprovider backends (you can write your own via an [interface](https://godoc.org/github.com/gbolo/protego/dataprovider#Provider))

## Building & Running
Requirements: `go version 1.13+`
```
# clone repo and build from source
git clone https://github.com/gbolo/protego.git
cd protego && go build -o bin/protego

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

##  Example Deployment
** TODO: Comming Soon... **

## Profiling
the golang pprof http server can be exposed via configuration flag:
```
export PROTEGO_SERVER_ENABLE_PROFILER=true

* pprof available on endpoint /debug/pprof
* memory stats available on endpoint /debug/vars

# visual memory stats - https://github.com/dche423/temi
temi -url http://127.0.0.1:8080/debug/vars
```
