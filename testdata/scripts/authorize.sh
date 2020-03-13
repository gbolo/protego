
URL="http://127.0.0.1:8080/api/v1/authorize"

# using httpie
http --print=Hhb GET ${URL} X-Real-IP:1.1.1.1 Host:git.fqdn
