
URL="http://127.0.0.1:8080/api/v1/challenge"

# using httpie
http --print=Hhb POST ${URL} X-Real-IP:1.1.1.1 User-Secret:password
