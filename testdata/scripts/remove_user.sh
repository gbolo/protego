
URL="http://127.0.0.1:8080/api/v1/user"

# using httpie
http --print=Hhb DELETE "${URL}/5e8848" ADMIN-SECRET:supersecret
