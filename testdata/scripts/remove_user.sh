
BASE_URL="${OVERRIDE_URL:-http://127.0.0.1:8081}" # admin listener
URL="${BASE_URL}/api/v1/user"

# using httpie
http --print=Hhb DELETE "${URL}/5e8848" ADMIN-SECRET:supersecret
