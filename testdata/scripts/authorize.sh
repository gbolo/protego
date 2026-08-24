
BASE_URL="${OVERRIDE_URL:-http://127.0.0.1:8081}" # admin listener
URL="${BASE_URL}/api/v1/authorize"

# using httpie
for i in $(seq 1 20); do
    http --print=Hhb GET ${URL} X-Real-IP:1.1.1.${i} Host:git.fqdn
    # sleep 1
done