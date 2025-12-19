
BASE_URL="${OVERRIDE_URL:-http://127.0.0.1:8080}"
URL="${BASE_URL}/api/v1/challenge"

# using httpie
for i in $(seq 1 20); do
    http --print=Hhb POST ${URL} X-Real-IP:1.1.1.${i} User-Secret:password${i}
    # sleep 1
done
