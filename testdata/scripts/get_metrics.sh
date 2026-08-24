
BASE_URL="${OVERRIDE_URL:-http://127.0.0.1:8081}" # admin listener
URL="${BASE_URL}/api/v1/metrics"

http --print=HhBb GET ${URL} ADMIN-SECRET:supersecret
