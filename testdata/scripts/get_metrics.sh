
BASE_URL="${OVERRIDE_URL:-http://127.0.0.1:8080}"
URL="${BASE_URL}/api/v1/metrics"

http --print=HhBb GET ${URL} ADMIN-SECRET:supersecret
