#!/bin/sh
set -eu

TURN_SECRET="${UCR_DEV_TURN_SECRET:-0123456789abcdef0123456789abcdef}"
TURN_REALM="${UCR_DEV_TURN_REALM:-ucr-dev.local}"
RUNTIME_LOG=/run/ucr/ucr-dev.log

mkdir -p /run/ucr

PIDS=""
cleanup() {
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup INT TERM EXIT

/usr/local/bin/ucr dev --bind 127.0.0.1:50051 >"$RUNTIME_LOG" 2>&1 &
UCR_PID=$!
PIDS="$PIDS $UCR_PID"

ready=0
attempt=0
while [ "$attempt" -lt 200 ]; do
  if grep -q '^UCR_DEV_READY ' "$RUNTIME_LOG" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$UCR_PID" 2>/dev/null; then
    cat "$RUNTIME_LOG" >&2 || true
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.05
done
if [ "$ready" -ne 1 ]; then
  cat "$RUNTIME_LOG" >&2 || true
  echo "ucr dev did not become ready" >&2
  exit 1
fi

cat "$RUNTIME_LOG"

socat TCP-LISTEN:150051,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:50051 &
PIDS="$PIDS $!"

python3 -m http.server 8080 --bind 0.0.0.0 --directory /opt/ucr/browser &
PIDS="$PIDS $!"

python3 /opt/ucr/dev/webhook_receiver.py --bind 0.0.0.0 --port 8090 &
PIDS="$PIDS $!"

UCR_DEV_TURN_SECRET="$TURN_SECRET" turnserver -n   --no-cli   --fingerprint   --use-auth-secret   --static-auth-secret="$TURN_SECRET"   --realm="$TURN_REALM"   --listening-ip=0.0.0.0   --relay-ip=0.0.0.0   --external-ip=127.0.0.1   --listening-port=3478   --min-port=49160   --max-port=49170   --no-tls   --no-dtls   --pidfile=/run/ucr/coturn.pid   --log-file=stdout &
PIDS="$PIDS $!"

echo "UCR_DEV_BROWSER=http://127.0.0.1:8080/"
echo "UCR_DEV_GRPC=http://127.0.0.1:50051"
echo "UCR_DEV_WEBHOOK_RECEIVER=http://127.0.0.1:8090/"
echo "UCR_DEV_TURN_URL=turn:127.0.0.1:3478?transport=udp"
UCR_DEV_TURN_SECRET="$TURN_SECRET" python3 /opt/ucr/dev/turn_credentials.py --session ucr-dev

while :; do
  for pid in $PIDS; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "local dev component exited unexpectedly: pid=$pid" >&2
      exit 1
    fi
  done
  sleep 1
done
