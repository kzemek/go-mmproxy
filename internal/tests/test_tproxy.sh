#!/usr/bin/env bash
set -euo pipefail

# Integration test: TPROXY scenario inside a container, connect from host to container IP.

IMAGE_NAME="go-mmproxy-tproxy-test"
CONTAINER_NAME="go-mmproxy-tproxy-test"
PORT_START=10000
PORT_END=10004

cleanup() {
  set +e
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/5] Building test image..."
docker build -t "$IMAGE_NAME" -f internal/tests/tproxy/Dockerfile .

echo "[2/5] Starting container..."
docker run -d --name "$CONTAINER_NAME" \
  --privileged \
  "$IMAGE_NAME" >/dev/null

echo "[3/5] Discovering container IP..."
CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")
if [[ -z "$CONTAINER_IP" ]]; then
  echo "Failed to determine container IP" >&2
  exit 1
fi

echo "[4/5] Waiting for container to be ready..."
ping -c 1 -w 5 "$CONTAINER_IP" >/dev/null

echo "[5/5] Verifying connectivity across TPROXY-redirected ports [$PORT_START-$PORT_END]..."
for PORT in $(seq "$PORT_START" "$PORT_END"); do
  MSG="PING-$PORT"
  HDR=$'PROXY TCP4 127.0.0.1 127.0.0.1 12345 25578\r\n'
  PAYLOAD="$HDR$MSG\r\n"
  if ! RESPONSE=$(printf "%s" "$PAYLOAD" | timeout 3s nc -w 2 "$CONTAINER_IP" "$PORT" || true); then
    echo "Port $PORT: failed to connect" >&2
    exit 1
  fi
  if [[ "$RESPONSE" != *"$MSG"* ]]; then
    echo "Port $PORT: unexpected response: '$RESPONSE'" >&2
    exit 1
  fi
  echo "Port $PORT OK"
done

echo "SUCCESS"
