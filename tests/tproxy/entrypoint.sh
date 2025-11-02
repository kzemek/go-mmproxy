#!/usr/bin/env bash
set -euo pipefail

# Ports to TPROXY and forward to go-mmproxy
PORT_START=${PORT_START:-10000}
PORT_END=${PORT_END:-10004}
LISTEN_PORT=${LISTEN_PORT:-25577}
TARGET_PORT=${TARGET_PORT:-25578}
TPROXY_MARK=${TPROXY_MARK:-1}

echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet

# Minimal routing so reply packets from loopback stay on loopback
ip rule add from 127.0.0.1/8 iif lo table 123 || true
ip route add local 0.0.0.0/0 dev lo table 123 || true

# Mark-based routing for TPROXY flows
ip rule add fwmark ${TPROXY_MARK} lookup 123 || true

# Flush potentially conflicting rules (idempotent best-effort)
iptables -t mangle -F || true

# Redirect any new packets coming in on ports range to go-mmproxy's listen port and mark
iptables -t mangle -A PREROUTING -p tcp --dport ${PORT_START}:${PORT_END} -j TPROXY \
  --tproxy-mark ${TPROXY_MARK}/${TPROXY_MARK} --on-port ${LISTEN_PORT} --on-ip 127.0.0.1

# Start a simple echo server on target port bound to loopback
nohup ncat -kvnl -e /bin/cat 127.0.0.1 ${TARGET_PORT} >/var/log/echo.out 2>&1 &

exec /usr/local/bin/go-mmproxy \
  -l 0.0.0.0:${LISTEN_PORT} \
  -4 127.0.0.1:${TARGET_PORT} \
  -6 [::1]:${TARGET_PORT} \
  -listen-transparent \
  -p tcp -v 2
