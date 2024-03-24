echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet

# Outgoing packets
iptables -t mangle -A OUTPUT -m mark --mark 123 -j CONNMARK --save-mark
iptables -t mangle -A OUTPUT -m mark --mark 123 -j MARK --set-mark 0
# Incoming packets
iptables -t mangle -A PREROUTING -m connmark --mark 123 -j CONNMARK --restore-mark

ip rule add fwmark 123 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

env "$@"
