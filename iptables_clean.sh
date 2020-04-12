iptables -t mangle -F PREROUTING
iptables -t mangle -F POSTROUTING
iptables -t nat -F PREROUTING
iptables -t nat -F INPUT
iptables -t nat -F POSTROUTING
