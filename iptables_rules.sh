# SYN Packet DEST NAT
iptables -t mangle -I POSTROUTING -p tcp --dport 8000 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-num 0 --queue-bypass
#iptables -A PREROUTING -t nat -p tcp --dport 8000 -j DNAT --to-destination 10.10.70.136:8000
#iptables -t nat -A POSTROUTING -j MASQUERADE

#iptables -t mangle -I PREROUTING -p tcp --sport 8000 --tcp-flags SYN,RST,ACK,FIN SYN,ACK -j NFQUEUE --queue-num 0 --queue-bypass # Get SYNACK handshake packet
#iptables -t mangle -A FORWARD -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j MARK --set-mark 145

#iptables -t mangle -I FORWARD -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j LOG --log-prefix "SYN_PACKET_DETECTED: FORWARD" --log-level 4

#iptables -t mangle -I POSTROUTING -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j LOG --log-prefix "SYN_PACKET_DETECTED: POSTROUTING" --log-level 4



