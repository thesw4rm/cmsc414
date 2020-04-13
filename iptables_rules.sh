# SYN Packet DEST NAT
iptables -t mangle -I PREROUTING -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 0 --queue-bypass


iptables -t mangle -I POSTROUTING -p tcp --sport 8000 --tcp-flags SYN,RST,ACK,FIN SYN,ACK -j NFQUEUE --queue-num 0 --queue-bypass # Get SYNACK handshake packet


iptables -t mangle -I PREROUTING -p tcp --dport 3306 --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 0 --queue-bypass


iptables -t mangle -I POSTROUTING -p tcp --sport 3306 --tcp-flags SYN,RST,ACK,FIN SYN,ACK -j NFQUEUE --queue-num 0 --queue-bypass # Get SYNACK handshake packet


iptables -t mangle -I PREROUTING -p tcp --dport 21 --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 0 --queue-bypass


iptables -t mangle -I POSTROUTING -p tcp --sport 21 --tcp-flags SYN,RST,ACK,FIN SYN,ACK -j NFQUEUE --queue-num 0 --queue-bypass # Get SYNACK handshake packet

#iptables -t mangle -A FORWARD -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j MARK --set-mark 145

#iptables -t mangle -I FORWARD -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j LOG --log-prefix "SYN_PACKET_DETECTED: FORWARD" --log-level 4

#iptables -t mangle -I POSTROUTING -p tcp --dport 8000 --tcp-flags SYN,RST,ACK,FIN SYN -j LOG --log-prefix "SYN_PACKET_DETECTED: POSTROUTING" --log-level 4



