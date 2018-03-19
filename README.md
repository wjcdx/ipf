# ipf
forward IP packets in application layer.

Designed based on iptables/netfilter:
Usage: ./ipf -d 192.168.1.9 -p tcp --dport 80 -j DNAT --to-destination 192.168.6.64

Notes:
1. The host running task ipf should has two network interfaces, 192.168.1.9 and 192.168.6.1.
2. NATed destination 192.168.6.64 should be a neighbor, whose mac address locates in ARP table.
3. TCP packets should be blocked to local TCP/IP stack, in case normal forwarding stream is
   interrupted by TCP RST sent by local host for unexpected TCP requests.
