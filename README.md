### Steps to Run
1) Type the following terminal command: 
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
2) Fill out the rules in the JSON file as follows:
3) Execute fw.py using python3

### Requirements
1) netfilterqueue
2) scapy
