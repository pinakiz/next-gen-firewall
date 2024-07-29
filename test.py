from scapy.all import *
from scapy.layers.inet import IP

# Send an ICMP ping packet to the target host
response = sr1(IP(dst="192.168.1.1")/ICMP())

# Print the response
print(response)
