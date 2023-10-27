#!/usr/bin/env scapy

from scapy.all import *

interface = "enp1s0f0"

#create a "spoofed" segment that ALWAYS lands on queue_0 and one that ALWAYS lands on queue_1

# Set the target host IP address
target_ip = "10.100.0.1"
target_port = 8080
target_mac = "a0:36:9f:28:15:34"

# set the source informations -> Queue 1 (IC)
source_ip = "10.100.0.2"
source_port = 53852
source_mac = "a0:36:9f:28:15:7c"

# set the source informations -> Queue 0 (OOC)
source_ip2 = "10.100.0.2"
source_port2 = 54083
source_mac2 = "a0:36:9f:28:15:7c"

# Create the Ethernet header
eth_q0 = Ether(dst=target_mac, src=source_mac)
eth_q1 = Ether(dst=target_mac, src=source_mac2)

# Create the IP header
ip_q0 = IP(dst=target_ip, src=source_ip)
ip_q1 = IP(dst=target_ip, src=source_ip2)

# Create the TCP header
tcp_q0 = TCP(dport=target_port, sport=source_port, flags="S", seq=0, ack=0)
tcp_q1 = TCP(dport=target_port, sport=source_port2, flags="S",seq=0, ack=0)

# Create the packet by combining the headers
packet_q0 = eth_q0/ip_q0/tcp_q0
packet_q1 = eth_q1/ip_q1/tcp_q1

import time
import random

packets_q0_send = 0
packets_q1_send = 0
t_end = time.time() + 5

while time.time() < t_end:
    coin = random.randint(0, 1)
    if coin == 1:
        # Send the packet and receive the response
        sendp(packet_q0, iface=interface)
        packets_q0_send += 1
    else:
        sendp(packet_q1, iface=interface)
        packets_q1_send += 1


print(f"{packets_q0_send} packets have been send for Queue 0!")
print(f"{packets_q1_send} packets have been send for Queue 1!")
print(f"{packets_q0_send + packets_q1_send} in total!")
