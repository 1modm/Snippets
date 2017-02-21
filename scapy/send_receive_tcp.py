#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from scapy.all import *

# OS will send a RST packet automatically in response to the SYN+ACK received.
# The issue can be resolved by adding an iptables rules to suppress the outgoing RST
iptables_add = os.system("iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP")


print os.linesep * 2 + '--------- Sending a TCP packet to Port 80 to www.cisco.com ---------'
packet=Ether()/IP(dst="www.cisco.com")/TCP(dport=80)/"GET / HTTP/1.1" 
output=sendp(Ether()/IP(dst="www.cisco.com")/TCP(dport=80, flags="S"), verbose=0)


print os.linesep * 2 + '--------- A TCP Three-way Handshake (SYN, SYN-ACK, ACK) ---------'
print "[*] ACK with GET request"
# Create SYN packet
SYN = IP(dst='192.168.9.1') / TCP(dport=80, flags='S')
SYNACK = sr1(SYN)
# Create ACK with GET request
GET = 'GET / HTTP/1.0\n\n'
ACK = IP(dst='192.168.9.1') / TCP(dport=80, sport=SYNACK[TCP].dport, seq=SYNACK[TCP].ack, ack=SYNACK[TCP].seq + 1, flags='A') / GET

# SEND ACK-GET request
print 'Sending ACK-GET packet'
reply,error = sr(ACK, multi=1, timeout=2)

print 'Reply from server:'
print reply.show()
print 'Output --> ' + str(reply)


print os.linesep * 2 + '--------- A custom TCP Three-way Handshake (SYN, SYN-ACK, ACK) ---------'
#A TCP Three-way Handshake
ip = IP(src='192.168.9.12', dst='192.168.9.1')
SYN = TCP(sport=1024, dport=5000, flags='S', seq=12345)
packet = ip/SYN
SYNACK = sr1(packet)
ack = SYNACK.seq + 1
ACK = TCP(sport=1024, dport=5000, flags='A', seq=12346, ack=ack)
send(ip/ACK)
PUSH = TCP(sport=1024, dport=5000, flags='', seq=12346, ack=ack)
data = "HELLO!"
output,error =sr(ip/PUSH/data)
print output.show()
print 'Output --> ' + str(output)

# Remove iptables rule
iptables_remove = os.system("iptables -D OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP")
