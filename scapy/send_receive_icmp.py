#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from scapy.all import *

print os.linesep + '--------- ICMP ---------'
output=sr(IP(dst='cisco.com')/ICMP())
print 'Output --> ' + str(output)
result, unanswered=output
print 'Result --> ' + str(result)

print os.linesep * 2 + '--------- ICMP Packet List ---------'
pkg_list=[IP(dst="cisco.com")/ICMP() for x in range(5)]
output=sr(pkg_list)
print 'Output --> ' + str(output)
result, unanswered=output
print 'Result --> ' + str(result)
