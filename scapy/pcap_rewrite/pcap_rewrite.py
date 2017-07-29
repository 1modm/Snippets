#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__ = """

Author: https://twitter.com/1_mod_m/

Project site: https://github.com/1modm/Snippets

Copyright (c) 2017, MM
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of copyright holders nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

import os
import sys
import logging
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from datetime import datetime, date
from thirdparty.color.termcolor import colored


#------------------------------------------------------------------------------
# Command line parser using argparse
#------------------------------------------------------------------------------

def cmdline_parser():
    parser = argparse.ArgumentParser(conflict_handler='resolve', add_help=True,
             description='Tool to replace SRC and DST IPs and data in a pcap \nExample: python rewrite.py test.pcap 1.1.1.1 2.2.2.2 blackhat TEST -ms 1f:ff:ff:ff:ff:ff -md 2f:ff:ff:ff:ff:ff', version='0.1',
             usage="python %(prog)s <PCAP> <SRC> <DST> <Data to be replaced> <New Data> [-ms <New MAC SRC> -md <New MAC SRC> -s <Original SRC IP to replace> -d <Original DST IP to replace> -a]")

    # Mandatory
    parser.add_argument('pcap', type=str, help='PCAP')
    parser.add_argument('src', type=str, help='SRC')
    parser.add_argument('dst', type=str, help='DST')
    parser.add_argument('data_orig', type=str, help='Data to replace')
    parser.add_argument('new_data', type=str, help='New data')

    # Optional
    parser.add_argument('-s', action='store', default='', dest='orig_src', help='Original SRC IP to replace')
    parser.add_argument('-d', action='store', default='', dest='orig_dst', help='Original DST IP to replace')
    parser.add_argument('-ms', action='store', default='', dest='mac_src', help='New MAC SRC')
    parser.add_argument('-md', action='store', default='', dest='mac_dst', help='New MAC DST')
    parser.add_argument('-a', action='store_true', default='', dest='all', help='Change all IPs')

    return parser


#------------------------------------------------------------------------------
# Start of program
#------------------------------------------------------------------------------

def main():

    # Get the command line parser.
    parser = cmdline_parser()

    # Show help if no args
    if len(sys.argv) < 6:
       parser.print_help()
       sys.exit(1)

    # Get results line parser.
    results = parser.parse_args()

    source_ip = results.src # New SRC IP
    destination_ip = results.dst # New DST IP
    data = results.data_orig # Data to be replaced
    new_data = results.new_data # New Data
    src_mac = results.mac_src # New MAC SRC
    dst_mac = results.mac_dst # New MAC DST

    datenow = datetime.now()
    datesec = datenow.strftime('%Y-%m-%d_%H_%M_%S')

    print(os.linesep + (colored('[+] Reading pcap: ' + results.pcap, 'green')))
    pcap_loaded=rdpcap(results.pcap)

    if (results.orig_src and results.orig_dst):
        sip = results.orig_src
        dip = results.orig_dst
    else:
        # Find the first TCP packet to use as reference for SRC and DST
        for p in pcap_loaded:
            if p.haslayer(IP):
                if p.haslayer(TCP):
                    sip = p[IP].src
                    dip = p[IP].dst

   
    if results.all:
        print((colored('[+] Rewriting original SRC and DST (also MACs and Data if provided) for ALL packets: ' + source_ip + ' and ' + destination_ip, 'yellow')))
    else:
        print((colored('[+] Original IPs to be replaced: ' + sip + ' and ' + dip, 'yellow')))
        print((colored('[+] Rewriting original SRC and DST (also MACs and Data if provided): ' + sip + ' --> ' + source_ip + ' and ' + dip + ' --> ' + destination_ip + ' only', 'yellow')))

    for p in pcap_loaded:
            if p.haslayer(IP):

                # Remove UDP checksum
                if p.haslayer(UDP):
                    del p[UDP].chksum
                    payload_orig = len(p[UDP].payload)

                # Remove TCP checksum
                elif p.haslayer(TCP):
                    del p[IP].chksum
                    del p[TCP].chksum
                    payload_orig = len(p[TCP].payload)

                # Replace SRC and DST IPs for all packets
                if results.all:
                        p[IP].src = source_ip
                        p[IP].dst = destination_ip
                # Replace SRC and DST IPs for packets with the IPs given only
                else:
                    if p[IP].src == sip:
                        # Replace IPs
                        p[IP].src = source_ip
                        p[IP].dst = destination_ip

                        # Replace MAC addresses
                        if (results.mac_src and results.mac_dst):
                            p[Ether].src= src_mac
                            p[Ether].dst= dst_mac


                    if p[IP].dst == sip:
                        # Replace IPs
                        p[IP].src = destination_ip
                        p[IP].dst = source_ip

                        # Replace MAC addresses
                        if (results.mac_src and results.mac_dst):
                            p[Ether].src= dst_mac
                            p[Ether].dst= src_mac

                # Replace data in payload
                if (data and new_data):
                    if p.haslayer(UDP):
                        p[UDP].payload = str(p[UDP].payload).replace(data, new_data)
                    elif p.haslayer(TCP):
                        p[TCP].payload = str(p[TCP].payload).replace(data, new_data)

                # Fix payload len
                if p.haslayer(UDP):
                    payload_modif = len(p[UDP].payload)
                    payload = payload_modif - payload_orig
                    p[IP].len = p[IP].len + payload
                elif p.haslayer(TCP):
                    payload_modif = len(p[TCP].payload)
                    payload = payload_modif - payload_orig
                    p[IP].len = p[IP].len + payload

    wrpcap("output_rewrite" + datesec + ".pcap", pcap_loaded)
    print((colored('[+] Output written to: output_rewrite' + datesec + '.pcap', 'green')) + os.linesep)

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    main()