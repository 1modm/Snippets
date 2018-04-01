#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__ = """

Author: https://twitter.com/1_mod_m/

Project site: https://github.com/1modm/Snippets

Copyright (c) 2018, MM
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

# Easy with tshark :)
# tshark -nr <PCAP-FILE> -T fields -e ip.src -e ip.dst -E separator=, > ouput.csv

import os
import sys
import json
import logging
import argparse
import pygeoip # pip install pygeoip
from scapy.all import *
from termcolor import colored # pip install termcolor
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#------------------------------------------------------------------------------
# Command line parser using argparse
#------------------------------------------------------------------------------

def cmdline_parser():
    parser = argparse.ArgumentParser(conflict_handler='resolve', add_help=True,
             description='Tool to get SRC and DST IPs from a pcap \nExample: python list-IPs.py test.pcap', version='0.1',
             usage="python %(prog)s <PCAP>")

    # Mandatory
    parser.add_argument('pcap', type=str, help='PCAP')

    return parser


#------------------------------------------------------------------------------
# Start of program
#------------------------------------------------------------------------------

def main():

	# Get the command line parser.
	parser = cmdline_parser()

	# Show help if no args
	if len(sys.argv) < 2:
	   parser.print_help()
	   sys.exit(1)

	# Get results line parser.
	results = parser.parse_args()

	print(os.linesep + (colored('[+] Reading pcap: ' + results.pcap, 'green')))
	pcap_loaded=rdpcap(results.pcap)

	Source_IPs = []
	Destination_IPs = []
	GeoIPs = []

	gi = pygeoip.GeoIP('GeoLiteCity.dat') # Downloaded from https://dev.maxmind.com/geoip/legacy/geolite/

	for pkt in pcap_loaded:
		if IP in pkt:
			ip_src=pkt[IP].src
			ip_dst=pkt[IP].dst

			Source_IPs.append(ip_src)
			Destination_IPs.append(ip_dst)

	print(os.linesep + (colored('[+] Source IPs:', 'green')))
	SIP = ",".join(str(i) for i in Source_IPs)
	print(os.linesep + (colored(str(SIP), 'white')))

	print(os.linesep + (colored('[+] Destination IPs:', 'green')))
	DIP = ",".join(str(d) for d in Destination_IPs)
	print(os.linesep + (colored(str(DIP), 'white')))
	
	print(os.linesep + (colored('[+] Country detected in Source IPs:', 'yellow')))
	for i in Source_IPs:
		rec_src = gi.record_by_addr(i)
		if str(rec_src) != "None":
			print((colored('IP: ' + i + ' ' + str(rec_src['country_code']) + ': '+ str(rec_src['country_name']), 'white')))

	print(os.linesep + (colored('[+] Country detected in Destination IPs:', 'yellow')))
	for d in Destination_IPs:
		rec_dst = gi.record_by_addr(d)
		if str(rec_dst) != "None":
			print((colored('IP: ' + d + ' ' + str(rec_dst['country_code']) + ': '+ str(rec_dst['country_name']), 'white')))
	

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    main()







