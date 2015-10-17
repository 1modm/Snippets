#!/usr/bin/env python
# -*- coding: utf-8 -*-

#------------------------------------------------------------------------------
# Modules
#------------------------------------------------------------------------------
import os
import commands
import platform
import sys
import socket
import struct
import fcntl
import re
from thirdparty.color.termcolor import colored
from platform import system
from netifaces import interfaces, ifaddresses, AF_INET
from fabric.api import settings
from fabric.operations import run, put

#------------------------------------------------------------------------------
# From bits/ioctls.h
SIOCGIFHWADDR  = 0x8927          # Get hardware address
SIOCGIFADDR    = 0x8915          # get PA address
SIOCGIFNETMASK = 0x891b          # get network PA mask
SIOCGIFNAME    = 0x8910          # get iface name
SIOCSIFLINK    = 0x8911          # set iface channel
SIOCGIFCONF    = 0x8912          # get iface list
SIOCGIFFLAGS   = 0x8913          # get flags
SIOCSIFFLAGS   = 0x8914          # set flags
SIOCGIFINDEX   = 0x8933          # name -> if_index mapping
SIOCGIFCOUNT   = 0x8938          # get number of devices
SIOCGSTAMP     = 0x8906          # get packet timestamp (as a timeval)
#------------------------------------------------------------------------------
CHECKRESULTOK = 'OK'
CHECKRESULTWARNING = 'WARNING'
CHECKRESULTCRITICAL = 'CRITICAL'
CHECKRESULTERROR = 'ERROR'
#------------------------------------------------------------------------------


def get_ip_address(ifname):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        #ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",iff))
        ifreq = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', ifname[:15]))
    except IOError: # interface is present in routing tables but does not have any assigned IP
        ifaddr="0.0.0.0"
    else:
        addrfamily = struct.unpack("h",ifreq[16:18])[0]
        if addrfamily == socket.AF_INET:
            ifaddr = socket.inet_ntoa(fcntl.ioctl(s.fileno(),SIOCGIFADDR, struct.pack('256s', ifname[:15]))[20:24])
        else:
            warning("Interface %s: unkown address family (%i)"%(ifname, addrfamily))
            #continue
    return ifaddr

def ip4_addresses():
      ip_list = []
      for interface in interfaces():
        addr = get_ip_address(interface)
        if addr is not None:
                ip_list.append(addr)
      return ip_list


#------------------------------------------------------------------------------
def execute_cmd(cmd, host, user_fabric, passwd_fabric, port_fabric):

    if host == 'localhost':
       print "%s local IP" % host
       __cmd_local__ = True
    elif host not in ip4_addresses():
       __cmd_local__ = False
    else:
       __cmd_local__ = True

    __output_cmd__ = cmd
    __command_check__ = CHECKRESULTERROR


    if __cmd_local__ == False:
        with settings(host_string=host,user=user_fabric, password=passwd_fabric, port=port_fabric):
            try:
                __output_cmd__ = run(cmd,shell=True,warn_only=True, quiet=True)
                if __output_cmd__.failed:
                    __command_check__ = CHECKRESULTERROR
                else:
                    __command_check__ = CHECKRESULTOK
            except:
                print((colored('*** Warning *** Host {host} on port {port} is down.', 'red')).format(host=host, port=port_fabric) + os.linesep*2)
                sys.exit(0)
    return (__output_cmd__, __command_check__)

#------------------------------------------------------------------------------
def putfile(filehost, remote, host, user_fabric, passwd_fabric, port_fabric):

    if host == 'localhost':
       print "%s local IP" % host
       __cmd_local__ = True
    elif host not in ip4_addresses():
       __cmd_local__ = False
    else:
       __cmd_local__ = True

    __command_check__ = CHECKRESULTERROR


    if __cmd_local__ == False:
        with settings(host_string=host,user=user_fabric, password=passwd_fabric, port=port_fabric):
            try:
                #__output_cmd__ = run(filehost,shell=True,warn_only=True, quiet=True)
		__output_cmd__ = put(filehost, remote)
                if __output_cmd__.failed:
                    __command_check__ = CHECKRESULTERROR
                else:
                    __command_check__ = CHECKRESULTOK
            except:
                print((colored('*** Warning *** Host {host} on port {port} is down.', 'red')).format(host=host, port=port_fabric) + os.linesep*2)
                sys.exit(0)
    return (__output_cmd__, __command_check__)


#------------------------------------------------------------------------------

def execution(__host__, __user__, __passwd__, __port__, __command__):
    """
    :returns: execute command.
    :param host: Target, cmd and fabric params.
    """
    __cmd__= __command__
    __output__, __command_check__ = execute_cmd(__cmd__, __host__, __user__, __passwd__, __port__)

    return (__output__, __command_check__, __cmd__)

#------------------------------------------------------------------------------


def copy(__filehost__, __remote__, __host__, __user__, __passwd__, __port__):
    """
    :returns: copy file.
    :param host: Target, cmd and fabric params.
    """
    __output__, __command_check__ = putfile(__filehost__, __remote__, __host__, __user__, __passwd__, __port__)

    return (__output__, __command_check__)

