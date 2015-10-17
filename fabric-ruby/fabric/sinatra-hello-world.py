#!/usr/bin/env python
# -*- coding: utf-8 -*-

#------------------------------------------------------------------------------
# Modules
#------------------------------------------------------------------------------

import os
import sys
import argparse
from tabulate import tabulate  # pip install tabulate
from datetime import datetime
from thirdparty.color.termcolor import colored


#------------------------------------------------------------------------------
# Python version check.
#------------------------------------------------------------------------------

if __name__ == "__main__":
    if sys.version_info < (2, 7) or sys.version_info >= (3, 0):
        show_banner()
        print ("[!] You must use Python version 2.7 or above")
        sys.exit(1)


#------------------------------------------------------------------------------
# Plugins
#------------------------------------------------------------------------------

import include.fabricpython as remote

#------------------------------------------------------------------------------
# Command line parser using argparse
#------------------------------------------------------------------------------

def cmdline_parser():
    parser = argparse.ArgumentParser(conflict_handler='resolve', add_help=True,
        description='Example: python %(prog)s -u root -p password -P 1299 puppetclient',
        version='MMI 1.0', usage="python %(prog)s [OPTIONS] HOST")

    # Mandatory
    parser.add_argument('target', action="store")

    # Optional
    parser.add_argument('-u', action='store',
        dest='user',
        help='Remote user')

    parser.add_argument('-p', action='store',
        dest='passwd',
        help='Remote user password')

    parser.add_argument('-P', action='store',
        dest='port',
        help='Remote port')

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

    #---------------------------------------------------------------------------

    # Get results line parser.
    results = parser.parse_args()

    #---------------------------------------------------------------------------

    # Fabric default
    if results.port:
        fabric_port = results.port
    else: fabric_port = '22'

    if results.user:
        fabric_user = results.user
    else: fabric_user = 'root'

    if results.passwd:
        fabric_passwd = results.passwd
    else: fabric_passwd = None


    # rubygems
    command = "apt-get --yes --force-yes install rubygems build-essential"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))



    # gem env
    command = "gem env"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))



    # gem install bundler
    command = "gem install bundler"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))



    # gem install rails
    command = "gem install rails"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # apt-get install apache2 apache2-mpm-prefork apache2-prefork-dev
    command = "apt-get --yes --force-yes install apache2 apache2-mpm-prefork apache2-prefork-dev"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # apt-get install libcurl4-gnutls-dev
    command = "apt-get --yes --force-yes install libcurl4-gnutls-dev"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # libapache2-mod-passenger
    command = "apt-get --yes --force-yes install libapache2-mod-passenger"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # gem install sinatra
    command = "gem install sinatra"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # gem install passenger
    command = "gem install passenger"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # apache
    command = "service apache2 restart"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    # conf
    command_output, command_check = remote.copy('helloworld/apache2/files/sites-enabled/sinatra.conf', '/etc/apache2/sites-enabled', results.target, fabric_user, fabric_passwd, fabric_port)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - sites-enabled/sinatra.conf ', 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - sites-enabled/sinatra.conf ', 'yellow')))

    # ruby
    command_output, command_check = remote.copy('helloworld/ruby/files/simple-sinatra-app-master', '/var/www/', results.target, fabric_user, fabric_passwd, fabric_port)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - simple-sinatra-app-master', 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - simple-sinatra-app-master', 'yellow')))

    # apache
    command = "service apache2 restart"
    command_output, command_check, cmd = remote.execution(results.target, fabric_user, fabric_passwd, fabric_port, command)
    if (command_check == 'OK'):
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'green')))
    else:
    	print((colored(' - Execution: ' + command_check+' - CMD: ' + cmd, 'yellow')))


    print os.linesep
    #---------------------------------------------------------------------------

    #---------------------------------------------------------------------------
    # The End
    #---------------------------------------------------------------------------

    sys.exit(0)


#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

if __name__ == '__main__':
    main()
