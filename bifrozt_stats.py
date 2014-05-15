#!/usr/bin/env python

"""
    Copyright (c) 2014, Are Hansen - Honeypot Development.

    All rights reserved.
    Redistribution and use in source and binary forms, with or without modification, are
    permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list
    of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this
    list of conditions and the following disclaimer in the documentation and/or other
    materials provided with the distribution.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
    SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
    STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
    THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__author__ = 'Are Hansen'
__date__ = '2014, May 15'
__version__ = '0.0.2'


import argparse
import GeoIP
import glob
import os
import re
import sys


def parse_args():
    """Defines the command line arguments. """
    parser = argparse.ArgumentParser('Gather data from HonSSH log files.')

    logs = parser.add_argument_group('- Log files')
    logs.add_argument('-L', dest='logdir', help='Logs directory (default: /opt/honssh/logs)',
                      default='/opt/honssh/logs')

    args = parser.parse_args()

    return args


def find_logs(logpath):
    """Searches the logpath and appends all the files that matches to a returned list object."""
    log_files = []
    os.chdir(logpath)
    for logs in glob.glob('honssh.log*'):
        log_files.append(logs)

    return log_files


def found_login(loglist):
    """Parses each item in the loglist for entries that shows a valid usr/passwd was found."""
    lines_log = []
    output = []

    for logs in loglist:
        with open(logs, 'r') as log:
            for line in log.readlines():
                lines_log.append(line)

    for line in lines_log:
        if 'LOGIN_SUCCESSFUL' in line:
            login_ok = line.split()
            output.append('{0} {1}'.format(login_ok[4], login_ok[5]))

    return sorted(output, reverse=True)


def geoip_output(attack_data):
    """Runs the attacker's IP against the GeoIP database and outputs the results to stdout."""
    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    h1 = '+---------+--------+----------------+---------------+'
    h2 = '|  Date   |  Time  |   IP address   |   Country     |'

    print('{0}\n{1}\n{0}'.format(h1, h2))
    for data in attack_data:
        data = data.split()
        time = data[0].replace('_', '   ')
        ipad = data[1]
        geo = gi.country_name_by_addr(data[1])
        print(' {0}   {1}   \t{2}'.format(time, ipad, geo))


def process_args(args):
    """Process the command line arguments. """
    logdir = args.logdir

    if not os.path.isdir(logdir):
        print('ERROR: {0} does not appear to exist!'.format(logdir))
        sys.exit(1)

    honssh_logs = find_logs(logdir)
    got_access = found_login(honssh_logs)
    geoip_output(got_access)


def main():
    """Do what Main does best... """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
