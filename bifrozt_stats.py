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
__version__ = '0.0.6'


import argparse
import GeoIP
import glob
import operator
import os
import sys
from collections import defaultdict


def parse_args():
    """
    Defines the command line arguments.
    """
    dlog = '/opt/honssh/logs'

    parser = argparse.ArgumentParser('Gather data from HonSSH log files')

    attacker = parser.add_argument_group('- Attacker data')
    attacker.add_argument('-A', dest='access', help='Attackers with a valid login',
                          action='store_true')

    logs = parser.add_argument_group('- Location of log files')
    logs.add_argument('-L', dest='logdir', help='({0})'.format(dlog), default=dlog)

    args = parser.parse_args()

    return args


def find_logs(logpath):
    """
    Searches the logpath and appends all the files that matches to a returned list object
    """
    log_files = []
    lines_log = []

    os.chdir(logpath)
    for logs in glob.glob('honssh.log*'):
        log_files.append(logs)

    if len(log_files) == 0:
        print 'ERROR: No honssh.log files found in "{0}"'.format(logpath)
        sys.exit(1)

    for logs in log_files:
        with open(logs, 'r') as log:
            for line in log.readlines():
                lines_log.append(line)

    return lines_log


def found_login(loglines):
    """
    Parses loglines for entries that shows a valid username/password was found. The date, time, IP
    address, username and password is appended to the output list and returned from the function.
    """
    func_ident = 'found_login'
    output = []

    for line in loglines:
        if 'LOGIN_SUCCESSFUL' in line:
            login = line.split()[4:8]
            date = login[0].split('_')[0]
            time = login[0].split('_')[1]
            out = func_ident, date, time, login[2], login[3], login[1]
            output.append(out)

    return output


def origin_country(item_list):
    """
    Given a list of IP addresses it will find the its country of origin.
    """
    gip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    output = []

    for item in item_list:

        if item[0] == 'found_login':
            geo = gip.country_name_by_addr(item[5])
            out = item[0], item[1], item[2], item[3], item[4], item[5], geo
            output.append(out)

    return output


def show_results(items):
    """
    Sorts the dictionary by value in decending order and prints the result to stdout.
    """
    result = []

    if items[0][0] == 'found_login':
        for it in items:
            login = '{0:<9} {1:<8} {2:<10} {3:<16} {4:<15} {5:>12}'.format(it[1], it[2], it[3],
                                                                           it[4], it[5], it[6])
            result.append(login)

        banner = '{0:<9} {1:<8} {2:<10} {3:<16} {4:<15} {5:>12}'.format('Date', 'Time', 'Username',
                                                                'Password', 'IP address', 'Country')

        print banner
        print '-' * 76
        for data in sorted(result, reverse=True):
            print data


def process_args(args):
    """
    Process the command line arguments.
    """
    if not os.path.isdir(args.logdir):
        print 'ERROR: {0} does not appear to exist!'.format(args.logdir)
        sys.exit(1)

    honssh_logs = find_logs(args.logdir)

    if args.access:
        list_items = found_login(honssh_logs)
        show_items = origin_country(list_items)
        show_results(show_items)


def main():
    """
    Do what Main does best...
    """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
