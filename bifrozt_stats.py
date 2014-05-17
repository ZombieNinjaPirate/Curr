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
__version__ = '0.0.4'


import argparse
import GeoIP
import glob
import operator
import os
import sys
from collections import defaultdict


def parse_args():
    """Defines the command line arguments. """
    dlog = '/opt/honssh/logs'

    parser = argparse.ArgumentParser('Gather data from HonSSH log files')

    attacker = parser.add_argument_group('- Attacker data')
    attacker.add_argument('-A', dest='access', help='Attackers with a valid login',
                          action='store_true')
    attacker.add_argument('-S', dest='source', help='Connection pr. IP address',
                          action='store_true')
    attacker.add_argument('-O', dest='origin', help='Connection pr. country',
                          action='store_true')

    auth = parser.add_argument_group('- Authentication data')
    auth.add_argument('-P', dest='passwd', help='Frequent passwords',
                      action='store_true')
    auth.add_argument('-U', dest='usrnam', help='Frequent usernames',
                      action='store_true')
    auth.add_argument('-C', dest='combos', help='Frequent combinations',
                      action='store_true')

    logs = parser.add_argument_group('- Location of log files')
    logs.add_argument('-L', dest='logdir', help='({0})'.format(dlog), default=dlog)

    args = parser.parse_args()

    return args


def find_logs(logpath):
    """Searches the logpath and appends all the files that matches to a returned list
    object."""
    log_files = []
    lines_log = []

    os.chdir(logpath)
    for logs in glob.glob('honssh.log*'):
        log_files.append(logs)

    if len(log_files) == 0:
        print('ERROR: No honssh.log files found in "{0}"'.format(logpath))
        sys.exit(1)

    for logs in log_files:
        with open(logs, 'r') as log:
            for line in log.readlines():
                lines_log.append(line)

    return lines_log


def found_login(loglines):
    """Parses each item in the loglines for entries that shows a valid usr/passwd was
    found. Then runs the attacker's IP address against the GeoIP database and outputs
    the results with date, time, IP and origin country to stdout."""
    #
    #   DEV NOTES:
    #   - show what username/password was used
    #
    hd0 = ".----------.--------.----------------.-------------."
    hd1 = '|   Date   :  Time  :   IP address   :   Country   |'
    hd2 = "'----------'--------'----------------'-------------'"
    #
    #   DEV NOTES:
    #   - geoiplookup should be move to a separate function
    #
    gip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    output = []

    for line in loglines:
        if 'LOGIN_SUCCESSFUL' in line:
            login_ok = line.split()
            output.append('{0} {1}'.format(login_ok[4], login_ok[5]))

    print('{0}\n{1}\n{2}'.format(hd0, hd1, hd2))

    for data in sorted(output, reverse=True):
        data = data.split()
        time = data[0].replace('_', '   ')
        ipad = data[1]
        geo = gip.country_name_by_addr(data[1])
        print('  {0}   {1}  \t{2}'.format(time, ipad, geo))


def source_ip(loglines):
    """Parses all the loglines to find entries indocating a new connection has been made.
    From the matching entries in loglines it will extract the IP address and append it
    to the output list and return it once all loglines has been checked. """
    output = []

    for line in loglines:
        if 'CONNECTION_MADE' in line:
            new_conn = line.split()[5]
            output.append(new_conn)

    return output


def origin_country(item_list):
    """Given a list of IP addresses it will find the its country of origin. """
    gip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    output = []

    for item in item_list:
        geo = gip.country_name_by_addr(item)
        output.append(geo)

    return output


def count_list(item_list):
    """Counts the occurence of a list item. """
    counts = defaultdict(int)
    
    for item in item_list:
        counts[item] += 1

    return dict(counts)

 
def show_results(dic):
    """Sorts the dictionary by value in decending order and prints the result to stdout.
    """
    for key, value in sorted(dic.iteritems(), key=operator.itemgetter(1), reverse=True):
        print('{0:>5}  {1}'.format(value, key))

    print('\n')


def process_args(args):
    """Process the command line arguments. """
    if not os.path.isdir(args.logdir):
        print('ERROR: {0} does not appear to exist!'.format(args.logdir))
        sys.exit(1)

    honssh_logs = find_logs(args.logdir)

    if args.access:
        found_login(honssh_logs)

    if args.source:
        list_items = source_ip(honssh_logs)
        dict_items = count_list(list_items)
        show_results(dict_items)

    if args.origin:
        list_items = source_ip(honssh_logs)
        orig_items = origin_country(list_items)
        dict_items = count_list(orig_items)
        show_results(dict_items)

    #if args.passwd:

    #if args.usrnam:

    #if args.combos:


def main():
    """Do what Main does best... """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
