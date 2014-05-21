#!/usr/bin/env python


"""
This script is used on the Bifrozt honeypot router to extract data from various system and attack logs. 
"""

"""
Copyright (c) 2014, Are Hansen - Honeypot Development.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__author__ = 'Are Hansen'
__date__ = '2014, May 15'
__version__ = '0.1.2'


import argparse
import glob
import operator
import os
import sys
try:
    import GeoIP
except ImportError:
    print'\nERROR: GeoIP module not installed!\nsudo apt-get install python-geoip\n'
    sys.exit(1)
from collections import defaultdict


def parse_args():
    """
    Defines the command line arguments.
    """
    hlog = '/opt/honssh/logs'

    parser = argparse.ArgumentParser('Bifrozt data extraction script')

    honssh = parser.add_argument_group('- HonSSH data')
    honssh.add_argument('-A', dest='access', help='Valid login found', action='store_true')
    honssh.add_argument('-S', dest='source', help='Connection/IP address', action='store_true')
    honssh.add_argument('-O', dest='origin', help='Connection/country', action='store_true')
    honssh.add_argument('-P', dest='passwd', help='Frequent passwords', action='store_true')
    honssh.add_argument('-U', dest='usrnam', help='Frequent usernames', action='store_true')
    honssh.add_argument('-C', dest='combos', help='Frequent combinations', action='store_true')

    out = parser.add_argument_group('- Output control')
    out.add_argument('-n', dest='number', help='Number of lines displayed (default: 50)')

    logs = parser.add_argument_group('- Log locations')
    logs.add_argument('-H', dest='logdir', help='HonSSH logs ({0})'.format(hlog), default=hlog)

    args = parser.parse_args()

    return args


def find_logs(logpath):
    """
    Searches the logpath and appends all the files that matches to a returned list object.
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
    output = []

    for line in loglines:
        if 'LOGIN_SUCCESSFUL' in line:
            login = line.split()[4:8]
            date = login[0].split('_')[0]
            time = login[0].split('_')[1]
            out = date, time, login[2], login[3], login[1]
            output.append(out)

    return output


def source_ip(loglines):
    """
    Parses all the loglines to find entries indocating a new connection has been made. From the
    matching entries in loglines it will extract the IP address and append it to the output list
    thats returned from the function.
    """
    output = []

    for line in loglines:
        if 'CONNECTION_MADE' in line:
            output.append(line.split()[5])

    return output


def auth_info(loglines):
    """
    Parses loglines to extracts attempted usernames and passwords. Both of these objects are added
    to the output list that will be returned at the end of this function.
    """
    output = []

    for line in loglines:
        if 'LOGIN_' in line:
            login = line.split()
            out = login[6], login[7]
            output.append(out)

    return output


def origin_country(item_list, fid):
    """
    Given a list of IP addresses it will find the its country of origin.
    """
    gip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    output = []

    if fid == 'access':
        for item in item_list:
            geo = gip.country_name_by_addr(item[4])
            out = item[0], item[1], item[2], item[3], item[4], geo
            output.append(out)

    if fid == 'origin':
        for item in item_list:
            geo = gip.country_name_by_addr(item)
            output.append(geo)

    return output


def count_list(item_list, fid):
    """
    Counts the occurence of a list item thats returned.
    """
    counts = defaultdict(int)

    if fid == 'source':
        for item in item_list:
            counts[item] += 1

    if fid == 'origin':
        for item in item_list:
            counts[item] += 1

    if fid == 'passwd':
        for item in item_list:
            counts[item[1]] += 1     

    if fid == 'usrnam':
        for item in item_list:
            counts[item[0]] += 1

    if fid == 'combos':
        for item in item_list:
            item = '{0}/{1}'.format(item[0], item[1])
            counts[item] += 1

    return dict(counts)


def show_results(items, fid, nol):
    """
    Checks the function identifier and processes the output accordingly before the results are
    printed to stdout.
    """
    result = []
    stdout_list = []

    if fid == 'access':
        header = '-' * 76
        banner = '{0:<9} {1:<8} {2:<10} {3:<16} {4:<15} {5:>12}'.format('Date', 'Time', 'Username',
                                                                'Password', 'IP address', 'Country')

        for itt in items:
            login = '{0:<9} {1:<8} {2:<10} {3:<16} {4:<15} {5:>12}'.format(itt[0], itt[1], itt[2],
                                                                           itt[3], itt[4], itt[5])
            result.append(login)

        for data in sorted(result, reverse=True):
            stdout_list.append(data)

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'source':
        banner = '   {0}   {1}'.format('Hits', 'IP address')
        header = '-' * 26

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'origin':
        banner = '   {0}   {1}'.format('Hits', 'Country of origin')
        header = '-' * 36

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'passwd':
        banner = '  {0}   {1}'.format('Tries', 'Password')
        header = '-' * 36

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'usrnam':
        banner = '  {0}   {1}'.format('Tries', 'Username')
        header = '-' * 42

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'combos':
        banner = '  {0}   {1}'.format('Tries', 'Combinations')
        header = '-' * 48

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''


def process_args(args):
    """
    Process the command line arguments.
    """
    number = 50

    if not os.path.isdir(args.logdir):
        print 'ERROR: {0} does not appear to exist!'.format(args.logdir)
        sys.exit(1)

    honssh_logs = find_logs(args.logdir)

    if args.number:
        number = int(args.number)

    if args.access:
        list_items = found_login(honssh_logs)
        show_items = origin_country(list_items, 'access')
        show_results(show_items, 'access', number)

    if args.source:
        list_items = source_ip(honssh_logs)
        dict_items = count_list(list_items, 'source')
        show_results(dict_items, 'source', number)

    if args.origin:
        list_items = source_ip(honssh_logs)
        orig_items = origin_country(list_items, 'origin')
        cunt_items = count_list(orig_items, 'origin')
        show_results(cunt_items, 'origin', number)

    if args.passwd:
        list_items = auth_info(honssh_logs)
        auth_items = count_list(list_items, 'passwd')
        show_results(auth_items, 'passwd', number)

    if args.usrnam:
        list_items = auth_info(honssh_logs)
        auth_items = count_list(list_items, 'usrnam')
        show_results(auth_items, 'usrnam', number)

    if args.combos:
        list_items = auth_info(honssh_logs)
        auth_items = count_list(list_items, 'combos')
        show_results(auth_items, 'combos', number)


def main():
    """
    Do what Main does best...
    """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()

