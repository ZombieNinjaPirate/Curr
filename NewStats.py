#!/usr/bin/env python


"""
Used on the Bifrozt honeypot router to extract data from various system and attack logs. 
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
__version__ = 'DEV 0.1.7'


import argparse
import glob
import operator
import os
import sys
try:
    import geoip2.database
except ImportError:
    print'\nERROR: geoip2 module not installed!\nsudo pip install geoip2\n'
    sys.exit(1)
from collections import defaultdict
from os import path, access, R_OK


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

    logs = parser.add_argument_group('- Log directory')
    logs.add_argument('-H', dest='hondir', help='HonSSH logs ({0})'.format(hlog))

    args = parser.parse_args()

    return args


def find_honssh_logs(logpath):
    """
    Searches the logpath for the daily files created by HonSSH.
    The lines of the daily logs can be converted into list items of 5 by spitting them on ','.

        Index[0] = YYYY-mm-dd HH:MM:SS
        Index[1] = ip.ad.dr.ess
        Index[2] = username
        Index[3] = password
        Index[4] = (success = 1, failed = 0)

    The lines of the daily logs are appended to the lines_log list and returned from this function.
    """
    log_files = []
    lines_log = []

    os.chdir(logpath)
    for logs in glob.glob('201*'):
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
    Checks for successful logins in the HonSSH loglines. This is done by itterating trough the
    loglines while splitting on ','. The last index of the list item thats created by doing so will
    either be a 0 (failed login) or a 1 (successful login). Any line with a 1 in index[4] will be
    appended to the output list and returned from the function.
    """
    output = []

    for line in loglines:
        line = line.split(',')
        if '1' in line[4]:
            output.append('{0} {1} {2} {3}'.format(line[0], line[1], line[2], line[3]))

    return output


def source_ip(loglines):
    """
    Splits the loglines on ',' and assumes that there will be an IP address at index[1], this IP
    address is appended to the output list and returned from the function.
    """
    output = []

    for line in loglines:
            line = line.split(',')
            output.append(line[1])

    return output


def auth_info(loglines):
    """
    Parses loglines to extracts attempted usernames and passwords. Both of these objects are added
    to the output list that will be returned at the end of this function.
    """
    output = []

    for line in loglines:
            line  = line.split(',')
            output.append('{0} {1}'.format(line[2], line[3]))

    return output


def origin_country(item_list, fid):
    """
    Looks up the origin country of the provided IP address.
    """
    countrydb = '/devel/Bifrozt_LOGS/GeoLite2-Country.mmdb'

    if path.isfile(countrydb) and access(countrydb, R_OK):
        pass
    else:
        print 'ERROR: GeoIP2 database was not found'
        sys.exit(1)

    reader = geoip2.database.Reader(countrydb)

    output = []

    # Splits the string in item_list on blank spaces and assumes that index[2] will contain an IP
    # address. The index[1] will be checked against the GeoIP database to find the country of origin
    # that IP address belongs to. The string will be reassembled with the country name appended to
    # the end of the string before the string is appended to the output list and returned from the
    # function. 
    if fid == 'access':
        for item in item_list:
            item = item.split(' ')
            response = reader.country(item[2])
            out = item[0], item[1], item[3], item[4], item[2], response.country.iso_code
            output.append(out)

    # The item_list, when fid == origin, will only have IP addreses in it. The origin country of
    # these IP addresses are checked agains the GeoIP database and the country of origin is appended
    # to the output list and returned from the function.
    if fid == 'origin':
        for item in item_list:
            response = reader.country(item)
            output.append(response.country.name)

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
            item = item.split(' ')
            counts[item[1]] += 1     

    if fid == 'usrnam':
        for item in item_list:
            item = item.split(' ')
            counts[item[0]] += 1

    if fid == 'combos':
        for item in item_list:
            item = item.split(' ')
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
        header = '-' * 85
        banner = '  {0:<12} {1:<10} {4:<16} {5:<8} {2:<15} {3:<9}'.format('Date', 'Time', 'User',
                                                                'Password', 'IP address', 'Origin')


        for itt in items:
            login = '  {0:<12} {1:<10} {4:<18} {5:<6} {2:<15} {3:<14}'.format(itt[0], itt[1], itt[2],
                                                                           itt[3], itt[4], itt[5])

            result.append(login)

        for data in sorted(result, reverse=True):
            stdout_list.append(data)

        if len(result) == 0:
            print '  {0}\n{1}'.format(banner, header)
            print '\t\t\tNo successful logins yet'
            print ''
            sys.exit(1)

        print '{0}\n{1}'.format(banner, header)
        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'source':
        banner = '   {0}   {1}'.format('Hits', 'IP address')
        header = '-' * 33

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'origin':
        banner = '   {0}   {1}'.format('Hits', 'Country of origin')
        header = '-' * 33

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'passwd':
        banner = '  {0}   {1}'.format('Tries', 'Password')
        header = '-' * 33

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'usrnam':
        banner = '  {0}   {1}'.format('Tries', 'Username')
        header = '-' * 33

        for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
            stdout_list.append('{0:>7}   {1}'.format(value, key))

        print '{0}\n{1}'.format(banner, header)

        for std in stdout_list[:nol]:
            print std
        print ''

    if fid == 'combos':
        banner = '  {0}   {1}'.format('Tries', 'Combinations')
        header = '-' * 33

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
    # - verify that the HonSSH log directory exists
    if args.hondir:
        if not os.path.isdir(args.hondir):
            print 'ERROR: {0} does not appear to exist!'.format(args.hondir)
            sys.exit(1)


    honssh_logs = find_honssh_logs(args.hondir)

    # - number of lines to output
    number = 50

    if args.number:
        number = int(args.number)

    if args.access:
        list_items = found_login(honssh_logs)
        show_items = origin_country(list_items, 'access')
        show_results(show_items, 'access', number)

    if args.source:
        list_items = source_ip(honssh_logs)
        count_list(list_items, 'source')
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
