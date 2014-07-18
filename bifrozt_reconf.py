#!/usr/bin/env python


#
#   DEVELOPMENT NOTES
#
#   This is one ugly looking script, but it works as intended :)
#


"""This script is intended to be used on the Bifrozt honeypot router, 
http://sourceforge.net/projects/bifrozt/, to generate dhcpd.conf, iptables and sshd_conf."""


"""
   Copyright (c) 2014, Are Hansen - Honeypot Development

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
__date__ = '2014, July 18'
__version__ = '0.0.1'


import os
import sys
import time
import re
try:
    import ipaddr
except ImportError:
    print '\nERROR: You need the module called "ipaddr"!\n'
    sys.exit(1)


def assign_values():
    """Assign DHCP values. """
    print '\nNetwork configuration\n'
    while True:
        # Get IPv4 and CIDR
        ipcidr = raw_input('- Enter IPv4/CIDR: ')

        # extract the IPv4.
        ipv4 = ipcidr.split('/')[0]

        # Make sure the last octet is 0.
        octets = ipv4.split('.')
        if octets[-1] != '0':
            octets[-1] = '0'
            ipv4 = '.'.join(octets) 

        # Call sys.exit(1) if CIDR is excluded.
        try:
            # Extract CIDR here.
            cidr = ipcidr.split('/')[1]
        except IndexError:
            print '\nERROR: You did not assign CIDR!\n'
            sys.exit(1)

        # CIDR cannot be greater than 31.
        if int(cidr) > 31:
            print 'The CIDR can not be higher than 31'

        # CIDR is less or equal to 31.
        if int(cidr) <= 31:
            break

    # Setup the IPv4 address for validation.
    check_ips = [ipv4]

    # Get the DNS servers.
    print '\nDNS Servers:'
    print 'Multiple DNS servers as space separated list'
    dnssrv = raw_input('- Enter DNS server(s): ')

    # Append the DNS server(s) to the check list
    for dns in dnssrv.split(' '):
        check_ips.append(dns)

    valid_ip = []
    # Pass the elements in the check list off for validation
    for ips in check_ips:
        validip = check_ipv4(ips)
        # Append the returned IPv4 address to the valid_ip list 
        valid_ip.append(validip)

    # Show default lease times.
    print '\nDHCP lease settings:'
    print 'Default values:'
    print 'default-lease-time:  600'
    print 'max-lease-time:     7200'
    print 'Press [ENTER] tngs.\n'

    # Get default-lease-time
    dltime = raw_input('- Default lease time: ')

    # Set default if len zero
    if len(dltime) == 0:
        dltime = '600'

    # Get max-lease-time
    mltime = raw_input('- Max lease time: ')

    # Set default if len zero
    if len(mltime) == 0:
        mltime = '7200'

    # Get domain-name.
    print '\nInternal domain name'
    while True:
        dname = raw_input('- Domain name: ')

        # Domain name should be two characters or more.
        if len(dname) < 2:
            print 'You have to enter a longer doamin name!'

        if len(dname) >= 2:
            break

    # Get static IPv4 and MAC address
    staticip = []
    print '\nStatic IPv4 addresse(s):'
    while True:
        # Get static IPv4 address,
        host_ip = raw_input('- IPv4: ')
        # validate IPv4.
        valid_host_ip = check_ipv4(host_ip) 

        # Check for previously used IPv4.
        if len(staticip) > 0:
            valid_host_ip = check_usedvar(valid_host_ip, staticip, 'ipv4')

        # Get MAC address of static host.
        host_mac = raw_input('- MAC: ')
        # validate MAC address.
        valid_host_mac = check_mac(host_mac)

        # Check for previously used MAC address.
        if len(staticip) > 0:
            valid_host_mac = check_usedvar(valid_host_mac, staticip, 'mac')

        # Get host name of static host
        valid_host_name = ''
        while True:
            host_name = raw_input('- Host name: ')

            # Check for previously used host names.
            if len(staticip) > 0:
                host_name = check_usedvar(host_name, staticip, 'hostname')

            # Host name should be three characters or more.
            if len(host_name) < 3:
                print 'The host name must be longer!'

            if len(host_name) >= 3:
                valid_host_name = host_name
                break

        # Append unique values to the staticip list
        staticip.append('{0} {1} {2}'.format(valid_host_ip, valid_host_mac, valid_host_name))

        # Await user input.
        verify = raw_input('\nAdd another static IPv4 address? Y/N ')

        # Restart loop to add additional static IP configuration
        if verify == 'Y':
            pass

        # or break to return values from function.
        if verify == 'N':
            break

        # Catch all invalid input.
        if verify != 'Y' and verify != 'N':
            print 'Please enter "Y" for Yes or "N" for No'

    return valid_ip, cidr, dltime, mltime, dname, staticip


def check_usedvar(str_item, list_item, fid):
    """Check if str_item is already in use in list_item. """
    while True:
        # Check for used IPv4 address.
        if fid == 'ipv4':
            for item in list_item:
                if str_item == item.split(' ')[0]:
                    print 'You have already used {0}'.format(str_item)
                    host_ip = raw_input('- IPv4: ')
                    str_item = check_ipv4(host_ip)

            if not re.match(str_item, item):
                break

        if fid == 'mac':
            # Check for used MAC address.
            for item in list_item:
                if str_item == item.split(' ')[1]:
                    print 'You have already used {0}'.format(str_item)
                    host_mac = raw_input('- MAC: ')
                    str_item = check_mac(host_mac)

            if not re.match(str_item, item):
                break

        if fid == 'hostname':
            # Check for used host name.
            for item in list_item:
                if str_item == item.split(' ')[2]:
                    print 'You have already used {0}'.format(str_item)
                    str_item = raw_input('- Host name: ')

            if not re.match(str_item, item):
                break

    return str_item


def check_mac(macadd):
    """Check for valid MAC address. """
    while True:
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macadd.lower()):
            print 'MAC address "{0}" is not valid!'.format(macadd)
            macadd = raw_input('- MAC: ')

        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macadd.lower()):
            break

    return macadd


def check_ipv4(ipv4):
    """Checks for valid ipv4 addresses. """
    while True:
        try:
            ip = ipaddr.ip_address(ipv4)
            break
        except ValueError:
            print '[!] - IPv4 {0} is not valid!'.format(ipv4)
            ipv4 = raw_input('Enter a valid IPv4: ')

    return ipv4


def network_summary(dhcp_info):
    """ Processes the tuple thats returned from the assign_values function. The tuple contain six
    elements.

    This is a reference of those elements:

    dhcp_info[0]                    dhcp_info[1]
        - valid_ip                      - cidr
          Type: list                    Type: str
          - 0: network                  - CIDR of the network
          - 1 - * : DNS servers

    dhcp_info[2]                    dhcp_info[3]
        - dltime                        - mltime
          Type: str                     Type: str
          - default-lease-time          - max-lease-time

    dhcp_info[4]                    dhcp_info[5]
        - dname                         - staticip
          Type: str                     Type: list
          - domain-name                 - each element contains three strings separated by a space
                                        -- str0: ipv4 address
                                        -- str1: mac address
                                        -- str2: host name
    
    The function will use these elements to get all the required values for the dhcpd.conf file.
    All the values will be appended to the dhcpd_conf list before its displayed to the user.
    The function will return the dhcpd_conf list if the user confirms the values to be correct. The
    entire script will be restarted if the user disaproves of the displayed values.
    """
    # Split address into octets.
    addr = dhcp_info[0][0].split('.')
    # Turn CIDR into int.
    cidr = int(dhcp_info[1])

    # Initialize the netmask and calculate based on CIDR mask.
    mask = [0, 0, 0, 0]
    for i in range(cidr):
        mask[i/8] = mask[i/8] + (1 << (7 - i % 8))

    # Initialize net and binary and netmask with addr to get network.
    net = []
    for i in range(4):
        net.append(int(addr[i]) & mask[i])

    # Duplicate net into broad array, gather host bits, and generate broadcast.
    broad = list(net)
    brange = 32 - cidr
    for i in range(brange):
        broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))

    # Declare the variabeles for the network.
    network = '.'.join(map(str, net))
    gateway = '{0}.1'.format('.'.join(map(str, net[0:3])))
    firstip = '{0}.2'.format('.'.join(map(str, net[0:3])))
    finalip = '{0}.{1}'.format('.'.join(map(str, broad[0:3])), int(broad[3]) - 1)
    brdcast = '{0}'.format('.'.join(map(str, broad)))
    netmask = '{0}'.format('.'.join(map(str, mask)))

    print '\nDHCP range:'
    print 'Starting IP address: {0}'.format(firstip)
    print 'Ending IP address:   {0}\n'.format(finalip)
    # Get start range
    startrange = raw_input('- Enter starting IP address: ')
    # and make sure its a valid IPv4 address.
    valid_start = check_ipv4(startrange)

    # Get end range
    endrange = raw_input('- Enter ending IP address: ')
    # and make sure its a valid IPv4 address.
    valid_end = check_ipv4(endrange)

    # Append all the configuration details to the dhcpd_conf list.
    dhcpd_conf = []
    dhcpd_conf.append('authoritative;')
    dhcpd_conf.append('ddns-update-style none;')
    dhcpd_conf.append('log-facility local7;')
    dhcpd_conf.append('default-lease-time {0};'.format(dhcp_info[2]))
    dhcpd_conf.append('max-lease-time {0};\n'.format(dhcp_info[3]))
    dhcpd_conf.append('option domain-name "{0}";'.format(dhcp_info[4]))
    dhcpd_conf.append('option domain-name-servers {0};'.format(', '.join(dhcp_info[0][1:])))
    dhcpd_conf.append('option subnet-mask {0};'.format(netmask))
    dhcpd_conf.append('option broadcast-address {0};'.format(brdcast))
    dhcpd_conf.append('option routers {0};\n'.format(gateway))
    dhcpd_conf.append('subnet {0} netmask {1} {2}'.format(network, netmask, '{'))
    dhcpd_conf.append('\trange {0} {1};\n'.format(valid_start, valid_end))

    # Create static host declarations and append to dhcpd_conf list.
    for static in dhcp_info[5]:
        ipaddress = static.split(' ')[0]
        macaddres = static.split(' ')[1]
        hostname = static.split(' ')[2]
        dhcpd_conf.append('\thost {0}.{1} {2}'.format(hostname, dhcp_info[4], '{'))
        dhcpd_conf.append('\thardware ethernet {0};'.format(macaddres))
        dhcpd_conf.append('\tfixed-address {0};'.format(ipaddress))
        dhcpd_conf.append('\t{0}\n'.format('}'))
    
    dhcpd_conf.append('{0}\n'.format('}'))

    # Present the dhcpd.conf file to the user
    print '\nThis is what your new dhcpd.conf will look like:\n'

    for line in dhcpd_conf:
        print line

    # Hold for user confirmation to
    while True:
        verify = raw_input('\nIs this the correct network settings? Y/N ')

        # break loop and return dhcpd_conf from function
        if verify == 'Y':
            break

        # or, if configuration is declined, restart the script.
        if verify == 'N':
            python = sys.executable
            os.execl(python, python, * sys.argv)

        # Catch all invalid inputs.
        if verify != 'Y' and verify != 'N':
            print 'Please enter "Y" for Yes or "N" for No'

    return dhcpd_conf, cidr, network, gateway, brdcast


def iptables_config(netvalues):
    """Configures the iptables. """
    cidr = netvalues[1]
    network = netvalues[2]
    gateway = netvalues[3]
    brdcast = netvalues[4]

    itl = []
    itl.append('*filter')
    itl.append(':INPUT ACCEPT [0:0]')
    itl.append(':FORWARD ACCEPT [0:0]')
    itl.append(':OUTPUT ACCEPT [0:0]')
    itl.append(':syn-flood - [0:0]')
    itl.append(':udp-flood - [0:0]')
    itl.append('-A INPUT -i lo -j ACCEPT')
    itl.append('-A INPUT -d 224.0.0.1/32 -j DROP')
    # INPUT
    itl.append('-A INPUT -d {0}/32 -i eth1 -j ACCEPT'.format(brdcast))
    itl.append('-A INPUT -s {0}/{1} -d {2} -i eth1 -p tcp -m tcp --dport 22 -j DROP'.format(network, cidr, gateway))
    itl.append('-A INPUT -s {0}/{1} -p tcp -m tcp --sport 22 -i eth1 -j ACCEPT'.format(network, cidr))
    itl.append('-A INPUT -s {0}/{1} ! -d {0}/{1} -i eth1 -j DROP'.format(network, cidr))
    itl.append('-A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT')
    itl.append('-A INPUT -i eth0 -p tcp -j ACCEPT')
    itl.append('-A INPUT -i eth0 -p udp -j ACCEPT')
    itl.append('-A INPUT -i eth0 -p icmp -j ACCEPT')
    itl.append('-A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT')

    # Get Admin sshd port from user.
    while True:
       sshd_port = raw_input('- Bifrozt SSHD Admin port: ')

       if int(sshd_port) > 65535 or int(sshd_port) == 0:
          print 'Choose a port number between 1 and 65535'

       if int(sshd_port) <= 65535 or int(sshd_port) > 0:
          itl.append('-A INPUT -i eth0 -p tcp -m tcp --dport {0} -j ACCEPT'.format(sshd_port))
          break

    # FORWARD
    itl.append('-A FORWARD -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT')
    itl.append('-A FORWARD -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT')


    # Get UDP flood values from user
    while True:
       udp_flood = raw_input('- UDP flood pkts/sec: ')

       if int(udp_flood) > 200 or int(udp_flood) <= 49:
          print 'You might consider keeping this value between 50 and 200 pkts/sec.'
          new_value = raw_input('- Press [ENTER] to keep current value, {0}, or enter new here: '.format(udp_flood))

          if len(new_value) == 0:
             itl.append('-A FORWARD -p udp -j udp-flood')
             itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - UDP-flood attack: "'.format(network, cidr, udp_flood))
             itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
             break

          if len(new_value) > 0:
             udp_flood = new_value
             itl.append('-A FORWARD -p udp -j udp-flood')
             itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - UDP-flood attack: "'.format(network, cidr, udp_flood))
             itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
             break      

       if int(udp_flood) <= 200 or int(udp_flood) >= 50:
          itl.append('-A FORWARD -p udp -j udp-flood')
          itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - UDP-flood attack: "'.format(network, cidr, udp_flood))
          itl.append('-A udp-flood -s {0}/{1} -i eth1 -p udp -m udp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break


    # Get UDP flood values from user
    while True:
       tcp_flood = raw_input('- TCP SYN flood pkts/sec: ')

       if int(tcp_flood) > 120 or int(tcp_flood) < 20:
          print 'You might consider keeping this value between 20 and 120 pkts/sec.'
          new_value = raw_input('- Press [ENTER] to keep current value, {0}, or enter new here: '.format(tcp_flood))

          print len(new_value)
          if len(new_value) == 0:
             itl.append('-A FORWARD -p tcp --syn -j syn-flood')
             itl.append('-A syn-flood -s {0}/{1} -i eth1 -p tcp -m tcp -m state --state NEW -m recent --set -m limit --limit 30/s --limit-burst 20 -j LOG --log-level 4 --log-prefix "BIFROZT - SYN-flood attack: "'.format(network, cidr, tcp_flood))
             itl.append('-A syn-flood -s {0}/{1} -i eth0 -p tcp -m tcp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
             break

          if len(new_value) > 0:
             tcp_flood = new_value
             itl.append('-A FORWARD -p tcp --syn -j syn-flood')
             itl.append('-A syn-flood -s {0}/{1} -i eth1 -p tcp -m tcp -m state --state NEW -m recent --set -m limit --limit 30/s --limit-burst 20 -j LOG --log-level 4 --log-prefix "BIFROZT - SYN-flood attack: "'.format(network, cidr, tcp_flood))
             itl.append('-A syn-flood -s {0}/{1} -i eth0 -p tcp -m tcp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
             break 

       if int(tcp_flood) <= 120 or int(tcp_flood) >= 20:
          itl.append('-A FORWARD -p tcp --syn -j syn-flood')
          itl.append('-A syn-flood -s {0}/{1} -i eth1 -p tcp -m tcp -m state --state NEW -m recent --set -m limit --limit 30/s --limit-burst 20 -j LOG --log-level 4 --log-prefix "BIFROZT - SYN-flood attack: "'.format(network, cidr, tcp_flood))
          itl.append('-A syn-flood -s {0}/{1} -i eth0 -p tcp -m tcp -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break 


    allowed_services = ['53']
    #  Get FTP values from user
    while True:
       ftp_values = raw_input('- Press [ENTER] to exclude FTP or enter pkts/sec: ')

       if len(ftp_values) == 0:
          print 'EXLUDED: FTP traffic'
          break

       if len(ftp_values) > 0:
          allowed_services.append('20:21')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 20:21 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 15 -j LOG --log-prefix "BIFROZT - FTP: " --log-level 7'.format(network, cidr, ftp_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 20:21 -m state --state NEW -m recent --update --seconds 1 --hitcount 15 -j DROP'.format(network, cidr))
          break

    #  DNS
    itl.append('-A FORWARD -s {0}/{1} -o eth0 -p udp -m udp --dport 53 -m state --state NEW -j LOG --log-prefix "BIFROZT - DNS: " --log-level 7'.format(network, cidr))


    #  Get HTTP values from user
    while True:
       http_values = raw_input('- Press [ENTER] to exclude HTTP or enter pkts/sec: ')

       if len(http_values) == 0:
          print 'EXLUDED: HTTP traffic'
          break

       if len(http_values) > 0:
          allowed_services.append('80')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 80 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - HTTP: " --log-level 7'.format(network, cidr, http_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 80 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break


    #  Get HTTP values from user
    while True:
       https_values = raw_input('- Press [ENTER] to exclude HTTPS or enter pkts/sec: ')

       if len(https_values) == 0:
          print 'EXLUDED: HTTPS traffic'
          break

       if len(https_values) > 0:
          allowed_services.append('443')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 443 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - HTTPS: " --log-level 7'.format(network, cidr, https_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 443 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break


    #  Get SMB values from user
    while True:
       smb_values = raw_input('- Press [ENTER] to exclude SMB or enter pkts/sec: ')

       if len(smb_values) == 0:
          print 'EXLUDED: SMB traffic'
          break

       if len(smb_values) > 0:
          allowed_services.append('445')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 445 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 3 -j LOG --log-prefix "BIFROZT - SMB: " --log-level 7'.format(network, cidr, smb_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 445 -m state --state NEW -m recent --update --seconds 1 --hitcount 3 -j DROP'.format(network, cidr))
          break


    #  Get AFP values from user
    while True:
       afp_values = raw_input('- Press [ENTER] to exclude AFP or enter pkts/sec: ')

       if len(afp_values) == 0:
          print 'EXLUDED: AFP traffic'
          break

       if len(afp_values) > 0:
          allowed_services.append('548')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 548 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 3 -j LOG --log-prefix "BIFROZT - AFP: " --log-level 7'.format(network, cidr, afp_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 548 -m state --state NEW -m recent --update --seconds 1 --hitcount 3 -j DROP'.format(network, cidr))
          break


    #  Get SMTP values from user
    while True:
       smtp_values = raw_input('- Press [ENTER] to exclude SMTP or enter pkts/sec: ')

       if len(smtp_values) == 0:
          print 'EXLUDED: SMTP traffic'
          break

       if len(smtp_values) > 0:
          allowed_services.append('587')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 587 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 6 -j LOG --log-prefix "BIFROZT - SMTP: " --log-level 7'.format(network, cidr, smtp_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 587 -m state --state NEW -m recent --update --seconds 1 --hitcount 6 -j DROP'.format(network, cidr))
          break


    #  Get POP3S values from user
    #  Get SMTP values from user
    while True:
       pop3s_values = raw_input('- Press [ENTER] to exclude POP3S or enter pkts/sec: ')

       if len(pop3s_values) == 0:
          print 'EXLUDED: POP3S traffic'
          break

       if len(pop3s_values) > 0:
          allowed_services.append('995')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 995 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 6 -j LOG --log-prefix "BIFROZT - POP3S: " --log-level 7'.format(network, cidr, pop3s_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 995 -m state --state NEW -m recent --update --seconds 1 --hitcount 6 -j DROP'.format(network, cidr))
          break

    #  Get MSSQL values from user
    while True:
       mssql_values = raw_input('- Press [ENTER] to exclude MSSQL or enter pkts/sec: ')

       if len(mssql_values) == 0:
          print 'EXLUDED: MSSQL traffic'
          break

       if len(mssql_values) > 0:
          allowed_services.append('1433')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 1433 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 3 -j LOG --log-prefix "BIFROZT - MSSQL: " --log-level 7'.format(network, cidr, mssql_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 1433 -m state --state NEW -m recent --update --seconds 1 --hitcount 3 -j DROP'.format(network, cidr))
          break

    #  Get MYSQL values from user
    while True:
       mysql_values = raw_input('- Press [ENTER] to exclude MySQL or enter pkts/sec: ')

       if len(mysql_values) == 0:
          print 'EXLUDED: MySQL traffic'
          break

       if len(mysql_values) > 0:
          allowed_services.append('3306')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 3306 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 3 -j LOG --log-prefix "BIFROZT - MYSQL: " --log-level 7'.format(network, cidr, mysql_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 3306 -m state --state NEW -m recent --update --seconds 1 --hitcount 3 -j DROP'.format(network, cidr))
          break


    #  Get MS-RDP values from user
    while True:
       ms_rdp_values = raw_input('- Press [ENTER] to exclude MS-RDP or enter pkts/sec: ')

       if len(ms_rdp_values) == 0:
          print 'EXLUDED: MS-RDP traffic'
          break

       if len(ms_rdp_values) > 0:
          allowed_services.append('3389')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 3389 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 6 -j LOG --log-prefix "BIFROZT - MS-RDP: " --log-level 7'.format(network, cidr, ms_rdp_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 3389 -m state --state NEW -m recent --update --seconds 1 --hitcount 6 -j DROP'.format(network, cidr))
          break


    #  Get IRC values from user
    while True:
       irc_values = raw_input('- Press [ENTER] to exclude IRC or enter pkts/sec: ')

       if len(irc_values) == 0:
          print 'EXLUDED: MySQL traffic'
          break

       if len(irc_values) > 0:
          allowed_services.append('6660:6667')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 6660:6667 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - IRC: " --log-level 7'.format(network, cidr, irc_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 6660:6667 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break


    #  Get HTTP-Alt values from user
    while True:
       http_alt_values = raw_input('- Press [ENTER] to exclude HTTP-Alt or enter pkts/sec: ')

       if len(http_alt_values) == 0:
          print 'EXLUDED: HTTP-Alt traffic'
          break

       if len(http_alt_values) > 0:
          allowed_services.append('8080:8081')
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 8080:8081 -m state --state NEW -m recent --set -m limit --limit {2}/s --limit-burst 20 -j LOG --log-prefix "BIFROZT - HTTP-Alt: " --log-level 7'.format(network, cidr, http_alt_values))
          itl.append('-A FORWARD -s {0}/{1} -o eth0 -p tcp -m tcp --dport 8081:8081 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j DROP'.format(network, cidr))
          break

    # Define the port list
    if len(allowed_services) > 10:
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j LOG --log-prefix "BIFROZT - FORWARD TCP DROP: " --log-level 7'.format(network, cidr, ','.join(allowed_services[0:9])))
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j DROP'.format(network, cidr, ','.join(allowed_services[0:9])))
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j LOG --log-prefix "BIFROZT - FORWARD TCP DROP: " --log-level 7'.format(network, cidr, ','.join(allowed_services[10:])))
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j DROP'.format(network, cidr, ','.join(allowed_services[10:])))

    if len(allowed_services) <= 10:
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j LOG --log-prefix "BIFROZT - FORWARD TCP DROP: " --log-level 7'.format(network, cidr, ','.join(allowed_services)))
       itl.append('-A FORWARD -s {0}/{1} ! -d {0}/{1} -p tcp -m tcp -m multiport ! --dports {2} -j DROP'.format(network, cidr, ','.join(allowed_services)))


    # OUTPUT
    itl.append('-A OUTPUT -s 127.0.0.1/32 -j ACCEPT')
    itl.append('-A OUTPUT -o lo -j ACCEPT')
    itl.append('-A OUTPUT -s {0}/{1} -j ACCEPT'.format(network, cidr))
    itl.append('-A OUTPUT -o eth1 -j ACCEPT')
    itl.append('-A OUTPUT -o eth0 -j ACCEPT')
    itl.append('COMMIT')

    # MANGLE
    itl.append('*mangle')
    itl.append(':PREROUTING ACCEPT [11555:635648]')
    itl.append(':INPUT ACCEPT [5541:383028]')
    itl.append(':FORWARD ACCEPT [6014:252620]')
    itl.append(':OUTPUT ACCEPT [1133:203218]')
    itl.append(':POSTROUTING ACCEPT [7147:455838]')
    itl.append('COMMIT')

    # NAT
    itl.append('*nat')
    itl.append(':PREROUTING ACCEPT [3275:176962]')
    itl.append(':INPUT ACCEPT [297:45950]')
    itl.append(':OUTPUT ACCEPT [12:3424]')
    itl.append(':POSTROUTING ACCEPT [0:0]')
    itl.append('-A POSTROUTING -o eth0 -j MASQUERADE')
    itl.append('COMMIT')

    return itl, sshd_port


def sshd_conf(port_number):
    """Writes the settigns to the sshd_config"""
    sshd_values = []
    sshd_values.append('Port {0}'.format(port_number[1]))
    sshd_values.append('Protocol 2')
    sshd_values.append('AddressFamily inet')
    sshd_values.append('HostKey /etc/ssh/ssh_host_rsa_key')
    sshd_values.append('HostKey /etc/ssh/ssh_host_dsa_key')
    sshd_values.append('HostKey /etc/ssh/ssh_host_ecdsa_key')
    sshd_values.append('UsePrivilegeSeparation yes')
    sshd_values.append('SyslogFacility AUTH')
    sshd_values.append('LogLevel VERBOSE')
    sshd_values.append('LoginGraceTime 120')
    sshd_values.append('PermitRootLogin no')
    sshd_values.append('StrictModes yes')
    sshd_values.append('RSAAuthentication yes')
    sshd_values.append('PubkeyAuthentication yes')
    sshd_values.append('IgnoreRhosts yes')
    sshd_values.append('RhostsRSAAuthentication no')
    sshd_values.append('HostbasedAuthentication no')
    sshd_values.append('PermitEmptyPasswords no')
    sshd_values.append('ChallengeResponseAuthentication no')
    sshd_values.append('X11Forwarding no')
    sshd_values.append('X11DisplayOffset 10')
    sshd_values.append('PrintMotd no')
    sshd_values.append('PrintLastLog no')
    sshd_values.append('TCPKeepAlive yes')
    sshd_values.append('Subsystem sftp /usr/lib/openssh/sftp-server')
    sshd_values.append('UsePAM yes')

    return sshd_values


def write_configs(dhcpd_values, fw_values, sshdsrv_values):
    """Writes the assigned values to configuration files. """
    make_time = time.strftime('%y%m%d%H%M%S')
    dhcpd_file = 'dhcpd.conf.{0}'.format(make_time)
    sshd_config = 'sshd_config.{0}'.format(make_time)
    iptables_file = 'iptables.{0}'.format(make_time)

    for values in dhcpd_values[0]:
        with open(dhcpd_file, 'a') as config:
            config.write('{0}\n'.format(values))

    print '\n- Created {0}'.format(dhcpd_file)

    for values in fw_values[0]:
        with open(iptables_file, 'a') as iptables:
            iptables.write('{0}\n'.format(values))

    print '- Created {0}'.format(iptables_file)

    for values in sshdsrv_values:
        with open(sshd_config, 'a') as sshd:
            sshd.write('{0}\n'.format(values))

    print '- Created {0}\n'.format(sshd_config)


def main():
    """...main..."""
    info = assign_values()
    dhcpd_config = network_summary(info)
    iptable_conf = iptables_config(dhcpd_config)
    sshdsrv_conf = sshd_conf(iptable_conf)
    write_configs(dhcpd_config, iptable_conf, sshdsrv_conf)


if __name__ == '__main__':
    main()
