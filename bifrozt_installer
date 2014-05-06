#!/bin/bash

#
#   Developer:      Are Hansen
#   Date:           2014, May 5
#
#   Usage:
#   This script is executed by the debconf installer and takes care of configuration,
#   package installation, updating and upgrading of Bifrozt during installation.
#
#   Copyright (c) 2014, Are Hansen - Honeypot Development
# 
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without modification, are
#   permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
# 
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or other
#   materials provided with the distribution.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
#   THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

unset DEBCONF_REDIR
unset DEBCONF_FRONTEND
unset DEBIAN_HAS_FRONTEND
unset DEBIAN_FRONTEND

declare Script="Bifrozt_Installer"
declare Slog="/var/log/$Script.log"
declare Elog="/var/log/$Script_Error.log"

# DEV NOTES:
#   - Add absolute paths to executables

function install_deb_pkgs()
{
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Updating current system seb packages" >> $Slog
    $apt-get update
    $apt-get upgrade -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: System is now up to date" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Bifrozt base deb packages" >> $Slog
    $apt-get install git isc-dhcp-server htop \
    slurm python-twisted python-mysqldb python-paramiko -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt base packages deb was installed" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Honeyd deb packages" >> $Slog
    $apt-get install honeyd honeyd-common iisemulator -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Honeyd deb packages was installed" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Dionaea deb packages" >> $Slog
    $apt-get install autoconf automake bison build-essential flex libcurl4-openssl-dev \
    libglib2.0-dev libreadline-dev libsqlite3-dev libssl-dev libtool libudns-dev \
    pkg-config python-dev subversion install libnl-3-dev libnl-genl-3-dev libnl-nf-3-dev \
    libnl-route-3-dev curl libcurl3 python-pycurl p0f -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Dionaea deb was installed" >> $Slog
}


function git_honssh()
{
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing HonSSH in /opt/honssh" >> $Slog
    $git clone https://code.google.com/p/honssh/ /opt/honssh >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: HonSSH was installed. Exit code: $?" >> $Slog
}


function wget_configs()
{
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching dhcpd.conf file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-dhcpd.conf \
    -O /etc/dhcp/dhcpd.conf >> $Slog
    $echo 'INTERFACES="eth1"' > /etc/default/isc-dhcp-server
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/dhcp/dhcpd.conf" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching interfaces file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-interfaces \
    -O /etc/network/interfaces >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/network/interfaces" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching sshd.config file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-sshd_config \
    -O /etc/ssh/sshd.config >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/ssh/sshd.config" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching sysctl.conf file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-sysctl.conf \
    -O /etc/sysctl.conf >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/sysctl.conf" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching iptables file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-tables \
    -O /etc/network/iptables >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/network/iptables" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching 10-help-text file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-10-help-text \
    -O /etc/update-motd.d/10-help-text >> $Slog
    $chmod 0755 /etc/update-motd.d/10-help-text
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/update-motd.d/10-help-text" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching motd-00-header file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-motd-00-header \
    -O /etc/update-motd.d/motd-00-header >> $Slog
    $chmod 0755 /etc/update-motd.d/motd-00-header
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/update-motd.d/motd-00-header" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching dionaea_run file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ikoniaris/dionaea-vagrant/master/runDionaea.sh \
    -O /usr/local/bin/dionaea_run >> $Slog
    $chmod 0755 /usr/local/bin/dionaea_run
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /usr/local/bin/dionaea_run" >> $Slog
}


function install_dionaea()
{
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Dionaea dependencies" >> $Slog
    $mkdir /opt/dionaea
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: liblcfg" >> $Slog
    $git clone git://git.carnivore.it/liblcfg.$git liblcfg
    cd /opt/dionaea/liblcfg/code
    $autoreconf -vi
    ./configure --prefix=/opt/dionaea
    $make install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: libemu" >> $Slog
    $git clone git://git.carnivore.it/libemu.$git libemu >> $Slog
    cd /opt/dionaea/libemu
    $autoreconf -vi
    ./configure --prefix=/opt/dionaea
    $make install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: libev-4.04" >> $Slog
    $wget http://dist.schmorp.de/libev/Attic/libev-4.04.tar.gz >> $Slog
    $tar xfz libev-4.04.tar.gz
    cd /opt/dionaea/libev-4.04
    ./configure --prefix=/opt/dionaea
    $make install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: Python-3.2.2" >> $Slog
    $wget http://www.python.org/ftp/python/3.2.2/Python-3.2.2.tgz >> $Slog
    $tar xfz Python-3.2.2.tgz
    cd /opt/dionaea/Python-3.2.2
    ./configure --enable-shared --prefix=/opt/dionaea --with-computed-gotos \
    --enable-ipv6 LDFLAGS="-Wl,-rpath=/opt/dionaea/lib/ -L/usr/lib/x86_64-linux-gnu/"
    $make
    $make install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: Cython-0.15" >> $Slog
    $wget http://cython.org/release/Cython-0.15.tar.gz >> $Slog
    $tar /opt/dionaea/Cython-0.15.tar.gz
    cd Cython-0.15
    /opt/dionaea/bin/python3 setup.py install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing dep: libpcap-1.1.1" >> $Slog
    $wget http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz >> $Slog
    $tar libpcap-1.1.1.tar.gz
    cd /opt/dionaea/libpcap-1.1.1
    ./configure --prefix=/opt/dionaea
    $make
    $make install
    cd /opt/dionaea

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Dependencies have been installed" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Compiling and installing Dionaea" >> $Slog
    $git clone git://git.carnivore.it/dionaea.$git dionaea >> $Slog
    cd /opt/dionaea
    $autoreconf -vi
    ./configure --with-lcfg-include=/opt/dionaea/include/ \
    --with-lcfg-lib=/opt/dionaea/lib/ \
    --with-python=/opt/dionaea/bin/python3.2 \
    --with-cython-dir=/opt/dionaea/bin \
    --with-udns-include=/opt/dionaea/include/ \
    --with-udns-lib=/opt/dionaea/lib/ \
    --with-emu-include=/opt/dionaea/include/ \
    --with-emu-lib=/opt/dionaea/lib/ \
    --with-gc-include=/usr/include/gc \
    --with-ev-include=/opt/dionaea/include \
    --with-ev-lib=/opt/dionaea/lib \
    --with-nl-include=/opt/dionaea/include \
    --with-nl-lib=/opt/dionaea/lib/ \
    --with-curl-config=/usr/bin/ \
    --with-pcap-include=/opt/dionaea/include \
    --with-pcap-lib=/opt/dionaea/lib/
    $make
    $make install
    cd /opt/dionaea
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Dionaea has been installed" >> $Slog

    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Configuring Dionaea" >> $Slog
    cd /opt/dionaea/etc/dionaea
    $sed -i 's/levels = "all"/levels = "all,-debug"/g' dionaea.conf
    $sed -i 's/mode = "getifaddrs"/mode = "manual"/g' dionaea.conf
    $sed -i 's/addrs = { eth1 = \["::"\] }/addrs = { eth0 = \["0.0.0.0"\] }/g' dionaea.conf
    $sed -i -r 's/\/\/\t\t\t"p0f"/\t\t\t"p0f"/g' dionaea.conf
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Dionaea may or may not be working now." >> $Slog
}


$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation has started" >> $Slog
install_deb_pkgs 2>>$Elog
fetch_configs 2>>$Elog
wget_configs 2>>$Elog
install_dionaea 2>>$Elog
$chmod 0644 $Slog
$chmod 0644 $Elog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation is complete" >> $Slog


exit 0
