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

declare Slog="/var/log/Bifrozt_Install.log"
declare Elog="/var/log/Bifrozt_Error.log"
declare -rx chmod="/bin/chmod"
declare -rx date="/bin/date"
declare -rx echo="/bin/echo"
declare -rx rm="/bin/rm"
declare -rx aptget="/usr/bin/apt-get"
declare -rx git="/usr/bin/git"
declare -rx wget="/usr/bin/wget"


function install_deb_pkgs()
{
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Updating current system seb packages" >> $Slog
    $aptget update
    $aptget upgrade -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: System is now up to date" >> $Slog


    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Bifrozt base deb packages" >> $Slog
    $aptget install git isc-dhcp-server htop slurm python-twisted python-mysqldb python-paramiko -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt base packages deb was installed" >> $Slog


    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Honeyd deb packages" >> $Slog
    $aptget install honeyd honeyd-common iisemulator -y
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Honeyd deb packages was installed" >> $Slog
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


    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Fetching sshd_config file" >> $Slog
    $wget -q https://raw.githubusercontent.com/ZombieNinjaPirate/Bifrozt/master/bifrozt-sshd_config \
    -O /etc/ssh/sshd_config >> $Slog
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/ssh/sshd_config" >> $Slog


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
    -O /etc/update-motd.d/00-header >> $Slog
    $chmod 0755 /etc/update-motd.d/motd-00-header
    $echo "$($date +"%Y  %b %d - %T") $Script[$$]: Created /etc/update-motd.d/motd-00-header" >> $Slog
}


$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation has started" >> $Slog
install_deb_pkgs 2>>$Elog
wget_configs 2>> $Elog
git_honssh 2>>$Elog
$chmod 0644 $Slog
$chmod 0644 $Elog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation is complete" >> $Slog


exit 0
