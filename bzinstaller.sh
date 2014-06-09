#!/bin/bash


# ------------------------------ The Bifrozt Honeypot Project 2014 ------------------------------ #
#
#   Developer:      Are Hansen
#   Date:           2014, May 5
#   Version:        0.1.7
#
#   Usage:
#   This script is executed by the debconf installer and takes care of configuration, package
#   installation, updating and upgrading of Bifrozt during installation.
#
#   Copyright (c) 2014, Are Hansen - Honeypot Development
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without modification, are permitted
#   provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list of
#   conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this list of
#   conditions and the following disclaimer in the documentation and/or other materials provided
#   with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
#   FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
# ------------------------------ The Bifrozt Honeypot Project 2014 ------------------------------ #


unset DEBCONF_REDIR
unset DEBCONF_FRONTEND
unset DEBIAN_HAS_FRONTEND
unset DEBIAN_FRONTEND


declare Script="Bifrozt-installer"
declare Slog="/var/log/Bifrozt_Install.log"
declare honeyd="/usr/share/honeyd/scripts"
declare -rx chmod="/bin/chmod"
declare -rx cp="/bin/cp"
declare -rx date="/bin/date"
declare -rx echo="/bin/echo"
declare -rx mkdir="/bin/mkdir"
declare -rx mv="/bin/mv"
declare -rx rm="/bin/rm"
declare -rx aptget="/usr/bin/apt-get"
declare -rx git="/usr/bin/git"
declare -rx touch="/usr/bin/touch"


function update_system()
{
    $aptget update &>/dev/null
    $aptget upgrade -y &>/dev/null
    $aptget dist-upgrade -y &>/dev/null
}


function install_bifrozt_pkgs()
{
    $aptget install git isc-dhcp-server htop slurm python-twisted python-mysqldb python-paramiko \
    geoip-bin geoip-database python-geoip honeyd iisemulator ttf-baekmuk ttf-arphic-gbsn00lp \
    ttf-arphic-bsmi00lp ttf-arphic-gkai00mp ttf-arphic-bkai00mp librrds-perl gawk tree -y
}


function git_bifrozt()
{
    $git clone https://are.hansen.floigir@code.google.com/p/bztest/ /root/bztest
}


function bifrozt_configs()
{
    cd /root/bztest
    $mv -v .git /.git

    cd /root/bztest/etc
    $cp -rv * /etc/

    cd /root/bztest/usr
    $cp -rv * /usr/
}


function git_honssh()
{
    $git clone https://code.google.com/p/honssh/ /opt/honssh
}


function install_check()
{
    if [ -e /etc/legal ]
    then
        $chmod 0644 /ect/legal &>/dev/null
    else
        echo 'ERROR: /ect/legal' >> $Slog
    fi

    if [ -e /etc/sysctl.conf ]
    then
        $chmod 0644 /etc/sysctl.conf &>/dev/null
    else
        echo 'ERROR: /etc/sysctl.conf' >> $Slog
    fi

    if [ -e /etc/cron.hourly/logrotate ]
    then
        $chmod 0755 /etc/cron.hourly/logrotate &>/dev/null
    else
        echo 'ERROR: /etc/cron.hourly/logrotate' >> $Slog
    fi

    if [ -e /etc/default/isc-dhcp-server ]
    then
        $chmod 0644 /etc/default/isc-dhcp-server &>/dev/null
    else
        echo 'ERROR: /etc/default/isc-dhcp-server' >> $Slog
    fi

    if [ -e /etc/dhcp/dhcpd.conf ]
    then
        $chmod 0644 /etc/dhcp/dhcpd.conf &>/dev/null
    else
        echo 'ERROR: /etc/dhcp/dhcpd.conf' >> $Slog
    fi

    if [ -e /etc/honeypot/honeyd.conf ]
    then
        $chmod 0644 /etc/honeypot/honeyd.conf &>/dev/null
    else
        echo 'ERROR: /etc/honeypot/honeyd.conf' >> $Slog
    fi

    if [ -e /etc/logrotate.d/iptables ]
    then
        $chmod 0755 /etc/logrotate.d/iptables &>/dev/null
    else
        echo 'ERROR: /etc/logrotate.d/iptables' >> $Slog
    fi

    if [ -e /etc/network/interfaces ]
    then
        $chmod 0644 /etc/network/interfaces &>/dev/null
    else
        echo 'ERROR: /etc/network/interfaces' >> $Slog
    fi

    if [ -e ]
    then
        $chmod 0644 /etc/network/iptables &>/dev/null
    else
        echo 'ERROR: /etc/network/iptables' >> $Slog
    fi

    if [ -e /etc/network/iptables6 ]
    then
        $chmod 0644 /etc/network/iptables6 &>/dev/null
    else
        echo 'ERROR: /etc/network/iptables6' >> $Slog
    fi

    if [ -e /etc/rsyslog.d/13-iptables.conf ]
    then
        $chmod 0644 /etc/rsyslog.d/13-iptables.conf &>/dev/null
    else
        echo 'ERROR: /etc/rsyslog.d/13-iptables.conf' >> $Slog
    fi

    if [ -e /etc/skel/.bash_logout ]
    then
        $chmod 0644 /etc/skel/.bash_logout &>/dev/null
    else
        echo 'ERROR: /etc/skel/.bash_logout' >> $Slog
    fi

    if [ -e ]
    then
        $chmod 0644 /etc/skel/.bashrc &>/dev/null
    else
        echo 'ERROR: /etc/skel/.bashrc' >> $Slog
    fi

    if [ -e /etc/skel/.profile ]
    then
        $chmod 0644 /etc/skel/.profile &>/dev/null
    else
        echo '/etc/skel/.profile' >> $Slog
    fi

    if [ -e /etc/skel/.vimrc ]
    then
        $chmod 0644 /etc/skel/.vimrc &>/dev/null
    else
        echo 'ERROR: /etc/skel/.vimrc' >> $Slog
    fi

    if [ -e /etc/skel/README.info ]
    then
        $chmod 0644 /etc/skel/README.info &>/dev/null
    else
        echo 'ERROR: /etc/skel/README.info' >> $Slog
    fi

    if [ -e /etc/ssh/sshd_config ]
    then
        $chmod 0644 /etc/ssh/sshd_config &>/dev/null
    else
        echo 'ERROR: /etc/ssh/sshd_config' >> $Slog
    fi

    if [ -e /etc/update-motd.d/00-header ]
    then
        $chmod 0755 /etc/update-motd.d/00-header &>/dev/null
    else
        echo 'ERROR: /etc/update-motd.d/00-header' >> $Slog
    fi

    if [ -e /etc/update-motd.d/10-help-text ]
    then
        $chmod 0755 /etc/update-motd.d/10-help-text &>/dev/null
    else
        echo 'ERROR: /etc/update-motd.d/10-help-text' >> $Slog
    fi

    if [ -e /usr/share/honeyd/scripts/unix/OSX/osx_ssh.sh ]
    then
        $chmod 0755 /usr/share/honeyd/scripts/unix/OSX/osx_ssh.sh &>/dev/null
    else
        echo 'ERROR: /usr/share/honeyd/scripts/unix/OSX/osx_ssh.sh' >> $Slog
    fi

    if [ -e /usr/share/honeyd/scripts/unix/linux/suse8.0/ssh.sh ]
    then
        $chmod 0755 /usr/share/honeyd/scripts/unix/linux/suse8.0/ssh.sh &>/dev/null
    else
        echo 'ERROR: /usr/share/honeyd/scripts/unix/linux/suse8.0/ssh.sh' >> $Slog
    fi

    if [ -e /usr/share/honeyd/scripts/win32/win2k/exchange-pop3.sh ]
    then
        $chmod 0755 /usr/share/honeyd/scripts/win32/win2k/exchange-pop3.sh &>/dev/null
    else
        echo '/usr/share/honeyd/scripts/win32/win2k/exchange-pop3.sh' >> $Slog
    fi

    if [ -e /var/log/honeypot/honeyd.log ]
    then
        $chmod 0666 /var/log/honeypot/honeyd.log &>/dev/null
    else
        $touch /var/log/honeypot/honeyd.log &>/dev/null

        if [ -e /var/log/honeypot/honeyd.log ]
        then
            $chmod 0666 /var/log/honeypot/honeyd.log &>/dev/null
        else
            echo 'ERROR: /var/log/honeypot/honeyd.log' >> $Slog
        fi
    fi
}


function congif_usracc()
{
    usgr="$(ls -gl /home/*/.bashrc | awk '{ print $3 }')"

    cd /etc/skel

    cp -r * /
}

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation has started" >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Updating the system." >> $Slog
update_system
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: System up to date." >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing Bifrozt base." >> $Slog
install_bifrozt_pkgs &>> $Slog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt base installed." >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Getting latest version of Bifrozt." >> $Slog
git_bifrozt &>> $Slog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Latest Bifrozt version accuired." >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installing configuration files." >> $Slog
bifrozt_configs &>> $Slog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Configuration files installed." >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Running installation checks." >> $Slog
install_check &>> $Slog
$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Installation checks completed." >> $Slog

$echo "$($date +"%Y  %b %d - %T") $Script[$$]: Bifrozt installation is complete" >> $Slog


exit 0
