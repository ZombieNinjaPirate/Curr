#!/usr/local/bin/bash


#
#
#   Bifrozt setup and management script.
#
#   NOTE: This version uses the absolute path declarations under OpenBSD 5.4 
#
#   Date:       2014, March 17
#   Version:    1.0.1
#   Plattform:  OpenBSD 5.4 amd64
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
#


# ----- Absolute path declarations
declare -rx Script="${0##*/}"
declare -rx cat="/bin/cat"
declare -rx cp="/bin/cp"
declare -rx date="/bin/date"
declare -rx echo="/bin/echo"
declare -rx ln="/bin/ln"
declare -rx ls="/bin/ls"
declare -rx md5="/bin/md5"
declare -rx sleep="/bin/sleep"
declare -rx pfctl="/sbin/pfctl"
declare -rx reboot="/sbin/reboot"
declare -rx awk="/usr/bin/awk"
declare -rx clear="/usr/bin/clear"
declare -rx cut="/usr/bin/cut"
declare -rx egrep="/usr/bin/egrep"
declare -rx grep="/usr/bin/grep"
declare -rx id="/usr/bin/id"
declare -rx sed="/usr/bin/sed"
declare -rx wc="/usr/bin/wc"


# ----- Directories
declare conf_dir="/root/configs"
declare active_dir="$conf_dir/active_configs"
declare setup_dir="$conf_dir/setup_files"
declare templ_dir="$conf_dir/template_files"


# ----- Template files
declare templ_dhcpd="$templ_dir/template_dhcpd.conf"
declare templ_pfconf="$templ_dir/template_pf.conf"
declare templ_setup="$templ_dir/template_setup_file"
declare templ_sshd="$templ_dir/template_sshd_config"
declare templ_em0="$templ_dir/template_hostname.em0"
declare templ_em1="$templ_dir/template_hostname.em1"
declare templ_rc="$templ_dir/template_rc.local"
declare templ_rcconf="$templ_dir/template_rc.conf"
declare templ_myname="$templ_dir/template_myname"
declare templ_motd="$templ_dir/template_motd"


# ----- Setup files
declare new_setup="$setup_dir/Bifrozt_setup"


# ----- Active configuration files
declare new_dhcpd="$active_dir/dhcpd.conf"
declare new_pfconf="$active_dir/pf.conf"
declare new_sshd="$active_dir/sshd_config"
declare new_em0="$active_dir/hostname.em0"
declare new_em1="$active_dir/hostname.em1"
declare new_rc="$active_dir/rc.local"
declare new_rcconf="$active_dir/rc.conf"
declare new_myname="$active_dir/myname"
declare new_motd="$active_dir/motd"


# ----- System configuration files
declare dhcpd_conf="/etc/dhcpd.conf"
declare pf_conf="/etc/pf.conf"
declare sshd_config="/etc/ssh/sshd_config"
declare tzinfo="/usr/share/zoneinfo"
declare kblayout="/etc/wsconsctl.conf"
declare hostname_file="/etc/myname"
declare external_if="/etc/hostname.em0"
declare internal_if="/etc/hostname.em1"
declare rc_local="/etc/rc.local"
declare rc_conf="/etc/rc.conf"
declare sysctl_conf="/etc/sysctl.conf"
declare motd="/etc/motd"


# ----- Sanity checks
if [ $# != 0 ]
then
    $echo "ERROR: $Script does not take any arguments."
    exit 1
fi

if [ $($id -u) != 0 ]
then
    $echo 'ERROR: YOU ARE NOT ROOT!!'
    exit 1
fi

root_md5="$($grep ^'root' /etc/master.passwd | $md5)"
md5_root='a60c5c5c7ac1fb5780370019692d4186'

if [ $root_md5 = $md5_root ]
then
    $echo 'STOP! You have to change the password for "root" and "winnie" before you can run this script!'
    exit 1
fi

winnie_md5="$($grep ^'winnie' /etc/master.passwd | $md5)"
md5_winnie='786e2a6092cc3924e436862c3e8c9a29'

if [ $winnie_md5 = $md5_winnie ]
then
    $echo 'STOP!...I said you have to change the password for "root" _AND_ "winnie"!!'
    exit 1
fi


#
# ============================================================ SYSTEM FUNCTIONS
#


function set_keyboard()
{
    change_kbl()
    {
        opt1='us de dk it fr uk jp sv no es hu be ru ua'
        opt2='sg sf pt lt la br nl tr pl si cf lv is'

        $echo 'These are your keyboard options:
             '
        $echo "$opt1"
        $echo "$opt2
             "
        $echo 'What keyboard layout would you like to use? (Example: ru)'
        while [ "$LOOP" != 'DONE' ]
        do
            read -p 'Please select a layout: ' LOUT
            case $LOUT in
                us)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                de)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                dk)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                it)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                fr)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                uk)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                jp)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                sv)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                no)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                es)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                hu)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                be)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                ru)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                ua)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                sg)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                sf)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                pt)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                lt)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                la)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                br)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                nl)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                tr)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                pl)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                si)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                cf)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                lv)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                is)
                    $echo "Setting the layout to: $LOUT"
                    KEYBOARD="$LOUT"
                    LOOP='DONE'
                    ;;
                 *)
                    $echo 'Please select a valid layout:
                        '
                    $echo "$opt1"
                    $echo "$opt2
                         "
                    ;;
            esac
        done
    }

    curr_kbl="$($cut -d '=' -f2 $kblayout)"
    $echo "The local keyboard layout is set to: $curr_kbl"
    while true
    do
        read -p 'Would you like to change this? y/n ' KBL
        case $KBL in
            y)
                change_kbl
                break
                ;;
            n)
                $echo "Keeping the \"$curr_kbl\" layout then.";
                KEYBOARD="$curr_kbl"
                break
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
        esac
    done
}


function set_tz()
{
    current_tz()
    {
        $ls -l /etc/localtime\
        | $awk '{ print $11 }'\
        | $cut -d '/' -f5-
    }

    new_tz()
    {
        $echo 'Choose a new time zone (Example: US/Arizona)'
        read -p 'New time zone: ' NEW_TZ

        while [ ! -f $tzinfo/$NEW_TZ ]
        do
            $echo "The time zone file $tzinfo/$NEW_TZ dont appear to exist."
            read -p 'Please, enter a valid  time zone: ' NEW_TZ
        done

        $echo "Setting new time zone: $NEW_TZ"
        TIMEZONE="$NEW_TZ"
    }

    $echo "The current time zone is set to: $(current_tz)"
    while [[ $TZ != 'y' && $TZ != 'n' ]]
    do
        read -p 'Is this time zone correct? y/n ' TZ
        case $TZ in
            y)
                $echo 'Cool, keeping this time zone then...moving on..';
                TIMEZONE="$(current_tz)"
                break
                ;;
            n)
                new_tz;
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no
                     '
                ;;
        esac
    done
}


function change_hostname()
{
$cat << _EOF_

You are about to chagne the hostname. Make sure to choose
a VALID hostname. If you choose a hostname containing invalid
characters you might get some strange issues, in the event of
this happening - go back and set a valid one.

_EOF_

read -p 'Enter the new hostname: ' NHN
HOST_NAME="$NHN"
}

function set_hostname()
{
    $echo 'The current hostname is: bifrozt'
    while true
    do
        read -p 'Would you like to change it? y/n ' CHN
        case $CHN in
            y)
                change_hostname
                break
                ;;
            n)
                $echo 'Kepping "bifrozt" as the hostname then.'
                HOST_NAME="bifrozt"
                break
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
}


function set_honssh_boot()
{
$cat << _EOF_

HonSSH can be configured to start as the system boots up.
Depending on how you are using Bifrozt this might be to an
advantage. The default is to NOT start HonSSH as the system
boots up.

_EOF_
while true
do
    read -p 'Would you like to start HonSSH as the system boots? y/n ' HAB
    case $HAB in
        y)
            $echo 'HonSSH will start at boot time.'
            HONSSH_BOOT=""
            break
            ;;
        n)
            $echo 'Okay, using the defaults then.'
            HONSSH_BOOT="#_HONSSH_BOOT_#"
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


#
# ======================================================================= NETWORK CONFIGURATION
#


function change_honeypot_mac()
{
    read -p 'Enter the honeypot MAC address: ' MAC

    check_mac()
    {
        $echo $MAC\
        | $egrep "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    }

    while [ "$(check_mac | $wc -c | $awk '{ print $1}')" != "18" ]
    do
        $echo "The MAC address '$MAC' appears to be invalid"
        read -p 'Please enter a valid MAC address: ' MAC
    done

    if [ ! -z "$(check_mac)" ]
    then
        $echo "The MAC address of your honeypot: $(check_mac)"
        HONEY_MAC="$(check_mac)"
    fi
}


function change_dhcpd_network()
{
$cat << _EOF_

The new nework must be in one of these (rfc 1918).

    1) 10.0.0.0
    2) 172.16.0.0
    3) 192.168.0.0

_EOF_

while true
do
    read -p 'Select a new network block: ' NNA
    case $NNA in
        1)
            while [[ -z $RFC102 || $RFC102 -gt 255 ]]
            do
                read -p 'Enter the second octet (0 - 255): 10.' RFC102
            done

            while [[ -z $RFC103 || $RFC103 -gt 255 ]]
            do
                read -p "Enter the third octet (0 - 255): 10.$RFC102." RFC103
            done

            NETWORK="10.$RFC102.$RFC103.0"
            GATEWAY="10.$RFC102.$RFC103.1"
            NETMASK="255.255.255.0"
            BROADCAST="10.$RFC102.$RFC103.255"
            DHCP_START="10.$RFC102.$RFC103.10"
            DHCP_STOP="10.$RFC102.$RFC103.100"
            HONEYPOT="10.$RFC102.$RFC103.200"
            break
            ;;
        2)
            while [[ -z $RFC1723 || $RFC1723 -gt 255 ]]
            do
                read -p "Enter the third octet (0 - 255): 172.16." RFC1723
            done

            NETWORK="172.16.$RFC1723.0"
            GATEWAY="172.16.$RFC1723.1"
            NETMASK="255.255.255.0"
            BROADCAST="172.16.$RFC1723.255"
            DHCP_START="172.16.$RFC1723.10"
            DHCP_STOP="172.16.$RFC1723.100"
            HONEYPOT="172.16.$RFC1723.200"
            break
            ;;
        3)
            while [[ -z $RFC1923 || $RFC1923 -gt 255 ]]
            do
                read -p "Enter the third octet (0 - 255): 192.168." RFC1923
            done

            NETWORK="192.168.$RFC1923.0"
            GATEWAY="192.168.$RFC1923.1"
            NETMASK="255.255.255.0"
            BROADCAST="192.168.$RFC1923.255"
            DHCP_START="192.168.$RFC1923.10"
            DHCP_STOP="192.168.$RFC1923.100"
            HONEYPOT="192.168.$RFC1923.200"
            break
            ;;
        *)
            $echo 'Your valid choices are 1, 2 or 3'
            ;;
    esac
done
}


function change_dhcpd_dns_servers()
{
$cat << _EOF_

This is the DNS server(s) used by the DHCP server:

    DNS server(s):      $DNS_SERVERS

_EOF_
while true
do
    read -p 'Would you like change this? y/n ' CDNS
    case $CDNS in
        y)
            read -p 'Enter the primary DNS server: ' PDNS   
            $echo 'If you dont want to use a secondary DNS server, press ENTER'
            read -p 'Enter your secondary DNS server: ' SDNS

            if [ ! -z $SDNS ]
            then
                DNS_SERVERS="$PDNS, $SDNS"
            else
                DNS_SERVERS="$PDNS"
            fi

            break
            ;;
        n)
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


function change_dhcpd_domain_name()
{
$cat << _EOF_

Tis is the domain name used by the DHCP server:

    Domain name:        $DOMAIN_NAME

_EOF_
while true
do
    read -p 'Would you like to change the domain name? y/n ' CDN
    case $CDN in
        y)
            while [ -z $NEWNAME ]
            do
                read -p 'Enter a new domain name: ' NEWNAME
            done

            DOMAIN_NAME="$NEWNAME"

            break
            ;;
        n)
            $echo 'Okay, keeping the current domain name'
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


function change_dhcpd_lease()
{
$cat << _EOF_

This is the maximum lease time used by the DHCP server:

    Lease time:         $DHCP_LEASE

_EOF_
while true
do
    read -p 'Would you like to change the dhcp lease time? y/n ' CDLT
    case $CDLT in
        y)
            while [[ -z $NEWLEASE || $NEWLEASE = 0 ]]
            do
                read -p 'Enter the new lease time: ' NEWLEASE
            done

            DHCP_LEASE="$NEWLEASE"
            
            break
            ;;
        n)
            $echo 'Okay, keeping the current lease time.'
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


function set_dhcpd()
{
$cat << _EOF_

Bifrozt will provide DHCP on its internal interface.
These are the settings provided by the DHCP server:

    Lease time:         $DHCP_LEASE
    DNS server(s):      $DNS_SERVERS
    Domain name:        $DOMAIN_NAME
    Subnet:             $NETWORK
    Netmask:            $NETMASK
    Start range:        $DHCP_START
    Stop range:         $DHCP_STOP
    Gateway:            $GATEWAY
    Broadcast:          $BROADCAST
    Honeypot:           $HONEYPOT

(Start and stop range will not be configurable until next version)

_EOF_
while true
do
    read -p 'Would you like to keep these settings? y/n ' CDHCP
    case $CDHCP in
        y)
            $echo 'Okay, keeping the current DHCP settings.'
            change_honeypot_mac
            break
            ;;
        n)
            change_dhcpd_network
            change_dhcpd_dns_servers
            change_dhcpd_domain_name
            change_dhcpd_lease
            change_honeypot_mac
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


#
# ======================================================================= FIREWALL CONFIGURATION
#


function change_firewall_ports()
{
while true
do
    while [ -z $SFTP ]
    do
        read -p 'Allow outbound FTP (tcp/20 -21)?  y/n ' SFTP
        case $SFTP in
            y)
                FTP=""
                SFTP="OK"
                ;;
            n)
                FTP="#_FTP_#"
                SFTP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SSSH ]
    do
        read -p 'Allow outbound SSH (tcp/22)? y/n ' SSSH
        case $SSSH in
            y)
                SSH=""
                SSSH="OK"
                ;;
            n)
                SSH="#_SSH_#"
                SSSH="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $STELNET ]
    do
        read -p 'Allow outbound TELNET (tcp/23)? y/n ' STELNET
        case $STELNET in
            y)
                TELNET=""
                STELNET="OK"
                ;;
            n)
                TELNET="#_TELNET_#"
                STELNET="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SSMTP1 ]
    do
        read -p 'Allow outbound SMTP (tcp/25)? y/n ' SSMTP1
        case $SSMTP1 in
            y)
                SMTP1=""
                SSMTP1="OK"
                ;;
            n)
                SMTP1="#_SMTP1_#"
                SSMTP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SDNS ]
    do
        read -p 'Allow outbound DNS (udp/53)? y/n ' SDNS
        case $SDNS in
            y)
                DNS=""
                SDNS="OK"
                ;;
            n)
                DNS="#_DNS_#"
                SDNS="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SHTTP ]
    do
        read -p 'Allow outbound HTTP (tcp/80)? y/n ' SHTTP
        case $SHTTP in
            y)
                HTTP=""
                SHTTP="OK"
                ;;
            n)
                HTTP="#_HTTP_#"
                SHTTP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SPOPV2 ]
    do
        read -p 'Allow outbound POPV2 (tcp/109)? y/n ' SPOPV2
        case $SPOPV2 in
            y)
                POPV2=""
                SPOPV2="OK"
                ;;
            n)
                POPV2="#_POPV2_#"
                SPOPV2="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
    
    while [ -z $SPOPV3 ]
    do
        read -p 'Allow outbound POPV3 (tcp/110)? y/n ' SPOPV3
        case $SPOPV3 in
            y)
                POPV3=""
                SPOPV3="OK"
                ;;
            n)
                POPV3="#_POPV3_#"
                SPOPV3="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SIMAP ]
    do
        read -p 'Allow outbound IMAP (tcp/143)? y/n ' SIMAP
        case $SIMAP in
            y)
                IMAP=""
                SIMAP="OK"
                ;;
            n)
                IMAP="#_IMAP_#"
                SIMAP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
    
    while [ -z $SHTTPS ]
    do
        read -p 'Allow outbound HTTPS (tcp/443)? y/n ' SHTTPS
        case $SHTTPS in
            y)
                HTTPS=""
                SHTTPS="OK"
                ;;
            n)
                HTTPS="#_HTTPS_#"
                SHTTPS="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SSMB ]
    do
        read -p 'Allow outbound SMB (tcp/445)? y/n ' SSMB
        case $SSMB in
            y)
                SMB=""
                SSMB="OK"
                ;;
            n)
                SMB="#_SMB_#"
                SSMB="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SAFP ]
    do
        read -p 'Allow outbound AFP(tcp/548)? y/n ' SAFP
        case $SAFP in
            y)
                AFP=""
                SAFP="OK"
                ;;
            n)
                AFP="#_AFP_#"
                SAFP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
    
    while [ -z $SSMTP2 ]
    do
        read -p 'Allow outbound SMTP (tcp/587)? y/n ' SSMTP2
        case $SSMTP2 in
            y)
                SMTP2=""
                SSMTP2="OK"
                ;;
            n)
                SMTP="#_SMTP2_#"
                SSMTP2="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SIMAPS ]
    do
        read -p 'Allow outbound IMAPS (tcp/993)? y/n ' SIMAPS
        case $SIMAPS in
            y)
                IMAPS=""
                SIMAPS="OK"
                ;;
            n)
                IMAPS="#_IMAPS_#"
                SIMAPS="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SPOP3S ]
    do
        read -p 'Allow outbound POP3S (tcp/995)? y/n ' SPOP3S
        case $SPOP3S in
            y)
                POP3S=""
                SPOP3S="OK"
                ;;
            n)
                POP3S="#_POP3S_#"
                SPOP3S="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
    
    while [ -z $SMSSQL ]
    do
        read -p 'Allow outbound MSSQL (tcp/1433)? y/n ' SMSSQL
        case $SMSSQL in
            y)
                MSSQL=""
                SMSSQL="OK"
                ;;
            n)
                MSSQL="#_MSSQL_#"
                SMSSQL="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SMYSQL ]
    do
        read -p 'Allow outbound MYSQL (tcp/3306)? y/n ' SMYSQL
        case $SMYSQL in
            y)
                MYSQL=""
                SMYSQL="OK"
                ;;
            n)
                MYSQL="#_MYSQL_#"
                SMYSQL="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SIRC ]
    do
        read -p 'Allow outbound IRC (tcp/6660 -6699)? y/n ' SIRC
        case $SIRC in
            y)
                IRC=""
                SIRC="OK"
                ;;
            n)
                IRC="#_IRC_#"
                SIRC="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SAHTTP ]
    do
        read -p 'Allow outbound ALT-HTTP (tcp/8080 -8081)? y/n ' SAHTTP
        case $SAHTTP in
            y)
                AHTTP=""
                SAHTTP="OK"
                ;;
            n)
                AHTTP="#_AHTTP_#"
                SAHTTP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done

    while [ -z $SICMP ]
    do
        read -p 'Allow outbound ICMP? y/n ' SICMP
        case $SICMP in
            y)
                ICMP=""
                SICMP="OK"
                ;;
            n)
                ICMP="#_ICMP_#"
                SICMP="OK"
                ;;
            *)
                $echo 'Please enter "y" for yes or "n" for no'
                ;;
        esac
    done
    break
done
}


function set_firewall_ports()
{
$cat << _EOF_

Bifrozt will allow the honeypot to make oubount connections on some ports.
This are the services that will be allowed to make outbound connections:

    FTP         tcp/20 - 21
    DNS         udp/53
    HTTP        tcp/80
    HTTPS       tcp/443
    IRC         tcp/6660 - 6699
    HTTP-ALT    tcp/8080 - 8081
    ICMP

_EOF_
while true
do
    read -p 'Would you like to change these settings? y/n ' CFW
    case $CFW in
        y)
            change_firewall_ports
            break
            ;;
        n)
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


function configure_admin_sshd()
{
$cat << _EOF_

Bifrozt can be remotely administered using SSH. As HonSSH is using the
default SSH port (tcp/22) you should pick another port to run it on.
Its good practice to use an ephemeral port (49152 – 65535).

_EOF_
while [ "$DONE" != 'OK' ]
do
    read -p 'Select a high numbered port (49152 - 65535): ' SSHPORT
    if [[ $SSHPORT -ge 49152 && $SSHPORT -le 65535 ]]
    then
        ADMIN_SSH="$SSHPORT"
        DONE="OK"
    fi
done
}


#
# ======================================================================= DATA CONTROL
#


function change_data_control()
{
    $echo 'Changing data control level 1'

    while [ -z $MSC1 ]
    do
        read -p 'Level 1 - Max source connections: ' MSC1
        MAX_SRC_CON_1="$MSC1"
    done

    while [ -z $MCR1 ]
    do
        read -p 'Level 1 - Max source connection rate: ' MCR1
        MAX_CON_RATE_1="$MCR1"
    done

    while [ -z $MRS1 ]
    do
        read -p 'Level 1 - Max connection pr.sec: ' MRS1
        MAX_RATE_SEC_1="$MRS1"
    done

    $echo 'Changing data control level 2'

    while [ -z $MSC2 ]
    do
        read -p 'Level 2 - Max source connections: ' MSC2
        MAX_SRC_CON_2="$MSC2"
    done

    while [ -z $MCR2 ]
    do
        read -p 'Level 2 - Max source connection rate: ' MCR2
        MAX_CON_RATE_2="$MCR2"
    done

    while [ -z $MRS2 ]
    do
        read -p 'Level 2 - Max connection pr.sec: ' MRS2
        MAX_RATE_SEC_2="$MRS2"
    done
}


function set_data_control()
{
$cat << _EOF_

!! DO NOT CHANGE THESE SETTINGS UNLESS YOU KNOW WHAT YOU ARE DOING !!

These are the current data control settings:

Level 1:
Max source connections:     $MAX_SRC_CON_1
Max source connection rate: $MAX_CON_RATE_1
Max connections pr.sec:     $MAX_RATE_SEC_1

Level 2:
Max source connections:     $MAX_SRC_CON_2
Max source connection rate: $MAX_CON_RATE_2
Max connections pr.sec:     $MAX_RATE_SEC_2

_EOF_
while true
do
    read -p 'Do you want to alter the data control settings? y/n ' CDC
    case $CDC in
        y)
            change_data_control
            break
            ;;
        n)
            break
            ;;
        *)
            $echo 'Please enter "y" for yes or "n" for no'
            ;;
    esac
done
}


#
# ======================================================================= SUPER FUNCTIONS
#


function fresh_configuration()
{
$clear
cat << _EOF_

                    WELCOME!

It appears that this installation havent been
configured yet. In order to use Bifrozt as a
high interaction honeypot router, please answer
the questions to complete the setup. Once the
setup is complete you must reboot for the chagnes
to take affect. If this is the first time you
deploy a honeynet, please make sure you are taking
the proper precautions. Only are responsible for
your systems and what the attackers use them for.

BY INITIATING THIS SETUP YOU AGREE TO UNDERSTANDING
THE RSISK IF DEPLOYING BIFROZT AND TAKE THE SOLE
RESPOSIBILLITY FOR EVERYTHING THAT HAPPENS FROM
THIS POINT AND ONWARDS.

1) I agree to this. Let start the Bifrozt setup.
2) I disagree to this. Get me out of here.

_EOF_
while true
do
    read -p 'Please make a choice: ' YON
    case $YON in
        1)
            $echo 'YES, I ACCEPT THE RISKS AND TAKE SOLE RESPONSIBILLITY'
            $echo 'Starting Bifrozt setup in 5 seconds. Press CTRL + C to abort.'
            new_setup
            break
            ;;
        2)
            $echo 'NO, I DO NOT ACCEPT THESE RISKS, GET ME OUT OF HERE!'
            exit 1
            ;;
        *)
            $echo 'Please make a valid selection (1 or 2)...'
            ;;  
    esac
done
}


function new_setup()
{
    # - Sourece the variables in to template_setup_file
    . $templ_setup
    set_keyboard
    set_tz
    set_hostname
    #set_honssh_boot
    set_dhcpd
    set_firewall_ports
    set_data_control
    configure_admin_sshd
}


function configuration_summary()
{
$echo '---------------------------------------------- Bifrozt summary'
$echo ''
$echo "Keyboard layout:          $KEYBOARD"
$echo "Time zone:                $TIMEZONE"
$echo "Hostname:                 $HOST_NAME"

#if [ -z $HONSSH_BOOT ]
#then
#    echo "Autostart HonSSH:         YES"
#else
#    echo "Autostart HonSSH:         NO"
#fi

$echo "Dhcp lease:               $DHCP_LEASE"
$echo "Domain name:              $DOMAIN_NAME"
$echo "Network:                  $NETWORK"
$echo "Network:                  $NETMASK"
$echo "DHCP start range:         $DHCP_START"
$echo "DHCP stop range:          $DHCP_STOP"
$echo "Gateway:                  $GATEWAY"
$echo "Broadcast:                $BROADCAST"
$echo "DNS server(s):            $DNS_SERVERS"
$echo "Honeypot IP:              $HONEYPOT"
$echo "Honeypot MAC:             $HONEY_MAC"
$echo "Admin SSH:                $ADMIN_SSH"

if [ -z $FTP ]
then
    $echo "FTP:                      Allowed"
else
    $echo "FTP:                      Blocked"
fi

if [ -z $SSH ]
then
    $echo "SSH:                      Allowed"
else
    $echo "SSH:                      Blocked"
fi

if [ -z $TELNET ]
then
    $echo "TELNET:                   Allowed"
else
    $echo "TELNET:                   Blocked"
fi

if [ -z $SMTP1 ]
then
    $echo "SMTP (25):                Allowed"
else
    $echo "SMTP (25):                Blocked"
fi

if [ -z $DNS ]
then
    $echo "DNS:                      Allowed"
else
    $echo "DNS:                      Blocked"
fi

if [ -z $HTTP ]
then
    $echo "HTTP:                     Allowed"
else
    $echo "HTTP:                     Blocked"
fi

if [ -z $POPV2 ]
then
    $echo "POPV2:                    Allowed"
else
    $echo "POPV2:                    Blocked"
fi

if [ -z $POPV3 ]
then
    $echo "POPV3:                    Allowed"
else
    $echo "POPV3:                    Blocked"
fi

if [ -z $IMAP ]
then
    $echo "IMAP:                     Allowed"
else
    $echo "IMAP:                     Blocked"
fi

#
#   ...Must convert this script to python ASAP.....
#

if [ -z $HTTPS ]
then
    $echo "HTTPS:                    Allowed"
else
    $echo "HTTPS:                    Blocked"
fi

if [ -z $SMB ]
then
    $echo "SMB:                      Allowed"
else
    $echo "SMB:                      Blocked"
fi

if [ -z $AFP ]
then
    $echo "AFP:                      Allowed"
else
    $echo "AFP:                      Blocked"
fi

if  [ -z $SMTP2 ]
then
    $echo "SMTP (587):               Allowed"
else
    $echo "SMTP (587):               Blocked"
fi

if [ -z $IMAPS ]
then
    $echo "IMAPS:                    Allowed"
else
    $echo "IMAPS:                    Blocked"
fi

if [ -z $POP3S ]
then
    $echo "POP3S:                    Allowed"
else
    $echo "POP3S:                    Blocked"
fi

if [ -z $MSSQL ]
then
    $echo "MSSQL:                    Allowed"
else
    $echo "MSSQL:                    Blocked"
fi

if [ -z $MYSQL ]
then
    $echo "MYSQL:                    Allowed"
else
    $echo "MYSQL:                    Blocked"
fi

if [ -z $IRC ]
then
    $echo "IRC:                      Allowed"
else
    $echo "IRC:                      Blocked"
fi

if [ -z $AHTTP ]
then
    $echo "Alt-HTTP:                 Allowed"
else
    $echo "Alt-HTTP:                 Blocked"
fi

if [ -z $ICMP ]
then
    $echo "ICMP:                     Allowed"
else
    $echo "ICMP:                     Blocked"
fi

$cat << _EOF_
- Data control level 1
Max source connections:         $MAX_SRC_CON_1
Max source connection rate:     $MAX_CON_RATE_1
Max connections pr.sec:         $MAX_RATE_SEC_1
- Data control level 2
Max source connections:         $MAX_SRC_CON_2
Max source connection rate:     $MAX_CON_RATE_2
Max connections pr.sec:         $MAX_RATE_SEC_2

---------------------------------------------- Generated: $($date +"%Y%m%d - %T")
_EOF_
}


#
# ============================================================================== COMPILE FUNCTIONS
#

# !!!!!! CLEAN UP !!!!!!!

function compile_pfconf()
{
    $echo "Generating firewall rule file: $new_pfconf"

    $sed -e "s/#_HOST_NAME_#/$HOST_NAME/g" -e "s/#_HONSSH_BOOT_#/$HONSSH_BOOT/g" \
         -e "s/#_DHCP_LEASE_#/$DHCP_LEASE/g" -e "s/#_DOMAIN_NAME_#/$DOMAIN_NAME/g" \
         -e "s/#_NETWORK_#/$NETWORK/g" -e "s/#_NETMASK_#/$NETMASK/g" \
         -e "s/#_DHCP_START_#/$DHCP_START/g" -e "s/#_DHCP_STOP_#/$DHCP_STOP/g" \
         -e "s/#_GATEWAY_#/$GATEWAY/g" -e "s/#_BROADCAST_#/$BROADCAST/g" \
         -e "s/#_DNS_SERVERS_#/$DNS_SERVERS/g" -e "s/#_HONEYPOT_#/$HONEYPOT/g" \
         -e "s/#_HONEY_MAC_#/$HONEY_MAC/g" -e "s/#_FTP_#/$FTP/g" \
         -e "s/#_SSH_#/$SSH/g" -e "s/#_TELNET_#/$TELNET/g" \
         -e "s/#_SMTP1_#/$SMTP1/g" -e "s/#_DNS_#/$DNS/g" \
         -e "s/#_HTTP_#/$HTTP/g" -e "s/#_POPV2_#/$POPV2/g" \
         -e "s/#_POPV3_#/$POPV3/g" -e "s/#_IMAP_#/$IMAP/g" \
         -e "s/#_HTTPS_#/$HTTPS/g" -e "s/#_SMB_#/$SMB/g" \
         -e "s/#_AFP_#/$AFP/g" -e "s/#_SMTP2_#/$SMTP2/g" \
         -e "s/#_IMAPS_#/$IMAPS/g" -e "s/#_POP3S_#/$POP3S/g" \
         -e "s/#_MSSQL_#/$MSSQL/g" -e "s/#_MYSQL_#/$MYSQL/g" \
         -e "s/#_IRC_#/$IRC/g" -e "s/#_AHTTP_#/$AHTTP/g" \
         -e "s/#_ICMP_#/$ICMP/g" -e "s/#_ADMIN_SSH_#/$ADMIN_SSH/g" \
         -e "s/#_MAX_SRC_CON_1_#/$MAX_SRC_CON_1/g" -e "s/#_MAX_CON_RATE_1_#/$MAX_CON_RATE_1/g" \
         -e "s/#_MAX_RATE_SEC_1_#/$MAX_RATE_SEC_1/g" -e "s/#_MAX_SRC_CON_2_#/$MAX_SRC_CON_2/g" \
         -e "s/#_MAX_CON_RATE_2_#/$MAX_CON_RATE_2/g" -e "s/#_MAX_RATE_SEC_2_#/$MAX_RATE_SEC_2/g" \
         -e "s/#_ACTIVE_#//g" $templ_pfconf | $grep -v "#" | $grep '[a-z,A-Z,0-9]' > $new_pfconf

    $echo "Checking firewall syntax.."

    sleep 0.2

    if [ -e $new_pfconf ]
    then
        $pfctl -vnf $new_pfconf 1>/dev/null
        if [ $? != 0 ]
        then
            $echo 'ERROR: Error(s) was found in the firewall syntax!'
            $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
            exit 1
        else
            $echo 'The firewall syntax appears to be okay :)'
        fi
    fi
}


function compile_dhcpdconf()
{
    $echo "Generating dhcpd.conf: $new_dhcpd"

    $sed -e "s/#_DHCP_LEASE_#/$DHCP_LEASE/g" -e "s/#_DOMAIN_NAME_#/$DOMAIN_NAME/g" \
         -e "s/#_NETWORK_#/$NETWORK/g" -e "s/#_NETMASK_#/$NETMASK/g" \
         -e "s/#_DHCP_START_#/$DHCP_START/g" -e "s/#_DHCP_STOP_#/$DHCP_STOP/g" \
         -e "s/#_GATEWAY_#/$GATEWAY/g" -e "s/#_BROADCAST_#/$BROADCAST/g" \
         -e "s/#_DNS_SERVERS_#/$DNS_SERVERS/g" -e "s/#_HONEYPOT_#/$HONEYPOT/g" \
         -e "s/#_HONEY_MAC_#/$HONEY_MAC/g" -e "s/#_ACTIVE_#//g" $templ_dhcpd  > $new_dhcpd

    $sleep 0.2

    if [ -e $new_dhcpd ]
    then
        $echo 'New dhcpd.conf was created'
    else
        $echo "ERROR: Unable to create $new_dhcpd"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi
}


function compile_sshdconfig()
{
    $echo "Generating sshd_config: $new_sshd"

    $sed -e "s/#_ADMIN_SSH_#/$ADMIN_SSH/g" -e "s/#_ACTIVE_#//g" $templ_sshd > $new_sshd

    $sleep 0.2

    if [ -e $new_sshd ]
    then
        $echo 'New sshd_config was created'
    else
        $echo "ERROR: Unable to create $new_sshd"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi
}


function compile_rclocal()
{
    $echo "Generating rc.local: $new_rc"

    $cp $templ_rcconf $new_rcconf
    $cp $templ_motd $new_motd

    $sed -e "s/#_ACTIVE_#//g" -e "s/#_HONSSH_BOOT_#/$HONSSH_BOOT/g" $templ_rc > $new_rc

    $sleep 0.2

    if [ -e $new_rc ]
    then
        $echo 'New rc.conf was created'
    else
        $echo "ERROR: Unable to create $new_rc"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi
}


function compile_hostname_ifs()
{
    $echo "Generating network files: $new_em0 $new_em1 $new_myname"

    $sed -e "s/#_ACTIVE_#//g" $templ_em0 > $new_em0

    $sleep 0.2

    if [ -e $new_em0 ]
    then
        $echo 'New hostname.em0 was created'
    else
        $echo "ERROR: Unable to create $new_em0"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi

    $sed -e "s/#_ACTIVE_#//g" -e "s/#_GATEWAY_#/$GATEWAY/g" \
         -e "s/#_NETMASK_#/$NETMASK/g" -e "s/#_BROADCAST_#/$BROADCAST/g" $templ_em1 > $new_em1

    $sleep 0.2

    if [ -e $new_em1 ]
    then
        $echo 'New hostname.em1 was created'
    else
        $echo "ERROR: Unable to create $new_em1"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi

    $sed -e "s/#_ACTIVE_#//g" -e "s/#_HOST_NAME_#/$HOST_NAME/g" \
         -e "s/#_DOMAIN_NAME_#/$DOMAIN_NAME/g" $templ_myname > $new_myname

    $sleep 0.2

    if [ -e $new_myname ]
    then
        $echo 'New myname was created'
    else
        $echo "ERROR: Unable to create $new_myname"
        $echo 'Please submitt a technical ticket here: https://sourceforge.net/p/bifrozt/tickets/'
        exit 1
    fi
}


function finalize_setup()
{
    $sleep 2
    $clear

    $echo 'The configuration will be applied system wide in 10 seconds.'
    $echo 'The system will be rebooted imedeatly after the changes have been applied.'
    $echo 'Press CTRL + C to abort if you want to abort.'

    for i in {10..1}
    do
        $echo "Point of no return in: $i"
        $sleep 1
    done

    $cp $new_dhcpd $dhcpd_conf
    $cp $new_pfconf $pf_conf
    $cp $new_sshd $sshd_config
    $cp $new_em0 $external_if
    $cp $new_em1 $internal_if
    $cp $new_rc $rc_local
    $cp $new_rcconf $rc_conf
    $cp $new_myname $hostname_file
    $cp $new_motd $motd

    $echo 'net.inet.ip.forwarding=1' > $sysctl_conf
    $echo "keyboard.encoding=$KEYBOARD" > $kblayout

    $ln -fs /usr/share/zoneinfo/$TIMEZONE /etc/localtime

    $reboot
}


if [ ! -f $new_setup ]
then
    fresh_configuration
    configuration_summary > /home/winnie/Bifrozt_configuration_summary.txt
    compile_pfconf
    compile_dhcpdconf
    compile_sshdconfig
    compile_rclocal
    compile_hostname_ifs
    finalize_setup
fi

#
# Mother of God...this was a long crappy script...I need a drink, no - i need two! :D
#

exit 0
