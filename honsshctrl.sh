#!/usr/bin/env bash

shopt -s -o nounset


#
#
#   HonSSH management script.
#   NOTE: This version uses the absolute path declarations under OpenBSD 5.4 
#
#   Date:       2014, March 1
#   Version:    1.2.3
#   Plattform:  OpenBSD 5.4 amd64
#
#   Copyright (c) 2014, Black September - Honeypot Development
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
declare -rx id="/usr/bin/id"
declare -rx twistd="/usr/local/bin/twistd"
declare -rx ckeygen="/usr/local/bin/ckeygen"
declare -rx cat="/bin/cat"
declare -rx echo="/bin/echo"
declare -rx kill="/bin/kill"


# ----- Files and directories
declare main_dir="/HONEY"
declare honssh_tac="$main_dir/honssh.tac"
declare honssh_log="$main_dir/logs/honssh.log"
declare honssh_pid="$main_dir/honssh.pid"
declare id_rsa="$main_dir/id_rsa"
declare id_rsa_pub="$main_dir/id_rsa.pub"


# ----- We require one argument
if [ $# != 1 ]
then
    $echo 'ERROR: This script requiers one argument'
    $echo "USAGE: $Script HELP"
    exit 1
else
    cd $main_dir
fi


# ----- If the public/private keys are missing, generate them
if [ ! -f $id_rsa ]
then
    $echo "WARNING: Unable to find $id_rsa, generating it now..."
    $ckeygen -t rsa -f id_rsa -f $id_rsa
fi


if [ ! -f $id_rsa_pub ]
then
    $echo "WARNING: Unable to find $id_rsa_pub, generating it now..."
    $ckeygen -t rsa -f id_rsa -f $id_rsa
fi


# ----- Check if effective UID is root
function root_check()
{
    if [ $($id -u) != 0 ]
    then
        $echo 'ERROR: You have to be root to do this!'
        exit 1
    fi
}


# ----- Start HonSSH
function start_honssh()
{
    root_check

    if [ ! -e $honssh_pid ]
    then
        $echo "Starting honssh in background..."
        $twistd -y $honssh_tac -l $honssh_log --pidfile $honssh_pid
    else
        $echo "ERROR: There appears to be a PID file already, HonSSH might be running"
        exit 1
    fi
}


# ----- Stop HonSSH
function stop_honssh()
{
    root_check

    if [ -e $honssh_pid ]
    then
        honey_pid="$($cat $honssh_pid)"
        $echo "Attempting to stop HonSSH ($honey_pid)..."
        $kill -15 $honey_pid &>/dev/null
        if [ $? != 0 ]
        then
            $echo "ERROR: Unable to stop HonSSH ($honey_pid)"        
            exit 1
        else
            $echo "OK: HonSSH has been stopped"
        fi
    else
        $echo "ERROR: No PID file was found, HonSSH might not be running."
        exit 1
    fi
}


# ----- Help text
function help_honssh()
{
$cat << _EOF_

    USAGE: $Script [ARGUMENT]

    $Script      START       Start HonSSH
    $Script      STOP        Stop HonSSH
    $Script      RESTART     Restart HonSSH
    $Script      HELP        Show this help

_EOF_
}


# ----- Check for known arguments, let the user know if they missed anything
if [ $1 = 'START' ]
then
    start_honssh
fi


if [ $1 = 'STOP' ]
then
    stop_honssh
fi


if [ $1 = 'RESTART' ]
then
    stop_honssh
    sleep 0.5
    start_honssh
fi


if [ $1 = 'HELP' ]
then
    help_honssh
fi


if [[ $1 != 'START' && $1 != 'STOP' && $1 != 'HELP' && $1 != 'RESTART' ]]
then
    help_honssh
fi


exit 0
