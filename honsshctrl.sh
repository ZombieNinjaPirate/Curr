#!/usr/bin/env bash

shopt -s -o nounset

#
#   Management script for HonSSH
#
#   Author:     Black September
#   Date:       2014, March 1
#   Version:    1.2.1
#

# ----- Absolute path declarations
declare -rx Script="${0##*/}"
declare -rx twistd="/usr/local/bin/twistd"
declare -rx cat="/bin/cat"
declare -rx echo="/bin/echo"
declare -rx kill="/bin/kill"

# ----- Files and directories
declare main_dir="/HONEY"
declare honssh_tac="$main_dir/honssh.tac"
declare honssh_log="$main_dir/logs/honssh.log"
declare honssh_pid="$main_dir/honssh.pid"


if [ $# != 1 ]
then
    $echo 'ERROR: This script requiers one argument'
    $echo "USAGE: $Script HELP"
    exit 1
fi


function start_honssh()
{
    if [ ! -e $honssh_pid ]
    then
        $echo "Starting honssh in background..."
        $twistd -y $honssh_tac -l $honssh_log --pidfile $honssh_pid
    else
        $echo "ERROR: There appears to be a PID file already, HonSSH might be running"
        exit 1
    fi
}


function stop_honssh()
{
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
