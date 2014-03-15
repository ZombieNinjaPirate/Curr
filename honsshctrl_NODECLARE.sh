#!/usr/bin/env bash


shopt -s -o nounset


#
#   Management script for HonSSH
#
#   Author:     Black September
#   Date:       2014, March 1
#   Version:    1.2.2
#   Plattform:  n/a
#


declare -rx Script="${0##*/}"
declare honssh_tac="honssh.tac"
declare honssh_log="logs/honssh.log"
declare honssh_pid="honssh.pid"


# ----- We require one argument
if [ $# != 1 ]
then
    echo 'ERROR: This script requiers one argument'
    echo "USAGE: $Script HELP"
    exit 1
fi


# ----- If the public/private keys are missing, generate them
if [ ! -e id_rsa ]
then
    echo "WARNING: Unable to find id_rsa, generating it now..."
    ckeygen -t rsa -f id_rsa
fi


if [ ! -e id_rsa.pub ]
then
    echo "WARNING: Unable to find id_rsa.pub, generating it now..."
    ckeygen -t rsa -f id_rsa
fi


# ----- Start HonSSh
function start_honssh()
{
    if [ ! -e $honssh_pid ]
    then
        echo "Starting honssh in background..."
        twistd -y $honssh_tac -l $honssh_log --pidfile $honssh_pid
    else
        echo "ERROR: There appears to be a PID file already, HonSSH might be running"
        exit 1
    fi
}


# ----- Stop HonSSH
function stop_honssh()
{
    if [ -e $honssh_pid ]
    then
        honey_pid="$(cat $honssh_pid)"
        echo "Attempting to stop HonSSH ($honey_pid)..."
        kill -15 $honey_pid &>/dev/null
        if [ $? != 0 ]
        then
            echo "ERROR: Unable to stop HonSSH ($honey_pid)"        
            exit 1
        else
            echo "OK: HonSSH has been stopped"
        fi
    else
        echo "ERROR: No PID file was found, HonSSH might not be running."
        exit 1
    fi
}


# ----- Help text
function help_honssh()
{
cat << _EOF_

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
