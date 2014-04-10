#!/usr/local/bin/bash


#
#
#   HonSSH update script.
#
#   Date:       2014, March 16
#   Version:    1.0.2
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


# ----- Absolute path declarations.
declare -rx Script="${0##*/}"
declare -rx cat="/bin/cat"
declare -rx echo="/bin/echo"
declare -rx mv="/bin/mv"
declare -rx rm="/bin/rm"
declare -rx sleep="/bin/sleep"
declare -rx cut="/usr/bin/cut"
declare -rx grep="/usr/bin/grep"
declare -rx sed="/usr/bin/sed"
declare -rx git="/usr/local/bin/git"


# ----- File declarations
declare revnr_file="/HONEY/.git/ORIG_HEAD"
declare honssh_pid="/HONEY/honssh.pid"
declare honssh_cfg="/HONEY/honssh.cfg"
declare honssh_bup="/HONEY/honssh.cfg.BACKUP"
declare honssh_ctrl="/HONEY/honsshctrl.sh"


# ----- We demand one argument.
if [ $# != 1 ]
then
    $echo "USAGE: $Script HELP" 
    exit 1
fi


# ----- Find and print the installed version.
function get_version()
{
    honssh_vers="$($cat $revnr_file  | $cut -c1-12)"
    $echo "Current HonSSH version: $honssh_vers"
}


# ----- Check HonSSH state
function check_state()
{
    if [ -e $honssh_pid ]
    then
        $echo 'ERROR: HonSSH cant be running during this task!'
        exit 1
    fi
}


# ----- Pull down the latest version.
function get_latest()
{
    check_state

    if [ -e $honssh_cfg ]
    then
        $mv $honssh_cfg $honssh_bup
    fi

    $sleep 0.2

    cd /HONEY && $git pull

    $sleep 0.2

    if [ -f $honssh_ctrl ]
    then
        $rm $honssh_ctrl
    fi
    
    if [ -e $honssh_cfg ]
    then
        $mv $honssh_cfg $honssh_new
        $sleep 0.2
        $mv $honssh_bup $honssh_cfg
        $echo 'Your original honssh.cfg file have replaced the newest version,'
        $echo "the newest version has been renamed to $honssh_new."
        $echo 'You might want to inspect the newest version before starting HonSSH again.$'
    else
        if [ -f $honssh_bup ]
        then
            $mv $honssh_bup $honssh_cfg
        fi
    fi
}


# ----- Pull down only missing files.
function get_missing()
{
    find_missing()
    {
        cd /HONEY && $git diff --name-status\
        | $sed -n '/^D/ s/^D\s*//gp'\
        | $sed 's/^ *//'\
        | $grep -v 'honsshctrl.sh'
    }

    if [ -z "$(find_missing)" ]
    then
        $echo 'OK: You dont appear to be missing any files'
    else
        $echo 'These files appear to be missing:'
        find_missing
        while true
        do
            read -p 'Do you want me to fetch those files? y/n ' GM
            case $GM in
                y)
                    check_state;
                    find_missing | xargs $git checkout origin/master;
                    exit 0
                    ;;
                n)
                    $echo 'Okay, you are the boss. Bye!';
                    exit 0
                    ;;
                *)
                    $echo 'Please enter "y" for yes and "n" for no.'
                    ;;
            esac
        done
    fi
}


function help_text()
{
$cat << _EOF_

        USAGE: $Script [ARGUMENT]

        $Script UPDATE

        Backsup the honssh.cfg, pulls down the latest version of HonSSH and
        replaces the default honssh.cfg with the original.

        $Script MISSING

        Checks the currently installed version for missing files and pulls
        the latest version of the missing file.

        $Script VERSION

        Prints the version number of the currently installed HonSSH.

        $Script HELP

        Shows this help text.

_EOF_
}


if [ $1 = 'UPDATE' ]
then
    $echo "Moving $honssh_cfg to $honssh_bup"
    get_latest
fi


if [ $1 = 'MISSING' ]
then
    get_missing
fi


if [ $1 = 'VERSION' ]
then
    get_version
fi


if [ $1 = 'HELP' ]
then
    help_text
fi


if [[ $1 != 'UPDATE' && $1 != 'MISSING' && $1 != 'VERSION' && $1 != 'HELP' ]]
then
    $echo "ERROR: You provided an invalid argument!!"
    help_text
    exit 1
fi


exit 0
