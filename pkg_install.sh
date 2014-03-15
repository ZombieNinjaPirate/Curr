#!/bin/sh


#
#   Installs the required Bifrozt packages and dependencies
#
#   Date:		2014, March 15
#   Version:	1.0.0
#   Plattform:	OpenBSD 5.4 amd64
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


export PKG_PATH=http://ftp.eu.openbsd.org/pub/OpenBSD/$(uname -r)/packages/amd64/

sleep 1

clear
echo -e '\n   -------==== Installing Bifrozt Dependencies ====------\n\n'

echo -e 'Installing software packages...\n'
pkg_add -v -i GeoIP
pkg_add -v -i bash
pkg_add -v -i curl
pkg_add -v -i pftop
pkg_add -v -i unzip
pkg_add -v -i vim
pkg_add -v -i wget
pkg_add -v -i py-paramiko
pkg_add -v -i py-asn1
pkg_add -v -i py-twisted-conch
pkg_add -v -i py-twisted-core
pkg_add -v -i py-twisted-lore
pkg_add -v -i py-twisted-mail
pkg_add -v -i py-twisted-names
pkg_add -v -i py-twisted-news
pkg_add -v -i py-twisted-pair
pkg_add -v -i py-twisted-runner
pkg_add -v -i py-twisted-web
pkg_add -v -i py-twisted-web2
pkg_add -v -i py-twisted-words

echo -e '\nChecking for package updates...'
pkg_add -ui -v

echo -e '\nCreating symbolic links for ruby...'
ln -sf /usr/local/bin/ruby18 /usr/local/bin/ruby
ln -sf /usr/local/bin/erb18 /usr/local/bin/erb
ln -sf /usr/local/bin/irb18 /usr/local/bin/irb
ln -sf /usr/local/bin/rdoc18 /usr/local/bin/rdoc
ln -sf /usr/local/bin/ri18 /usr/local/bin/ri
ln -sf /usr/local/bin/testrb18 /usr/local/bin/testrb

echo -e '\nCreating symbolic links for python...'
ln -sf /usr/local/bin/python2.7 /usr/local/bin/python
ln -sf /usr/local/bin/python2.7-2to3 /usr/local/bin/2to3
ln -sf /usr/local/bin/python2.7-config /usr/local/bin/python-config
ln -sf /usr/local/bin/pydoc2.7 /usr/local/bin/pydoc

echo -e '\nSetting login shell for "winnie" to /usr/local/bin/bash...'
usermod -s /usr/local/bin/bash winnie

echo -e '\n   ------==== Installation Complete ====------\n\n'
