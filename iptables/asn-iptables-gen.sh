#!/bin/bash

# asn-iptables-gen.sh: Generates a rules script for iptables based on an input AS-SET or ASN.

# Copyright 2014 Andrea Gozzi
# Copyright 2009-2011 Matthew Walster

# Distributed under the terms of the GNU General Public Licence

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Define a usage statement
usage()
{
        echo "$0: A iptables rules script generator"
        echo "Usage: $0 [OPTS] AS-SET"
        echo "    -t | --type [ iptables ]"
        echo "    -n | --name [ Filter Name ]"
        echo "    -h | --host [ WHOIS server ]"
        echo "         --ipv4"
        echo "         --ipv6"
        echo " -ipth | --iptheader  [ iptables header file ]"
        echo " -iptd | --iptdesc    [ iptables rule comment ]"
        echo " -iptc | --iptchain   [ iptables chain name ]"
        echo "         --aggregate"
        echo "         --verbose    [ show generated rules on stdout ]"
}

# Initialise some variables, to make it safe to use
SEQNUM=10
INC=5
WHOISSERVER="whois.radb.net"
IP_VERSION="4"
CRAZY="0"
AGGREGATE="0"

VERBOSE="0"

# default shell
DEF_SHELL=/bin/bash

# path to iptables
IPTABLES_BIN="/sbin/iptables"

# header to be included in iptables rules script
# fill this to avoid passing the parameter each time
# see repo for example file with substitutions
#HEADER_FILE="/etc/iptables/header.txt"
HEADER_FILE=""

# output directory for iptables rules script
DEFAULT_DIR="/etc/iptables"

CURDATE=$(date +%m-%d-%Y)
CURUSER=$(whoami)

# Parse the command line options
while [[ $1 = -* ]]; do
        case "$1" in
                -t|--type)
                        TYPE="$2"
                        shift 2
                        ;;
                -n|--name)
                        FILTERNAME="$2"
                        shift 2
                        ;;
                -h|--host)
                        WHOISSERVER="$2"
                        shift 2
                        ;;
                -s|--seq)
                        SEQNUM="$2"
                        INC="$3"
                        shift 3
                        ;;
                --ipv4)
                        IP_VERSION="4"
                        shift
                        ;;
                --ipv6)
                        IP_VERSION="6"
                        shift
                        ;;
                -ipth|--iptheader)
                        HEADER_FILE="$2"
                        shift 2
                        ;;
                -iptd|--iptdesc)
                        IPTABLES_DESC="$2"
                        shift 2
                        ;;
                -iptc|--iptchain)
                        IPTABLES_CHAIN="$2"
                        shift 2
                        ;;
                --aggregate)
                        AGGREGATE="1"
                        shift
                        ;;
                --crazy)
                        CRAZY="1"
                        shift
                        ;;
                --verbose)
                        VERBOSE="1"
                        shift
                        ;;
                --help)
                        usage
                        exit 1
                        ;;
                *)
                        echo "Error: Unknown option: $1" >&2
                        usage
                        exit 1
                        ;;
        esac
done

# If no arguments, then just show the usage statement
if [[ $# -lt 1 ]]
        then usage
        exit 1
fi

# Do we have an AS-SET or an ASN?
IS_SET=$(whois -h whois.radb.net $1 | grep -i ^as-set: | awk -F: '{print $1}')

# If we've got an AS-SET, use the handy !i and ,1 commands on RADB
if [[ "as-set" == "$IS_SET" ]]
then
        AS_LIST=$(whois -h whois.radb.net \!i$1,1 | sed '/^\[/d' | sed 2\!d)
else
        AS_LIST=$1
fi

if [[ $CRAZY == 0 ]]
then
        # Find out which prefixes are contained within that AS number
        for i in $AS_LIST
        do
                case "$IP_VERSION" in
                        4)
                                IP_LIST_UNSORTED+=$(whois -h $WHOISSERVER -- "-i origin $i" | grep ^route: | cut -f 2 -d: | sed 's/ //g')
                                ;;
                        6)
                                IP_LIST_UNSORTED+=$(whois -h $WHOISSERVER -- "-i origin $i" | grep ^route6: | cut -f 2- -d: | sed 's/ //g')
                                ;;
                esac
                IP_LIST_UNSORTED+=$(echo " ")
        done
elif [[ $CRAZY == 1 ]]
then
        tmpfile=$(mktemp /tmp/filter.XXXXXXXX) || exit 1
        case "$IP_VERSION" in
                4)
                        curl ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz \
                                | gunzip -dc \
                                | grep -e '^route:' -e '^origin:' \
                                | sed -e 'N;s/\n/ /' -re 's/route:\s+//g;s/origin:\s+//g' \
                                >$tmpfile
                        GREP_OPTS=$(sed -re 's/AS/ -e AS/g' <<<$AS_LIST)
                        IP_LIST_UNSORTED=$(grep $GREP_OPTS $tmpfile | cut -f1 -d" ")
                        ;;
                6)
                        curl ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz \
                                | gunzip -dc \
                                | grep -e '^route:' -e '^origin:' \
                                | sed -e 'N;s/\n/ /' -re 's/route6:\s+//g;s/origin:\s+//g' \
                                >$tmpfile
                        GREP_OPTS=$(sed -re 's/AS/ -e AS/g' <<<$AS_LIST)
                        IP_LIST_UNSORTED=$(grep $GREP_OPTS $tmpfile | cut -f1 -d" ")
                        ;;
        esac

        rm $tmpfile
fi

# Remove duplicate routes
IP_LIST=$(printf "%s\n" $IP_LIST_UNSORTED | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | uniq)

#
if [[ "$AGGREGATE" == 1 ]]
then
        tmpfile=$(mktemp /tmp/filteraggr.XXXXXXXX) || exit 1

        for i in $IP_LIST
        do
                echo $i >> $tmpfile
        done

        IP_LIST_NEW=$(aggregate < $tmpfile)
	rm $tmpfile
elif [[ "$AGGREGATE" == 0 ]]
then
        IP_LIST_NEW=$IP_LIST
fi

# check environment
if [[ "$TYPE" == "iptables" ]]
then
	if [[ -z "$IPTABLES_DESC" ]]
	then
		echo "$0: error: invalid iptables rule description"
		exit 1
	fi

	if [[ -z "$IPTABLES_BIN" ]]
	then
		echo "$0: error: empty iptables bin path"
		exit 1
	else
		if [[ ! -e "$IPTABLES_BIN" ]]
		then
			echo "$0: error: empty iptables bin path"
			exit 1
		fi
	fi

	if [[ ! -d "$DEFAULT_DIR" ]]
	then
		mkdir -p "$DEFAULT_DIR"
		if [[ ! -d "$DEFAULT_DIR" ]]
		then
			echo "$0: error: could not create iptables rule script output directory"
			exit 1
		fi
	fi

	if [[ "$IP_VERSION" == 6 ]]
	then
		IPTABLES_BIN="/sbin/ip6tables"
	fi

	if [[ -n "$HEADER_FILE" ]]
	then
		if [[ -e "$HEADER_FILE" ]]
		then
			cp $HEADER_FILE $DEFAULT_DIR/$IPTABLES_DESC.sh
			# process substitutions in header file
			perl -pi -e "s=%DEFSHELL%=#!$DEF_SHELL=g" $DEFAULT_DIR/$IPTABLES_DESC.sh
			perl -pi -e "s/%ASNUM%/$1/g" $DEFAULT_DIR/$IPTABLES_DESC.sh
			perl -pi -e "s/%CURDATE%/$CURDATE/g" $DEFAULT_DIR/$IPTABLES_DESC.sh
			perl -pi -e "s/%CURUSER%/$CURUSER/g" $DEFAULT_DIR/$IPTABLES_DESC.sh
			perl -pi -e "s#%IPTBIN%#IPTABLES_BIN="$IPTABLES_BIN" \-v#g" $DEFAULT_DIR/$IPTABLES_DESC.sh
		else
			echo "$0: error: specified header file does not exist"
			exit 1
		fi
	else
		# create file and add sh def
		touch $DEFAULT_DIR/$IPTABLES_DESC.sh
		if [[ -e "$DEFAULT_DIR/$IPTABLES_DESC.sh" ]]
		then
			echo -e "#!$DEF_SHELL\n" >> $DEFAULT_DIR/$IPTABLES_DESC.sh
			echo -e "IPTABLES_BIN=\"$IPTABLES_BIN -v\"\n\n" >> $DEFAULT_DIR/$IPTABLES_DESC.sh
		else
			echo "$0: error: could not create iptables rule script output file"
			exit 1	
		fi
	fi
fi

# generate rules
for i in $IP_LIST_NEW
do
        case "$TYPE" in
                iptables)
			if [[ "$VERBOSE" == "1" ]]
			then
                        	echo "\$IPTABLES_BIN -I INPUT -s $i -j $IPTABLES_CHAIN -m comment --comment \"$IPTABLES_DESC\""
			fi
			echo "\$IPTABLES_BIN -I INPUT -s $i -j $IPTABLES_CHAIN -m comment --comment \"$IPTABLES_DESC\"" >> $DEFAULT_DIR/$IPTABLES_DESC.sh
			let SEQNUM=SEQNUM+$INC
                        ;;
                *)
                        echo $i
                        ;;
        esac
done

echo -e "\nexit 0" >> $DEFAULT_DIR/$IPTABLES_DESC.sh

exit 0