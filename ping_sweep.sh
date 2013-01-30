#!/bin/sh

TARGET=$@
BASEDIR=$(dirname $0)

if [ -z "$TARGET" ] ; then
    echo "Usage: $0 <target>"
    exit
fi

TCP_PORTS=21,22,23,25,53,80,81,82,110,111,135,139,161,389,443,445,636,993,1025,1352,1433,1434,1157,3128,3389,8080,8081,8118,8443
UDP_PORTS=51,161

BASENAME="pingsweep_`date +"%F_%X"`"
nmap -sn -PS$TCP_PORTS -PU$UDP_PORTS -oX ${BASENAME}.xml $TARGET
$BASEDIR/hosts_up.pl --xml ${BASENAME}.xml --out ${BASENAME}.hosts_up
