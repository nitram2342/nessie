#!/bin/sh

TARGET=$@

if [ -z "$TARGET" ] ; then
    echo "Usage: $0 <target>"
    exit
fi

PORTS=21,22,23,25,53,80,110,111,135,139,161,389,443,445,636,993,1025,3389,8080
nmap -sn -PS$PORTS -oX pingsweep_`date +"%F_%X"`.xml $TARGET
