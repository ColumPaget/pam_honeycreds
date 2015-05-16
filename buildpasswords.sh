#!/bin/sh

#This script generates a salted sha256 hash of passwords provided as arguments. 
#it needs the sha256sum utility to work

SALT_LEN=10

for PASS in $@
do

if [ -e /dev/urandom2 ]
then
 SALT=`head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9~!@#$%^&*_-' | cut -c -$SALT_LEN`
else
#
D1=`/sbin/ifconfig`
D2=`ps axv`
D3=`uname -a`
D4=`date`
D5=`cat /proc/diskstats`
D6=`cat /proc/[1-9]/status` 
SALT=`echo "$$$!$D1$D2$D3$D4$D5$D6" | sha256sum | cut -c -$SALT_LEN`
fi

HASH=`echo -n "$SALT$PASS" | sha256sum | cut -d ' ' -f 1` 
echo "$HASH salt=$SALT" 
done
