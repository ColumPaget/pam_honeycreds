#!/bin/sh

#This script generates a salted sha256 hash of passwords provided as arguments. 
#it needs the sha256sum utility to work

for PASS in $@
do
LEN=`echo "5+($$%6)" | bc`

if [ -e /dev/urandom ]
then
 SALT=`head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9~!@#$%^&*_-' | cut -c -$LEN`
else
SALT=`date +%H%M%S`
SALT="$SALT$$$!"
fi

VAL="$SALT$PASS"
HASH=`echo -n $VAL | sha256sum | cut -d ' ' -f 1` 
echo "$HASH salt=$SALT" 
done
