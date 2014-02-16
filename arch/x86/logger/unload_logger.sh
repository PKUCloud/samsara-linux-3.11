#!/bin/sh
module="logger"
device="logger"

# invoke rmmod with all arguments we got
/sbin/rmmod $module $* || exit 1

# remove nodes
rm -f /dev/${device}

exit 0
