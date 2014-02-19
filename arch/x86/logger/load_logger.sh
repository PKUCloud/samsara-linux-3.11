#!/bin/sh
module="logger"
device="logger"
mode="664"

# Group: since distributions do it differently, look for wheel or use staff
if grep '^staff:' /etc/group > /dev/null; then
    group="staff"
else
    group="wheel"
fi

# remove stale nodes
rm -f /dev/${device}

# invoke insmod with all arguments we got
# and use a pathname, as newer modutils don't look in . by default
#/sbin/insmod -f $module.ko $* || exit 1

major=`cat /proc/devices | awk "\\$2==\"$module\" {print \\$1}"`

mknod /dev/${device} c $major 0

# give appropriate group/permissions
chgrp $group /dev/${device}
chmod $mode  /dev/${device}
