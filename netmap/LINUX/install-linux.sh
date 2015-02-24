#!/bin/bash
if [ $# -ne 1 ]; then
	echo "provide ifname"
	exit 0
fi
#make; make KSRC=$1
#make clean; make KSRC=$1 &&
cp ../sys/net/netmap* /usr/include/net/
rmmod ixgbe
rmmod e1000
rmmod netmap_lin
insmod netmap_lin.ko
insmod ixgbe/ixgbe.ko
insmod e1000/e1000.ko
ifconfig $1 up
ethtool -A $1 autoneg off rx off
ethtool -A $1 autoneg off tx off
