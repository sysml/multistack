#!/bin/sh

if [ ! $# = 2 ]; then
	echo "Usage: setup.sh ifname [start|finish]"
	exit
fi

if [ ! -f ../../netmap-release/examples/vale-ctl ]; then
	echo Usage: place ../../netmap-release/examples/vale-ctl
	exit
fi

if [ $2 = start ]; then
	../../netmap-release/examples/vale-ctl -a valem:$1
	if [ `uname` = "FreeBSD" ]; then
		kldload ../sys/contrib/multistack/multistack.ko
	elif [ `uname` = "Linux" ]; then
		insmod ../LINUX/multistack_lin.ko
	fi
elif [ $2 = finish ]; then
	if [ `uname` = "FreeBSD" ]; then
		kldunload multistack
	elif [ `uname` = "Linux" ]; then
		rmmod multistack
	fi
	../../netmap-release/examples/vale-ctl -d valem:$1
fi
