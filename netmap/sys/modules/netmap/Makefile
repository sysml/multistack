# $FreeBSD$
#
# Compile netmap as a module, though it is not useful now
# because drivers do depend on it.

.PATH: ${.CURDIR}/../../dev/netmap
.PATH.h: ${.CURDIR}/../../net
KMOD	= netmap
SRCS	= device_if.h bus_if.h opt_netmap.h
SRCS	+= netmap.c netmap.h netmap_kern.h

# CFLAGS	+= -I${.CURDIR}/../.. -DDEV_NETMAP

.include <bsd.kmod.mk>
