# $Id: Makefile 11707 2012-08-13 10:11:00Z luigi $
# targets to build tarballs and diffs

# build a distribution
DIST_NAME := /tmp/20120813-netmap.tgz
DIST_SRCS := ./README ./sys/net ./sys/modules ./Makefile ./LINUX
DIST_SRCS += ./sys/dev
DIST_SRCS += ./examples
DIST_EXCL += --exclude .svn
DIST_EXCL += --exclude connlib\* --exclude netmap_vale.c
DIST_EXCL += --exclude examples/testmod
DIST_EXCL += --exclude cxgbe_netmap.h
DIST_EXCL += --exclude if_sfxge_netmap.h
DIST_EXCL += --exclude if_bge_netmap.h

RELEASE_SRCS := ./sys/net ./sys/dev ./sys/modules ./examples
RELEASE_SRCS += ./README ./LINUX
RELEASE_EXCL := --exclude .svn --exclude sys/dev/\*/i\*.c --exclude examples/testmod
RELEASE_EXCL += --exclude connlib\* --exclude netmap_vale.c

all:
	@echo "What do you want to do ?"

tgz:
	tar cvzf ${DIST_NAME} \
		-s'/^./netmap/' $(DIST_EXCL) $(DIST_SRCS)

diff-head:
	(cd ~/FreeBSD/head ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > head-netmap.diff

# XXX remember to patch sbin/ifconfig if not done yet
diff-r8:
	(cd ~/FreeBSD/RELENG_8 ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > r8-netmap.diff

release:
	D=`date +%Y%m%d` && tar cvzf /tmp/$${D}-netmap.tgz \
		-s'/^./netmap-release/' $(RELEASE_EXCL) $(RELEASE_SRCS)
