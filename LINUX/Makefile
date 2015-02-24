CONFIG_MSTACK:=m
mstack_lin-objs := mstack.o
obj-$(CONFIG_MSTACK) = mstack_lin.o

M:=$(CURDIR)
#OVS_DIR = openvswitch
#OVS_SRC = net/$(OVS_DIR)/
SRC ?= $(KSRC)
#DIST = $(SRC)/$(OVS_SRC)
#EXTRA_CFLAGS := -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(NSRC)/sys/contrib -DCONFIG_NETMAP
EXTRA_CFLAGS := -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(M)/../sys -DCONFIG_NETMAP

#all:	get-ovs build
all:	build
build:
	make -C $(SRC) M=$(CURDIR) \
		CONFIG_NETMAP=m CONFIG_MSTACK=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers
	ls -l `find . -name \*.ko`
clean:
#	make -C $(SRC) M=$(CURDIR)/$(OVS_DIR) clean
	(rm -rf *.o *.ko modules.order mstack_lin.mod.c Module.symvers)

$(obj)/mstack.o:	$(M)/../sys/net/mstack.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
