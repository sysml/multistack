CONFIG_MSTACK:=m
multistack_lin-objs := multistack.o multistack_linux.o
obj-$(CONFIG_MSTACK) = multistack_lin.o

M:=$(CURDIR)
#OVS_DIR = openvswitch
#OVS_SRC = net/$(OVS_DIR)/
SRC ?= $(KSRC)
#DIST = $(SRC)/$(OVS_SRC)
#EXTRA_CFLAGS := -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(NSRC)/sys/contrib -DCONFIG_NETMAP
EXTRA_CFLAGS := -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(M)/../sys -I$(M) -DCONFIG_NETMAP $(NMVER)

#all:	get-ovs build
all:	build
build:
	make -C $(SRC) M=$(CURDIR) \
		CONFIG_NETMAP=m CONFIG_NETMAP_VALE=y CONFIG_MSTACK=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' \
		KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers
	ls -l `find . -name \*.ko`
clean:
#	make -C $(SRC) M=$(CURDIR)/$(OVS_DIR) clean
	(rm -rf *.o *.ko modules.order multistack_lin.mod.c Module.symvers)

$(obj)/multistack.o:	$(M)/../sys/contrib/multistack/multistack.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
$(obj)/multistack_linux.o:	$(M)/multistack_linux.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
