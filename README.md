# MultiStack - Multiplexing and isolating user-space stacks and in-kernel stack

MultiStack is a kernel module that enables user-level network stacks to run alongside the in-kernel stack on the same NIC securely.

To isolate multiple network stacks including in-kernel stack, traditional 3-tuple (address, port and protocol) is used.
Currently, applications that run on socket APIs are isolated such that they exclusively use the same 3-tuple using bind() or equivalent systemcalls (except for special cases like fork()).
MultiStack extends this primitive to user-space stacks.

For example, when a user-level stack wishes to use local port TCP 80 on the NIC that has IP address 10.0.0.2, it must create a socket and bind() this 3 tuple, then registers this 3 tuple into MultiStack.

MultiStack is implemented as a module in [VALE](http://info.iet.unipi.it/~luigi/netmap/) which is a fast, scalable and modular software switch.
VALE's virtual port is used to interconnect a user-level stack and the NIC.
MultiStack forwards packets from the NIC to virtual ports or in-kernel stack based on registered 3 tuple.
It also validates packets from the virtual port to check whether they match registered 3 tuple.


## How to build the code (Linux)

1. Make sure you have installed [netmap](http://info.iet.unipi.it/~luigi/netmap/).

2. do the following in multistack directory:
	- cd LINUX
	- make KSRC=YOUR_KERNEL_SOURCE NSRC=YOUR_NETMAP_SOURCE
	
	(In my environment, make KSRC=/home/micchie/net-next NSRC=/home/micchie/netmap)
	
## How to use the code (Linux)

I expect you installed netmap and MultiStack at ~/netmap and ~/multistack, respectively. Then I also expect you configured PATH environment variable for ~/netmap/examples/ and ~/multistack/examples/ 

1. Constract a VALE switch named "valem:" such that it attaches a NIC that is wished to be shared between the in-kernel stack and user-space stacks using vale-ctl command included in [netmap](http://info.iet.unipi.it/~luigi/netmap/), like
	- vale-ctl -h valem:eth1
	
	This means that you attach a NIC eth1 to a switch instance "valem:". Since you use "-h" option, the in-kernel stack is also attached to this switch instance (the in-kernel stack is still able to refer to eth1).
	
2. Load MultiStack kernel module
	- insmod ~/multistack/LINUX/multistack_lin.ko
	
## How to run apps

Applications or user-level stacks that run on top of netmap API can be easily ported.
First, you must run the app on top of a virtual port that attaches to the switch instance "valem:", represented like "valem:vp0".

Second, you need to create a socket and bind() a 3-tuple.
Finally, you need to issue an ioctl() with MULTISTACK_BIND argument to register this 3-tuple into MultiStack.

For more details, see multistack/examples/pkt-gen.c (modified version of netmap/examples/pkt-gen.c to run on top of MultiStack)
	
## Author

Michio Honda (firstname@netapp.com)
	

## References

Michio Honda, Felipe Huici, Costin Raiciu, Joao Araujo and Luigi Rizzo, ["Rekindling network protocol innovation with user-level stacks"](http://www.sigcomm.org/sites/default/files/ccr/papers/2014/April/0000000-0000006.pdf), ACM SIGCOMM Computer Communication Review 44(2), 52-58, April, 2014


## Credits

MultiStack was initially developed in NEC Laboratories Europe, partially supported by EU FP7 projects CHANGE, Trilogy2 and SSICLOPS, and NetApp
