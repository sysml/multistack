# MultiStack - Kernel Support for Multiplexing and Isolating User-space Stacks.

MultiStack is a kernel module that enables user-level network stacks to securely run alongside the in-kernel stack on the same NIC.

To isolate multiple network stacks including the in-kernel stack, a <dst ip address, dst port and protocol> 3-tuple is used. Currently, applications that run on socket APIs are isolated such that they exclusively use this 3-tuple through a call to bind() or equivalent system calls (except for special cases like fork()); MultiStack extends this primitive to user-space stacks.

For example, when a user-level stack wishes to use local port TCP 80 on a NIC configured with IP address 10.0.0.2, it must create a socket, call bind() with the corresponding 3-tuple, and register the tuple with MultiStack.

MultiStack is implemented as a module in [VALE](http://info.iet.unipi.it/~luigi/netmap/), a fast, scalable and modular software switch. A VALE virtual port is used to interconnect a user-level stack and a NIC. MultiStack forwards packets from the NIC to the different virtual ports (or the in-kernel network stack) based on the set of currently registered 3-tuples. It also validates packets sent from virtual ports to ensure that they match the registered 3-tuples.

## How to Build the Code (Linux)

1. Make sure you have [netmap](http://info.iet.unipi.it/~luigi/netmap/) installed.

2. In the Multistack directory:
	- cd LINUX
	- make KSRC=PATH_TO_KERNEL_SOURCES NSRC=PATH_TO_NETMAP_SOURCES
	
	
## How to Use the Code (Linux)

Assuming you've already installed netmap and Multistack in ~/netmap and ~/multistack respectively, and that you configured your PATH environment variable to include ~/netmap/examples/ and ~/multistack/examples/ : 

1. Instantiate a VALE switch named "valem:", and attach eth1 and the in-kernel network stack to it:

	- vale-ctl -h valem:eth1

The vale-ctl command is included in [netmap](http://info.iet.unipi.it/~luigi/netmap/), and the "-h" option attaches the in-kernel network stack to the switch.
	
2. Load the MultiStack kernel module
	- insmod ~/multistack/LINUX/multistack_lin.ko
	
## How to Run Apps

Applications or user-level stacks that run on top of the netmap API can be easily ported. To run a user-level network stack or app:

1. Run the app on top of a virtual port that attaches to the switch instance "valem:", represented by "valem:vp0".
	- You can choose arbitrary name for "vp0"
	- You don't need any system-wide configuration to create "valem:vp0". When your app registers this name with nm_open(), the virtual port is dynamically created.

2. Create a socket and bind() a 3-tuple.
	- This process is important so that afterwards MultiStack can confirm this process owns credential to this 3 tuple.

3. Issue an ioctl() for a file descripter opened by nm_open() (you can refer to it with nmd->fd) with MULTISTACK_BIND as an argument in order to register this 3-tuple with MultiStack.
	- Here MultiStack internally checks if the caller process owns credential to register this 3 tuple. Since you have bind()ed this 3 tuple, it will success.
	
4. You can now send (raw) packets whose source matches this 3 tuple, and receive (raw) packets whose destination is this 3 tuple on "valem:vp0" using netmap API.

For more details, see multistack/examples/pkt-gen.c (a modified version of netmap/examples/pkt-gen.c that can run on top of MultiStack)
	
## Author

Michio Honda (firstname@netapp.com)


## References

Michio Honda, Felipe Huici, Costin Raiciu, Joao Araujo and Luigi Rizzo, ["Rekindling network protocol innovation with user-level stacks"](http://www.sigcomm.org/sites/default/files/ccr/papers/2014/April/0000000-0000006.pdf), ACM SIGCOMM Computer Communication Review 44(2), 52-58, April, 2014


## Credits

MultiStack was developed at NEC Laboratories Europe, with partial funding from EU FP7 projects CHANGE and Trilogy2. It is currently maintained with support from the EU FP7 SSICLOPS project and NetApp.
