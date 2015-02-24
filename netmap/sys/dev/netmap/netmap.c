/*
 * Copyright (C) 2011-2012 Matteo Landi, Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define NM_BRIDGE

/*
 * This module supports memory mapped access to network devices,
 * see netmap(4).
 *
 * The module uses a large, memory pool allocated by the kernel
 * and accessible as mmapped memory by multiple userspace threads/processes.
 * The memory pool contains packet buffers and "netmap rings",
 * i.e. user-accessible copies of the interface's queues.
 *
 * Access to the network card works like this:
 * 1. a process/thread issues one or more open() on /dev/netmap, to create
 *    select()able file descriptor on which events are reported.
 * 2. on each descriptor, the process issues an ioctl() to identify
 *    the interface that should report events to the file descriptor.
 * 3. on each descriptor, the process issues an mmap() request to
 *    map the shared memory region within the process' address space.
 *    The list of interesting queues is indicated by a location in
 *    the shared memory region.
 * 4. using the functions in the netmap(4) userspace API, a process
 *    can look up the occupation state of a queue, access memory buffers,
 *    and retrieve received packets or enqueue packets to transmit.
 * 5. using some ioctl()s the process can synchronize the userspace view
 *    of the queue with the actual status in the kernel. This includes both
 *    receiving the notification of new packets, and transmitting new
 *    packets on the output interface.
 * 6. select() or poll() can be used to wait for events on individual
 *    transmit or receive queues (or all queues for a given interface).
 */

#ifdef linux
#include "bsd_glue.h"
static netdev_tx_t linux_netmap_start(struct sk_buff *skb, struct net_device *dev);
#endif /* linux */

#ifdef __APPLE__
#include "osx_glue.h"
#endif /* __APPLE__ */

#ifdef __FreeBSD__
#include <sys/cdefs.h> /* prerequisite */
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/jail.h>
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct */
#include <sys/uio.h>	/* uio struct */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/mman.h>	/* PROT_EXEC */
#include <sys/poll.h>
#include <sys/proc.h>
#include <vm/vm.h>	/* vtophys */
#include <vm/pmap.h>	/* vtophys */
#include <sys/socket.h> /* sockaddrs */
#include <machine/bus.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <net/vnet.h>
#include <machine/bus.h>	/* bus_dmamap_* */
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

MALLOC_DEFINE(M_NETMAP, "netmap", "Network memory map");
#endif /* __FreeBSD__ */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

u_int netmap_total_buffers;
u_int netmap_buf_size;
char *netmap_buffer_base;	/* address of an invalid buffer */

/* user-controlled variables */
int netmap_verbose;


static int netmap_no_timestamp; /* don't timestamp on rxsync */

SYSCTL_NODE(_dev, OID_AUTO, netmap, CTLFLAG_RW, 0, "Netmap args");
SYSCTL_INT(_dev_netmap, OID_AUTO, verbose,
    CTLFLAG_RW, &netmap_verbose, 0, "Verbose mode");
SYSCTL_INT(_dev_netmap, OID_AUTO, no_timestamp,
    CTLFLAG_RW, &netmap_no_timestamp, 0, "no_timestamp");
int netmap_mitigate = 1;
SYSCTL_INT(_dev_netmap, OID_AUTO, mitigate, CTLFLAG_RW, &netmap_mitigate, 0, "");
int netmap_no_pendintr = 1;
SYSCTL_INT(_dev_netmap, OID_AUTO, no_pendintr,
    CTLFLAG_RW, &netmap_no_pendintr, 0, "Always look for new received packets.");
int netmap_bdg_txintr = 0;
SYSCTL_INT(_dev_netmap, OID_AUTO, bdg_txintr,
    CTLFLAG_RW, &netmap_bdg_txintr, 0, "bdg ports uses TX intr of the NIC.");
int netmap_bdg_unicastalgo = 0;
SYSCTL_INT(_dev_netmap, OID_AUTO, bdg_unicastalgo,
    CTLFLAG_RW, &netmap_bdg_unicastalgo, 0, "unicast bridge algorithm.");

int netmap_drop = 0;	/* debugging */
int netmap_flags = 0;	/* debug flags */
int netmap_fwd = 0;	/* force transparent mode */
int netmap_copy = 0;	/* debugging, copy content */

SYSCTL_INT(_dev_netmap, OID_AUTO, drop, CTLFLAG_RW, &netmap_drop, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, flags, CTLFLAG_RW, &netmap_flags, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, fwd, CTLFLAG_RW, &netmap_fwd, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, copy, CTLFLAG_RW, &netmap_copy, 0 , "");

/* Quick sysctl */
#ifdef linux
static ctl_table netmap_table[] = {
       {
               .procname = "verbose",
               .data = &netmap_verbose,
               .maxlen = sizeof(int),
               .mode = 0644,
               .proc_handler = proc_dointvec,
       },
       {
               .procname = "bdg_txintr",
               .data = &netmap_bdg_txintr,
               .maxlen = sizeof(int),
               .mode = 0644,
               .proc_handler = proc_dointvec,
       },
       {
               .procname = "bdg_unicastalgo",
               .data = &netmap_bdg_unicastalgo,
               .maxlen = sizeof(int),
               .mode = 0644,
               .proc_handler = proc_dointvec,
       },
       {}
};
static struct ctl_path netmap_path[] = {
       { .procname = "net", },
       { .procname = "netmap", },
       {}
};
static struct ctl_table_header * netmap_sysctl_header;
void netmap_sysctl_register(void)
{
       netmap_sysctl_header = register_sysctl_paths(netmap_path, netmap_table);
}
void netmap_sysctl_unregister(void)
{
       unregister_sysctl_table(netmap_sysctl_header);
}
#endif /* Linux */


#ifdef NM_BRIDGE /* support for netmap bridge */

/*
 * system parameters.
 *
 * All switched ports have prefix NM_NAME.
 * The switch has a max of NM_BDG_MAXPORTS ports (often stored in a bitmap,
 * so a practical upper bound is 64).
 * Each tx ring is read-write, whereas rx rings are readonly (XXX not done yet).
 * The virtual interfaces use per-queue lock instead of core lock.
 * In the tx loop, we aggregate traffic in batches to make all operations
 * faster. The batch size is NM_BDG_BATCH
 */
#define	NM_NAME			"vale"	/* prefix for the interface */
#define NM_BDG_MAXPORTS		16	/* up to 64 ? */
#define NM_UNIBDG_MAXPORTS	256
//#define NM_BRIDGE_RINGSIZE	1024	/* in the device */
#define NM_BRIDGE_RINGSIZE	256	/* in the device */
#define NM_BDG_HASH		1024	/* forwarding table entries */
//#define NM_BDG_BATCH		1024	/* entries in the forwarding buffer */
#define NM_BDG_BATCH		256	/* entries in the forwarding buffer */
#define	NM_BRIDGES		4	/* number of bridges */
#define NM_VRF_IFNUM	4	/* XXX */
#define NM_VRF_RINGNUM	16	/* XXX */
#define NM_DEFAULT_RINGID	0	/* XXX */
#define NM_IFA_HASH		1024
#define NM_UNIBDG_IDX		1	/* index of a unicast bridge */
#define NM_UNIBDG_FWDALGO_IDX	0
#define NM_UNIBDG_FWDALGO_BATCHSIZ	1
#define NM_UNIBDG_FWDALGO_IDXX	3
#define NM_UNIBDG_FWDALGO_MBDG	4
#define NM_UNIBDG_FWDALGO_RPS	2
int netmap_bridge = NM_BDG_BATCH; /* bridge batch size */
SYSCTL_INT(_dev_netmap, OID_AUTO, bridge, CTLFLAG_RW, &netmap_bridge, 0 , "");

#ifdef linux
#define	ADD_BDG_REF(ifp)	(NA(ifp)->if_refcount++)
#define	DROP_BDG_REF(ifp)	(NA(ifp)->if_refcount-- <= 1)
#else /* !linux */
#define	ADD_BDG_REF(ifp)	(ifp)->if_refcount++
#define	DROP_BDG_REF(ifp)	refcount_release(&(ifp)->if_refcount)
#ifdef __FreeBSD__
#include <sys/endian.h>
#include <sys/refcount.h>
#endif /* __FreeBSD__ */
/* #define prefetch(x)	__builtin_prefetch(x) */
static inline void prefetch (const void *x)
{
	__asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));
}
#endif /* !linux */

/* pre-definitions for MiniStack extensions */
struct netmap_priv_d;
struct netmap_vrf_if;
struct netmap_vrf;
struct nm_bdg_fwd;
static int get_ifp(const struct nmreq *, struct ifnet **);
static void nm_del_ifaddr(struct netmap_ifaddr *, struct ifnet *);
static __inline int nm_ifa_rthash_from_ifa(struct netmap_ifaddr *nifa);
static __inline void vrf_if_ref(struct netmap_vrf_if *vif);
static void vrf_if_rele(struct netmap_vrf_if *vif);
static int vrf_netmap_regif(struct ifnet *, uint16_t, struct netmap_vrf_if **);
static void nm_bdg_detach_vif(struct netmap_adapter *);
static void *nm_findifa_system(struct sockaddr *);
static struct netmap_ifaddr *netmap_findifa_pkt(uint8_t *buf, uint8_t **hint);
static int nm_unibdg_flush(struct nm_bdg_fwd *, int, struct ifnet *, u_int);
static int nm_unibdg_flush2(struct nm_bdg_fwd *, int, struct ifnet *, u_int);
static int nm_unibdg_flush3(struct nm_bdg_fwd *, int, struct ifnet *, u_int);
static int nm_unibdg_flush_rps(struct nm_bdg_fwd *, int, struct ifnet *, u_int);
static int nm_bdg_flush_from_vrf(struct nm_bdg_fwd *, int, struct ifnet *, u_int);

static void bdg_netmap_attach(struct ifnet *ifp, int num_queues);
static int bdg_netmap_reg(struct ifnet *ifp, int onoff);
/* per-tx-queue entry */
STAILQ_HEAD(nm_unibdgfwd_head, nm_bdg_fwd);
struct nm_bdg_fwd {	/* forwarding entry for a bridge */
	void *buf;
	uint64_t dst;	/* dst mask */
	uint32_t src;	/* src index ? */
	uint16_t len;	/* src len */
	STAILQ_ENTRY(nm_bdg_fwd) next;
};


struct nm_hash_ent {
	uint64_t	mac;	/* the top 2 bytes are the epoch */
	uint64_t	ports;
};

/*
 * Interfaces for a bridge are all in ports[].
 * The array has fixed size, an empty entry does not terminate
 * the search.
 */
struct nm_bridge {
//	struct ifnet *bdg_ports[NM_BDG_MAXPORTS];
	struct ifnet *bdg_ports[NM_UNIBDG_MAXPORTS];
	int n_ports;
	uint64_t act_ports;
	int freelist;	/* first buffer index */
	NM_SELINFO_T si;	/* poll/select wait queue */
	NM_LOCK_T bdg_lock;	/* protect the selinfo ? */

	/* the forwarding table, MAC+ports */
	struct nm_hash_ent ht[NM_BDG_HASH];

	int namelen;	/* 0 means free */
	char basename[IFNAMSIZ];
};

struct nm_bridge nm_bridges[NM_BRIDGES];

/*
 * Virtual router feature (VRF), similar concept to that of SCTP.
 * This manages the actual NICs in netmap-mode, which are kept in viflist,
 * one entry for one NIC.  Each entry, netmap_vrf_if (Vif) is refcounted by
 * VALE ports. VRF is protected by a reader-writer lock.
 * Write-lock is only acquired for interface addition/deletion operation.
 *
 * Vif maintains NIC's private structure represented in netmap_priv_d.
 * Vif also implements TX side queue management.  When the application blocks
 * on the VALE port until this port provides available TX slots, it would want
 * to sleep on the NIC's queue.  However, 1.) it will make controlling the
 * process (owning a VALE port) harder, and 2.) it will mess semantics of the
 * VALE ports.  Therefore, we make per-NIC queue that accommodate threads
 * blocking on VALE ports connecting to that NIC.  Upon the TX interrupt from
 * the NIC, the kernel thread wakes up threads from this queue. (see
 * netmap_vrf_txintr().) This queue is separated in per ring basis.
 *
 * Incoming-packet routing is also done in the VRF.  List of the local
 * namespace (IP address, protocol and port) is stored in ifa_ht.
 * To increase parallelizm, this list is split based on the hash value of
 * the local name space (IP address, protocol and port).  So the kernel thread
 * can lock only the necessary part of the list, this minimizes effects of
 * registration/unregistration of the local namespace to the entire system.
 */

struct netmap_vrf;
struct netmap_priv_d;

/* This is stored in the netmap_adapter */
struct nm_txintrq_ent {
	TAILQ_ENTRY(nm_txintrq_ent) txintrq_next;
	struct netmap_adapter *na;
	uint32_t ringmask; /* currently we support 32 rings */
};

TAILQ_HEAD(nm_txintrq_head, nm_txintrq_ent);
struct netmap_vrf_if {
	LIST_ENTRY(netmap_vrf_if) next_ifn;
	struct ifnet *ifn;
	struct netmap_priv_d *priv;
	NM_REFCOUNT_T refcount;
	struct netmap_vrf *vrf;
	struct nm_txintrq_head txintrq_head[NM_VRF_RINGNUM+1];
	NM_LOCK_T txintrq_mtx[NM_VRF_RINGNUM+1];
	int (*bdgfwd_func)(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp,
				u_int ring_nr);
	struct nm_unibdgfwd_head *unibdgfwd_head; /* short cut */
	/* Forwarding table used in the RX context (NM_BDG_BATCH * num rings) */
	struct nm_bdg_fwd *ft;
};

#ifdef linux
struct nm_vrfiflist {
	struct netmap_vrf_if *lh_first;
};
struct nm_ifahashhead {
	struct netmap_ifaddr *lh_first;
};
#else
LIST_HEAD(nm_vrfiflist, netmap_vrf_if);
LIST_HEAD(nm_ifahashhead, netmap_ifaddr);
#endif
struct netmap_vrf {
	struct nm_vrfiflist viflist;
	NM_RWLOCK_T	vrf_mtx;
	struct nm_ifahashhead ifa_ht[NM_IFA_HASH];
	NM_RWLOCK_T	ipi_addr_mtx[NM_IFA_HASH];
} nm_vrf; /* Currently we support a single VRF */

static inline int BDGIDX(struct nm_bridge *b)
{
	int i;
	for (i = 0; i < NM_BRIDGES; i++)
		if (&nm_bridges[i] == b)
			return i;
	D("no bridge is found");
	return -1;
}

static int bdg_do_options(struct ifnet *, u_long, caddr_t);

#define BDG_LOCK(b)	mtx_lock(&(b)->bdg_lock)
#define BDG_UNLOCK(b)	mtx_unlock(&(b)->bdg_lock)

/*
 * NA(ifp)->bdg_port	port index
 */

// XXX only for multiples of 64 bytes, non overlapped.
static inline void
pkt_copy(void *_src, void *_dst, int l)
{
        uint64_t *src = _src;
        uint64_t *dst = _dst;
        if (unlikely(l >= 1024)) {
                bcopy(src, dst, l);
                return;
        }
        for (; likely(l > 0); l-=64) {
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
        }
}

/*
 * locate a bridge among the existing ones.
 * a ':' in the name terminates the bridge name. Otherwise, just NM_NAME.
 * We assume that this is called with a name of at least NM_NAME chars.
 */
static struct nm_bridge *
nm_find_bridge(const char *name)
{
	int i, l, namelen, e;
	struct nm_bridge *b = NULL;

	namelen = strlen(NM_NAME);	/* base length */
	l = strlen(name);		/* actual length */
	for (i = namelen + 1; i < l; i++) {
		if (name[i] == ':') {
			namelen = i;
			break;
		}
	}
	if (namelen >= IFNAMSIZ)
		namelen = IFNAMSIZ;
	ND("--- prefix is '%.*s' ---", namelen, name);

	/* use the first entry for locking */
	BDG_LOCK(nm_bridges); // XXX do better
	/* XXX */
	if (namelen != strlen(NM_NAME) && name[strlen(NM_NAME)] == 'u') {
		b = nm_bridges+NM_UNIBDG_IDX;
		if (b->namelen == 0) {
			if (netmap_verbose & NM_VERB_DBG)
				D("activate the unicast bridge");
			strncpy(b->basename, name, namelen);
		}
		b->namelen = namelen;
		b->n_ports = NM_UNIBDG_MAXPORTS;
		BDG_UNLOCK(nm_bridges);
		return b;
	}
	for (e = -1, i = 1; i < NM_BRIDGES; i++) {
		if (i == NM_UNIBDG_IDX)
			continue;
		b = nm_bridges + i;
		if (b->namelen == 0)
			e = i;	/* record empty slot */
		else if (strncmp(name, b->basename, namelen) == 0) {
			ND("found '%.*s' at %d", namelen, name, i);
			break;
		}
	}
	if (i == NM_BRIDGES) { /* all full */
		if (e == -1) { /* no empty slot */
			b = NULL;
		} else {
			b = nm_bridges + e;
			strncpy(b->basename, name, namelen);
			b->namelen = namelen;
		}
	}
	BDG_UNLOCK(nm_bridges);
	return b;
}
#endif /* NM_BRIDGE */


/*
 * Fetch configuration from the device, to cope with dynamic
 * reconfigurations after loading the module.
 */
static int
netmap_update_config(struct netmap_adapter *na)
{
	struct ifnet *ifp = na->ifp;
	u_int txr, txd, rxr, rxd;

	txr = txd = rxr = rxd = 0;
	if (na->nm_config) {
		na->nm_config(ifp, &txr, &txd, &rxr, &rxd);
	} else {
		/* take whatever we had at init time */
		txr = na->num_tx_rings;
		txd = na->num_tx_desc;
		rxr = na->num_rx_rings;
		rxd = na->num_rx_desc;
	}

	if (na->num_tx_rings == txr && na->num_tx_desc == txd &&
	    na->num_rx_rings == rxr && na->num_rx_desc == rxd)
		return 0; /* nothing changed */
	if (netmap_verbose || na->refcount > 0) {
		D("stored config %s: txring %d x %d, rxring %d x %d",
			ifp->if_xname,
			na->num_tx_rings, na->num_tx_desc,
			na->num_rx_rings, na->num_rx_desc);
		D("new config %s: txring %d x %d, rxring %d x %d",
			ifp->if_xname, txr, txd, rxr, rxd);
	}
	if (na->refcount == 0) {
		D("configuration changed (but fine)");
		na->num_tx_rings = txr;
		na->num_tx_desc = txd;
		na->num_rx_rings = rxr;
		na->num_rx_desc = rxd;
		return 0;
	}
	D("configuration changed while active, this is bad...");
	return 1;
}

/*------------- memory allocator -----------------*/
#ifdef NETMAP_MEM2
#include "netmap_mem2.c"
#else /* !NETMAP_MEM2 */
#include "netmap_mem1.c"
#endif /* !NETMAP_MEM2 */
/*------------ end of memory allocator ----------*/


/* Structure associated to each thread which registered an interface.
 *
 * The first 4 fields of this structure are written by NIOCREGIF and
 * read by poll() and NIOC?XSYNC.
 * There is low contention among writers (actually, a correct user program
 * should have no contention among writers) and among writers and readers,
 * so we use a single global lock to protect the structure initialization.
 * Since initialization involves the allocation of memory, we reuse the memory
 * allocator lock.
 * Read access to the structure is lock free. Readers must check that
 * np_nifp is not NULL before using the other fields.
 * If np_nifp is NULL initialization has not been performed, so they should
 * return an error to userlevel.
 *
 * The ref_done field is used to regulate access to the refcount in the
 * memory allocator. The refcount must be incremented at most once for
 * each open("/dev/netmap"). The increment is performed by the first
 * function that calls netmap_get_memory() (currently called by
 * mmap(), NIOCGINFO and NIOCREGIF).
 * If the refcount is incremented, it is then decremented when the
 * private structure is destroyed.
 */
struct netmap_priv_d {
	struct netmap_if * volatile np_nifp;	/* netmap interface descriptor. */

	struct ifnet	*np_ifp;	/* device for which we hold a reference */
	int		np_ringid;	/* from the ioctl */
	u_int		np_qfirst, np_qlast;	/* range of rings to scan */
	uint16_t	np_txpoll;

	unsigned long	ref_done;	/* use with NMA_LOCK held */
};


static int
netmap_get_memory(struct netmap_priv_d* p)
{
	int error = 0;
	NMA_LOCK();
	if (!p->ref_done) {
		error = netmap_memory_finalize();
		if (!error)
			p->ref_done = 1;
	}
	NMA_UNLOCK();
	return error;
}

/*
 * File descriptor's private data destructor.
 *
 * Call nm_register(ifp,0) to stop netmap mode on the interface and
 * revert to normal operation. We expect that np_ifp has not gone.
 */
/* call with NMA_LOCK held */
static void
netmap_dtor_locked(void *data)
{
	struct netmap_priv_d *priv = data;
	struct ifnet *ifp = priv->np_ifp;
	struct netmap_adapter *na = NA(ifp);
	struct netmap_if *nifp = priv->np_nifp;

	na->refcount--;
	if (na->refcount <= 0) {	/* last instance */
		u_int i, j, lim;

		KASSERT((na->refcount == 0), ("refcount is %d", na->refcount));
		if (netmap_verbose & NM_VERB_DBG)
			D("deleting last instance for %s", ifp->if_xname);
		/*
		 * there is a race here with *_netmap_task() and
		 * netmap_poll(), which don't run under NETMAP_REG_LOCK.
		 * na->refcount == 0 && na->ifp->if_capenable & IFCAP_NETMAP
		 * (aka NETMAP_DELETING(na)) are a unique marker that the
		 * device is dying.
		 * Before destroying stuff we sleep a bit, and then complete
		 * the job. NIOCREG should realize the condition and
		 * loop until they can continue; the other routines
		 * should check the condition at entry and quit if
		 * they cannot run.
		 */
		na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
		NMA_UNLOCK();
		tsleep(na, 0, "NIOCUNREG", 4);
		if (na->nm_ifflags & NM_IFF_BDG_HW) {
			struct netmap_vrf_if *vif = na->dst_vif;

			/* No more poll() will come */
			nm_bdg_detach_vif(na);
			vrf_if_rele(vif);
		}
		NMA_LOCK();
		na->nm_lock(ifp, NETMAP_REG_LOCK, 0);
		na->nm_register(ifp, 0); /* off, clear IFCAP_NETMAP */
		/* Wake up any sleeping threads. netmap_poll will
		 * then return POLLERR
		 */
		for (i = 0; i < na->num_tx_rings + 1; i++)
			selwakeuppri(&na->tx_rings[i].si, PI_NET);
		for (i = 0; i < na->num_rx_rings + 1; i++)
			selwakeuppri(&na->rx_rings[i].si, PI_NET);
		selwakeuppri(&na->tx_si, PI_NET);
		selwakeuppri(&na->rx_si, PI_NET);
		/* release all buffers */
		for (i = 0; i < na->num_tx_rings + 1; i++) {
			struct netmap_ring *ring = na->tx_rings[i].ring;
			lim = na->tx_rings[i].nkr_num_slots;
			for (j = 0; j < lim; j++)
				netmap_free_buf(nifp, ring->slot[j].buf_idx);
			/* knlist_destroy(&na->tx_rings[i].si.si_note); */
			mtx_destroy(&na->tx_rings[i].q_lock);
		}
		for (i = 0; i < na->num_rx_rings + 1; i++) {
			struct netmap_ring *ring = na->rx_rings[i].ring;
			lim = na->rx_rings[i].nkr_num_slots;
			for (j = 0; j < lim; j++)
				netmap_free_buf(nifp, ring->slot[j].buf_idx);
			/* knlist_destroy(&na->rx_rings[i].si.si_note); */
			mtx_destroy(&na->rx_rings[i].q_lock);
		}
		/* XXX kqueue(9) needed; these will mirror knlist_init. */
		/* knlist_destroy(&na->tx_si.si_note); */
		/* knlist_destroy(&na->rx_si.si_note); */
		netmap_free_rings(na);
		wakeup(na);
	}
	netmap_if_free(nifp);
}

static inline void
nm_ref_ifa(struct netmap_ifaddr *nifa)
{
	atomic_add_int(&nifa->refcount, 1);
}

static inline void
nm_free_ifa(struct netmap_ifaddr *nifa)
{
	if (NM_DECREMENT_AND_CHECK_REFCOUNT(&nifa->refcount)) {
		nifa->egress_filter = NULL;
		free(nifa, M_IFADDR); /* XXX */
	}
}

/*
 * Detach ifaddr from the upper half (not from VRF).
 * This might be still referred from the bottom half
 */
static void
nm_del_ifaddr(struct netmap_ifaddr *nifa, struct ifnet *ifp)
{
	if (netmap_verbose & NM_VERB_DBG) {
		D("removing addr from %s", ifp->if_xname);
		nm_print_address(&nifa->laddr.sa);
		D("passed %u err %u unknown %u rcved %u",
			nifa->cnt_passed, nifa->cnt_err,
			nifa->cnt_unknown, nifa->cnt_rcved);
	}

	if (!nifa) {
		D("no ifa");
		return;
	}
	nm_free_ifa(nifa);
	NA(ifp)->nm_ifflags &= ~NM_IFF_BDG_FILTERED;
	NA(ifp)->nifa = NULL;
}

static __inline u_int
get_dstringid(struct netmap_adapter *dst_na, u_int myring)
{
	if (dst_na->num_tx_rings > myring || myring == 0)
		return myring;
	return (myring+1)%dst_na->num_tx_rings;
}

static void
nm_del_from_txintrq(struct netmap_adapter *na, u_int ring_nr) {
	struct netmap_vrf_if *vif = na->dst_vif;
	struct nm_txintrq_ent *tmp, *tmp2;
	struct nm_txintrq_head *head;

	NM_VRF_TXINTRQ_LOCK(ring_nr, vif);
	head = &vif->txintrq_head[ring_nr];
	TAILQ_FOREACH_SAFE(tmp, head, txintrq_next, tmp2) {
		if (tmp->na != na)
			continue;
		tmp->ringmask = 0;
		TAILQ_REMOVE(head, tmp, txintrq_next);
		break; /* We have only one same na in the queue */
	}
	NM_VRF_TXINTRQ_UNLOCK(ring_nr, vif);
}

/*
 * dstring == dst_na->num_tx_rings means sleeping on the global queue
 */
static void
nm_add_to_txintrq(struct netmap_adapter *na, u_int dstring, u_int myring)
{
	struct netmap_vrf_if *vif = na->dst_vif;
	struct nm_txintrq_head *head;

	NM_VRF_TXINTRQ_LOCK(dstring, vif);
	if (na->txintrq_ent[dstring].ringmask) {
		na->txintrq_ent[dstring].ringmask |= 1 << myring;
		NM_VRF_TXINTRQ_UNLOCK(dstring, vif);
		return;
	}
	na->txintrq_ent[dstring].ringmask |= 1 << myring;
	head = &vif->txintrq_head[dstring];
	TAILQ_INSERT_TAIL(head, &na->txintrq_ent[dstring], txintrq_next);
	NM_VRF_TXINTRQ_UNLOCK(dstring, vif);
}

/*
 * VALE rings waiting for a TX interrupt don't sleep directly on the NIC.
 * So I Wakeup processes traversing TXINTRQ, attached to vif in per-ring basis.
 * In the first pass, the outer loop traverses the TXINTRQ corresponding
 * to the ring where interrupt has occurred.  The inner loop traverses the
 * rings in the VALE adapter, because we assume multiple VALE rings in
 * the same adapter might be sleeping in the same TXINTRQ, such as when
 * num. VALE rings > num. NIC's rings.
 * I'm called from ***txeof or rx_irq.
 */
void
netmap_vrf_txintr(struct ifnet *ifp, u_int ring_nr)
{
	struct netmap_adapter *na = NA(ifp);
	struct nm_txintrq_ent *dst, *tmp;
	struct nm_txintrq_head *head;
	struct netmap_vrf_if *vif;
	struct netmap_vrf *vrf = &nm_vrf; /* don't acquire from vif */
	int i;

	NM_VRF_RLOCK(vrf);
	vif = NETMAP_VIF(ifp);
	if (unlikely(vif == NULL)) {
		D("vif destruction just before starting vrf_txintr(), return");
		NM_VRF_RUNLOCK(vrf);
		return;
	}
	/* XXX we assume the destination na is alive */
//	na->nm_txsync(ifp, ring_nr, 1);
	NM_VRF_TXINTRQ_LOCK(ring_nr, vif);
	head = &vif->txintrq_head[ring_nr];
	TAILQ_FOREACH_SAFE(dst, head, txintrq_next, tmp) {
		struct netmap_adapter *d_na = dst->na;

		for (i = 0; i < d_na->num_tx_rings; i++) {
			struct netmap_kring *d_kring;

			if (!(dst->ringmask & 1<<i))
				continue;
			d_kring = &d_na->tx_rings[i];
			/*
			* XXX In Linux, the client context might be already
		        * running.  We give up if the lock is already owned...
			* FreeBSD also fails to lock in some cases.  I found
			* this situation when we use 4 process, and each has 4
		        * threads and 4 VALE rings.
			*/
			if (mtx_trylock(&d_kring->q_lock)) {
				selwakeuppri(&d_kring->si, PI_NET);
				d_na->nm_lock(d_na->ifp, NETMAP_TX_UNLOCK, i);
				dst->ringmask &= ~(1<<i);
				if (!dst->ringmask)
					TAILQ_REMOVE(head, dst, txintrq_next);
			}
		}
	}
	NM_VRF_TXINTRQ_UNLOCK(ring_nr, vif);

	/* Wakeup from global queues */
	ring_nr = na->num_tx_rings;
	NM_VRF_TXINTRQ_LOCK(ring_nr, vif);
	head = &vif->txintrq_head[ring_nr];
	TAILQ_FOREACH_SAFE(dst, head, txintrq_next, tmp) {
		struct netmap_adapter *d_na = dst->na;

		if (mtx_trylock(&d_na->core_lock)) {
			selwakeuppri(&d_na->tx_si, PI_NET);
			d_na->nm_lock(d_na->ifp, NETMAP_CORE_UNLOCK, 0);
			dst->ringmask &= ~(1);
			TAILQ_REMOVE(head, dst, txintrq_next);
		}
		/* it's global queue, no care on ringmask */
	}
	NM_VRF_TXINTRQ_UNLOCK(ring_nr, vif);
	NM_VRF_RUNLOCK(vrf);
}

/* Must be guaranteed that no more poll() will come */
static void
nm_bdg_detach_vif(struct netmap_adapter *na)
{
	struct netmap_vrf_if *vif;
	struct netmap_vrf *vrf;
	int i;

//	D("detaching %s from vif (refcount %d)", na->ifp->if_xname, vif->refcount);
	vif = na->dst_vif;
	vrf = vif->vrf;
	NM_VRF_WLOCK(vrf);
	if (na->nm_ifflags & NM_IFF_BDG_FILTERED) {
		LIST_REMOVE(na->nifa, ifahash_next);
		nm_del_ifaddr(na->nifa, na->ifp);
		na->nm_ifflags &= ~NM_IFF_BDG_FILTERED;
	}

	KASSERT((na->dst_vif), ("no dst_vif"));
	for (i = 0; i <= NA(vif->ifn)->num_tx_rings; ++i)
		nm_del_from_txintrq(na, i);
	na->nm_ifflags &= ~NM_IFF_BDG_HW;
	na->dst_vif = NULL; /* XXX too early ? */
	KASSERT((na->txintrq_ent), ("no txintrq_ent"));
	free(na->txintrq_ent, M_DEVBUF);
	na->txintrq_ent = NULL;
	NM_VRF_WUNLOCK(vrf);
}

static void
nm_if_rele(struct ifnet *ifp)
{
#ifndef NM_BRIDGE
	if_rele(ifp);
#else /* NM_BRIDGE */
	int i, full;
	struct nm_bridge *b;
	int act_ports;

	if (strncmp(ifp->if_xname, NM_NAME, sizeof(NM_NAME) - 1)) {
		if_rele(ifp);
		return;
	}
	if (!DROP_BDG_REF(ifp))
		return;
	b = ifp->if_bridge;
	BDG_LOCK(nm_bridges);
	BDG_LOCK(b);
	ND("want to disconnect %s from the bridge", ifp->if_xname);
	full = 0;
	act_ports = (b->n_ports == NM_UNIBDG_MAXPORTS) ? NM_UNIBDG_MAXPORTS : NM_BDG_MAXPORTS;
	for (i = 0; i < act_ports; i++) {
		if (b->bdg_ports[i] == ifp) {
			b->bdg_ports[i] = NULL;
			bzero(ifp, sizeof(*ifp));
			free(ifp, M_DEVBUF);
			break;
		}
		else if (b->bdg_ports[i] != NULL)
			full = 1;
	}
	BDG_UNLOCK(b);
	if (full == 0) {
		ND("freeing bridge %d", b - nm_bridges);
		b->namelen = 0;
	}
	BDG_UNLOCK(nm_bridges);
	if (i == act_ports)
		D("ouch, cannot find ifp to remove");
#endif /* NM_BRIDGE */
}

static void
netmap_dtor(void *data)
{
	struct netmap_priv_d *priv = data;
	struct ifnet *ifp = priv->np_ifp;
	struct netmap_adapter *na;

	NMA_LOCK();
	if (ifp) {
		na = NA(ifp);
		na->nm_lock(ifp, NETMAP_REG_LOCK, 0);
		netmap_dtor_locked(data);
		na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);

		nm_if_rele(ifp);
	}
	if (priv->ref_done) {
		netmap_memory_deref();
	}
	NMA_UNLOCK();
	bzero(priv, sizeof(*priv));	/* XXX for safety */
	free(priv, M_DEVBUF);
}

#ifdef __FreeBSD__
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/uma.h>

static struct cdev_pager_ops saved_cdev_pager_ops;

static int
netmap_dev_pager_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	if (netmap_verbose)
		D("first mmap for %p", handle);
	return saved_cdev_pager_ops.cdev_pg_ctor(handle,
			size, prot, foff, cred, color);
}

static void
netmap_dev_pager_dtor(void *handle)
{
	saved_cdev_pager_ops.cdev_pg_dtor(handle);
	ND("ready to release memory for %p", handle);
}


static struct cdev_pager_ops netmap_cdev_pager_ops = {
        .cdev_pg_ctor = netmap_dev_pager_ctor,
        .cdev_pg_dtor = netmap_dev_pager_dtor,
        .cdev_pg_fault = NULL,
};

static int
netmap_mmap_single(struct cdev *cdev, vm_ooffset_t *foff,
	vm_size_t objsize,  vm_object_t *objp, int prot)
{
	vm_object_t obj;

	ND("cdev %p foff %jd size %jd objp %p prot %d", cdev,
	    (intmax_t )*foff, (intmax_t )objsize, objp, prot);
	obj = vm_pager_allocate(OBJT_DEVICE, cdev, objsize, prot, *foff,
            curthread->td_ucred);
	ND("returns obj %p", obj);
	if (obj == NULL)
		return EINVAL;
	if (saved_cdev_pager_ops.cdev_pg_fault == NULL) {
		ND("initialize cdev_pager_ops");
		saved_cdev_pager_ops = *(obj->un_pager.devp.ops);
		netmap_cdev_pager_ops.cdev_pg_fault =
			saved_cdev_pager_ops.cdev_pg_fault;
	};
	obj->un_pager.devp.ops = &netmap_cdev_pager_ops;
	*objp = obj;
	return 0;
}
#endif /* __FreeBSD__ */


/*
 * mmap(2) support for the "netmap" device.
 *
 * Expose all the memory previously allocated by our custom memory
 * allocator: this way the user has only to issue a single mmap(2), and
 * can work on all the data structures flawlessly.
 *
 * Return 0 on success, -1 otherwise.
 */

#ifdef __FreeBSD__
static int
netmap_mmap(__unused struct cdev *dev,
#if __FreeBSD_version < 900000
		vm_offset_t offset, vm_paddr_t *paddr, int nprot
#else
		vm_ooffset_t offset, vm_paddr_t *paddr, int nprot,
		__unused vm_memattr_t *memattr
#endif
	)
{
	int error = 0;
	struct netmap_priv_d *priv;

	if (nprot & PROT_EXEC)
		return (-1);	// XXX -1 or EINVAL ?

	error = devfs_get_cdevpriv((void **)&priv);
	if (error == EBADF) {	/* called on fault, memory is initialized */
		ND(5, "handling fault at ofs 0x%x", offset);
		error = 0;
	} else if (error == 0)	/* make sure memory is set */
		error = netmap_get_memory(priv);
	if (error)
		return (error);

	ND("request for offset 0x%x", (uint32_t)offset);
	*paddr = netmap_ofstophys(offset);

	return (*paddr ? 0 : ENOMEM);
}

static int
netmap_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	if (netmap_verbose)
		D("dev %p fflag 0x%x devtype %d td %p",
			dev, fflag, devtype, td);
	return 0;
}

static int
netmap_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct netmap_priv_d *priv;
	int error;

	priv = malloc(sizeof(struct netmap_priv_d), M_DEVBUF,
			      M_NOWAIT | M_ZERO);
	if (priv == NULL)
		return ENOMEM;

	error = devfs_set_cdevpriv(priv, netmap_dtor);
	if (error)
	        return error;

	return 0;
}
#endif /* __FreeBSD__ */


/*
 * Handlers for synchronization of the queues from/to the host.
 * Netmap has two operating modes:
 * - in the default mode, the rings connected to the host stack are
 *   just another ring pair managed by userspace;
 * - in transparent mode (XXX to be defined) incoming packets
 *   (from the host or the NIC) are marked as NS_FORWARD upon
 *   arrival, and the user application has a chance to reset the
 *   flag for packets that should be dropped.
 *   On the RXSYNC or poll(), packets in RX rings between
 *   kring->nr_kcur and ring->cur with NS_FORWARD still set are moved
 *   to the other side.
 * The transfer NIC --> host is relatively easy, just encapsulate
 * into mbufs and we are done. The host --> NIC side is slightly
 * harder because there might not be room in the tx ring so it
 * might take a while before releasing the buffer.
 */

/*
 * pass a chain of buffers to the host stack as coming from 'dst'
 */
static void
netmap_send_up(struct ifnet *dst, struct mbuf *head)
{
	struct mbuf *m;

	/* send packets up, outside the lock */
	while ((m = head) != NULL) {
		head = head->m_nextpkt;
		m->m_nextpkt = NULL;
		if (netmap_verbose & NM_VERB_HOST)
			D("sending up pkt %p size %d", m, MBUF_LEN(m));
		NM_SEND_UP(dst, m);
	}
}

struct mbq {
	struct mbuf *head;
	struct mbuf *tail;
	int count;
};

/*
 * put a copy of the buffers marked NS_FORWARD into an mbuf chain.
 * Run from hwcur to cur - reserved
 */
static void
netmap_grab_packets(struct netmap_kring *kring, struct mbq *q, int force)
{
	/* Take packets from hwcur to cur-reserved and pass them up.
	 * In case of no buffers we give up. At the end of the loop,
	 * the queue is drained in all cases.
	 * XXX handle reserved
	 */
	int k = kring->ring->cur - kring->ring->reserved;
	u_int n, lim = kring->nkr_num_slots - 1;
	struct mbuf *m, *tail = q->tail;

	if (k < 0)
		k = k + kring->nkr_num_slots;
	for (n = kring->nr_hwcur; n != k;) {
		struct netmap_slot *slot = &kring->ring->slot[n];

		n = (n == lim) ? 0 : n + 1;
		if ((slot->flags & NS_FORWARD) == 0 && !force)
			continue;
		if (slot->len < 14 || slot->len > NETMAP_BUF_SIZE) {
			D("bad pkt at %d len %d", n, slot->len);
			continue;
		}
		slot->flags &= ~NS_FORWARD; // XXX needed ?
		m = m_devget(NMB(slot), slot->len, 0, kring->na->ifp, NULL);

		if (m == NULL)
			break;
		if (tail)
			tail->m_nextpkt = m;
		else
			q->head = m;
		tail = m;
		q->count++;
		m->m_nextpkt = NULL;
	}
	q->tail = tail;
}

/*
 * called under main lock to send packets from the host to the NIC
 * The host ring has packets from nr_hwcur to (cur - reserved)
 * to be sent down. We scan the tx rings, which have just been
 * flushed so nr_hwcur == cur. Pushing packets down means
 * increment cur and decrement avail.
 * XXX to be verified
 */
static void
netmap_sw_to_nic(struct netmap_adapter *na)
{
	struct netmap_kring *kring = &na->rx_rings[na->num_rx_rings];
	struct netmap_kring *k1 = &na->tx_rings[0];
	int i, howmany, src_lim, dst_lim;

	howmany = kring->nr_hwavail;	/* XXX otherwise cur - reserved - nr_hwcur */

	src_lim = kring->nkr_num_slots;
	for (i = 0; howmany > 0 && i < na->num_tx_rings; i++, k1++) {
		ND("%d packets left to ring %d (space %d)", howmany, i, k1->nr_hwavail);
		dst_lim = k1->nkr_num_slots;
		while (howmany > 0 && k1->ring->avail > 0) {
			struct netmap_slot *src, *dst, tmp;
			src = &kring->ring->slot[kring->nr_hwcur];
			dst = &k1->ring->slot[k1->ring->cur];
			tmp = *src;
			src->buf_idx = dst->buf_idx;
			src->flags = NS_BUF_CHANGED;

			dst->buf_idx = tmp.buf_idx;
			dst->len = tmp.len;
			dst->flags = NS_BUF_CHANGED;
			ND("out len %d buf %d from %d to %d",
				dst->len, dst->buf_idx,
				kring->nr_hwcur, k1->ring->cur);

			if (++kring->nr_hwcur >= src_lim)
				kring->nr_hwcur = 0;
			howmany--;
			kring->nr_hwavail--;
			if (++k1->ring->cur >= dst_lim)
				k1->ring->cur = 0;
			k1->ring->avail--;
		}
		kring->ring->cur = kring->nr_hwcur; // XXX
		k1++;
	}
}

/*
 * netmap_sync_to_host() passes packets up. We are called from a
 * system call in user process context, and the only contention
 * can be among multiple user threads erroneously calling
 * this routine concurrently.
 */
static void
netmap_sync_to_host(struct netmap_adapter *na)
{
	struct netmap_kring *kring = &na->tx_rings[na->num_tx_rings];
	struct netmap_ring *ring = kring->ring;
	u_int k, lim = kring->nkr_num_slots - 1;
	struct mbq q = { NULL, NULL };

	k = ring->cur;
	if (k > lim) {
		netmap_ring_reinit(kring);
		return;
	}
	// na->nm_lock(na->ifp, NETMAP_CORE_LOCK, 0);

	/* Take packets from hwcur to cur and pass them up.
	 * In case of no buffers we give up. At the end of the loop,
	 * the queue is drained in all cases.
	 */
	netmap_grab_packets(kring, &q, 1);
	kring->nr_hwcur = k;
	kring->nr_hwavail = ring->avail = lim;
	// na->nm_lock(na->ifp, NETMAP_CORE_UNLOCK, 0);

	netmap_send_up(na->ifp, q.head);
}

/*
 * rxsync backend for packets coming from the host stack.
 * They have been put in the queue by netmap_start() so we
 * need to protect access to the kring using a lock.
 *
 * This routine also does the selrecord if called from the poll handler
 * (we know because td != NULL).
 *
 * NOTE: on linux, selrecord() is defined as a macro and uses pwait
 *     as an additional hidden argument.
 */
static void
netmap_sync_from_host(struct netmap_adapter *na, struct thread *td, void *pwait)
{
	struct netmap_kring *kring = &na->rx_rings[na->num_rx_rings];
	struct netmap_ring *ring = kring->ring;
	u_int j, n, lim = kring->nkr_num_slots;
	u_int k = ring->cur, resvd = ring->reserved;

	(void)pwait;	/* disable unused warnings */
	na->nm_lock(na->ifp, NETMAP_CORE_LOCK, 0);
	if (k >= lim) {
		netmap_ring_reinit(kring);
		return;
	}
	/* new packets are already set in nr_hwavail */
	/* skip past packets that userspace has released */
	j = kring->nr_hwcur;
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim - resvd;
        }
	if (j != k) {
		n = k >= j ? k - j : k + lim - j;
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
	}
	k = ring->avail = kring->nr_hwavail - resvd;
	if (k == 0 && td)
		selrecord(td, &kring->si);
	if (k && (netmap_verbose & NM_VERB_HOST))
		D("%d pkts from stack", k);
	na->nm_lock(na->ifp, NETMAP_CORE_UNLOCK, 0);
}

/* From sctputil.c */
void
nm_print_address(struct sockaddr *sa)
{
//#ifdef INET6
	char ip6buf[46]; /* INET6_ADDR_STRLEN is 46 in FreeBSD 48 in Linux */

	ip6buf[0] = 0;
//#endif

	switch (sa->sa_family) {
//#ifdef INET6
	case AF_INET6:
		{
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)sa;
			D("IPv6 address: %s:port:%d scope:%u",
			    ip6_sprintf(ip6buf, &sin6->sin6_addr),
			    ntohs(sin6->sin6_port),
			    sin6->sin6_scope_id);
			break;
		}
//#endif
//#ifdef INET
	case AF_INET:
		{
			struct sockaddr_in *sin;
			unsigned char *p;

			sin = (struct sockaddr_in *)sa;
			p = (unsigned char *)&sin->sin_addr;
			D("IPv4 address: %u.%u.%u.%u:%d",
			    p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
			break;
		}
//#endif
	default:
		D("?");
		break;
	}
}

#ifdef NM_BRIDGE
/* from tcp_lro.c iph->ip_sum = 0xffff ^ do_csum_data(...) */
static inline uint16_t
ipv4_csum(uint16_t *raw, int len)
{
        uint32_t csum;
        csum = 0;
        while (len > 0) {
                csum += *raw;
                raw++;
                csum += *raw;
                raw++;
                len -= 4;
        }
        csum = (csum >> 16) + (csum & 0xffff);
        csum = (csum >> 16) + (csum & 0xffff);
        return (uint16_t)csum;
}

#define ETHER_TYPE_OFF 12
/* We don't check existence of if_addrhead entry anymore */
static inline int
src_port_valid(uint16_t *toff, uint8_t protocol, struct netmap_ifaddr *nifa)
{
	if (protocol == nifa->protocol && *toff == nifa->laddr.sin.sin_port)
		return 1;
	else
		return 0;
}

/*
static inline int ipv6_addr_equal(const struct in6_addr *a1,
                                  const struct in6_addr *a2)
{
        return ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
                (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
                (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
                (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;
}
*/

static inline int
src_ipv4addr_valid(uint8_t *saddr, struct netmap_ifaddr *nifa)
{
	return *(uint32_t *)saddr == nifa->laddr.sin.sin_addr.s_addr;
}

static inline int
src_ipv6addr_valid(uint8_t *saddr, struct netmap_ifaddr *nifa)
{
	return IN6_ARE_ADDR_EQUAL((struct in6_addr *)saddr,
	    &nifa->laddr.sin6.sin6_addr);
}

#if 0
/* We assume at least one entry in if_addrhead */
static int
src_addr_pkt(uint8_t *buf, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa;
	struct ip *iph;
	struct ip6_hdr *ip6;
	uint16_t *ether_type;

	/* Walking in TAILQ seems to be very stupid!
	 * We therefore always put the first element as the source address
	 */
	nifa = (struct netmap_ifaddr *)TAILQ_FIRST(&ifp->if_addrhead);
	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	ether_type = (uint16_t *)(buf + ETHER_TYPE_OFF);
	/* We currently assume the ethernet header is filled by the app */
	/* AF_INET */
	if (ntohs(*ether_type) == 0x0800) {
		iph = (struct ip *)(buf + ETHER_HDR_LEN);
		if (unlikely(iph->ip_hl != 5))
			goto ipv4_slowpath;
		if (nifa->flags & NM_ADDRFLAG_AUTO_SADDR) {
			if (nifa->flags & NM_ADDRFLAG_AUTO_DADDR)
				iph->ip_dst = nifa->raddr.sin.sin_addr;
			iph->ip_src = nifa->laddr.sin.sin_addr;
			iph->ip_sum = 0xffff ^ ipv4_csum((uint16_t *)iph,
						sizeof(struct ip));
		} else if (nifa->flags & NM_ADDRFLAG_CHECK_SADDR) {
			if (iph->ip_src.s_addr !=
			    nifa->laddr.sin.sin_addr.s_addr) {
				nifa->cnt_err++;
				return 1;
			}
			if (nifa->flags & NM_ADDRFLAG_CHECK_DADDR)
				if (iph->ip_dst.s_addr !=
				    nifa->raddr.sin.sin_addr.s_addr) {
					nifa->cnt_err++;
					return 1;
				}
		}
		if (!src_port_valid((uint16_t *)(iph+1), (uint8_t)iph->ip_p,
		    nifa)) {
			nifa->cnt_err++;
			return 1;
		}
		if ((nifa->flags & NM_ADDRFLAG_AUTO_DADDR) ||
		    (nifa->flags & NM_ADDRFLAG_CHECK_DADDR)) {
			if (*((uint16_t *)(iph+1)+1) !=
			    nifa->raddr.sin.sin_port) {
				nifa->cnt_err++;
				return 1;
			}
		}
		nifa->cnt_passed++;
		return 0;
	} else if (ntohs(*ether_type) == 0x86DD) {
		ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
		if (nifa->flags & NM_ADDRFLAG_AUTO_SADDR) {
			memcpy(&ip6->ip6_src, &nifa->laddr.sin6.sin6_addr,
					sizeof(struct in6_addr));
			if (nifa->flags & NM_ADDRFLAG_AUTO_DADDR)
				memcpy(&ip6->ip6_dst,
				    &nifa->raddr.sin6.sin6_addr,
				    sizeof(struct in6_addr));
		}
		else if (nifa->flags & NM_ADDRFLAG_CHECK_SADDR) {
			if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src,
			    &nifa->laddr.sin6.sin6_addr)) {
				nifa->cnt_err++;
				return 1;
			}
			if (nifa->flags & NM_ADDRFLAG_CHECK_DADDR) {
				if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
				    &nifa->raddr.sin6.sin6_addr)) {
					nifa->cnt_err++;
					return 1;
				}
			}
		}
		if (!src_port_valid((uint16_t *)(ip6+1), (uint8_t)ip6->ip6_nxt,
		    nifa)) {
			nifa->cnt_err++;
			return 1;
		}
		if ((nifa->flags & NM_ADDRFLAG_AUTO_DADDR) ||
		    (nifa->flags & NM_ADDRFLAG_CHECK_DADDR)) {
			if (*((uint16_t *)(ip6+1)+1) !=
			    nifa->raddr.sin6.sin6_port) {
				nifa->cnt_err++;
				return 1;
			}
		}
		nifa->cnt_passed++;
		return 0;
	} else {
		nifa->cnt_unknown++;
		return 1;
	}
ipv4_slowpath:
	nifa->cnt_unknown++;
	return 1;
}
#endif /* 0 */

static int
bdg_egress_ipv4_fill(uint8_t *buf, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa = NULL;
	struct ip *iph;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x0800))
		goto out_err;
	nifa = NA(ifp)->nifa;
	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	/* We currently assume the ethernet header is filled by the app */
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	if (unlikely(iph->ip_hl != 5))
		goto ipv4_slowpath;
	if (nifa->flags & NM_ADDRFLAG_AUTO_DADDR) {
		if (*((uint16_t *)(iph+1)+1) != nifa->raddr.sin.sin_port)
			goto out_err;
		iph->ip_dst = nifa->raddr.sin.sin_addr;
	}
	iph->ip_src = nifa->laddr.sin.sin_addr;
	iph->ip_sum = 0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(struct ip));
	if (!src_port_valid((uint16_t *)(iph+1), (uint8_t)iph->ip_p, nifa))
		goto out_err;
	nifa->cnt_passed++;
	return 0;
ipv4_slowpath:
out_err:
	nifa->cnt_err++;
	return 1;
}

static int
bdg_egress_ipv6_fill(uint8_t *buf, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa = NULL;
	struct ip6_hdr *ip6;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x86DD))
		goto out_err;
	nifa = NA(ifp)->nifa;
	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	/* We currently assume the ethernet header is filled by the app */
	ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
	if (nifa->flags & NM_ADDRFLAG_AUTO_DADDR) {
		if (*((uint16_t *)(ip6+1)+1) != nifa->raddr.sin6.sin6_port)
			goto out_err;
		memcpy(&ip6->ip6_dst, &nifa->raddr.sin6.sin6_addr,
		    sizeof(struct in6_addr));
	}
	memcpy(&ip6->ip6_src, &nifa->laddr.sin6.sin6_addr,
	    sizeof(struct in6_addr));
	if (!src_port_valid((uint16_t *)(ip6+1), (uint8_t)ip6->ip6_nxt, nifa))
		goto out_err;
	nifa->cnt_passed++;
	return 0;
out_err:
	nifa->cnt_err++;
	return 1;
}

static int
bdg_egress_ipv4_chk(uint8_t *buf, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa = NULL;
	struct ip *iph;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x0800))
		goto out_err;
	nifa = NA(ifp)->nifa;
	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	/* We currently assume the ethernet header is filled by the app */
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	if (unlikely(iph->ip_hl != 5))
		goto ipv4_slowpath;
	if (nifa->flags & NM_ADDRFLAG_CHECK_DADDR) {
		if (*((uint16_t *)(iph+1)+1) != nifa->raddr.sin.sin_port)
			goto out_err;
		if (iph->ip_dst.s_addr != nifa->raddr.sin.sin_addr.s_addr)
			goto out_err;
	}
	if (iph->ip_src.s_addr != nifa->laddr.sin.sin_addr.s_addr)
		goto out_err;
	if (!src_port_valid((uint16_t *)(iph+1), (uint8_t)iph->ip_p, nifa))
		goto out_err;
	nifa->cnt_passed++;
	return 0;
ipv4_slowpath:
out_err:
	nifa->cnt_err++;
	return 1;
}

static int
bdg_egress_ipv6_chk(uint8_t *buf, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa = NULL;
	struct ip6_hdr *ip6;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x86DD))
		goto out_err;
	nifa = NA(ifp)->nifa;
	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	/* We currently assume the ethernet header is filled by the app */
	ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
	if (nifa->flags & NM_ADDRFLAG_CHECK_DADDR) {
		if (*((uint16_t *)(ip6+1)+1) != nifa->raddr.sin6.sin6_port)
			goto out_err;
		if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
		    &nifa->raddr.sin6.sin6_addr))
			goto out_err;
	}
	if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &nifa->laddr.sin6.sin6_addr))
		goto out_err;
	if (!src_port_valid((uint16_t *)(ip6+1), (uint8_t)ip6->ip6_nxt, nifa))
		goto out_err;
	nifa->cnt_passed++;
	return 0;
out_err:
	nifa->cnt_err++;
	return 1;
}

static int
nm_print_pkt(uint8_t *buf)
{
	uint16_t ether_type;
	uint8_t *th, *s, *d;
	char strbuf[128], saddr_str[46], daddr_str[46];

	strbuf[0] = 0;
	ether_type = ntohs(*(uint16_t *)(buf + ETHER_TYPE_OFF));
	if (ether_type == 0x0800) {
		struct ip *iph = (struct ip *)(buf + ETHER_HDR_LEN);

		th = ((uint8_t *)iph) + (iph->ip_hl << 2);
		s = (uint8_t *)&iph->ip_src;
		d = (uint8_t *)&iph->ip_dst;
		sprintf(strbuf, "%u.%u.%u.%u:%d > %u.%u.%u.%u:%d %u",
		    s[0], s[1], s[2], s[3], ntohs(*(uint16_t *)th),
		    d[0], d[1], d[2], d[3], ntohs(*(((uint16_t *)th)+1)),
		    iph->ip_p);
		D("%s", strbuf);
	} else if (ether_type == 0x86DD) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);

		th = (uint8_t *)(ip6+1);
		ip6_sprintf(saddr_str, &ip6->ip6_src);
		ip6_sprintf(daddr_str, &ip6->ip6_src);
		sprintf(strbuf, "%s:port:%d > %s:port:%d %u", saddr_str,
		    ntohs(*(uint16_t *)th), daddr_str,
		    ntohs(*(((uint16_t *)th)+1)), ip6->ip6_nxt);
		D("%s", strbuf);
	} else {
		if (netmap_verbose & NM_VERB_DBG)
			D("unsupported protocol 0x%x", ether_type);
	}
	return 0;
}

static int
tcp_dump_seqno(uint8_t *buf, uint32_t *seq, uint32_t *endseq)
{
	struct ip *iph;
	uint16_t ether_type;
	char *tcphdr;
	uint32_t *seq_p;

	ether_type = ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF)));
	if (ether_type != 0x0800) {
		if (netmap_verbose & NM_VERB_DBG)
			D("unsupported ether_type");
		return -1;
	}
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	if (unlikely(iph->ip_hl != 5)) {
		if (netmap_verbose & NM_VERB_DBG)
			D("unsupported ipv4 hdr len");
		return -1;
	}
	tcphdr = (char *)(iph+1);
	if (unlikely((tcphdr[12] >> 4) != 5)) {
		if (netmap_verbose & NM_VERB_DBG)
			D("unsupported tcp hdr len %d", (int)tcphdr[12]);
		return -1;
	}
	seq_p = (uint32_t *)(tcphdr + 4);
	*seq = ntohl(*seq_p);
	*endseq = *seq + (ntohs(iph->ip_len) - (iph->ip_hl << 2) -
			((tcphdr[12] >> 4) << 2));
	return 0;
}

static int
proto_number(uint8_t *buf)
{
	struct ip *iph;
	struct ip6_hdr *ip6;
	uint16_t ether_type;

	ether_type = ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF)));
	if (ether_type == 0x0800) {
		iph = (struct ip *)(buf + ETHER_HDR_LEN);
		return (int)iph->ip_p;
	} else if (ether_type == 0x86DD) {
		ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
		return (int)ip6->ip6_nxt;
	} else {
//		if (netmap_verbose & NM_VERB_DBG)
//			D("%s unsupported ether_type", __FUNCTION__);
	}
	return -1;
}

/* Dump TCP sequence number from hwcur to cur */
static int
dump_pkts_ring(struct netmap_kring *kring, int rx)
{
	struct netmap_ring *ring = kring->ring;
	u_int k = ring->cur;
	int lim, scanned = 0, j;
	uint32_t seq=0, endseq=0, tot_seq=0, tot_endseq=0;
	int num_pkts=0;
	int validpkt=0;
	int p;

	lim = kring->nkr_num_slots - 1;
	if (rx) {
		k = kring->nr_hwcur + kring->nr_hwavail;
		if (k > lim)
			k -= lim;
	}
	for (j = kring->nr_hwcur; likely(j != k); j = unlikely(j == lim) ? 0 : j+1) {
		struct netmap_slot *slot = &ring->slot[j];
		char *buf = NMB(slot);
		int len = slot->len;

		scanned++;
		if (unlikely(len < 14))
			continue;
		p = proto_number(buf);
		if (p > 0)
			validpkt++;
		if (p != IPPROTO_TCP) {
			if (validpkt%256 == 0)
				D("proto number %d", p);
			continue;
		}
		if (tcp_dump_seqno(buf, &seq, &endseq) < 0) {
			D("invalid TCP packet");
			continue;
		}
		if (tot_seq == 0) {
			tot_seq = seq;
			tot_endseq = endseq;
			num_pkts++;
			continue;
		}
		if (seq == tot_endseq) {
			tot_endseq = endseq;
			num_pkts++;
		} else {
			D("seq %u-%u by %d pkts in %d slots",tot_seq, tot_endseq, num_pkts, scanned);
			tot_seq = tot_endseq = 0;
			num_pkts = 0;
		}
	}
	if (num_pkts)
		D("seq %u-%u by %d pkts in %d slots", tot_seq, tot_endseq,
				num_pkts, scanned);
	return scanned;
}

static int
bdg_ingress_filter(uint8_t *buf, struct netmap_ifaddr *nifa)
{
	struct ip *iph;
	struct ip6_hdr *ip6;
	uint16_t ether_type;

	if (nifa->flags & NM_ADDRFLAG_ANY_ADDR)
		return 0;
	ether_type = ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF)));
	/* AF_INET */
	if (ether_type == 0x0800) {
		uint16_t sum;

		iph = (struct ip *)(buf + ETHER_HDR_LEN);
		if (unlikely(iph->ip_hl != 5))
			goto ipv4_slowpath;
		if (iph->ip_dst.s_addr != nifa->laddr.sin.sin_addr.s_addr)
			return 1;
		if ((nifa->flags & NM_ADDRFLAG_AUTO_DADDR) ||
		    (nifa->flags & NM_ADDRFLAG_CHECK_DADDR)) {
			if (iph->ip_src.s_addr !=
			    nifa->raddr.sin.sin_addr.s_addr)
				return 1;
			if (*((uint16_t *)(iph+1)) != nifa->raddr.sin.sin_port)
				return 1;
		}
		sum = iph->ip_sum;
		iph->ip_sum = 0;
		if (unlikely(sum !=
		    (0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(*iph))))) {
			iph->ip_sum = sum;
			return 1;
		}
		iph->ip_sum = sum;
		if (!src_port_valid((uint16_t *)(iph+1)+1, (uint8_t)iph->ip_p,
		    nifa))
			return 1;
		nifa->cnt_rcved++;
		return 0;
	} else if (ether_type == 0x86DD) {
		ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
		if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
		    &nifa->laddr.sin6.sin6_addr))
			return 1;
		if ((nifa->flags & NM_ADDRFLAG_AUTO_DADDR) ||
		    (nifa->flags & NM_ADDRFLAG_CHECK_DADDR)) {
			if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src,
			    &nifa->raddr.sin6.sin6_addr))
				return 1;
			if (*((uint16_t *)(ip6+1)) !=
			    nifa->raddr.sin6.sin6_port)
				return 1;
		}
		if (!src_port_valid((uint16_t *)(ip6+1)+1,
			(uint8_t)ip6->ip6_nxt, nifa))
			return 1;
		nifa->cnt_rcved++;
		return 0;
	}
ipv4_slowpath:
	/* XXX */
	return 1;
}

static struct netmap_ifaddr *
nm_findifa_sa(struct sockaddr *sa, uint8_t protocol)
{
	int i, found = 0;
	struct nm_ifahashhead *head;
	struct netmap_vrf *vrf = &nm_vrf;
	struct netmap_ifaddr *nifa;

	for (i = 0; i < NM_IFA_HASH; ++i) {
		NM_IFAHASH_RLOCK(i, vrf);
		head = &vrf->ifa_ht[i];
		LIST_FOREACH(nifa, head, ifahash_next) {
			if (nifa->laddr.sa.sa_family != sa->sa_family)
				continue;
			if (nifa->protocol != protocol)
				continue;
			if (sa->sa_family == AF_INET) {
				if (nifa->laddr.sin.sin_port !=
				    satosin(sa)->sin_port)
					continue;
				if (nifa->laddr.sin.sin_addr.s_addr !=
				    satosin(sa)->sin_addr.s_addr)
					continue;
			} else if (sa->sa_family == AF_INET6) {
				if (nifa->laddr.sin6.sin6_port !=
				    satosin6(sa)->sin6_port)
					continue;
				if (!IN6_ARE_ADDR_EQUAL(
				    &nifa->laddr.sin6.sin6_addr,
				    &satosin6(sa)->sin6_addr))
					continue;
			} else
				continue;
			found = 1;
			break;
		}
		NM_IFAHASH_RUNLOCK(i, vrf);
		if (found)
			return nifa;
	}
	return NULL;
}

# if 0
static int
nm_del_addr_bdgif(struct sockaddr *sa, uint8_t protocol, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa;

	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
		D("unknown address family");
		return -1;
	}
	nifa = nm_findifa_sa(sa, protocol);
	if (nifa)
		nm_del_ifaddr(nifa, ifp);
	else {
		D("requested address does not exist in the list");
		nm_print_address(sa);
	}
	return 0;
}
#endif /* 0 */

static int
nm_add_addr_bdgif(struct sockaddr *sa, struct sockaddr *dsa, uint8_t protocol,
		uint8_t flags, struct ifnet *ifp)
{
	struct netmap_ifaddr *nifa = NULL;
	struct netmap_adapter *na = NA(ifp);
	struct nm_ifahashhead *head;
	struct netmap_vrf *vrf = &nm_vrf;
	int hashval;

	nifa = nm_findifa_sa(sa, protocol);
	if (nifa) {
		D("already registered");
		return 0;
	}
	nifa = (struct netmap_ifaddr *)malloc(sizeof(*nifa), M_IFADDR,
			M_WAITOK | M_ZERO);
	if (nifa == NULL)
		return ENOMEM;
	NM_REFCOUNT_SET(&nifa->refcount, 0); /* XXX */
	nifa->protocol = protocol;
	nifa->flags = flags ? flags : NM_ADDRFLAG_AUTO_SADDR;
	nifa->laddr.sa.sa_family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		nifa->laddr.sin.sin_port = satosin(sa)->sin_port;
		nifa->laddr.sin.sin_addr.s_addr = satosin(sa)->sin_addr.s_addr;
		if (dsa) {
			nifa->raddr.sin.sin_family = AF_INET;
			nifa->raddr.sin.sin_port = satosin(dsa)->sin_port;
			nifa->raddr.sin.sin_addr.s_addr =
			    satosin(dsa)->sin_addr.s_addr;
		}
		if (nifa->flags & NM_ADDRFLAG_CHECK_SADDR)
			nifa->egress_filter = bdg_egress_ipv4_chk;
		else
			nifa->egress_filter = bdg_egress_ipv4_fill;
	} else if (sa->sa_family == AF_INET6) {
		nifa->laddr.sin6.sin6_port = satosin6(sa)->sin6_port;
		memcpy(&nifa->laddr.sin6.sin6_addr, &satosin6(sa)->sin6_addr,
				sizeof(struct in6_addr));
		if (dsa) {
			nifa->raddr.sin6.sin6_family = AF_INET6;
			nifa->raddr.sin6.sin6_port = satosin6(dsa)->sin6_port;
			memcpy(&nifa->raddr.sin6.sin6_addr,
			    &satosin6(dsa)->sin6_addr, sizeof(struct in6_addr));
		}
		if (nifa->flags & NM_ADDRFLAG_CHECK_SADDR)
			nifa->egress_filter = bdg_egress_ipv6_chk;
		else
			nifa->egress_filter = bdg_egress_ipv6_fill;
	}
	nifa->bdg_idx = na->bdg_idx;
	nifa->bdg_port = na->bdg_port;
	hashval = nm_ifa_rthash_from_ifa(nifa);
	NM_IFAHASH_WLOCK(hashval, vrf);
	head = &vrf->ifa_ht[hashval];
	if (!LIST_EMPTY(head) && netmap_verbose & NM_VERB_DBG)
		D("hash collision (%u)", hashval);
	LIST_INSERT_HEAD(head, nifa, ifahash_next);
	nm_ref_ifa(nifa); /* reference from the hash table */
	na->nifa = nifa;
	na->nm_ifflags |= NM_IFF_BDG_FILTERED;
	if (netmap_verbose & NM_VERB_DBG) {
		D("added (flags 0x%02x hash %d port %d)", nifa->flags, hashval, na->bdg_port);
		nm_print_address(&nifa->laddr.sa);
		if (dsa) {
			D("dst ");
			nm_print_address(&nifa->raddr.sa);
		}
	}
	NM_IFAHASH_WUNLOCK(hashval, vrf);
	return 0;
}

static void
vif_set_fwdfunc(int algo, struct netmap_vrf_if *vif)
{
	switch (algo) {
	case NM_UNIBDG_FWDALGO_MBDG:
		vif->bdgfwd_func = nm_bdg_flush_from_vrf;
		D("nm_bdg_flush_from_vrf()");
		break;
	case NM_UNIBDG_FWDALGO_IDX:
		vif->bdgfwd_func = nm_unibdg_flush;
		D("unibdg_flush()");
		break;
	case NM_UNIBDG_FWDALGO_IDXX:
		vif->bdgfwd_func = nm_unibdg_flush3;
		D("unibdg_flush3()");
		break;
	case NM_UNIBDG_FWDALGO_BATCHSIZ:
		vif->bdgfwd_func = nm_unibdg_flush2;
		D("unibdg_flush2()");
		break;
	case NM_UNIBDG_FWDALGO_RPS:
		vif->bdgfwd_func = nm_unibdg_flush_rps;
		D("unibdg_flush_rps()");
		break;
	default:
		vif->bdgfwd_func = nm_unibdg_flush;
		D("unibdg_flush()");
		break;
	}

}

static struct netmap_vrf_if *
netmap_alloc_vif(struct ifnet *ifp, struct netmap_vrf *vrf) {
	struct netmap_vrf_if *vif;

	vif = malloc(sizeof(*vif), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!vif)
		return NULL;
	vif->vrf = vrf;
	vif->ifn = ifp;
	/* refcount is set to 1 when configuration has completed */
	NM_REFCOUNT_SET(&vif->refcount, 0);
	return vif;
}

static int
bdg_do_options(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
	struct nmaddrreq *nma = (struct nmaddrreq *)data;
	int err = 0;
	struct sockaddr *dst = NULL;
	struct ifnet *dst_ifp;
	struct netmap_vrf *vrf = &nm_vrf;
	struct netmap_vrf_if *vif;
	int i;
	struct nmreq nmr;
	struct netmap_adapter *na = NA(ifp);

	/* First, validate parameter */
	if ((nma->nar_laddr.sa.sa_family != AF_INET) &&
	    (nma->nar_laddr.sa.sa_family != AF_INET6))
		return EINVAL;
	/* the given local address exists in one of our interfaces ? */
	if (!nm_findifa_system(&nma->nar_laddr.sa)) {
		if ((netmap_verbose & NM_VERB_DBG) && (cmd == NIOCSMSOPEN))
			D("requested address does not exist in the system");
	//	return EINVAL; /* for debug I ignore existence of the address */
	}
	if ((nma->nar_flags == NM_ADDRFLAG_AUTO_SRCDST) ||
	    (nma->nar_flags == NM_ADDRFLAG_CHECK_SRCDST)) {
		if ((nma->nar_raddr.sa.sa_family != AF_INET) &&
		    (nma->nar_raddr.sa.sa_family != AF_INET6))
			return EINVAL;
		if (nma->nar_laddr.sa.sa_family !=
		    nma->nar_raddr.sa.sa_family)
			return EINVAL;
		dst = &nma->nar_raddr.sa;
	}

	switch (cmd) {
	case NIOCSMSOPEN:
		/* Register to vrf */
		bzero(&nmr, sizeof(nmr));
		strncpy(nmr.nr_name, nma->nar_hwifname, sizeof(nmr.nr_name));
		err = get_ifp(&nmr, &dst_ifp);
		if (err)
			return EINVAL;
		NM_VRF_WLOCK(vrf); /* protect from interrupts */
	        if ((vif = NETMAP_VIF(dst_ifp)) != NULL) {
			vrf_if_ref(vif);
			goto skip_regif;
		}
		err = vrf_netmap_regif(dst_ifp, nma->nar_dst_ringid, &vif);
		if (err) {
			free(vif, M_DEVBUF);
			nm_if_rele(dst_ifp);
			NM_VRF_WUNLOCK(vrf);
			return err;
		}
skip_regif:
		/* Allocate entries in the TX intr queues */
		na->txintrq_ent = malloc(sizeof(struct nm_txintrq_ent) *
			(NA(dst_ifp)->num_tx_rings+1), M_DEVBUF,
			M_NOWAIT | M_ZERO);
		if (!na->txintrq_ent) {
			NM_VRF_WUNLOCK(vrf);
			vrf_if_rele(vif);
			nm_if_rele(dst_ifp);
			return ENOMEM;
		}
		for (i=0; i <= NA(dst_ifp)->num_tx_rings; ++i)
			na->txintrq_ent[i].na = na;
		na->dst_vif = vif;
		na->nm_ifflags |= NM_IFF_BDG_HW;

		/* Register a packet filter */
		err = nm_add_addr_bdgif(&nma->nar_laddr.sa, dst,
				nma->nar_protocol, nma->nar_flags, ifp);
		if (err) {
			na->dst_vif = NULL;
			na->nm_ifflags &= ~NM_IFF_BDG_HW;
			free(na->txintrq_ent, M_DEVBUF);
			nm_if_rele(dst_ifp);
		}
		NM_VRF_WUNLOCK(vrf);
		if (err)
			vrf_if_rele(vif);
		return err;
	case NIOCSMSCLOSE:
		/* We don't support this operation anymore, because to protect
		 * from the other threads running, we need to lock somehow.
		 */
#if 0
		if (!(na->nm_ifflags & NM_IFF_BDG_HW))
			return EINVAL;
		dst_ifp = ifunit_ref(nma->nar_hwifname);
		if (!dst_ifp)
			return EINVAL;

		NM_VRF_WLOCK(vrf);
		if ((vif = NETMAP_VIF(dst_ifp)) == NULL) {
			NM_VRF_WUNLOCK(vrf);
			nm_if_rele(dst_ifp);
			return EINVAL;
		}
		nm_if_rele(dst_ifp); /* for the last ifunit_ref */
		if (netmap_verbose & NM_VERB_DBG)
			D("next, del_addr_bdgif for %s", ifp->if_xname);
		err = nm_del_addr_bdgif(&nma->nar_laddr.sa,
				nma->nar_protocol, ifp);
		if (!err) {
			if (netmap_verbose & NM_VERB_DBG)
				D("next, bdg_deach_vif for %s", ifp->if_xname);
			nm_bdg_detach_vif(na);
			if (netmap_verbose & NM_VERB_DBG)
				D("success for NIOCSMSCLOSE %s", ifp->if_xname);
		}
		NM_VRF_WUNLOCK(vrf);
		return err;
#endif /* 0 */
	default:
		break;

	}

	return err;
}
#ifdef __FreeBSD__
#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL
static void *
nm_findifa_system(struct sockaddr *sa)
{
	struct ifnet *ifn;
	struct ifaddr *ifa;
	struct ifaddr *retval = NULL;

	IFNET_RLOCK();
	TAILQ_FOREACH(ifn, &MODULE_GLOBAL(ifnet), if_list) {
		IF_ADDR_RLOCK(ifn);
		TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
			if (sa->sa_family == AF_INET) {
				if (satosin(sa)->sin_addr.s_addr !=
				    satosin(ifa->ifa_addr)->sin_addr.s_addr)
					continue;
			}
			if (sa->sa_family == AF_INET6) {
				if (!IN6_ARE_ADDR_EQUAL(
				    &satosin6(sa)->sin6_addr,
				    &satosin6(ifa->ifa_addr)->sin6_addr))
					continue;
			}
			retval = ifa;
		}
		IF_ADDR_RUNLOCK(ifn);
		if (retval)
			/* ifn is still locked */
			break;
	}
	IFNET_RUNLOCK();

	return retval;
}
#elif defined(linux)
#include <linux/inetdevice.h>
#include <net/addrconf.h>
static void *
nm_findifa_system(struct sockaddr *sa, int *nic_port)
{
	struct net_device *dev;
	void *retval = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		rcu_read_lock();
		if (sa->sa_family == AF_INET) {
			struct in_device *in_dev;
			struct in_ifaddr *ifa;
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if ((in_dev = __in_dev_get_rcu(dev)) == NULL) {
				rcu_read_unlock();
				continue;
			}
			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_local == sin->sin_addr.s_addr) {
					retval = (void *)ifa;
					break;
				}
			}
			rcu_read_unlock();
		} else if (sa->sa_family == AF_INET6) {
			struct inet6_dev *in6_dev;
			struct inet6_ifaddr *ifa;
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			rcu_read_lock();
			if ((in6_dev = __in6_dev_get(dev)) == NULL) {
				rcu_read_unlock();
				continue;
			}
			read_lock_bh(&in6_dev->lock);
			list_for_each_entry(ifa, &in6_dev->addr_list, if_list) {
				if (ipv6_addr_equal(&ifa->addr,
				    &sin6->sin6_addr)) {
					retval = (void *)ifa;
					break;
				}
			}
			read_unlock_bh(&in6_dev->lock);
			rcu_read_unlock();
		}
		if (retval)
			break;
	}
	rcu_read_unlock();
	return retval;
}
#endif /* FreeBSD, linux */

/* We don't wanna create new bdgif when the specified one does not exist ... */
static int
get_bdgifp_exist(const char *name, struct ifnet **ifp)
{
	struct ifnet *iter = NULL;
	int namelen, i, l, act_ports;
	struct nm_bridge *b = NULL;

	*ifp = NULL;
	if (strncmp(name, NM_NAME, sizeof(NM_NAME) -1))
		return -1;
	/* get base name */
	namelen = strlen(NM_NAME);
	l = strlen(name);
	for (i = namelen + 1; i < l; i++) {
		if (name[i] == ':') {
			namelen = i;
			break;
		}
	}
	if (namelen >= IFNAMSIZ)
		namelen = IFNAMSIZ;
	BDG_LOCK(nm_bridges);
	for (i = 0; i < NM_BRIDGES; i++) {
		b = nm_bridges + i;
		if (b->namelen == namelen) {
			if (!strncmp(b->basename, name, b->namelen))
				break;
		}
	}
	if (i == NM_BRIDGES) {
		BDG_UNLOCK(nm_bridges);
		return -1;
	}
	act_ports = (b->n_ports == NM_UNIBDG_MAXPORTS) ?
		NM_UNIBDG_MAXPORTS : NM_BDG_MAXPORTS;
	for (i = 0; i < act_ports; i++) {
		iter = b->bdg_ports[i];
		if (iter == NULL)
			continue;
		if (!strcmp(iter->if_xname, name)) {
			BDG_UNLOCK(nm_bridges);
			*ifp = iter;
			return 0;
		}
	}
	BDG_UNLOCK(nm_bridges);
	return -1;
}
#endif /* NM_BRIDGE */

/*
 * get a refcounted reference to an interface.
 * Return ENXIO if the interface does not exist, EINVAL if netmap
 * is not supported by the interface.
 * If successful, hold a reference.
 */
static int
get_ifp(const struct nmreq *nmr, struct ifnet **ifp)
{
#ifdef NM_BRIDGE
	struct ifnet *iter = NULL;
	const char *name = nmr->nr_name;

	do {
		struct nm_bridge *b;
		int i, l, cand = -1;
		int act_ports;
		int num_rings = 1;

		if (strncmp(name, NM_NAME, sizeof(NM_NAME) - 1))
			break;
		b = nm_find_bridge(name);
		if (b == NULL) {
			D("no bridges available for '%s'", name);
			return (ENXIO);
		}
		act_ports = (b->n_ports == NM_UNIBDG_MAXPORTS) ? NM_UNIBDG_MAXPORTS : NM_BDG_MAXPORTS;
		/* XXX locking */
		BDG_LOCK(b);
		/* lookup in the local list of ports */
		for (i = 0; i < act_ports; i++) {
			iter = b->bdg_ports[i];
			if (iter == NULL) {
				if (cand == -1)
					cand = i; /* potential insert point */
				continue;
			}
			if (!strcmp(iter->if_xname, name)) {
				ADD_BDG_REF(iter);
				ND("found existing interface");
				BDG_UNLOCK(b);
				break;
			}
		}
		if (i < act_ports) /* already unlocked */
			break;
		if (cand == -1) {
			D("bridge full, cannot create new port");
no_port:
			BDG_UNLOCK(b);
			*ifp = NULL;
			return EINVAL;
		}
		ND("create new bridge port %s", name);
		/* space for forwarding list after the ifnet */
		l = sizeof(*iter) +
			 sizeof(struct nm_bdg_fwd)*NM_BDG_BATCH ;
//		if (b->n_ports == NM_UNIBDG_MAXPORTS)
//			l += sizeof(struct nm_unibdgfwd_head)*NM_UNIBDG_MAXPORTS;
		iter = malloc(l, M_DEVBUF, M_NOWAIT | M_ZERO);
		if (!iter)
			goto no_port;
		strcpy(iter->if_xname, name);
		/* XXX do better... */
		if (nmr->nr_tx_rings && (nmr->nr_tx_rings == nmr->nr_rx_rings))
			num_rings = nmr->nr_tx_rings > NM_VRF_RINGNUM ?
				1 : nmr->nr_tx_rings;
		bdg_netmap_attach(iter, num_rings);
		b->bdg_ports[cand] = iter;
		iter->if_bridge = b;
		ADD_BDG_REF(iter);
		BDG_UNLOCK(b);
		ND("attaching virtual bridge %p", b);
	} while (0);
	*ifp = iter;
	if (! *ifp)
#endif /* NM_BRIDGE */
	*ifp = ifunit_ref(name);
	if (*ifp == NULL)
		return (ENXIO);
	/* can do this if the capability exists and if_pspare[0]
	 * points to the netmap descriptor.
	 */
	if (NETMAP_CAPABLE(*ifp))
		return 0;	/* valid pointer, we hold the refcount */
	nm_if_rele(*ifp);
	return EINVAL;	// not NETMAP capable
}


/*
 * Error routine called when txsync/rxsync detects an error.
 * Can't do much more than resetting cur = hwcur, avail = hwavail.
 * Return 1 on reinit.
 *
 * This routine is only called by the upper half of the kernel.
 * It only reads hwcur (which is changed only by the upper half, too)
 * and hwavail (which may be changed by the lower half, but only on
 * a tx ring and only to increase it, so any error will be recovered
 * on the next call). For the above, we don't strictly need to call
 * it under lock.
 */
int
netmap_ring_reinit(struct netmap_kring *kring)
{
	struct netmap_ring *ring = kring->ring;
	u_int i, lim = kring->nkr_num_slots - 1;
	int errors = 0;

//	RD(10, "called for %s", kring->na->ifp->if_xname);
	if (ring->cur > lim)
		errors++;
	for (i = 0; i <= lim; i++) {
		u_int idx = ring->slot[i].buf_idx;
		u_int len = ring->slot[i].len;
		if (idx < 2 || idx >= netmap_total_buffers) {
			if (!errors++)
				D("bad buffer at slot %d idx %d len %d ", i, idx, len);
			ring->slot[i].buf_idx = 0;
			ring->slot[i].len = 0;
		} else if (len > NETMAP_BUF_SIZE) {
			ring->slot[i].len = 0;
			if (!errors++)
				D("bad len %d at slot %d idx %d",
					len, i, idx);
		}
	}
	if (errors) {
//		int pos = kring - kring->na->tx_rings;
//		int n = kring->na->num_tx_rings + 1;

//		RD(10, "total %d errors", errors);
		errors++;
//		RD(10, "%s %s[%d] reinit, cur %d -> %d avail %d -> %d",
//			kring->na->ifp->if_xname,
//			pos < n ?  "TX" : "RX", pos < n ? pos : pos - n,
//			ring->cur, kring->nr_hwcur,
//			ring->avail, kring->nr_hwavail);
		ring->cur = kring->nr_hwcur;
		ring->avail = kring->nr_hwavail;
	}
	return (errors ? 1 : 0);
}


/*
 * Set the ring ID. For devices with a single queue, a request
 * for all rings is the same as a single ring.
 */
static int
netmap_set_ringid(struct netmap_priv_d *priv, u_int ringid)
{
	struct ifnet *ifp = priv->np_ifp;
	struct netmap_adapter *na = NA(ifp);
	u_int i = ringid & NETMAP_RING_MASK;
	/* initially (np_qfirst == np_qlast) we don't want to lock */
	int need_lock = (priv->np_qfirst != priv->np_qlast);
	int lim = na->num_rx_rings;

	if (na->num_tx_rings > lim)
		lim = na->num_tx_rings;
	if ( (ringid & NETMAP_HW_RING) && i >= lim) {
		D("invalid ring id %d", i);
		return (EINVAL);
	}
	if (need_lock)
		na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
	priv->np_ringid = ringid;
	if (ringid & NETMAP_SW_RING) {
		priv->np_qfirst = NETMAP_SW_RING;
		priv->np_qlast = 0;
	} else if (ringid & NETMAP_HW_RING) {
		priv->np_qfirst = i;
		priv->np_qlast = i + 1;
	} else {
		priv->np_qfirst = 0;
		priv->np_qlast = NETMAP_HW_RING ;
	}
	priv->np_txpoll = (ringid & NETMAP_NO_TX_POLL) ? 0 : 1;
	if (need_lock)
		na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);
    if (netmap_verbose & NM_VERB_DBG) {
	if (ringid & NETMAP_SW_RING)
		D("ringid %s set to SW RING", ifp->if_xname);
	else if (ringid & NETMAP_HW_RING)
		D("ringid %s set to HW RING %d", ifp->if_xname,
			priv->np_qfirst);
	else
		D("ringid %s set to all %d HW RINGS", ifp->if_xname, lim);
    }
	return 0;
}

/*
 * ioctl(2) support for the "netmap" device.
 *
 * Following a list of accepted commands:
 * - NIOCGINFO
 * - SIOCGIFADDR	just for convenience
 * - NIOCREGIF
 * - NIOCUNREGIF
 * - NIOCTXSYNC
 * - NIOCRXSYNC
 *
 * Return 0 on success, errno otherwise.
 */
static int
netmap_ioctl(struct cdev *dev, u_long cmd, caddr_t data,
	int fflag, struct thread *td)
{
	struct netmap_priv_d *priv = NULL;
	struct ifnet *ifp;
	struct nmreq *nmr = (struct nmreq *) data;
	struct netmap_adapter *na;
	int error;
	u_int i, lim;
	struct netmap_if *nifp;

	(void)dev;	/* UNUSED */
	(void)fflag;	/* UNUSED */
#ifdef linux
#define devfs_get_cdevpriv(pp)				\
	({ *(struct netmap_priv_d **)pp = ((struct file *)td)->private_data;	\
		(*pp ? 0 : ENOENT); })

/* devfs_set_cdevpriv cannot fail on linux */
#define devfs_set_cdevpriv(p, fn)				\
	({ ((struct file *)td)->private_data = p; (p ? 0 : EINVAL); })


#define devfs_clear_cdevpriv()	do {				\
		netmap_dtor(priv); ((struct file *)td)->private_data = 0;	\
	} while (0)
#endif /* linux */

	CURVNET_SET(TD_TO_VNET(td));

	error = devfs_get_cdevpriv((void **)&priv);
	if (error) {
		CURVNET_RESTORE();
		/* XXX ENOENT should be impossible, since the priv
		 * is now created in the open */
		return (error == ENOENT ? ENXIO : error);
	}

	nmr->nr_name[sizeof(nmr->nr_name) - 1] = '\0';	/* truncate name */
	switch (cmd) {
	case NIOCGINFO:		/* return capabilities etc */
		if (nmr->nr_version != NETMAP_API) {
			D("API mismatch got %d have %d",
				nmr->nr_version, NETMAP_API);
			nmr->nr_version = NETMAP_API;
			error = EINVAL;
			break;
		}
		/* update configuration */
		error = netmap_get_memory(priv);
		ND("get_memory returned %d", error);
		if (error)
			break;
		/* memsize is always valid */
		nmr->nr_memsize = nm_mem.nm_totalsize;
		nmr->nr_offset = 0;
		if (!(nmr->nr_rx_rings && nmr->nr_rx_rings == nmr->nr_tx_rings))
			nmr->nr_rx_rings = nmr->nr_tx_rings = 0;
		nmr->nr_rx_slots = nmr->nr_tx_slots = 0;
		if (nmr->nr_name[0] == '\0')	/* just get memory info */
			break;
		error = get_ifp(nmr, &ifp); /* get a refcount */
		if (error)
			break;
		na = NA(ifp); /* retrieve netmap_adapter */
		netmap_update_config(na);
		nmr->nr_rx_rings = na->num_rx_rings;
		nmr->nr_tx_rings = na->num_tx_rings;
		nmr->nr_rx_slots = na->num_rx_desc;
		nmr->nr_tx_slots = na->num_tx_desc;
		nm_if_rele(ifp);	/* return the refcount */
		break;

	case NIOCREGIF:
		if (nmr->nr_version != NETMAP_API) {
			nmr->nr_version = NETMAP_API;
			error = EINVAL;
			break;
		}
		/* ensure allocators are ready */
		error = netmap_get_memory(priv);
		ND("get_memory returned %d", error);
		if (error)
			break;

		/* protect access to priv from concurrent NIOCREGIF */
		NMA_LOCK();
		if (priv->np_ifp != NULL) {	/* thread already registered */
			error = netmap_set_ringid(priv, nmr->nr_ringid);
			NMA_UNLOCK();
			break;
		}
		/* find the interface and a reference */
		error = get_ifp(nmr, &ifp); /* keep reference */
		if (error) {
			NMA_UNLOCK();
			break;
		}
		na = NA(ifp); /* retrieve netmap adapter */

		for (i = 10; i > 0; i--) {
			na->nm_lock(ifp, NETMAP_REG_LOCK, 0);
			if (!NETMAP_DELETING(na))
				break;
			na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
			tsleep(na, 0, "NIOCREGIF", hz/10);
		}
		if (i == 0) {
			D("too many NIOCREGIF attempts, give up");
			error = EINVAL;
			nm_if_rele(ifp);	/* return the refcount */
			NMA_UNLOCK();
			break;
		}

		/* ring configuration may have changed, fetch from the card */
		netmap_update_config(na);
//		NM_VRF_WLOCK(vrf); /* XXX is this right place? */
		priv->np_ifp = ifp;	/* store the reference */
		error = netmap_set_ringid(priv, nmr->nr_ringid);
		if (error)
			goto error;
		nifp = netmap_if_new(nmr->nr_name, na);
		if (nifp == NULL) { /* allocation failed */
			error = ENOMEM;
		} else if (ifp->if_capenable & IFCAP_NETMAP) {
			/* was already set */
		} else {
			/* Otherwise set the card in netmap mode
			 * and make it use the shared buffers.
			 */
			for (i = 0 ; i < na->num_tx_rings + 1; i++)
				mtx_init(&na->tx_rings[i].q_lock, "nm_txq_lock", MTX_NETWORK_LOCK, MTX_DEF);
			for (i = 0 ; i < na->num_rx_rings + 1; i++) {
				mtx_init(&na->rx_rings[i].q_lock, "nm_rxq_lock", MTX_NETWORK_LOCK, MTX_DEF);
			}
			error = na->nm_register(ifp, 1); /* mode on */
			if (error) {
				netmap_dtor_locked(priv);
				netmap_if_free(nifp);
			}
		}

		if (error) {	/* reg. failed, release priv and ref */
error:
			na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
//			NM_VRF_WUNLOCK(vrf);
			nm_if_rele(ifp);	/* return the refcount */
			priv->np_ifp = NULL;
			priv->np_nifp = NULL;
			NMA_UNLOCK();
			break;
		}

		na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);

		/* the following assignment is a commitment.
		 * Readers (i.e., poll and *SYNC) check for
		 * np_nifp != NULL without locking
		 */
		wmb(); /* make sure previous writes are visible to all CPUs */
		priv->np_nifp = nifp;
		NMA_UNLOCK();

		/* return the offset of the netmap_if object */
		nmr->nr_rx_rings = na->num_rx_rings;
		nmr->nr_tx_rings = na->num_tx_rings;
		nmr->nr_rx_slots = na->num_rx_desc;
		nmr->nr_tx_slots = na->num_tx_desc;
		nmr->nr_memsize = nm_mem.nm_totalsize;
		nmr->nr_offset = netmap_if_offset(nifp);
		break;

	case NIOCUNREGIF:
		// XXX we have no data here ?
//		D("deprecated, data is %p", nmr);
		ND("deprecated, data is %p", nmr);
		error = EINVAL;
		break;

	/* taken from in6.c, in6_var.h and if.h (already included) */
	case NIOCSMSOPEN:
	case NIOCSMSCLOSE:
		{
			struct ifnet *ifp;
			struct nmaddrreq *nma = (struct nmaddrreq *)data;

			if (priv == NULL) {
				error = ENXIO;
				break;
			}
			/* XXX we need check of whether data have length... */
			if (get_bdgifp_exist(nma->nar_ifname, &ifp))  {
				D("cannot find bdgifp");
				error = EINVAL;
				break;
			}
			error = bdg_do_options(ifp, cmd, data);
			break;
		}
	case NIOCTXSYNC:
	case NIOCRXSYNC:
		nifp = priv->np_nifp;

		if (nifp == NULL) {
			error = ENXIO;
			break;
		}
		rmb(); /* make sure following reads are not from cache */


		ifp = priv->np_ifp;	/* we have a reference */

		if (ifp == NULL) {
			D("Internal error: nifp != NULL && ifp == NULL");
			error = ENXIO;
			break;
		}

		na = NA(ifp); /* retrieve netmap adapter */
		if (priv->np_qfirst == NETMAP_SW_RING) { /* host rings */
			if (cmd == NIOCTXSYNC)
				netmap_sync_to_host(na);
			else
				netmap_sync_from_host(na, NULL, NULL);
			break;
		}
		/* find the last ring to scan */
		lim = priv->np_qlast;
		if (lim == NETMAP_HW_RING)
			lim = (cmd == NIOCTXSYNC) ?
			    na->num_tx_rings : na->num_rx_rings;

		for (i = priv->np_qfirst; i < lim; i++) {
			if (cmd == NIOCTXSYNC) {
				struct netmap_kring *kring = &na->tx_rings[i];
				if (netmap_verbose & NM_VERB_TXSYNC) {
					/*
					D("pre txsync ring %d cur %d hwcur %d",
					    i, kring->ring->cur,
					    kring->nr_hwcur);
					    */
					D("pre txsync %s ring %d cur %d hwcur %d avail %d hwavail %d",
					    ifp->if_xname, i, kring->ring->cur,
					    kring->nr_hwcur, kring->ring->avail,
					    kring->nr_hwavail);
				}
				na->nm_txsync(ifp, i, 1 /* do lock */);
				if (netmap_verbose & NM_VERB_TXSYNC)
					/*
					D("post txsync ring %d cur %d hwcur %d",
					    i, kring->ring->cur,
					    kring->nr_hwcur);
					    */
					D("post txsync %s ring %d cur %d hwcur %d avail %d hwavail %d",
					    ifp->if_xname, i, kring->ring->cur,
					    kring->nr_hwcur,
					    kring->ring->avail,
					    kring->nr_hwavail);
			} else {
				na->nm_rxsync(ifp, i, 1 /* do lock */);
				microtime(&na->rx_rings[i].ring->ts);
			}
		}

		break;

#ifdef __FreeBSD__
	case BIOCIMMEDIATE:
	case BIOCGHDRCMPLT:
	case BIOCSHDRCMPLT:
	case BIOCSSEESENT:
		D("ignore BIOCIMMEDIATE/BIOCSHDRCMPLT/BIOCSHDRCMPLT/BIOCSSEESENT");
		break;

	default:	/* allow device-specific ioctls */
	    {
		struct socket so;
		bzero(&so, sizeof(so));
		error = get_ifp(nmr, &ifp); /* keep reference */
		if (error)
			break;
		so.so_vnet = ifp->if_vnet;
		// so->so_proto not null.
		error = ifioctl(&so, cmd, data, td);
		nm_if_rele(ifp);
		break;
	    }

#else /* linux */
	default:
		error = EOPNOTSUPP;
#endif /* linux */
	}

	CURVNET_RESTORE();
	return (error);
}

/*
 * select(2) and poll(2) handlers for the "netmap" device.
 *
 * Can be called for one or more queues.
 * Return true the event mask corresponding to ready events.
 * If there are no ready events, do a selrecord on either individual
 * selfd or on the global one.
 * Device-dependent parts (locking and sync of tx/rx rings)
 * are done through callbacks.
 *
 * On linux, arguments are really pwait, the poll table, and 'td' is struct file *
 * The first one is remapped to pwait as selrecord() uses the name as an
 * hidden argument.
 */
static int
netmap_poll(struct cdev *dev, int events, struct thread *td)
{
	struct netmap_priv_d *priv = NULL;
	struct netmap_adapter *na;
	struct ifnet *ifp;
	struct netmap_kring *kring;
	u_int core_lock, i, check_all, want_tx, want_rx, revents = 0;
	u_int lim_tx, lim_rx, host_forwarded = 0;
	struct mbq q = { NULL, NULL, 0 };
	enum {NO_CL, NEED_CL, LOCKED_CL }; /* see below */
	void *pwait = dev;	/* linux compatibility */

	(void)pwait;

	if (devfs_get_cdevpriv((void **)&priv) != 0 || priv == NULL)
		return POLLERR;

	if (priv->np_nifp == NULL) {
		D("No if registered");
		return POLLERR;
	}
	rmb(); /* make sure following reads are not from cache */

	ifp = priv->np_ifp;
	// XXX check for deleting() ?
	if ( (ifp->if_capenable & IFCAP_NETMAP) == 0)
		return POLLERR;

	if (netmap_verbose & 0x8000)
		D("device %s events 0x%x", ifp->if_xname, events);
	want_tx = events & (POLLOUT | POLLWRNORM);
	want_rx = events & (POLLIN | POLLRDNORM);

	na = NA(ifp); /* retrieve netmap adapter */

	lim_tx = na->num_tx_rings;
	lim_rx = na->num_rx_rings;
	/* how many queues we are scanning */
	if (priv->np_qfirst == NETMAP_SW_RING) {
		if (priv->np_txpoll || want_tx) {
			/* push any packets up, then we are always ready */
			kring = &na->tx_rings[lim_tx];
			netmap_sync_to_host(na);
			revents |= want_tx;
		}
		if (want_rx) {
			kring = &na->rx_rings[lim_rx];
			if (kring->ring->avail == 0)
				netmap_sync_from_host(na, td, dev);
			if (kring->ring->avail > 0) {
				revents |= want_rx;
			}
		}
		return (revents);
	}

	/* if we are in transparent mode, check also the host rx ring */
	kring = &na->rx_rings[lim_rx];
	if ( (priv->np_qlast == NETMAP_HW_RING) // XXX check_all
			&& want_rx
			&& (netmap_fwd || kring->ring->flags & NR_FORWARD) ) {
		if (kring->ring->avail == 0)
			netmap_sync_from_host(na, td, dev);
		if (kring->ring->avail > 0)
			revents |= want_rx;
	}

	/*
	 * check_all is set if the card has more than one queue and
	 * the client is polling all of them. If true, we sleep on
	 * the "global" selfd, otherwise we sleep on individual selfd
	 * (we can only sleep on one of them per direction).
	 * The interrupt routine in the driver should always wake on
	 * the individual selfd, and also on the global one if the card
	 * has more than one ring.
	 *
	 * If the card has only one lock, we just use that.
	 * If the card has separate ring locks, we just use those
	 * unless we are doing check_all, in which case the whole
	 * loop is wrapped by the global lock.
	 * We acquire locks only when necessary: if poll is called
	 * when buffers are available, we can just return without locks.
	 *
	 * rxsync() is only called if we run out of buffers on a POLLIN.
	 * txsync() is called if we run out of buffers on POLLOUT, or
	 * there are pending packets to send. The latter can be disabled
	 * passing NETMAP_NO_TX_POLL in the NIOCREG call.
	 */
	check_all = (priv->np_qlast == NETMAP_HW_RING) && (lim_tx > 1 || lim_rx > 1);

	/*
	 * core_lock indicates what to do with the core lock.
	 * The core lock is used when either the card has no individual
	 * locks, or it has individual locks but we are cheking all
	 * rings so we need the core lock to avoid missing wakeup events.
	 *
	 * It has three possible states:
	 * NO_CL	we don't need to use the core lock, e.g.
	 *		because we are protected by individual locks.
	 * NEED_CL	we need the core lock. In this case, when we
	 *		call the lock routine, move to LOCKED_CL
	 *		to remember to release the lock once done.
	 * LOCKED_CL	core lock is set, so we need to release it.
	 */
	core_lock = (check_all || !na->separate_locks) ? NEED_CL : NO_CL;
#ifdef NM_BRIDGE
	/* the bridge uses separate locks */
	if (na->nm_register == bdg_netmap_reg && (lim_tx == 1 || lim_rx == 1)) {
		ND("not using core lock for %s", ifp->if_xname);
		core_lock = NO_CL;
	}
#endif /* NM_BRIDGE */
	if (priv->np_qlast != NETMAP_HW_RING) {
		lim_tx = lim_rx = priv->np_qlast;
	}

	/*
	 * We start with a lock free round which is good if we have
	 * data available. If this fails, then lock and call the sync
	 * routines.
	 */
	for (i = priv->np_qfirst; want_rx && i < lim_rx; i++) {
		kring = &na->rx_rings[i];
		if (kring->ring->avail > 0) {
			revents |= want_rx;
			want_rx = 0;	/* also breaks the loop */
		}
	}
	for (i = priv->np_qfirst; want_tx && i < lim_tx; i++) {
		kring = &na->tx_rings[i];
		if (kring->ring->avail > 0) {
			revents |= want_tx;
			want_tx = 0;	/* also breaks the loop */
		}
	}

	/*
	 * If we to push packets out (priv->np_txpoll) or want_tx is
	 * still set, we do need to run the txsync calls (on all rings,
	 * to avoid that the tx rings stall).
	 */
	if (priv->np_txpoll || want_tx) {
flush_tx:
	//	int dst_selrecorded = 0;
		for (i = priv->np_qfirst; i < lim_tx; i++) {
			kring = &na->tx_rings[i];
			/*
			 * Skip the current ring if want_tx == 0
			 * (we have already done a successful sync on
			 * a previous ring) AND kring->cur == kring->hwcur
			 * (there are no pending transmissions for this ring).
			 */
			if (!want_tx && kring->ring->cur == kring->nr_hwcur)
				continue;
			if (core_lock == NEED_CL) {
				na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
				core_lock = LOCKED_CL;
			}
			if (na->separate_locks)
				na->nm_lock(ifp, NETMAP_TX_LOCK, i);
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("send %d on %s %d",
					kring->ring->cur,
					ifp->if_xname, i);
			/* debug */
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("pre txsync %s ring %d cur %d hwcur %d avail %d hwavail %d",
				    ifp->if_xname, i, kring->ring->cur,
				    kring->nr_hwcur, kring->ring->avail,
				    kring->nr_hwavail);
			if (na->nm_txsync(ifp, i, 0 /* no lock */))
				revents |= POLLERR;
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("post txsync %s ring %d cur %d hwcur %d avail %d hwavail %d",
				    ifp->if_xname, i, kring->ring->cur,
				    kring->nr_hwcur, kring->ring->avail,
				    kring->nr_hwavail);

			/* Check avail/call selrecord only if called with POLLOUT */
			if (want_tx) {
				int dst_full = 1, d_ringid = 0;
				struct netmap_adapter *d_na;

				if (kring->ring->avail == 0 &&
				    na->nm_ifflags & NM_IFF_BDG_HW) {
					/*
					 * We sleep only both the virtual ring
					 * and the destination ring are full
					 */
					struct netmap_kring *d_kring;

					d_na = NA(na->dst_vif->ifn);
					d_ringid = get_dstringid(d_na, i);
					d_kring = &d_na->tx_rings[d_ringid];
					/* XXX need lock? */
					dst_full = d_kring->ring->avail ? 0 : 1;
					if (!dst_full || netmap_bdg_txintr == 2) {
						revents |= want_tx;
						want_tx = 0;
					}
				}
				if (kring->ring->avail > 0) {
					/* stop at the first ring. We don't risk
					 * starvation.
					 */
					revents |= want_tx;
					want_tx = 0;
				} else if (!check_all) {
					if (dst_full) {
						selrecord(td, &kring->si);
						if (na->nm_ifflags &
						   NM_IFF_BDG_HW)
							nm_add_to_txintrq(
							    na, d_ringid, i);
					}
				}
			}
			if (na->separate_locks)
				na->nm_lock(ifp, NETMAP_TX_UNLOCK, i);
		}
	}

	/*
	 * now if want_rx is still set we need to lock and rxsync.
	 * Do it on all rings because otherwise we starve.
	 */
	if (want_rx) {
		for (i = priv->np_qfirst; i < lim_rx; i++) {
			kring = &na->rx_rings[i];
			if (core_lock == NEED_CL) {
				na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
				core_lock = LOCKED_CL;
			}
			if (na->separate_locks)
				na->nm_lock(ifp, NETMAP_RX_LOCK, i);
			if (netmap_fwd ||kring->ring->flags & NR_FORWARD) {
				ND(10, "forwarding some buffers up %d to %d",
				    kring->nr_hwcur, kring->ring->cur);
				netmap_grab_packets(kring, &q, netmap_fwd);
			}

			if (na->nm_rxsync(ifp, i, 0 /* no lock */))
				revents |= POLLERR;
			if (netmap_no_timestamp == 0 ||
					kring->ring->flags & NR_TIMESTAMP) {
				microtime(&kring->ring->ts);
			}

			if (kring->ring->avail > 0)
				revents |= want_rx;
			else if (!check_all)
				selrecord(td, &kring->si);
			if (na->separate_locks)
				na->nm_lock(ifp, NETMAP_RX_UNLOCK, i);
		}
	}
	if (check_all && revents == 0) { /* signal on the global queue */
		if (want_tx) {
			selrecord(td, &na->tx_si);
			if (na->nm_ifflags & NM_IFF_BDG_HW)
				nm_add_to_txintrq(na,
				    NA(na->dst_vif->ifn)->num_tx_rings, 0);
		}
		if (want_rx)
			selrecord(td, &na->rx_si);
	}

	/* forward host to the netmap ring */
	kring = &na->rx_rings[lim_rx];
	if (kring->nr_hwavail > 0)
		ND("host rx %d has %d packets", lim_rx, kring->nr_hwavail);
	if ( (priv->np_qlast == NETMAP_HW_RING) // XXX check_all
			&& (netmap_fwd || kring->ring->flags & NR_FORWARD)
			 && kring->nr_hwavail > 0 && !host_forwarded) {
		if (core_lock == NEED_CL) {
			na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
			core_lock = LOCKED_CL;
		}
		netmap_sw_to_nic(na);
		host_forwarded = 1; /* prevent another pass */
		want_rx = 0;
		goto flush_tx;
	}

	if (core_lock == LOCKED_CL)
		na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);
	if (q.head)
		netmap_send_up(na->ifp, q.head);

	return (revents);
}

/*------- driver support routines ------*/

/*
 * default lock wrapper.
 */
static void
netmap_lock_wrapper(struct ifnet *dev, int what, u_int queueid)
{
	struct netmap_adapter *na = NA(dev);

	switch (what) {
#ifdef linux	/* some system do not need lock on register */
	case NETMAP_REG_LOCK:
	case NETMAP_REG_UNLOCK:
		break;
#endif /* linux */

	case NETMAP_CORE_LOCK:
		mtx_lock(&na->core_lock);
		break;

	case NETMAP_CORE_UNLOCK:
		mtx_unlock(&na->core_lock);
		break;

	case NETMAP_TX_LOCK:
		mtx_lock(&na->tx_rings[queueid].q_lock);
		break;

	case NETMAP_TX_UNLOCK:
		mtx_unlock(&na->tx_rings[queueid].q_lock);
		break;

	case NETMAP_RX_LOCK:
		mtx_lock(&na->rx_rings[queueid].q_lock);
		break;

	case NETMAP_RX_UNLOCK:
		mtx_unlock(&na->rx_rings[queueid].q_lock);
		break;
	}
}


/*
 * Initialize a ``netmap_adapter`` object created by driver on attach.
 * We allocate a block of memory with room for a struct netmap_adapter
 * plus two sets of N+2 struct netmap_kring (where N is the number
 * of hardware rings):
 * krings	0..N-1	are for the hardware queues.
 * kring	N	is for the host stack queue
 * kring	N+1	is only used for the selinfo for all queues.
 * Return 0 on success, ENOMEM otherwise.
 *
 * By default the receive and transmit adapter ring counts are both initialized
 * to num_queues.  na->num_tx_rings can be set for cards with different tx/rx
 * setups.
 */
int
netmap_attach(struct netmap_adapter *arg, int num_queues)
{
	struct netmap_adapter *na = NULL;
	struct ifnet *ifp = arg ? arg->ifp : NULL;

	if (arg == NULL || ifp == NULL)
		goto fail;
	na = malloc(sizeof(*na), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (na == NULL)
		goto fail;
	WNA(ifp) = na;
	*na = *arg; /* copy everything, trust the driver to not pass junk */
	NETMAP_SET_CAPABLE(ifp);
	if (na->num_tx_rings == 0)
		na->num_tx_rings = num_queues;
	na->num_rx_rings = num_queues;
	na->refcount = na->na_single = na->na_multi = 0;
	/* Core lock initialized here, others after netmap_if_new. */
	mtx_init(&na->core_lock, "netmap core lock", MTX_NETWORK_LOCK, MTX_DEF);
	if (na->nm_lock == NULL) {
		ND("using default locks for %s", ifp->if_xname);
		na->nm_lock = netmap_lock_wrapper;
	}
#ifdef linux
	if (ifp->netdev_ops) {
		ND("netdev_ops %p", ifp->netdev_ops);
		/* prepare a clone of the netdev ops */
		na->nm_ndo = *ifp->netdev_ops;
	}
	na->nm_ndo.ndo_start_xmit = linux_netmap_start;
#endif
	if (netmap_verbose & NM_VERB_DBG)
		D("success for %s", ifp->if_xname);
	return 0;

fail:
	D("fail, arg %p ifp %p na %p", arg, ifp, na);
	return (na ? EINVAL : ENOMEM);
}


/*
 * Free the allocated memory linked to the given ``netmap_adapter``
 * object.
 */
void
netmap_detach(struct ifnet *ifp)
{
	struct netmap_adapter *na = NA(ifp);

	if (!na)
		return;

	mtx_destroy(&na->core_lock);

	if (na->tx_rings) { /* XXX should not happen */
		D("freeing leftover tx_rings");
		free(na->tx_rings, M_DEVBUF);
	}
	bzero(na, sizeof(*na));
	WNA(ifp) = NULL;
	free(na, M_DEVBUF);
}


/*
 * Intercept packets from the network stack and pass them
 * to netmap as incoming packets on the 'software' ring.
 * We are not locked when called.
 */
int
netmap_start(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[na->num_rx_rings];
	u_int i, len = MBUF_LEN(m);
	u_int error = EBUSY, lim = kring->nkr_num_slots - 1;
	struct netmap_slot *slot;

	if (netmap_verbose & NM_VERB_HOST)
		D("%s packet %d len %d from the stack", ifp->if_xname,
			kring->nr_hwcur + kring->nr_hwavail, len);
	na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
	if (kring->nr_hwavail >= lim) {
		if (netmap_verbose)
			D("stack ring %s full\n", ifp->if_xname);
		goto done;	/* no space */
	}
	if (len > NETMAP_BUF_SIZE) {
		D("%s from_host, drop packet size %d > %d", ifp->if_xname,
			len, NETMAP_BUF_SIZE);
		goto done;	/* too long for us */
	}

	/* compute the insert position */
	i = kring->nr_hwcur + kring->nr_hwavail;
	if (i > lim)
		i -= lim + 1;
	slot = &kring->ring->slot[i];
	m_copydata(m, 0, len, NMB(slot));
	slot->len = len;
	slot->flags = kring->nkr_slot_flags;
	kring->nr_hwavail++;
	if (netmap_verbose  & NM_VERB_HOST)
		D("wake up host ring %s %d", na->ifp->if_xname, na->num_rx_rings);
	selwakeuppri(&kring->si, PI_NET);
	error = 0;
done:
	na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);

	/* release the mbuf in either cases of success or failure. As an
	 * alternative, put the mbuf in a free list and free the list
	 * only when really necessary.
	 */
	m_freem(m);

	return (error);
}


/*
 * netmap_reset() is called by the driver routines when reinitializing
 * a ring. The driver is in charge of locking to protect the kring.
 * If netmap mode is not set just return NULL.
 */
struct netmap_slot *
netmap_reset(struct netmap_adapter *na, enum txrx tx, int n,
	u_int new_cur)
{
	struct netmap_kring *kring;
	int new_hwofs, lim;

	if (na == NULL)
		return NULL;	/* no netmap support here */
	if (!(na->ifp->if_capenable & IFCAP_NETMAP))
		return NULL;	/* nothing to reinitialize */

	if (tx == NR_TX) {
		if (n >= na->num_tx_rings)
			return NULL;
		kring = na->tx_rings + n;
		new_hwofs = kring->nr_hwcur - new_cur;
	} else {
		if (n >= na->num_rx_rings)
			return NULL;
		kring = na->rx_rings + n;
		new_hwofs = kring->nr_hwcur + kring->nr_hwavail - new_cur;
	}
	lim = kring->nkr_num_slots - 1;
	if (new_hwofs > lim)
		new_hwofs -= lim + 1;

	/* Alwayws set the new offset value and realign the ring. */
	kring->nkr_hwofs = new_hwofs;
	if (tx == NR_TX)
		kring->nr_hwavail = kring->nkr_num_slots - 1;
	if (netmap_verbose & NM_VERB_DBG)
		ND(10, "new hwofs %d on %s %s[%d]",
			kring->nkr_hwofs, na->ifp->if_xname,
			tx == NR_TX ? "TX" : "RX", n);

#if 0 // def linux
	/* XXX check that the mappings are correct */
	/* need ring_nr, adapter->pdev, direction */
	buffer_info->dma = dma_map_single(&pdev->dev, addr, adapter->rx_buffer_len, DMA_FROM_DEVICE);
	if (dma_mapping_error(&adapter->pdev->dev, buffer_info->dma)) {
		D("error mapping rx netmap buffer %d", i);
		// XXX fix error handling
	}

#endif /* linux */
	/*
	 * Wakeup on the individual and global lock
	 * We do the wakeup here, but the ring is not yet reconfigured.
	 * However, we are under lock so there are no races.
	 */
	selwakeuppri(&kring->si, PI_NET);
	selwakeuppri(tx == NR_TX ? &na->tx_si : &na->rx_si, PI_NET);
	return kring->ring->slot;
}


/*
 * Default functions to handle rx/tx interrupts
 * we have 4 cases:
 * 1 ring, single lock:
 *	lock(core); wake(i=0); unlock(core)
 * N rings, single lock:
 *	lock(core); wake(i); wake(N+1) unlock(core)
 * 1 ring, separate locks: (i=0)
 *	lock(i); wake(i); unlock(i)
 * N rings, separate locks:
 *	lock(i); wake(i); unlock(i); lock(core) wake(N+1) unlock(core)
 * work_done is non-null on the RX path.
 */
int
netmap_rx_irq(struct ifnet *ifp, int q, int *work_done)
{
	struct netmap_adapter *na;
	struct netmap_kring *r;
	NM_SELINFO_T *main_wq;

//	D("start for ifp %s work_done %d", ifp->if_xname, work_done?*work_done:0);
	if (!(ifp->if_capenable & IFCAP_NETMAP))
		return 0;
	ND(5, "received %s queue %d", work_done ? "RX" : "TX" , q);
	na = NA(ifp);
	if (na->na_flags & NAF_SKIP_INTR) {
		ND("use regular interrupt");
		return 0;
	}

	if (work_done) { /* RX path */
		if (q >= na->num_rx_rings)
			return 0;	// regular queue
		r = na->rx_rings + q;
		r->nr_kflags |= NKR_PENDINTR;
		main_wq = (na->num_rx_rings > 1) ? &na->rx_si : NULL;
		if (NETMAP_VIF(ifp) != NULL)
			netmap_sync_to_vrf(ifp, q);
	} else { /* tx path */
		if (q >= na->num_tx_rings)
			return 0;	// regular queue
		r = na->tx_rings + q;
		main_wq = (na->num_tx_rings > 1) ? &na->tx_si : NULL;
		work_done = &q; /* dummy */
		if (netmap_bdg_txintr && NETMAP_VIF(ifp))
			netmap_vrf_txintr(ifp, q);
	}
	if (na->separate_locks) {
		mtx_lock(&r->q_lock);
		selwakeuppri(&r->si, PI_NET);
		mtx_unlock(&r->q_lock);
		if (main_wq) {
			mtx_lock(&na->core_lock);
			selwakeuppri(main_wq, PI_NET);
			mtx_unlock(&na->core_lock);
		}
	} else {
		mtx_lock(&na->core_lock);
		selwakeuppri(&r->si, PI_NET);
		if (main_wq)
			selwakeuppri(main_wq, PI_NET);
		mtx_unlock(&na->core_lock);
	}
	*work_done = 1; /* do not fire napi again */
	return 1;
}

/*
 * This is very much like nm_bdg_flush(), but in the first pass, it applies
 * the packet filter to decide the destination port (and bridge).  In the
 * second pass, it iterates all the bridges
 * We now expect maximum 64 bridges, so the maximum number of
 * bridge ports is 4096.
 *
 * We deliver packets to the corresponding ring number of the VALE port.
 * If the number of rings of the vale port is less, packets from the greater
 * ring number number go to the ring 0.
 */
static int
nm_bdg_flush_from_vrf(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp,
		u_int ring_nr)
{
	int i, ifn;
	uint64_t all_dst, dst, dst_bridges; /* see above */
	u_int bi;
	struct nm_bridge *b;
	struct netmap_slot *slot;

	ND("prepare to send %d packets", n);
	dst_bridges = 0;
	for (i = 0; likely(i < n); i++) {
		uint8_t *buf = ft[i].buf;
		struct netmap_ifaddr *nifa;
		uint8_t *hint = NULL;

		nifa = netmap_findifa_pkt(buf, &hint); /* Here nifa is ref-counted */
		if (!nifa) {
			ft[i].dst = 0;
			continue;
		}
		if (unlikely(nifa->bdg_idx == NM_UNIBDG_IDX &&
		    nifa->bdg_port > NM_BDG_MAXPORTS)) {
			ft[i].dst = 0;
			continue;
		}
		/* XXX now we support only unicast */
		ft[i].dst = 1<<nifa->bdg_port;
		/* this bridge is to be scanned */
		dst_bridges |= 1<<nifa->bdg_idx;
	}
	for (bi = 0; bi < NM_BRIDGES; bi++) {
		if (!(1<<bi & dst_bridges))
			/* nothing to forward to this bridge */
			continue;
		b = &nm_bridges[bi];
		all_dst = b->act_ports;
		for (ifn = 0; all_dst; ifn++) {
			struct ifnet *dst_ifp = b->bdg_ports[ifn];
			struct netmap_adapter *na;
			struct netmap_kring *kring;
			struct netmap_ring *ring;
			int j, lim, sent, locked;
			u_int d_ringid = 0;

			if (!dst_ifp)
				continue;
			ND("scan port %d %s", ifn, dst_ifp->if_xname);
			dst = 1 << ifn;
			if ((dst & all_dst) == 0)	/* skip if not set */
				continue;
			all_dst &= ~dst;	/* clear current node */
			na = NA(dst_ifp);

			ring = NULL;
			kring = NULL;
			lim = sent = locked = 0;
			/* inside, scan slots */
			for (i = 0; likely(i < n); i++) {
				if ((ft[i].dst & dst) == 0)
					continue;	/* not here */
				if (!locked) {
					d_ringid =
						get_dstringid(na, ring_nr);
					kring = &na->rx_rings[d_ringid];
					ring = kring->ring;
					lim = kring->nkr_num_slots - 1;
					na->nm_lock(dst_ifp, NETMAP_RX_LOCK, d_ringid);
					locked = 1;
				}
				if (unlikely(kring->nr_hwavail >= lim)) {
					if (netmap_verbose & NM_VERB_PKT)
						D("rx ring full on %s", ifp->if_xname);
					break;
				}
				j = kring->nr_hwcur + kring->nr_hwavail;
				if (j > lim)
					j -= kring->nkr_num_slots;
				slot = &ring->slot[j];
				ND("send %d %d bytes at %s:%d", i, ft[i].len, dst_ifp->if_xname, j);
				pkt_copy(ft[i].buf, NMB(slot), ft[i].len);
				slot->len = ft[i].len;
				kring->nr_hwavail++;
				sent++;
			}
			if (locked) {
				ND("sent %d on %s", sent, dst_ifp->if_xname);
				if (sent)
					selwakeuppri(&kring->si, PI_NET);
				na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, d_ringid);
				/*
				 * XXX we would have some flags to avoid
				 * unnecessary selwakeuppri that needs lock...
				 */
				if (sent) {
#if defined(linux)
					if (!spin_trylock(&na->core_lock))
						continue;
#else
					na->nm_lock(dst_ifp, NETMAP_CORE_LOCK, 0);
#endif
					selwakeuppri(&na->rx_si, PI_NET);
					na->nm_lock(dst_ifp, NETMAP_CORE_UNLOCK, 0);
				}
			}
		}
	}
	return 0;
}

static int
nm_unibdg_flush(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp, u_int ring_nr)
{
       int i, ifn, total_sent = 0;
       struct netmap_slot *slot;
       struct nm_bridge *b;
       struct nm_unibdgfwd_head *my_fwdhead;

       if (unlikely(!nm_bridges[NM_UNIBDG_IDX].namelen))
	       return 0;
       b = &nm_bridges[NM_UNIBDG_IDX];
       my_fwdhead = NA(ifp)->vif->unibdgfwd_head + NM_UNIBDG_MAXPORTS * ring_nr;
       ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
       /* first pass: find a destination (don't use ft[i].dst) */
       for (i = 0; likely(i < n); i++) {
               uint8_t *buf = ft[i].buf;
               struct netmap_ifaddr *nifa;
	       struct nm_unibdgfwd_head *head;
		uint8_t *hint = NULL;

               /* find a bdg_port based on dst addr, port and protocol */
               nifa = netmap_findifa_pkt(buf, &hint); /* here ifa is ref-counted */
               if (!nifa)
                       continue;
	       if (unlikely(nifa->bdg_idx != NM_UNIBDG_IDX))
		       continue;
	       head = my_fwdhead + nifa->bdg_port;
	       STAILQ_INSERT_TAIL(head, &ft[i], next);
       }
       for (ifn = 0; likely(ifn < NM_UNIBDG_MAXPORTS); ifn++) {
               struct ifnet *dst_ifp = b->bdg_ports[ifn];
               struct netmap_adapter *na;
               struct netmap_kring *kring;
               struct netmap_ring *ring;
               struct nm_bdg_fwd *ft_p;
               int j, lim, sent = 0;
	       struct nm_unibdgfwd_head *head;
	       u_int d_ringid;

               if (!dst_ifp)
                       continue;
	       head = my_fwdhead + ifn;
               if (STAILQ_EMPTY(head))
                       continue; /* nothing to forward here */
               na = NA(dst_ifp);
	       d_ringid = get_dstringid(na, ring_nr);
               kring = &na->rx_rings[d_ringid];
               ring = kring->ring;
               lim = kring->nkr_num_slots - 1;
               na->nm_lock(dst_ifp, NETMAP_RX_LOCK, d_ringid);
               STAILQ_FOREACH(ft_p, head, next) {
                       if (unlikely(kring->nr_hwavail >= lim)) {
                               if (netmap_verbose & NM_VERB_PKT)
                                       D("rx ring full on %s", ifp->if_xname);
                               break;
                       }
                       j = kring->nr_hwcur + kring->nr_hwavail;
                       if (unlikely(j > lim))
                               j -= kring->nkr_num_slots;
                       slot = &ring->slot[j];
                       pkt_copy(ft_p->buf, NMB(slot), ft_p->len);
                       slot->len = ft_p->len;
                       kring->nr_hwavail++;
                       sent++;
               }
               STAILQ_INIT(head);
               if (sent) {
                       selwakeuppri(&kring->si, PI_NET);
                       total_sent += sent;
               }
               na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, d_ringid);
	       if (sent) {
#if defined(linux)
		      if (!spin_trylock(&na->core_lock)) {
		              if (total_sent == NM_BDG_BATCH)
		                      break;
		              else
				      continue;
		      }
#else
		      na->nm_lock(dst_ifp, NETMAP_CORE_LOCK, 0);
#endif
		      selwakeuppri(&na->rx_si, PI_NET);
		      na->nm_lock(dst_ifp, NETMAP_CORE_UNLOCK, 0);

	       }
               if (total_sent == NM_BDG_BATCH)
                       break;
       }
//       bzero(ft, sizeof(struct nm_bdg_fwd) * n);
       return 0;
}

/* NM_UNIBDG_FWDALGO_BATCHSIZ */
static int
nm_unibdg_flush2(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp, u_int ring_nr)
{
       int i, ifn, total_sent = 0;
       struct netmap_slot *slot;
       struct nm_bridge *b;
       int num_dst = 0;
       struct nm_unibdgfwd_head *my_fwdhead;

       if (unlikely(!nm_bridges[NM_UNIBDG_IDX].namelen))
	       return 0;
       b = &nm_bridges[NM_UNIBDG_IDX];
       my_fwdhead = NA(ifp)->vif->unibdgfwd_head + NM_BDG_BATCH * ring_nr;
       ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
       /* first pass: find a destination (don't use ft[i].dst) */
       for (i = 0; likely(i < n); i++) {
               uint8_t *buf = ft[i].buf;
               struct netmap_ifaddr *nifa;
	       struct nm_unibdgfwd_head *head;
	       int j;
		uint8_t *hint = NULL;

               /* find a bdg_port based on dst addr, port and protocol */
               nifa = netmap_findifa_pkt(buf, &hint); /* here ifa is ref-counted */
               if (!nifa)
                       continue;
	       if (unlikely(nifa->bdg_idx != NM_UNIBDG_IDX))
		       continue;
	       for (j = 0; j < NM_BDG_BATCH; j++) {
		       head = my_fwdhead + j;
		       if (STAILQ_EMPTY(head)) {
			       STAILQ_INSERT_TAIL(head, &ft[i], next);
			       /* only the first entry has to keep the dst */
			       ft[i].dst = nifa->bdg_port;
			       num_dst++;
			       break;
		       } else if (STAILQ_FIRST(head)->dst == nifa->bdg_port) {
			       STAILQ_INSERT_TAIL(head, &ft[i], next);
			       break;
		       }
	       }
       }
       for (i = 0; likely(i < num_dst); i++) {
               struct ifnet *dst_ifp;
               struct netmap_adapter *na;
               struct netmap_kring *kring;
               struct netmap_ring *ring;
               struct nm_bdg_fwd *ft_p;
               int j, lim, sent = 0;
	       struct nm_unibdgfwd_head *head;
	       u_int d_ringid;

	       head = my_fwdhead + i;
	       ifn = STAILQ_FIRST(head)->dst;
	       dst_ifp = b->bdg_ports[ifn];

               na = NA(dst_ifp);
	       d_ringid = get_dstringid(na, ring_nr);
               kring = &na->rx_rings[d_ringid];
               ring = kring->ring;
               lim = kring->nkr_num_slots - 1;
               na->nm_lock(dst_ifp, NETMAP_RX_LOCK, d_ringid);
               STAILQ_FOREACH(ft_p, head, next) {
                       if (unlikely(kring->nr_hwavail >= lim)) {
                               if (netmap_verbose & NM_VERB_PKT)
                                       D("rx ring full on %s", ifp->if_xname);
                               break;
                       }
                       j = kring->nr_hwcur + kring->nr_hwavail;
                       if (unlikely(j > lim))
                               j -= kring->nkr_num_slots;
                       slot = &ring->slot[j];
                       pkt_copy(ft_p->buf, NMB(slot), ft_p->len);
                       slot->len = ft_p->len;
                       kring->nr_hwavail++;
                       sent++;
               }
               if (sent) {
                       selwakeuppri(&kring->si, PI_NET);
                       total_sent += sent;
               }
               STAILQ_INIT(head);
               na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, d_ringid);
               if (total_sent == NM_BDG_BATCH)
                       break;
       }
 //      bzero(ft, sizeof(struct nm_bdg_fwd) * n);
       return 0;
}

static int
nm_unibdg_flush3(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp, u_int ring_nr)
{
       int i, ifn, total_sent = 0;
       struct netmap_slot *slot;
       struct nm_bridge *b;
       u_int dsts[NM_BDG_BATCH];
       int num_dst = 0;
       struct nm_unibdgfwd_head *my_fwdhead;

       if (unlikely(!nm_bridges[NM_UNIBDG_IDX].namelen))
	       return 0;
       b = &nm_bridges[NM_UNIBDG_IDX];
       my_fwdhead = NA(ifp)->vif->unibdgfwd_head + NM_UNIBDG_MAXPORTS * ring_nr;
       ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
       /* first pass: find a destination (don't use ft[i].dst) */
       for (i = 0; likely(i < n); i++) {
               uint8_t *buf = ft[i].buf;
               struct netmap_ifaddr *nifa;
	       struct nm_unibdgfwd_head *head;
		uint8_t *hint = NULL;

               /* find a bdg_port based on dst addr, port and protocol */
               nifa = netmap_findifa_pkt(buf, &hint); /* here ifa is ref-counted */
               if (!nifa)
                       continue;
	       if (unlikely(nifa->bdg_idx != NM_UNIBDG_IDX))
		       continue;
	       head = my_fwdhead + nifa->bdg_port;
	       if (STAILQ_EMPTY(head))
		       dsts[num_dst++] = nifa->bdg_port;
	       STAILQ_INSERT_TAIL(head, &ft[i], next);
       }
       for (i = 0; likely(i < num_dst); i++) {
               struct ifnet *dst_ifp;
               struct netmap_adapter *na;
               struct netmap_kring *kring;
               struct netmap_ring *ring;
               struct nm_bdg_fwd *ft_p;
               int j, lim, sent = 0;
	       struct nm_unibdgfwd_head *head;
	       u_int d_ringid;

	       ifn = dsts[i];
	       dst_ifp = b->bdg_ports[ifn];
               na = NA(dst_ifp);
	       d_ringid = get_dstringid(na, ring_nr);
               kring = &na->rx_rings[d_ringid];
               ring = kring->ring;
               lim = kring->nkr_num_slots - 1;
	       head = my_fwdhead + ifn;
               na->nm_lock(dst_ifp, NETMAP_RX_LOCK, d_ringid);
               STAILQ_FOREACH(ft_p, head, next) {
                       if (unlikely(kring->nr_hwavail >= lim)) {
                               if (netmap_verbose & NM_VERB_PKT)
                                       D("rx ring full on %s", ifp->if_xname);
                               break;
                       }
                       j = kring->nr_hwcur + kring->nr_hwavail;
                       if (unlikely(j > lim))
                               j -= kring->nkr_num_slots;
                       slot = &ring->slot[j];
                       pkt_copy(ft_p->buf, NMB(slot), ft_p->len);
                       slot->len = ft_p->len;
                       kring->nr_hwavail++;
                       sent++;
               }
               if (sent) {
                       selwakeuppri(&kring->si, PI_NET);
                       total_sent += sent;
               }
               STAILQ_INIT(head);
               na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, d_ringid);
               if (total_sent == NM_BDG_BATCH)
                       break;
       }
//       bzero(ft, sizeof(struct nm_bdg_fwd) * n);
       return 0;
}

/* NM_UNIBDG_FWDALGO_BATCHSIZ */
static int
nm_unibdg_flush_rps(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp, u_int ring_nr)
{
       int i, ifn, total_sent = 0;
       struct netmap_slot *slot;
       struct nm_bridge *b;
       int num_dst = 0;
       struct nm_unibdgfwd_head *my_fwdhead;

       if (unlikely(!nm_bridges[NM_UNIBDG_IDX].namelen))
	       return 0;
       b = &nm_bridges[NM_UNIBDG_IDX];
       my_fwdhead = NA(ifp)->vif->unibdgfwd_head + NM_BDG_BATCH * ring_nr;
       ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
       /* first pass: find a destination (don't use ft[i].dst) */
       for (i = 0; likely(i < n); i++) {
               uint8_t *buf = ft[i].buf;
               struct netmap_ifaddr *nifa;
	       struct nm_unibdgfwd_head *head;
	       int j;
		uint8_t *hint = NULL;
		uint16_t d_ring;

               /* find a bdg_port based on dst addr, port and protocol */
               nifa = netmap_findifa_pkt(buf, &hint); /* here ifa is ref-counted */
               if (!nifa)
                       continue;
	       if (unlikely(nifa->bdg_idx != NM_UNIBDG_IDX))
		       continue;
	       d_ring = (ntohs(*(uint16_t *)hint) & 0xF);
	       for (j = 0; likely(j < NM_BDG_BATCH); j++) {
		       head = my_fwdhead + j;
		       if (STAILQ_EMPTY(head)) {
			       STAILQ_INSERT_TAIL(head, &ft[i], next);
			       /* only the first entry has to keep the dst */
			       ft[i].dst = nifa->bdg_port;
			       ft[i].src = d_ring;
			       num_dst++;
			       break;
		       } else if (STAILQ_FIRST(head)->dst == nifa->bdg_port &&
				    STAILQ_FIRST(head)->src == d_ring) {
			       STAILQ_INSERT_TAIL(head, &ft[i], next);
			       break;
		       }
	       }
       }
       for (i = 0; likely(i < num_dst); i++) {
               struct ifnet *dst_ifp;
               struct netmap_adapter *na;
               struct netmap_kring *kring;
               struct netmap_ring *ring;
               struct nm_bdg_fwd *ft_p;
               int j, lim, sent = 0;
	       struct nm_unibdgfwd_head *head;
	       u_int d_ringid;

	       head = my_fwdhead + i;
	       ifn = STAILQ_FIRST(head)->dst;
	       dst_ifp = b->bdg_ports[ifn];

               na = NA(dst_ifp);
	       ring_nr = STAILQ_FIRST(head)->src;
	       d_ringid = get_dstringid(na, ring_nr);
               kring = &na->rx_rings[d_ringid];
               ring = kring->ring;
               lim = kring->nkr_num_slots - 1;
               na->nm_lock(dst_ifp, NETMAP_RX_LOCK, d_ringid);
               STAILQ_FOREACH(ft_p, head, next) {
                       if (unlikely(kring->nr_hwavail >= lim)) {
                               if (netmap_verbose & NM_VERB_PKT)
                                       D("rx ring full on %s", ifp->if_xname);
                               break;
                       }
                       j = kring->nr_hwcur + kring->nr_hwavail;
                       if (unlikely(j > lim))
                               j -= kring->nkr_num_slots;
                       slot = &ring->slot[j];
                       pkt_copy(ft_p->buf, NMB(slot), ft_p->len);
                       slot->len = ft_p->len;
                       kring->nr_hwavail++;
                       sent++;
               }
               if (sent) {
                       selwakeuppri(&kring->si, PI_NET);
                       total_sent += sent;
               }
               STAILQ_INIT(head);
               na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, d_ringid);
               if (total_sent == NM_BDG_BATCH)
                       break;
       }
 //      bzero(ft, sizeof(struct nm_bdg_fwd) * n);
       return 0;
}

/* XXX this is totally improvised, perhaps wrong manner... */
static int
is_rxring_polled(NM_SELINFO_T *si)
{
#if defined(__FreeBSD__)
	return !TAILQ_EMPTY(&si->si_tdlist);
#elif defined(linux)
	return waitqueue_active(si);
#else
	return 0;
#endif
}

int
netmap_sync_to_vrf(struct ifnet *ifp, u_int ring_nr)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int lim, cur, scanned, ft_i;
	struct nm_bdg_fwd *ft;
	NM_SELINFO_T *si;
	struct netmap_vrf *vrf = &nm_vrf; /* don't acquire from vif */
	struct netmap_vrf_if *vif;

	if (!na->separate_locks)
		na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
	else
		na->nm_lock(ifp, NETMAP_RX_LOCK, ring_nr);
	/*
	 * We might start during sleeping in dtor_locked(), but in this case
	 * na->vif is NULLed.  Once this lock has been acquired "and" na->vif
	 * exists, na should be safe until unlock.
	 * See a comment in nm_bdg_detach_vif() too.
	 */
	NM_VRF_RLOCK(vrf);
	vif = NETMAP_VIF(ifp);
	if (unlikely(vif == NULL))
		goto unlock_return;
	ft = &vif->ft[NM_BDG_BATCH * ring_nr];
	/* update NIC's ring */
	na->nm_rxsync(ifp, ring_nr, 0); /* already locked */
	cur = ring->cur;
	lim = ring->avail;
	/* XXX we probably won't need bzero */
//	bzero(ft, sizeof(struct nm_bdg_fwd)*NM_BDG_BATCH);
	ft_i = 0;	/* start from 0 */
	/* XXX One could lookup the destination in this loop */
	for (scanned = 0; likely(scanned < lim); ++scanned) {
		struct netmap_slot *slot = &ring->slot[cur];
		int len = ft[ft_i].len = slot->len;
		char *buf = ft[ft_i].buf = NMB(slot);

		prefetch(buf);
		if (unlikely(len < 14)) {
			/* we don't advance ft_i */
			cur = (cur+1 == ring->num_slots ? 0: cur+1);
			continue;
		}
		if (unlikely(++ft_i == netmap_bridge))
			ft_i = vif->bdgfwd_func(ft, ft_i, ifp, ring_nr);
		cur = (cur+1 == ring->num_slots ? 0: cur+1);
	}
	if (ft_i)
		ft_i = vif->bdgfwd_func(ft, ft_i, ifp, ring_nr);
	/*
	 * If there is another process directly reads the NIC
	 * we shouldn't update the source ring.
	 */
	si = &na->rx_si;
	if (na->separate_locks) {
		if (!is_rxring_polled(&na->rx_si) &&
		    !is_rxring_polled(&na->rx_rings[ring_nr].si)) {
			ring->cur = cur;
			ring->avail -= scanned;
		} else if (netmap_verbose & NM_VERB_DBG)
			D("did not adjusted NIC's cur and avail");
	} else {
		if (!is_rxring_polled(&na->rx_si)) {
			ring->cur = cur;
			ring->avail -= scanned;
		} else if (netmap_verbose & NM_VERB_DBG)
			D("did not adjusted NIC's cur and avail");
	}
unlock_return:
	NM_VRF_RUNLOCK(vrf);
	if (!na->separate_locks)
		na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);
	else
		na->nm_lock(ifp, NETMAP_RX_UNLOCK, ring_nr);
	return 0;
}

#ifdef linux	/* linux-specific routines */

/*
 * Remap linux arguments into the FreeBSD call.
 * - pwait is the poll table, passed as 'dev';
 *   If pwait == NULL someone else already woke up before. We can report
 *   events but they are filtered upstream.
 *   If pwait != NULL, then pwait->key contains the list of events.
 * - events is computed from pwait as above.
 * - file is passed as 'td';
 */
static u_int
linux_netmap_poll(struct file * file, struct poll_table_struct *pwait)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
	int events = pwait ? pwait->key : POLLIN | POLLOUT;
#else /* in 3.4.0 field 'key' was renamed to '_key' */
	int events = pwait ? pwait->_key : POLLIN | POLLOUT;
#endif
	return netmap_poll((void *)pwait, events, (void *)file);
}

static int
linux_netmap_mmap(struct file *f, struct vm_area_struct *vma)
{
	int lut_skip, i, j;
	int user_skip = 0;
	struct lut_entry *l_entry;
	int error = 0;
	unsigned long off, tomap;
	/*
	 * vma->vm_start: start of mapping user address space
	 * vma->vm_end: end of the mapping user address space
	 * vma->vm_pfoff: offset of first page in the device
	 */

	// XXX security checks

	error = netmap_get_memory(f->private_data);
	ND("get_memory returned %d", error);
	if (error)
	    return -error;

	off = vma->vm_pgoff << PAGE_SHIFT; /* offset in bytes */
	tomap = vma->vm_end - vma->vm_start;
	for (i = 0; i < NETMAP_POOLS_NR; i++) {  /* loop through obj_pools */
		const struct netmap_obj_pool *p = &nm_mem.pools[i];
		/*
		 * In each pool memory is allocated in clusters
		 * of size _clustsize, each containing clustentries
		 * entries. For each object k we already store the
		 * vtophys mapping in lut[k] so we use that, scanning
		 * the lut[] array in steps of clustentries,
		 * and we map each cluster (not individual pages,
		 * it would be overkill).
		 */

		/*
		 * We interpret vm_pgoff as an offset into the whole
		 * netmap memory, as if all clusters where contiguous.
		 */
		for (lut_skip = 0, j = 0; j < p->_numclusters; j++, lut_skip += p->clustentries) {
			unsigned long paddr, mapsize;
			if (p->_clustsize <= off) {
				off -= p->_clustsize;
				continue;
			}
			l_entry = &p->lut[lut_skip]; /* first obj in the cluster */
			paddr = l_entry->paddr + off;
			mapsize = p->_clustsize - off;
			off = 0;
			if (mapsize > tomap)
				mapsize = tomap;
			ND("remap_pfn_range(%lx, %lx, %lx)",
				vma->vm_start + user_skip,
				paddr >> PAGE_SHIFT, mapsize);
			if (remap_pfn_range(vma, vma->vm_start + user_skip,
					paddr >> PAGE_SHIFT, mapsize,
					vma->vm_page_prot))
				return -EAGAIN; // XXX check return value
			user_skip += mapsize;
			tomap -= mapsize;
			if (tomap == 0)
				goto done;
		}
	}
done:

	return 0;
}

static netdev_tx_t
linux_netmap_start(struct sk_buff *skb, struct net_device *dev)
{
	netmap_start(dev, skb);
	return (NETDEV_TX_OK);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)	// XXX was 38
#define LIN_IOCTL_NAME	.ioctl
int
linux_netmap_ioctl(struct inode *inode, struct file *file, u_int cmd, u_long data /* arg */)
#else
#define LIN_IOCTL_NAME	.unlocked_ioctl
long
linux_netmap_ioctl(struct file *file, u_int cmd, u_long data /* arg */)
#endif
{
	int ret;
	struct nmreq nmr;
	bzero(&nmr, sizeof(nmr));

	if (data && (cmd == NIOCSMSOPEN || cmd == NIOCSMSCLOSE)) {
		struct nmaddrreq nma;

		bzero(&nma, sizeof(nma));
		if (copy_from_user(&nma, (void *)data, sizeof(nma) ) != 0)
			return -EFAULT;
		ret = netmap_ioctl(NULL, cmd, (caddr_t)&nma, 0, (void *)file);
		if (data && copy_to_user((void*)data, &nma, sizeof(nma) ) != 0)
			return -EFAULT;
		return -ret;
	}
	if (data && copy_from_user(&nmr, (void *)data, sizeof(nmr) ) != 0)
		return -EFAULT;
	ret = netmap_ioctl(NULL, cmd, (caddr_t)&nmr, 0, (void *)file);
	if (data && copy_to_user((void*)data, &nmr, sizeof(nmr) ) != 0)
		return -EFAULT;
	return -ret;
}


static int
netmap_release(struct inode *inode, struct file *file)
{
	(void)inode;	/* UNUSED */
	if (file->private_data)
		netmap_dtor(file->private_data);
	return (0);
}

static int
linux_netmap_open(struct inode *inode, struct file *file)
{
	struct netmap_priv_d *priv;
	(void)inode;	/* UNUSED */

	priv = malloc(sizeof(struct netmap_priv_d), M_DEVBUF,
			      M_NOWAIT | M_ZERO);
	if (priv == NULL)
		return -ENOMEM;

	file->private_data = priv;

	return (0);
}

static struct file_operations netmap_fops = {
    .open = linux_netmap_open,
    .mmap = linux_netmap_mmap,
    LIN_IOCTL_NAME = linux_netmap_ioctl,
    .poll = linux_netmap_poll,
    .release = netmap_release,
};

static struct miscdevice netmap_cdevsw = {	/* same name as FreeBSD */
	MISC_DYNAMIC_MINOR,
	"netmap",
	&netmap_fops,
};

static int netmap_init(void);
static void netmap_fini(void);

/* Errors have negative values on linux */
static int linux_netmap_init(void)
{
	return -netmap_init();
}

module_init(linux_netmap_init);
module_exit(netmap_fini);
/* export certain symbols to other modules */
EXPORT_SYMBOL(netmap_attach);		// driver attach routines
EXPORT_SYMBOL(netmap_detach);		// driver detach routines
EXPORT_SYMBOL(netmap_ring_reinit);	// ring init on error
EXPORT_SYMBOL(netmap_buffer_lut);
EXPORT_SYMBOL(netmap_total_buffers);	// index check
EXPORT_SYMBOL(netmap_buffer_base);
EXPORT_SYMBOL(netmap_reset);		// ring init routines
EXPORT_SYMBOL(netmap_buf_size);
EXPORT_SYMBOL(netmap_rx_irq);		// default irq handler
EXPORT_SYMBOL(netmap_no_pendintr);	// XXX mitigation - should go away


MODULE_AUTHOR("http://info.iet.unipi.it/~luigi/netmap/");
MODULE_DESCRIPTION("The netmap packet I/O framework");
MODULE_LICENSE("Dual BSD/GPL"); /* the code here is all BSD. */

#else /* __FreeBSD__ */

static struct cdevsw netmap_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "netmap",
	.d_open = netmap_open,
	.d_mmap = netmap_mmap,
	.d_mmap_single = netmap_mmap_single,
	.d_ioctl = netmap_ioctl,
	.d_poll = netmap_poll,
	.d_close = netmap_close,
};
#endif /* __FreeBSD__ */

#ifdef NM_BRIDGE
/*
 *---- support for virtual bridge -----
 */

/* ----- FreeBSD if_bridge hash function ------- */

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 *
 * http://www.burtleburtle.net/bob/hash/spooky.html
 */
#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static __inline uint32_t
nm_bridge_rthash(const uint8_t *addr)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key

        b += addr[5] << 8;
        b += addr[4];
        a += addr[3] << 24;
        a += addr[2] << 16;
        a += addr[1] << 8;
        a += addr[0];

        mix(a, b, c);
#define BRIDGE_RTHASH_MASK	(NM_BDG_HASH-1)
        return (c & BRIDGE_RTHASH_MASK);
}

static __inline uint32_t
nm_ifa_rthash(uint8_t *addr, uint8_t *port)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	p = port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = addr;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	mix(a, b, c);
#define IFA_RTHASH_MASK	(NM_IFA_HASH-1)
	return (c & IFA_RTHASH_MASK);
}

static __inline int
nm_ifa_rthash_from_ifa(struct netmap_ifaddr *nifa)
{
	uint8_t *addr, *port;
	addr = port = NULL;

	if (nifa->laddr.sa.sa_family == AF_INET) {
		addr = (uint8_t *)&nifa->laddr.sin.sin_addr;
		port = (uint8_t *)&nifa->laddr.sin.sin_port;
	} else if (nifa->laddr.sa.sa_family == AF_INET6) {
		addr = (uint8_t *)&nifa->laddr.sin6.sin6_addr.s6_addr32[3];
		port = (uint8_t *)&nifa->laddr.sin6.sin6_port;
	} else
		D("unsupported network protocol");
	return nm_ifa_rthash(addr, port);
}

#undef mix


static int
bdg_netmap_reg(struct ifnet *ifp, int onoff)
{
	int i, err = 0;
	struct nm_bridge *b = ifp->if_bridge;

	BDG_LOCK(b);
	if (onoff) {
		int act_ports;
		act_ports = (b->n_ports == NM_UNIBDG_MAXPORTS) ? NM_UNIBDG_MAXPORTS : NM_BDG_MAXPORTS;
		/* the interface must be already in the list.
		 * only need to mark the port as active
		 */
		ND("should attach %s to the bridge", ifp->if_xname);
		for (i=0; i < act_ports; i++)
			if (b->bdg_ports[i] == ifp)
				break;
		if (i == act_ports) {
			D("no more ports available");
			err = EINVAL;
			goto done;
		}
		ND("setting %s in netmap mode", ifp->if_xname);
		ifp->if_capenable |= IFCAP_NETMAP;
		NA(ifp)->bdg_port = i;
		NA(ifp)->bdg_idx = BDGIDX(b);
		b->act_ports |= (1<<i);
		b->bdg_ports[i] = ifp;
	} else {
		/* should be in the list, too -- remove from the mask */
		ND("removing %s from netmap mode", ifp->if_xname);
		ifp->if_capenable &= ~IFCAP_NETMAP;
		i = NA(ifp)->bdg_port;
		b->act_ports &= ~(1<<i);
	}
done:
	BDG_UNLOCK(b);
	return err;
}


static int
nm_bdg_flush(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp)
{
	int i, ifn;
	uint64_t all_dst, dst;
	uint32_t sh, dh;
	uint64_t mysrc = 1 << NA(ifp)->bdg_port;
	uint64_t smac, dmac;
	struct netmap_slot *slot;
	struct nm_bridge *b = ifp->if_bridge;

	ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
	/* only consider valid destinations */
	all_dst = (b->act_ports & ~mysrc);
	/* first pass: hash and find destinations */
	for (i = 0; likely(i < n); i++) {
		uint8_t *buf = ft[i].buf;
		dmac = le64toh(*(uint64_t *)(buf)) & 0xffffffffffff;
		smac = le64toh(*(uint64_t *)(buf + 4));
		smac >>= 16;
		if (unlikely(netmap_verbose & NM_VERB_PKT)) {
		    uint8_t *s = buf+6, *d = buf;
		    D("%d len %4d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
			i,
			ft[i].len,
			s[0], s[1], s[2], s[3], s[4], s[5],
			d[0], d[1], d[2], d[3], d[4], d[5]);
		}
		/*
		 * The hash is somewhat expensive, there might be some
		 * worthwhile optimizations here.
		 */
		if ((buf[6] & 1) == 0) { /* valid src */
			uint8_t *s = buf+6;
			sh = nm_bridge_rthash(buf+6); // XXX hash of source
			/* update source port forwarding entry */
			b->ht[sh].mac = smac;	/* XXX expire ? */
			b->ht[sh].ports = mysrc;
			if (netmap_verbose & NM_VERB_PKT)
			    D("src %02x:%02x:%02x:%02x:%02x:%02x on port %d",
				s[0], s[1], s[2], s[3], s[4], s[5], NA(ifp)->bdg_port);
		}
		dst = 0;
		if ( (buf[0] & 1) == 0) { /* unicast */
			uint8_t *d = buf;
			dh = nm_bridge_rthash(buf); // XXX hash of dst
			if (b->ht[dh].mac == dmac) {	/* found dst */
				dst = b->ht[dh].ports;
				if (netmap_verbose & NM_VERB_PKT)
				    D("dst %02x:%02x:%02x:%02x:%02x:%02x to port %x",
					d[0], d[1], d[2], d[3], d[4], d[5], (uint32_t)(dst >> 16));
			}
		}
		if (dst == 0)
			dst = all_dst;
		dst &= all_dst; /* only consider valid ports */
		if (unlikely(netmap_verbose & NM_VERB_PKT))
			D("pkt goes to ports 0x%x", (uint32_t)dst);
//		else if (unlikely(netmap_verbose & NM_VERB_DBG && !(i%64)))
//			D("pkt goes to ports 0x%x%x (printing only at every 64 pkts)", (uint32_t)(dst >> 32), (uint32_t)(dst));
		ft[i].dst = dst;
	}

	/* second pass, scan interfaces and forward */
	all_dst = (b->act_ports & ~mysrc);
	for (ifn = 0; all_dst; ifn++) {
		struct ifnet *dst_ifp = b->bdg_ports[ifn];
		struct netmap_adapter *na;
		struct netmap_kring *kring;
		struct netmap_ring *ring;
		int j, lim, sent, locked;

		if (!dst_ifp)
			continue;
		ND("scan port %d %s", ifn, dst_ifp->if_xname);
		dst = 1 << ifn;
		if ((dst & all_dst) == 0)	/* skip if not set */
			continue;
		all_dst &= ~dst;	/* clear current node */
		na = NA(dst_ifp);

		ring = NULL;
		kring = NULL;
		lim = sent = locked = 0;
		/* inside, scan slots */
		for (i = 0; likely(i < n); i++) {
			if ((ft[i].dst & dst) == 0)
				continue;	/* not here */
			if (!locked) {
				kring = &na->rx_rings[0];
				ring = kring->ring;
				lim = kring->nkr_num_slots - 1;
				na->nm_lock(dst_ifp, NETMAP_RX_LOCK, 0);
				locked = 1;
			}
			if (unlikely(kring->nr_hwavail >= lim)) {
				if (netmap_verbose & NM_VERB_PKT)
					D("rx ring full on %s", ifp->if_xname);
				break;
			}
			if (na->nm_ifflags & NM_IFF_BDG_FILTERED)
				if (bdg_ingress_filter(ft[i].buf, na->nifa))
					continue;
			j = kring->nr_hwcur + kring->nr_hwavail;
			if (j > lim)
				j -= kring->nkr_num_slots;
			slot = &ring->slot[j];
			ND("send %d %d bytes at %s:%d", i, ft[i].len, dst_ifp->if_xname, j);
			pkt_copy(ft[i].buf, NMB(slot), ft[i].len);
			slot->len = ft[i].len;
			kring->nr_hwavail++;
			sent++;
		}
		if (locked) {
			ND("sent %d on %s", sent, dst_ifp->if_xname);
			if (sent)
				selwakeuppri(&kring->si, PI_NET);
			na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, 0);
		}
	}
	return 0;
}

/*
 * Returns the number of packets moved.
 * We expect the source ring and its packet filter is already locked.
 */
static int
nm_bridge_txrings(struct ifnet *ifp, u_int src_ring, u_int dst_ring, int *err)
{
	/* source interface variables */
	struct netmap_adapter *na = NA(ifp);
	struct ifnet *dst_ifp = na->dst_vif->ifn;
	struct netmap_adapter *d_na = NA(dst_ifp);
	struct netmap_kring *kring, *d_kring;
	struct netmap_ring *ring, *d_ring;
	struct netmap_slot *d_slot;
	u_int d_cur, sent = 0;
	int j, k, lim, d_lim, i=0;

	*err = 0;
	kring = &na->tx_rings[src_ring];
	ring = kring->ring;
	k = ring->cur;
	lim = kring->nkr_num_slots - 1;

	dst_ring = get_dstringid(d_na, dst_ring);
	if (!d_na->separate_locks)
		d_na->nm_lock(dst_ifp, NETMAP_CORE_LOCK, 0);
	else
		d_na->nm_lock(dst_ifp, NETMAP_TX_LOCK, dst_ring);
	if (!(na->nm_ifflags & NM_IFF_BDG_FILTERED)) {
		*err = 1;
		goto unlock_out;
	}
	d_na->nm_txsync(dst_ifp, dst_ring, 0);
	d_kring = &d_na->tx_rings[dst_ring];
	d_ring = d_kring->ring;
	d_lim = d_ring->avail;
	d_cur = d_ring->cur;

	if (netmap_verbose & NM_VERB_PKT) {
		D("source ring has: ");
		dump_pkts_ring(kring, 0);
	}

	for (j = kring->nr_hwcur; likely(j != k);
	    j = unlikely(j == lim) ? 0 : j+1) {
		struct netmap_slot *slot = &ring->slot[j];
		char *buf = NMB(slot);
		int len = slot->len;

//		prefetch(buf);
		if (unlikely(len < 14))
			continue;
		/*
		 * XXX One might check all the packets beforehand.
		 * Pro: Reduced duration locking the destination ring.
		 * Con: Walking the ring twice. This reduced the
		 *      throughput from 14.88 Mpps to 13.54 (Core i5)
		 */
		if (unlikely(na->nifa->egress_filter(buf, ifp))) {
			D("error in egress_filter");
			*err = 1;
			break;
		}
		if (unlikely(sent == d_lim))
			break;
		d_slot = &d_ring->slot[d_cur];
		pkt_copy(buf, NMB(d_slot), len);
		d_slot->len = len;
		d_cur = (d_cur+1 == d_ring->num_slots ? 0 : d_cur+1);
		sent++;
	}
	d_ring->avail -= sent;
	d_ring->cur = d_cur;
	d_na->nm_txsync(dst_ifp, dst_ring, 0);
	/* If we don't use TXINTR on bridge ports, drop the unsent packets */
	if (!netmap_bdg_txintr)
		j = k;
	i = k - j;
	if (i < 0)
		i += kring->nkr_num_slots;
	kring->nr_hwavail = kring->nkr_num_slots - 1 - i;
	kring->nr_hwcur = j;
	ring->avail = kring->nr_hwavail;
unlock_out:
	if (!d_na->separate_locks)
		d_na->nm_lock(dst_ifp, NETMAP_CORE_UNLOCK, 0);
	else
		d_na->nm_lock(dst_ifp, NETMAP_TX_UNLOCK, dst_ring);

	if (netmap_verbose & NM_VERB_TXSYNC)
		D("done sent %d sent_i %d", sent, i);
	return sent;
}

/*
 * main dispatch routine
 */
static int
bdg_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int i, j, k, lim = kring->nkr_num_slots - 1;
	struct nm_bdg_fwd *ft = (struct nm_bdg_fwd *)(ifp + 1);
	int ft_i;	/* position in the forwarding table */
	int err = 0;

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);
	if (do_lock)
		na->nm_lock(ifp, NETMAP_TX_LOCK, ring_nr);

	if (netmap_bridge <= 0) { /* testing only */
		j = k; // used all
		goto done;
	}
	if (netmap_bridge > NM_BDG_BATCH)
		netmap_bridge = NM_BDG_BATCH;

	if (na->nm_ifflags & NM_IFF_BDG_HW) {
		nm_bridge_txrings(ifp, ring_nr, ring_nr, &err);
		goto done_hw_bridge;
	}
	ft_i = 0;	/* start from 0 */
	for (j = kring->nr_hwcur; likely(j != k); j = unlikely(j == lim) ? 0 : j+1) {
		struct netmap_slot *slot = &ring->slot[j];
		int len = ft[ft_i].len = slot->len;
		char *buf = ft[ft_i].buf = NMB(slot);

		prefetch(buf);
		if (unlikely(len < 14))
			continue;
		if (na->nm_ifflags & NM_IFF_BDG_FILTERED) {
			struct netmap_ifaddr *nifa = na->nifa;
			err = nifa->egress_filter(buf, ifp);
			if (unlikely(err))
				break;
		}
		if (unlikely(++ft_i == netmap_bridge))
			ft_i = nm_bdg_flush(ft, ft_i, ifp);
	}
	if (ft_i)
		ft_i = nm_bdg_flush(ft, ft_i, ifp);
	/* count how many packets we sent */
	i = k - j;
	if (i < 0)
		i += kring->nkr_num_slots;
	kring->nr_hwavail = kring->nkr_num_slots - 1 - i;
	if (j != k)
		D("early break at %d/ %d, avail %d", j, k, kring->nr_hwavail);

done:
	kring->nr_hwcur = j;
	ring->avail = kring->nr_hwavail;
done_hw_bridge:
	if (do_lock)
		na->nm_lock(ifp, NETMAP_TX_UNLOCK, ring_nr);

	if (netmap_verbose & NM_VERB_TXSYNC)
		D("%s ring %d lock %d", ifp->if_xname, ring_nr, do_lock);
	/* XXX is this really a right point to handle egress filter error ? */
	return err;
}

static int
bdg_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, lim = kring->nkr_num_slots - 1;
	u_int k = ring->cur, resvd = ring->reserved;
	int n;

	ND("%s ring %d lock %d avail %d",
		ifp->if_xname, ring_nr, do_lock, kring->nr_hwavail);

	if (k > lim)
		return netmap_ring_reinit(kring);
	if (do_lock)
		na->nm_lock(ifp, NETMAP_RX_LOCK, ring_nr);

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur;    /* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}

	if (j != k) { /* userspace has released some packets. */
		n = k - j;
		if (n < 0)
			n += kring->nkr_num_slots;
		ND("userspace releases %d packets", n);
                for (n = 0; likely(j != k); n++) {
                        struct netmap_slot *slot = &ring->slot[j];
                        void *addr = NMB(slot);

                        if (addr == netmap_buffer_base) { /* bad buf */
                                if (do_lock)
                                        na->nm_lock(ifp, NETMAP_RX_UNLOCK, ring_nr);
                                return netmap_ring_reinit(kring);
                        }
			/* decrease refcount for buffer */

			slot->flags &= ~NS_BUF_CHANGED;
                        j = unlikely(j == lim) ? 0 : j + 1;
                }
                kring->nr_hwavail -= n;
                kring->nr_hwcur = k;
        }

        /* tell userspace that there are new packets */
        ring->avail = kring->nr_hwavail - resvd;

	if (do_lock)
		na->nm_lock(ifp, NETMAP_RX_UNLOCK, ring_nr);
	return 0;
}

static void
bdg_netmap_attach(struct ifnet *ifp, int num_queues)
{
	struct netmap_adapter na;

	ND("attaching virtual bridge");
	bzero(&na, sizeof(na));

	na.ifp = ifp;
	na.separate_locks = 1;
	na.num_tx_desc = NM_BRIDGE_RINGSIZE;
	na.num_rx_desc = NM_BRIDGE_RINGSIZE;
	na.nm_txsync = bdg_netmap_txsync;
	na.nm_rxsync = bdg_netmap_rxsync;
	na.nm_register = bdg_netmap_reg;
	netmap_attach(&na, num_queues);
}

#endif /* NM_BRIDGE */

static struct cdev *netmap_dev; /* /dev/netmap character device. */


/*
 * Module loader.
 *
 * Create the /dev/netmap device and initialize all global
 * variables.
 *
 * Return 0 on success, errno on failure.
 */
static int
netmap_init(void)
{
	int error;

	error = netmap_memory_init();
	if (error != 0) {
		printf("netmap: unable to initialize the memory allocator.\n");
		return (error);
	}
	printf("netmap: loaded module\n");
	netmap_dev = make_dev(&netmap_cdevsw, 0, UID_ROOT, GID_WHEEL, 0660,
			      "netmap");

#ifdef NM_BRIDGE
	{
	int i;
	for (i = 0; i < NM_BRIDGES; i++)
		mtx_init(&nm_bridges[i].bdg_lock, "bdg lock", "bdg_lock", MTX_DEF);
	}
	{
	int i;
	struct netmap_vrf *vrf = &nm_vrf;

	NM_VRF_LOCK_INIT(vrf);
	for (i = 0; i < NM_IFA_HASH; i++) {
		LIST_INIT(&vrf->ifa_ht[i]);
		NM_IFAHASH_LOCK_INIT(i, vrf);
	}
	}
#endif
#ifdef linux
	netmap_sysctl_register();
#endif
	return (error);
}


/*
 * Module unloader.
 *
 * Free all the memory, and destroy the ``/dev/netmap`` device.
 */
static void
netmap_fini(void)
{
#ifdef __FreeBSD__
	struct netmap_vrf *vrf = &nm_vrf;
	int i;

	NM_VRF_LOCK_DESTROY(vrf);
	for (i = 0; i < NM_BRIDGES; i++)
		mtx_destroy(&nm_bridges[i].bdg_lock);
	for (i = 0; i < NM_IFA_HASH; i++) {
		NM_IFAHASH_LOCK_DESTROY(i, vrf);
	}
	D("destroyed the ADDR locks");
#endif
#ifdef linux
	netmap_sysctl_unregister();
#endif
	destroy_dev(netmap_dev);
	netmap_memory_fini();
	printf("netmap: unloaded module.\n");
}


#ifdef __FreeBSD__
/*
 * Kernel entry point.
 *
 * Initialize/finalize the module and return.
 *
 * Return 0 on success, errno on failure.
 */
static int
netmap_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = netmap_init();
		break;

	case MOD_UNLOAD:
		netmap_fini();
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}


DEV_MODULE(netmap, netmap_loader, NULL);
#endif /* __FreeBSD__ */

static __inline void
vrf_if_ref(struct netmap_vrf_if *vif)
{
	atomic_add_int(&vif->refcount, 1);
}

/* called without VRF_WLOCKED */
static void
vrf_if_rele(struct netmap_vrf_if *vif)
{
	struct ifnet *ifp = vif->ifn;

	if (NM_DECREMENT_AND_CHECK_REFCOUNT(&vif->refcount)) {
		struct netmap_vrf *vrf = vif->vrf;
		struct netmap_priv_d *priv = vif->priv;
		u_int i, q = NA(ifp)->num_tx_rings;

		/*
		 * We have already guaranteed no race with clients' contexts
		 * (e.g., poll()).  But we still have race with interrupts'
		 * ones (e.g., vrf_txintr() and sync_to_vrf()).
		 * So, we now acquire VRF_WLOCK() to stop these contexts come
		 * in, we then detach vif from the NIC.
		 */
		NM_VRF_WLOCK(vrf);
		NA(ifp)->vif = NULL;
		/* Release references from VALE ports */
		LIST_REMOVE(vif, next_ifn);
		NM_VRF_WUNLOCK(vrf);
		/* detached from vrf. No more interrupt context starts  */
		vif->ifn = NULL;
		vif->priv = NULL;
		NMA_LOCK();
		NA(ifp)->nm_lock(ifp, NETMAP_REG_LOCK, 0);
		netmap_dtor_locked(priv);
		NA(ifp)->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
		if_rele(ifp); /* XXX nm_if_rele ? */
		NMA_UNLOCK();
		bzero(priv, sizeof(*priv));
		free(priv, M_DEVBUF);
		for (i = 0; i <= q; i++)
			KASSERT(TAILQ_EMPTY(&vif->txintrq_head[i]), ("still some entry remains"));
		for (i = 0; i <= q; i++) {
			NM_VRF_TXINTRQ_LOCK_DESTROY(i, vif);
		}
		free(vif->ft, M_DEVBUF);
		vif->ft = NULL;
		free(vif, M_DEVBUF);
	}
}

/* taken from dtor_locked(). Can run with VRF_WLOCK. NMA_LOCK() is owned */
static void
netmap_dtor_bh(struct netmap_adapter *na, struct netmap_if *nifp)
{
	int i, j, lim;

	na->refcount--;
	for (i = 0; i < na->num_tx_rings + 1; i++) {
		struct netmap_ring *ring = na->tx_rings[i].ring;
		lim = na->tx_rings[i].nkr_num_slots;
		for (j = 0; j < lim; j++)
			netmap_free_buf(nifp, ring->slot[j].buf_idx);
		/* knlist_destroy(&na->tx_rings[i].si.si_note); */
		mtx_destroy(&na->tx_rings[i].q_lock);
	}
	for (i = 0; i < na->num_rx_rings + 1; i++) {
		struct netmap_ring *ring = na->rx_rings[i].ring;
		lim = na->rx_rings[i].nkr_num_slots;
		for (j = 0; j < lim; j++)
			netmap_free_buf(nifp, ring->slot[j].buf_idx);
		/* knlist_destroy(&na->rx_rings[i].si.si_note); */
		mtx_destroy(&na->rx_rings[i].q_lock);
	}
	netmap_free_rings(na);
}

/*
 * taken from the NIOCREGIF code path in netmap_ioctl()
 * ifp must be already reference-counted as with get_ifp()
 * If failed, vif is not dtor_lock()-able.
 * VRF is write-locked
 */
static int
vrf_netmap_regif(struct ifnet *ifp, uint16_t ringid, struct netmap_vrf_if **vif_p)
{
	struct netmap_adapter *na;
	struct netmap_if *nifp;
	struct netmap_priv_d *priv;
	struct netmap_vrf *vrf = &nm_vrf;
	struct netmap_vrf_if *vif;
	int error = 0, i, ext_siz = 0, base_siz;

	vif = netmap_alloc_vif(ifp, vrf);
	if (!vif)
		return ENOMEM;

	/* XXX We might need to check whether ifp supports netmap */
	na = NA(ifp);
	if (netmap_verbose & NM_VERB_DBG)
		D("for ringid 0x%x (max. num %d)", ringid, na->num_tx_rings);
	priv = malloc(sizeof(struct netmap_priv_d), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (priv == NULL) {
		bzero(vif, sizeof(*vif));
		free(vif, M_DEVBUF);
		return ENOMEM;
		/* refcount is released by the caller */
	}
	error = netmap_get_memory(priv);
	if (error) {
		bzero(vif, sizeof(*vif));
		free(vif, M_DEVBUF);
		bzero(priv, sizeof(*priv));
		free(priv, M_DEVBUF);
		return EFAULT;
	}
	/*
	 * we give up if dst_ifp is NETMAP_DELETING. We cannot sleep
	 * under VRF_WLOCK()
	 */
	NMA_LOCK();
	na->nm_lock(ifp, NETMAP_REG_LOCK, 0);
	if (NETMAP_DELETING(na)) {
		D("NETMAP_DELETING, give up...");
		error = EFAULT;
		goto error;
	}
	priv->np_ifp = ifp;
	error = netmap_set_ringid(priv, ringid);
	if (error)
		goto error;
	nifp = netmap_if_new(ifp->if_xname, na);
	if (nifp == NULL)
		error = ENOMEM;
	else if (ifp->if_capenable & IFCAP_NETMAP) {
		/* was already set */
	} else {
		for (i = 0 ; i < na->num_tx_rings + 1; i++)
			mtx_init(&na->tx_rings[i].q_lock, "nm_txq_lock", MTX_NETWORK_LOCK, MTX_DEF);
		for (i = 0; i < na->num_rx_rings + 1; i++)
			mtx_init(&na->rx_rings[i].q_lock, "nm_rxq_lock", MTX_NETWORK_LOCK, MTX_DEF);
		error = na->nm_register(ifp, 1); /* mode on */
		if (error) {
			/* XXX do better */
			netmap_dtor_bh(na, nifp);
			netmap_if_free(nifp);
		}
	}
	if (error)
		goto error;

	/* We keep holding REG_LOCK */

	/*
	 * allocate the memory for per-ring forwarding table
	 * used by the NIC's RX context.  See sync_to_vrf()
	 * XXX If we want to forward packets to multicast bridges, the algo
	 * must be NM_UNIBDG_FWDALGO_MBDG
	 */
	vif_set_fwdfunc(netmap_bdg_unicastalgo, vif);
	KASSERT((vif->ft == NULL), ("na->ft is already allocated?"));
	base_siz = sizeof(struct nm_bdg_fwd)*NM_BDG_BATCH*na->num_rx_rings;
	if (vif->bdgfwd_func == nm_unibdg_flush ||
	    vif->bdgfwd_func == nm_unibdg_flush3)
		ext_siz = sizeof(struct nm_unibdgfwd_head) *
			NM_UNIBDG_MAXPORTS * na->num_rx_rings;
	else if (vif->bdgfwd_func == nm_unibdg_flush2 || vif->bdgfwd_func == nm_unibdg_flush_rps)
		ext_siz = sizeof(struct nm_unibdgfwd_head) * NM_BDG_BATCH *
			na->num_rx_rings;
	vif->ft = malloc(base_siz + ext_siz, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!vif->ft) {
		error = ENOMEM;
		netmap_dtor_bh(na, nifp);
		netmap_if_free(nifp);
		goto error;
	}
	if (ext_siz) {
		int lim;

		vif->unibdgfwd_head = (struct nm_unibdgfwd_head *)(vif->ft +
			NM_BDG_BATCH * na->num_rx_rings);
		if (vif->bdgfwd_func == nm_unibdg_flush2)
			lim = NM_BDG_BATCH * na->num_rx_rings;
		else
			lim = NM_UNIBDG_MAXPORTS * na->num_rx_rings;
		for (i = 0; i < lim; i++)
			STAILQ_INIT(&vif->unibdgfwd_head[i]);
	}

	if (error) {
error:
		na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
		bzero(vif, sizeof(*vif));
		free(vif, M_DEVBUF);
		/* No dtor for vrf, so free priv */
		bzero(priv, sizeof(*priv));
		free(priv, M_DEVBUF);
		NMA_UNLOCK();
		/* refcount for ifp is decremented by the caller */
		return error;
	}

	na->vif = vif;
	vrf_if_ref(vif);
	na->nm_lock(ifp, NETMAP_REG_UNLOCK, 0);
	wmb();
	priv->np_nifp = nifp;
	NMA_UNLOCK();

	/* Initialize TX interrupt queues */
	for (i=0; i <= na->num_tx_rings; i++) {
		TAILQ_INIT(&vif->txintrq_head[i]);
		NM_VRF_TXINTRQ_LOCK_INIT(i, vif);
	}
	LIST_INSERT_HEAD(&vrf->viflist, vif, next_ifn);

	/* don't set_cdevpriv */
	vif->priv = priv;
	*vif_p = vif;
	D("registered %s to netmap-mode", ifp->if_xname);
	return error;
}

/* Return refcounted nifa */
static struct netmap_ifaddr *
netmap_findifa_pkt(uint8_t *buf, uint8_t **hint)
{
	struct netmap_ifaddr *nifa;
	struct nm_ifahashhead *head;
	int hashval; /* in case of error it is -1 */
	struct netmap_vrf *vrf = &nm_vrf;
	uint16_t ether_type;
	uint8_t *daddr, *dport;
	struct ip *iph = NULL;
	struct ip6_hdr *ip6 = NULL;

	dport = daddr = NULL;
	ether_type = ntohs(*(uint16_t *)(buf + ETHER_TYPE_OFF));
	/* get hash of identifier */
	if (ether_type == 0x0800) {
		uint16_t sum;
		iph = (struct ip* )(buf + ETHER_HDR_LEN);
		/* XXX */
		dport = (uint8_t *)(((uint8_t *)iph) + (iph->ip_hl<<2));
		sum = iph->ip_sum;
		iph->ip_sum = 0;
		if (unlikely(sum != (0xffff ^
		    ipv4_csum((uint16_t *)iph, sizeof(*iph))))) {
			iph->ip_sum = sum;
			return NULL;
		}
		iph->ip_sum = sum;
		*hint = dport;
		dport+=2;
		daddr = (uint8_t *)&iph->ip_dst;
	} else if (ether_type == 0x86DD) {
		ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
		dport = (uint8_t *)(ip6+1);
		*hint = dport;
		dport += 2;
		daddr = (uint8_t *)&ip6->ip6_dst.s6_addr32[3];
	} else
		return NULL;
	if (unlikely(netmap_verbose & NM_VERB_PKT))
		nm_print_pkt(buf);
	hashval = nm_ifa_rthash(daddr, dport);

	if (unlikely(hashval < 0))
		/* Malformed or unsupported packets */
		return NULL;
	NM_IFAHASH_RLOCK(hashval, vrf);
	head = &vrf->ifa_ht[hashval];
	LIST_FOREACH(nifa, head, ifahash_next) {
		if (iph) {
			if (iph->ip_dst.s_addr !=
			    nifa->laddr.sin.sin_addr.s_addr)
				continue;
			else if (!src_port_valid((uint16_t *)(iph+1)+1,
			    (uint8_t)iph->ip_p, nifa))
				continue;
		} else if (ip6) {
			if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
		    	    &nifa->laddr.sin6.sin6_addr))
				continue;
			else if (!src_port_valid((uint16_t *)(ip6+1)+1,
			    (uint8_t)ip6->ip6_nxt, nifa))
				continue;
		}
		NM_IFAHASH_RUNLOCK(hashval, vrf);
		return nifa;
		/*
		if (!bdg_ingress_filter(buf, nifa)) {
			NM_IFAHASH_RUNLOCK(hashval, vrf);
			return nifa;
		}
		*/
	}
	NM_IFAHASH_RUNLOCK(hashval, vrf);
	return NULL;
}

