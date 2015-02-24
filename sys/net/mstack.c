/*
 *  BSD LICENSE
 *
 * Copyright(c) 2015 NEC Europe Ltd. All rights reserved.
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of NEC Europe Ltd. nor the names of
 *      its contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#if defined(__FreeBSD__)
#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/module.h>
#include <sys/conf.h>

#include <sys/malloc.h>
#include <machine/bus.h>
#include <sys/socket.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/sockio.h> /* XXX _IOWR. Should we use ioccom.h ? */
#include <sys/proc.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h> /* struct in_addr in ip.h */
#include <netinet/ip.h> /* struct ip */
#include <netinet/ip6.h> /* struct ip6 */

#define MSTACK_REFCOUNT_T	int
#define MSTACK_REFCOUNT_SET(addr, val)	(*(addr) = val)
#define MSTACK_DECREMENT_AND_CHECK_REFCOUNT(addr) atomic_fetchadd_int(addr, -1)

#define MSTACK_RWLOCK_T	struct rwlock

#define MSTACK_LOCK_INIT(o)	rw_init(&(o)->mtx, "mstackglobal")
#define MSTACK_LOCK_DESTROY(o)	do { \
		if(rw_wowned(&(o)->mtx)) { \
			rw_wunlock(&(o)->mtx); \
		} \
		rw_destroy(&(o)->mtx); \
	} while (0)
#define MSTACK_RLOCK(o)	rw_rlock(&(o)->mtx)
#define MSTACK_RUNLOCK(o)	rw_runlock(&(o)->mtx)
#define MSTACK_WLOCK(o)	rw_wlock(&(o)->mtx)
#define MSTACK_WUNLOCK(o)	rw_wunlock(&(o)->mtx)
#define MSTACK_IFAHASH_LOCK_INIT(i)            \
	rw_init(&mstackglobal.ipi_addr_mtx[i], "mstack-addr")
#define MSTACK_IFAHASH_LOCK_DESTROY(i) do { \
	if(rw_wowned(&mstackglobal.ipi_addr_mtx[i])) { \
		rw_wunlock(&mstackglobal.ipi_addr_mtx[i]); \
	} \
	rw_destroy(&mstackglobal.ipi_addr_mtx[i]); \
} while (0)
#define MSTACK_IFAHASH_RLOCK(i) do {                   \
        rw_rlock(&mstackglobal.ipi_addr_mtx[i]);                      \
} while (0)
#define MSTACK_IFAHASH_WLOCK(i) do {                   \
        rw_wlock(&mstackglobal.ipi_addr_mtx[i]);                      \
} while (0)
#define MSTACK_IFAHASH_RUNLOCK(i) do {                         \
        rw_runlock(&mstackglobal.ipi_addr_mtx[i]);            \
} while (0)
#define MSTACK_IFAHASH_WUNLOCK(i) do {                         \
        rw_wunlock(&mstackglobal.ipi_addr_mtx[i]);            \
} while (0)

#elif defined(linux)

#include <bsd_glue.h>
#include <net/ipv6.h>

#define MSTACK_REFCOUNT_T   atomic_t
#define MSTACK_REFCOUNT_SET(addr, val)      atomic_set(addr, val)
#define MSTACK_DECREMENT_AND_CHECK_REFCOUNT(addr) atomic_dec_and_test(addr)

#define MSTACK_RWLOCK_T     rwlock_t

#define MSTACK_LOCK_INIT(o)	rwlock_init(&(o)->mtx)
#define MSTACK_LOCK_DESTROY(o)
#define MSTACK_RLOCK(o)	read_lock(&(o)->mtx)
#define MSTACK_RUNLOCK(o)	read_unlock(&(o)->mtx)
#define MSTACK_WLOCK(o)	write_lock(&(o)->mtx)
#define MSTACK_WUNLOCK(o)	write_unlock(&(o)->mtx)

#define MSTACK_IFAHASH_LOCK_INIT(i) rwlock_init(&mstackglobal.ipi_addr_mtx[i])
#define MSTACK_IFAHASH_LOCK_DESTROY(i)
#define MSTACK_IFAHASH_RLOCK(i) read_lock(&mstackglobal.ipi_addr_mtx[i])
#define MSTACK_IFAHASH_RUNLOCK(i) read_unlock(&mstackglobal.ipi_addr_mtx[i])
#define MSTACK_IFAHASH_WLOCK(i) write_lock(&mstackglobal.ipi_addr_mtx[i])
#define MSTACK_IFAHASH_WUNLOCK(i) write_unlock(&mstackglobal.ipi_addr_mtx[i])

#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include "mstack.h"
#define MSTACK_IFA_HASH		1024

struct mstack_ifaddr {
	union mstack_addr laddr;
	uint8_t protocol;
	LIST_ENTRY(mstack_ifaddr) ifahash_next;
	MSTACK_REFCOUNT_T refcount;
	uint8_t bdg_port;
	uint8_t nic_port;
	int (*egress_filter)(uint8_t *, struct mstack_ifaddr *);
};


#ifdef linux
struct mstack_ifahashhead {
	struct mstack_ifaddr *lh_first;
};
#else
LIST_HEAD(mstack_ifahashhead, mstack_ifaddr);
#endif

struct mstack_global {
	struct mstack_ifahashhead ifa_ht[MSTACK_IFA_HASH];
	MSTACK_RWLOCK_T	ipi_addr_mtx[MSTACK_IFA_HASH];
	struct mstack_ifaddr *porttable[NM_BDG_MAXPORTS];
	MSTACK_RWLOCK_T mtx;
} mstackglobal;

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
mstack_ifa_rthash(uint8_t *addr, uint8_t *port)
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
#define IFA_RTHASH_MASK	(MSTACK_IFA_HASH-1)
	return (c & IFA_RTHASH_MASK);
}

static __inline int
mstack_ifa_rthash_from_ifa(struct mstack_ifaddr *mifa)
{
	uint8_t *addr, *port;
	addr = port = NULL;

	if (mifa->laddr.sa.sa_family == AF_INET) {
		addr = (uint8_t *)&mifa->laddr.sin.sin_addr;
		port = (uint8_t *)&mifa->laddr.sin.sin_port;
	} else if (mifa->laddr.sa.sa_family == AF_INET6) {
		addr = (uint8_t *)&mifa->laddr.sin6.sin6_addr.s6_addr32[3];
		port = (uint8_t *)&mifa->laddr.sin6.sin6_port;
	} else
		D("unsupported network protocol");
	return mstack_ifa_rthash(addr, port);
}

#undef mix

static inline void
mstack_ref_ifa(struct mstack_ifaddr *mifa)
{
	atomic_add_int(&mifa->refcount, 1);
}


static struct mstack_ifaddr *
mstack_findifa_sa(struct sockaddr *sa, uint8_t protocol)
{
	int i, found = 0;
	struct mstack_ifahashhead *head;
	struct mstack_ifaddr *mifa;

	for (i = 0; i < MSTACK_IFA_HASH; ++i) {
		MSTACK_IFAHASH_RLOCK(i);
		head = &mstackglobal.ifa_ht[i];
		LIST_FOREACH(mifa, head, ifahash_next) {
			if (mifa->laddr.sa.sa_family != sa->sa_family)
				continue;
			if (mifa->protocol != protocol)
				continue;
			if (sa->sa_family == AF_INET) {
				if (mifa->laddr.sin.sin_port !=
				    satosin(sa)->sin_port)
					continue;
			} else if (sa->sa_family == AF_INET6) {
				if (mifa->laddr.sin6.sin6_port !=
				    satosin6(sa)->sin6_port)
					continue;
				if (!IN6_ARE_ADDR_EQUAL(
				    &mifa->laddr.sin6.sin6_addr,
				    &satosin6(sa)->sin6_addr))
					continue;
			} else
				continue;
			found = 1;
			break;
		}
		MSTACK_IFAHASH_RUNLOCK(i);
		if (found) {
			return mifa;
		}
	}
	return NULL;
}

/* We don't check existence of if_addrhead entry anymore */
static inline int
src_port_valid(uint16_t *toff, uint8_t protocol, struct mstack_ifaddr *mifa)
{
	if (protocol == mifa->protocol && *toff == mifa->laddr.sin.sin_port)
		return 1;
	else
		return 0;
}

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
static int
egress_ipv4_chk(uint8_t *buf, struct mstack_ifaddr *mifa)
{
	struct ip *iph;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x0800))
		goto out_err;
	/* We currently assume the ethernet header is filled by the app */
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	if (unlikely(iph->ip_hl != 5))
		goto ipv4_slowpath;
	if (iph->ip_src.s_addr != mifa->laddr.sin.sin_addr.s_addr)
		goto out_err;
	if (!src_port_valid((uint16_t *)(iph+1), (uint8_t)iph->ip_p, mifa))
		goto out_err;
	return 0;
ipv4_slowpath:
out_err:
	return 1;
}

static int
egress_ipv6_chk(uint8_t *buf, struct mstack_ifaddr *mifa)
{
	struct ip6_hdr *ip6;

	if (unlikely(ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF))) != 0x86DD))
		goto out_err;
	/* We currently assume the ethernet header is filled by the app */
	ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);
	if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &mifa->laddr.sin6.sin6_addr))
		goto out_err;
	if (!src_port_valid((uint16_t *)(ip6+1), (uint8_t)ip6->ip6_nxt, mifa))
		goto out_err;
	return 0;
out_err:
	return 1;
}

static int
mstack_add_addr(struct sockaddr *sa, uint8_t protocol, uint8_t bdg_port,
		uint8_t nic_port)
{
	struct mstack_ifaddr *mifa = NULL;
	struct mstack_ifahashhead *head;
	int hashval;

	mifa = mstack_findifa_sa(sa, protocol);
	if (mifa) {
		D("already registered");
		return 0;
	}
	mifa = (struct mstack_ifaddr *)malloc(sizeof(*mifa), M_IFADDR,
			M_WAITOK | M_ZERO);
	if (mifa == NULL)
		return ENOMEM;
	MSTACK_REFCOUNT_SET(&mifa->refcount, 0); /* XXX */
	mifa->protocol = protocol;
	mifa->laddr.sa.sa_family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		mifa->laddr.sin.sin_port = satosin(sa)->sin_port;
		mifa->laddr.sin.sin_addr.s_addr = satosin(sa)->sin_addr.s_addr;
		mifa->egress_filter = egress_ipv4_chk;
	} else /* AF_INET6 */ {
		mifa->laddr.sin6.sin6_port = satosin6(sa)->sin6_port;
		memcpy(&mifa->laddr.sin6.sin6_addr, &satosin6(sa)->sin6_addr,
				sizeof(struct in6_addr));
		mifa->egress_filter = egress_ipv6_chk;
	}
	mifa->bdg_port = bdg_port;
	mifa->nic_port = nic_port;

	hashval = mstack_ifa_rthash_from_ifa(mifa);
	MSTACK_IFAHASH_WLOCK(hashval);
	head = &mstackglobal.ifa_ht[hashval];
	LIST_INSERT_HEAD(head, mifa, ifahash_next);
	mstack_ref_ifa(mifa); /* reference from the hash table */
	mstackglobal.porttable[bdg_port] = mifa;
	MSTACK_IFAHASH_WUNLOCK(hashval);
	return 0;
}

#ifdef __FreeBSD__
#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL
static void *
mstack_findifa_system(struct sockaddr *sa, uint8_t *nic_port)
{
	struct ifnet *ifn;
	struct ifaddr *ifa;
	struct ifaddr *retval = NULL;
	int finish = 0;

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
			if (NETMAP_CAPABLE(ifn)) {
				struct netmap_vp_adapter *vp;
				vp = netmap_ifp_to_vp(ifn);
				if (vp) {
					*nic_port = vp->bdg_port;
					retval = ifa;
				}
			}
			finish = 1;
			break;
		}
		IF_ADDR_RUNLOCK(ifn);
		if (finish)
			break;
	}
	IFNET_RUNLOCK();

	return retval;
}
#elif defined(linux)
#include <linux/inetdevice.h>
#include <net/addrconf.h>
static void *
mstack_findifa_system(struct sockaddr *sa, uint8_t *nic_port)
{
	struct net_device *dev;
	void *retval = NULL;
	int finish = 0;

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
					if (NETMAP_CAPABLE(dev)) {
						struct netmap_vp_adapter *vp;
						vp = netmap_ifp_to_vp(dev);
						if (vp) {
							*nic_port = vp->bdg_port;
							retval = (void *)ifa;
						}
					}
					finish = 1;
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
					if (NETMAP_CAPABLE(dev)) {
						struct netmap_vp_adapter *vp;
						vp = netmap_ifp_to_vp(dev);
						if (vp) {
							*nic_port = vp->bdg_port;
							retval = (void *)ifa;
						}
					}
					finish = 1;
					break;
				}
			}
			read_unlock_bh(&in6_dev->lock);
			rcu_read_unlock();
		}
		if (finish)
			break;
	}
	rcu_read_unlock();
	return retval;
}
#endif /* FreeBSD, linux */

static inline void
mstack_free_ifa(struct mstack_ifaddr *mifa)
{
	if (MSTACK_DECREMENT_AND_CHECK_REFCOUNT(&mifa->refcount)) {
		mifa->egress_filter = NULL;
		free(mifa, M_IFADDR); /* XXX */
	}
}

static void
mstack_del_ifaddr(struct mstack_ifaddr *mifa)
{
	if (!mifa) {
		D("no ifa");
		return;
	}
	mstack_free_ifa(mifa);
}

static void
mstack_dtor(const struct netmap_vp_adapter *vpna)
{
	uint8_t bdg_port = vpna->bdg_port;
	int hashval;
	struct mstack_ifaddr *mifa;
	struct mstack_ifahashhead *head;

       	mifa = mstackglobal.porttable[bdg_port];
	if (!mifa)
		return;
	hashval = mstack_ifa_rthash_from_ifa(mifa);
	MSTACK_IFAHASH_WLOCK(hashval);
	head = &mstackglobal.ifa_ht[hashval];
	LIST_REMOVE(mifa, ifahash_next);
	mstackglobal.porttable[bdg_port] = NULL; /* XXX safe ? */
	MSTACK_IFAHASH_WUNLOCK(hashval);
	mstack_del_ifaddr(mifa);
}

static int
mstack_config(struct nm_ifreq *data)
{
	struct mstack_req *mreq = (struct mstack_req *)data;
	int err = 0;
	uint8_t nic_port, me;
	struct nmreq nmr;

	if ((mreq->mr_laddr.sa.sa_family != AF_INET) &&
	    (mreq->mr_laddr.sa.sa_family != AF_INET6))
		return EINVAL;
	if (!mstack_findifa_system(&mreq->mr_laddr.sa, &nic_port)) {
		D("address is not found in the system");
		return EINVAL; /* for debug I ignore existence of the address */
	}

        bzero(&nmr, sizeof(nmr));
        nmr.nr_cmd = NETMAP_BDG_LIST;
        nmr.nr_version = NETMAP_API;
        strncpy(nmr.nr_name, mreq->mr_ifname, sizeof(nmr.nr_name));
        err = netmap_bdg_ctl(&nmr, NULL);
        if (err) {
                return err;
        }
        me = nmr.nr_arg2;

	switch (mreq->mr_cmd) {
	case MSTACK_OPEN:
		err = mstack_add_addr(&mreq->mr_laddr.sa, mreq->mr_protocol,
			       	me, nic_port);
	default:
		break;
	}
	return err;
}

static struct mstack_ifaddr *
mstack_findifa_pkt(uint8_t *buf, uint8_t **hint)
{
	struct mstack_ifaddr *mifa;
	struct mstack_ifahashhead *head;
	int hashval; /* in case of error it is -1 */
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
	hashval = mstack_ifa_rthash(daddr, dport);

	if (unlikely(hashval < 0))
		/* Malformed or unsupported packets */
		return NULL;
	MSTACK_IFAHASH_RLOCK(hashval);
	head = &mstackglobal.ifa_ht[hashval];
	LIST_FOREACH(mifa, head, ifahash_next) {
		if (iph) {
			if (iph->ip_dst.s_addr !=
			    mifa->laddr.sin.sin_addr.s_addr)
				continue;
			else if (!src_port_valid((uint16_t *)(iph+1)+1,
			    (uint8_t)iph->ip_p, mifa))
				continue;
		} else if (ip6) {
			if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
		    	    &mifa->laddr.sin6.sin6_addr))
				continue;
			else if (!src_port_valid((uint16_t *)(ip6+1)+1,
			    (uint8_t)ip6->ip6_nxt, mifa))
				continue;
		}
		MSTACK_IFAHASH_RUNLOCK(hashval);
		return mifa;
		/*
		if (!bdg_ingress_filter(buf, nifa)) {
			NM_IFAHASH_RUNLOCK(hashval, vrf);
			return nifa;
		}
		*/
	}
	MSTACK_IFAHASH_RUNLOCK(hashval);
	return NULL;
}

static u_int
mstack_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
		const struct netmap_vp_adapter *vpna)
{
	struct mstack_ifaddr *mifa;

	mifa = mstackglobal.porttable[vpna->bdg_port];
	if (mifa)
		return mifa->egress_filter(ft->ft_buf, mifa) ?
			NM_BDG_NOPORT : mifa->nic_port;
	mifa = mstack_findifa_pkt(ft->ft_buf, &ring_nr);
	return mifa ? mifa->bdg_port : NM_BDG_NOPORT;
}

#ifdef linux
static int mstack_init(void);
static void mstack_fini(void);

static int linux_mstack_init(void)
{
	return -mstack_init();
}

module_init(linux_mstack_init);
module_exit(mstack_fini);
MODULE_AUTHOR("NEC Europe Ltd.");
MODULE_DESCRIPTION("MultiStack packet mux/demux module");
MODULE_LICENSE("Dual BSD/GPL");

#endif /* Linux */

static struct netmap_bdg_ops mstack_bdg_ops =
	{ mstack_lookup, mstack_config, mstack_dtor };

#define MSTACK_NAME	"valem:"
	
static int
mstack_init(void)
{
        struct nmreq nmr;
        int i;

        bzero(&nmr, sizeof(nmr));
        nmr.nr_version = NETMAP_API;
        strncpy(nmr.nr_name, MSTACK_NAME, strlen(MSTACK_NAME));
        nmr.nr_cmd = NETMAP_BDG_REGOPS;
        if (netmap_bdg_ctl(&nmr, &mstack_bdg_ops)) {
                D("no bridge named %s", nmr.nr_name);
                return ENOENT;
        }

        bzero(&mstackglobal, sizeof(mstackglobal));
        MSTACK_LOCK_INIT(&mstackglobal);
        for (i = 0; i < MSTACK_IFA_HASH; i++) {
                LIST_INIT(&mstackglobal.ifa_ht[i]);
		MSTACK_IFAHASH_LOCK_INIT(i);
	}

        printf("MultiStack: loaded module\n");
        return 0;
}

static void
mstack_fini(void)
{
	struct nmreq nmr;
	int error;
	struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, MSTACK_NAME, sizeof(nmr.nr_name));
	nmr.nr_cmd = NETMAP_BDG_REGOPS;
	error = netmap_bdg_ctl(&nmr, &tmp);
	if (error)
		D("failed in netmap_bdg_ctl() %d", error);
	/* XXX temporarily comment out to handle failure in init */
//        for (i = 0; i < MSTACK_IFA_HASH; i++)
//		MSTACK_IFAHASH_LOCK_DESTROY(i);
	printf("MultiStack: Unloaded module\n");
}

#ifdef __FreeBSD__

static int
mstack_loader(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = mstack_init();
		break;
	case MOD_UNLOAD:
		mstack_fini();
		break;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

DEV_MODULE(mstack, mstack_loader, NULL);
#endif /* __FreeBSD__ */
