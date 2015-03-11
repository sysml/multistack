/*
 * Copyright (C) 2013 Michio Honda. All rights reserved.
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

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/module.h>
#include <sys/conf.h>

/* to compile netmap_kern.h */
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
#include <netinet/in_pcb.h> /* struct inpcb */
#include <netinet/ip.h> /* struct ip */
#include <netinet/ip6.h> /* struct ip6 */
#include <netinet6/in6_var.h> /* in6_sprintf */
#include <netinet/tcp_var.h> /* V_tcbinfo */
/* For debug */
#include <net/if_arp.h>
#include <netinet/tcp.h> /* struct tcp_hdr */

/* For ms_pcb_clash() */
#include "opt_inet6.h"
#include "opt_sctp.h"
#include <sys/protosw.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#ifdef SCTP
#include <netinet/sctp_pcb.h>
#endif /* SCTP */
#ifdef INET6
#include <netinet6/in6_pcb.h>
#endif
extern struct protosw inetsw[];

#define MS_RWLOCK_T	struct rwlock
#define	MS_RWINIT(_lock, _m)	rw_init(_lock, _m)
#define MS_WLOCK()	rw_wlock(&ms_global.lock)
#define MS_WUNLOCK()	rw_wunlock(&ms_global.lock)
#define MS_RLOCK()	rw_rlock(&ms_global.lock)
#define MS_RUNLOCK()	rw_runlock(&ms_global.lock)

#define MS_LIST_INIT(_head)	LIST_INIT(_head)
#define MS_LIST_ENTRY(_type)	LIST_ENTRY(_type)
#define MS_LIST_ADD(_head, _n, _pos) 	LIST_INSERT_HEAD(_head, _n, _pos)
#define MS_LIST_DEL(_n, _pos)		LIST_REMOVE(_n, _pos)
LIST_HEAD(ms_routelist, ms_route);
#define MS_LIST_FOREACH	LIST_FOREACH
#define MS_LIST_FOREACH_SAFE	LIST_FOREACH_SAFE
#define MS_ROUTE_LIST	struct ms_routelist

#define MS_GET_VAR(lval)	(lval)
#define MS_SET_VAR(lval, p)	((lval) = (p))

#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL

#elif defined (linux)

#include <bsd_glue.h> /* from netmap-release */
#include <bsd_glue_multistack.h>
#include <contrib/multistack/multistack_kern.h>
#include <net/addrconf.h>
#endif /* linux */

/* Common headers */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */
#include <net/multistack.h>

#define MS_NAME		"valem:"
#define MS_ROUTEHASHSIZ	16384
#define MS_F_STACK	0x01
#define MS_F_HOST	0x02

#ifdef MULTITACK_MBOXFILTER
uint16_t udp_tbl[65536];
uint16_t tcp_tbl[65536];
#endif /* MULTITACK_MBOXFILTER */

/* struct tcphdr of FreeBSD */
struct ms_tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#elif defined (__BIG_ENDIAN_BITFIELD)
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define	PRINT_TH_FLAGS	"\20\1FIN\2SYN\3RST\4PUSH\5ACK\6URG\7ECE\10CWR"

	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

static inline void
ip_sprintf(char *buf, struct in_addr *addr)
{
	uint8_t *p = (uint8_t *)addr;
	sprintf(buf, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static void
ms_addr_sprintf(char *buf, const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		ip_sprintf(buf, &satosin(sa)->sin_addr);
	else if (sa->sa_family == AF_INET6)
		ip6_sprintf(buf, &satosin6(sa)->sin6_addr);
}
static inline void
eth_sprintf(char *buf, uint8_t *addr)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],
		addr[2], addr[3], addr[4], addr[5]);
}
/* XXX non static just to silence compiler */
void ms_pkt2str(const uint8_t *, char *);
void
ms_pkt2str(const uint8_t *buf, char *dst)
{
	uint16_t et;
        uint8_t *th;
	char saddr_str[INET6_ADDRSTRLEN], daddr_str[INET6_ADDRSTRLEN];
	char smac_str[18], dmac_str[18];
	struct ether_header *eth = (struct ether_header *)buf;
	struct ms_tcphdr *tcph;

        et = ntohs(eth->ether_type);
	eth_sprintf(smac_str, eth->ether_shost);
	eth_sprintf(dmac_str, eth->ether_dhost);

        if (et == ETHERTYPE_IP) {
                struct ip *iph = (struct ip *)(buf + ETHER_HDR_LEN);

              //  th = (uint8_t *)iph + (iph->ip_hl << 2);
		th = (uint8_t *)iph;
//		th += (iph->ip_hl << 2);
		th += 20;
		ip_sprintf(saddr_str, &iph->ip_src);
		ip_sprintf(daddr_str, &iph->ip_dst);

		sprintf(dst, "%s %s:%u > %s %s:%u %u len %u",
		       	smac_str, saddr_str, ntohs(*(uint16_t *)th),
			dmac_str, daddr_str, ntohs(*( ((uint16_t *)th)+1)),
		       	iph->ip_p, ntohs(iph->ip_len));
		if (iph->ip_p == IPPROTO_TCP) {
			tcph = (struct ms_tcphdr *)th;
			sprintf(dst + strlen(dst), " tcp flags 0x%x seq %u ack %u", tcph->th_flags, tcph->th_seq, tcph->th_ack);

		}
	} else if (et == ETHERTYPE_IPV6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);

		th = (uint8_t *)(ip6+1);
                ip6_sprintf(saddr_str, &ip6->ip6_src);
                ip6_sprintf(daddr_str, &ip6->ip6_src);
		sprintf(dst, "%s %s:%u > %s:%s:%u %u len %u",
			smac_str, saddr_str, ntohs(*(uint16_t *)th),
			dmac_str, daddr_str, ntohs(*( ((uint16_t *)th)+1)),
			ip6->ip6_nxt, ntohs(ip6->ip6_plen));
		if (ip6->ip6_nxt == IPPROTO_TCP) {
			tcph = (struct ms_tcphdr *)th;
			sprintf(dst + strlen(dst), "tcp flags 0x%x seq %u ack %u", tcph->th_flags, tcph->th_seq, tcph->th_ack);

		}
        } else if (et == ETHERTYPE_ARP) {
		struct arphdr *ah = (struct arphdr *)(buf + ETHER_HDR_LEN);
	       
		if (ntohs(ah->ar_op) == ARPOP_REQUEST) {
			ip_sprintf(saddr_str,
				(struct in_addr *)((char *)(ah+1) + 6));
			ip_sprintf(daddr_str,
				(struct in_addr *)((char *)(ah+1) + 16));
			sprintf(dst, "%s %s > %s ARP whohas %s", smac_str,
				saddr_str, dmac_str, daddr_str);
		} else if (ntohs(ah->ar_op) == ARPOP_REPLY) {
			ip_sprintf(saddr_str,
				(struct in_addr *)((char *)(ah+1) + 6));
			ip_sprintf(daddr_str,
				(struct in_addr *)((char *)(ah+1) + 16));
			sprintf(dst, "%s %s > %s ARP reply %s", smac_str,
				saddr_str, dmac_str, daddr_str);
		} else
			sprintf(dst, "%s > %s unknown ARP op %u",
				saddr_str, daddr_str, ah->ar_op);
	} else
		sprintf(dst, "unknown protocol");
}

/*
 * container of 3-tuple registered by the app/port.
 * The app/port can register multiple 3-tuples, but a unique 3-tuple can
 * be registered only by a single app/port.
 * A single 3-tuple can be associated with only a single destination.
 * XXX fix alignment
 */
struct ms_route {
	MS_LIST_ENTRY(ms_route) next; /* hlist_node in linux */
	struct msaddr addr;
	uint8_t bdg_port;
	uint8_t bdg_dstport;
};

static void
ms_rt2str(const struct ms_route *mrt, char *dst)
{
	char tmp[64];
	ms_addr_sprintf(tmp, &mrt->addr.sa);
	sprintf(dst, "bdg_port %u->%u %s:%u %u",
		mrt->bdg_port, mrt->bdg_dstport, tmp,
		ntohs(mrt->addr.sin.sin_port), mrt->addr.protocol);
}

/* useful pointers to manipulate 3-tuple */
struct ms_ptrs {
	uint32_t *addr;
	uint16_t *port;
	uint8_t *proto;
	uint8_t addrlen;
	uint8_t hashoff;
};

static __inline int
ms_addr_equal(struct ms_route *m, struct ms_ptrs *p)
{
	return !memcmp(p->addr, &m->addr.sin.sin_addr, p->addrlen) &&
		*p->proto == m->addr.protocol &&
		*p->port == m->addr.sin.sin_port;
}

struct ms_portinfo {
	uint32_t flags;
};

static struct ms_global {
	MS_ROUTE_LIST routelist[MS_ROUTEHASHSIZ];
	struct ms_portinfo portinfo[NM_BDG_MAXPORTS];
	MS_RWLOCK_T	lock;
	int num_routes;
} ms_global;

/* writer-lock must be owned */
static void
ms_route_free(struct ms_route *mrt)
{
	char buf[64];
	ms_rt2str(mrt, buf);
	D("freeing entry %s", buf);

	MS_LIST_DEL(mrt, next);
	free(mrt, M_DEVBUF);
	--ms_global.num_routes;
}

/* taken from netmap implementation */
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

static inline uint32_t
ms_rthash(struct ms_ptrs *ptrs)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	b += *ptrs->proto;
	p = (uint8_t *)ptrs->port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (uint8_t *)ptrs->addr + ptrs->hashoff;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	mix(a, b, c);
#define MS_ROUTE_RTHASH_MASK	(MS_ROUTEHASHSIZ-1)
	return (c & MS_ROUTE_RTHASH_MASK);
}
#undef mix

#ifndef MULTISTACK_NOIPV4CSUM
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
#endif /* MULTISTACK_IPV4CSUM */

static struct ms_route *
ms_route_pkt(uint8_t *buf, uint8_t **hint, int input)
{
	struct ms_route *mrt;
	MS_ROUTE_LIST *head;
	uint16_t et;
	struct ms_ptrs ptrs;

	et = ntohs(*((uint16_t *)(buf + ETHER_ADDR_LEN * 2)));
	if (et == ETHERTYPE_IP) {
		struct ip *iph = (struct ip *)(buf + ETHER_HDR_LEN);
#ifndef MULTISTACK_NOIPV4CSUM
		uint16_t sum;

		sum = iph->ip_sum;
		iph->ip_sum = 0;
		if (unlikely(sum !=
		    (0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(*iph))))) {
			iph->ip_sum = sum;
			goto error;
		}
		iph->ip_sum = sum;
#endif /* MULTISTACK_IPV4CSUM */
		ptrs.proto = (uint8_t *)&iph->ip_p;
		if (input) {
			ptrs.addr = (uint32_t *)&iph->ip_dst;
			ptrs.port = (uint16_t *)((uint8_t *)iph
				       	+ (iph->ip_hl<<2)) + 1;
		} else {
			ptrs.addr = (uint32_t *)&iph->ip_src;
			ptrs.port = (uint16_t *) ((uint8_t *)iph + 
					(iph->ip_hl<<2));
		}
		ptrs.addrlen = 4;
		ptrs.hashoff = 0;
	} else if (et == ETHERTYPE_IPV6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(buf + ETHER_HDR_LEN);

		ptrs.proto = (uint8_t *)&ip6->ip6_nxt;
		if (input) {
			ptrs.addr = (uint32_t *)&ip6->ip6_dst;
			ptrs.port = (uint16_t *)(&ip6 + 1) + 1;
		} else {
			ptrs.addr = (uint32_t *)&ip6->ip6_src;
			ptrs.port = (uint16_t *)(&ip6 + 1);
		}
		ptrs.addrlen = 16;
		ptrs.hashoff = 3;
	} else
		goto error;

	MS_RLOCK();

	/* the least significant 4 bytes for IPv6 */
	head = &ms_global.routelist[ms_rthash(&ptrs)];
	MS_LIST_FOREACH(mrt, head, next) {
		if (ms_addr_equal(mrt, &ptrs)) {
			MS_RUNLOCK();
			*hint = (uint8_t *)
				(input ? (ptrs.port-1) : (ptrs.port+1));
			return mrt;
		}
	}
	MS_RUNLOCK();
error:
	return NULL;
}

#ifdef MULTITACK_MBOXFILTER
static uint8_t
ms_route_pkt2(uint8_t *buf, uint8_t **hint)
{
	uint16_t et = ntohs(*((uint16_t *)(buf + ETHER_ADDR_LEN * 2)));

	if (et == ETHERTYPE_IP) {
		struct ip *iph = (struct ip *)(buf + ETHER_HDR_LEN);
		uint16_t sport, dport, *p, *tbl = NULL;
#ifndef MULTISTACK_NOIPV4CSUM
		uint16_t sum;

		sum = iph->ip_sum;
		iph->ip_sum = 0;
		if (unlikely(sum !=
		    (0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(*iph))))) {
			iph->ip_sum = sum;
			return NM_BDG_NOPORT;
		}
		iph->ip_sum = sum;
#endif /* MULTISTACK_IPV4CSUM */
		if (iph->ip_p == IPPROTO_UDP)
			tbl = udp_tbl;
		else if (iph->ip_p == IPPROTO_TCP)
			tbl = tcp_tbl;
		else
			return NM_BDG_NOPORT;

		p = (uint16_t *)((uint8_t *)iph + (iph->ip_hl<<2));
		sport = ntohs(*p++);
		dport = ntohs(*p);

		if (tbl[dport] < NM_BDG_MAXPORTS)
			/* XXX go to default middlebox? */
			return tbl[dport];
		else if (tbl[sport] < NM_BDG_MAXPORTS)
			return tbl[sport];
	}
	return NM_BDG_NOPORT;
}
#endif /* MULTITACK_MBOXFILTER */

/* Lookup function to be registered */
static u_int
#ifdef NETMAP_API_4
ms_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr, const struct netmap_adapter *na)
#else
ms_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
	const struct netmap_vp_adapter *na)
#endif
{
	struct ms_route *mrt;
	uint8_t *hint;
	int input;
	char tmp[256];

#ifdef MULTITACK_MBOXFILTER
	if (ms_global.portinfo[na->bdg_port].flags & MS_F_STACK) {
		return NM_BDG_NOPORT; /* XXX */
	} else {
		*ring_nr = 0;
		return ms_route_pkt2(ft->ft_buf, &hint);
	}
#endif /* MULTITACK_MBOXFILTER */
       	
	/* XXX treat packets from an unrecognized port as input */
	ms_pkt2str(ft->ft_buf, tmp);
	input = ms_global.portinfo[na->bdg_port].flags & MS_F_STACK ? 0 : 1;

	mrt = ms_route_pkt(ft->ft_buf, &hint, input);
	if (mrt == NULL)
       		/* XXX just for testing. Actually this packet
		 * should go to the host stack
		 */
		return NM_BDG_NOPORT;
	/* The least significant byte of the opposite port */
	*ring_nr = ntohs(*hint) & 0xF;
	return input ? mrt->bdg_port : mrt->bdg_dstport;
}

/* Callback on destruction of the bridge port (incl. process dies) */
static void
#ifdef NETMAP_API_4
ms_dtor(u_int bdg, u_int port)
#else
ms_dtor(const struct netmap_vp_adapter *vpna)
#endif
{
	struct ms_route *mrt, *tmp;
	MS_ROUTE_LIST *head;
	int i;
#ifndef NETMAP_API_4
	u_int port = vpna->bdg_port;
#endif
#ifdef linux
	(void)tmp;
#endif

	MS_WLOCK();
	/* XXX should be optimized */
	for (i = 0; i < MS_ROUTEHASHSIZ; i++) {
		head = &ms_global.routelist[i];
		MS_LIST_FOREACH_SAFE(mrt, head, next, tmp) {
			if (mrt->bdg_port == port)
				ms_route_free(mrt);
		}
	}
	bzero(&ms_global.portinfo[port], sizeof(struct ms_portinfo));
	MS_WUNLOCK();
}

#ifdef __FreeBSD__
int
ms_getifname(struct sockaddr *sa, char *ifname)
{
	struct ifnet *ifn;
	struct ifaddr *ifa;
	int retval = 0;

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
			retval = 1;
			strncpy(ifname, ifn->if_xname, IFNAMSIZ);
		}
		IF_ADDR_RUNLOCK(ifn);
		if (retval)
			break;
	}
	IFNET_RUNLOCK();
	return retval;
}

int
ms_pcb_clash(struct sockaddr *sa, uint8_t protocol)
{
	uint8_t proto;
	struct inpcb *inp;
	int error;
	struct in_addr faddr = {INADDR_ANY};
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	u_short fport = 0;
	char buf[64]; /* just for debug */
#ifdef INET6
	struct in6_addr faddr6 = IN6ADDR_ANY_INIT;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	if (sa->sa_family == AF_INET6) {
		proto = inet6sw[ip6_protox[protocol]].pr_protocol;
		ip6_sprintf(buf, &sin6->sin6_addr);
	} else
#endif /* INET6 */
	{
		proto = inetsw[ip_protox[protocol]].pr_protocol;
		ip_sprintf(buf, &sin->sin_addr);
	}

	if (proto != protocol) /* not registered in protosw */
		return 0;

	if (proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
		struct inpcbinfo *ipi;

		ipi = proto == IPPROTO_UDP ? &V_udbinfo : &V_tcbinfo;
		INP_INFO_RLOCK(ipi);
#ifdef INET6
		if (sa->sa_family == AF_INET6)
			inp = in6_pcblookup(ipi, &faddr6, fport,
				&sin6->sin6_addr, sin6->sin6_port,
				INPLOOKUP_WILDCARD|INPLOOKUP_RLOCKPCB, NULL);
		else
#endif /* INET6 */
		inp = in_pcblookup(ipi, faddr, fport,
				sin->sin_addr, sin->sin_port,
				INPLOOKUP_WILDCARD|INPLOOKUP_RLOCKPCB, NULL);
		if (!inp || inp->inp_socket == NULL) {
			D("%s:%u is not bound", buf, ntohs(sin->sin_port));
			error = ENOENT;/* I haven't bind this address */
		} else {
			error = cr_canseeinpcb(curthread->td_ucred, inp);
			if (error) {
				/* I'm not the one bind() before */
				D("%s:%u is not mine", buf, ntohs(sin->sin_port));
			}
		}
		if (inp)
			INP_RUNLOCK(inp);
		INP_INFO_RUNLOCK(ipi);
	}
#ifdef SCTP
	else if (proto == IPPROTO_SCTP) {
		struct sctp_inpcb *sinp;

		/* XXX not sure how we should do on find_tcp_pool and vrf_id */
		sinp = sctp_pcb_findep(sa, 1, 0, SCTP_DEFAULT_VRFID);
		if (!sinp) {
			D("%s:%u is not bound", buf, ntohs(sin->sin_port));
			error = ENOENT;
		}
		inp = &sinp->ip_inp.inp;
		if (inp->inp_socket == NULL) {
			D("%s:%u is not bound", buf, ntohs(sin->sin_port));
			error = ENOENT;
		} else {
			error = cr_canseeinpcb(curthread->td_ucred, inp);
			if (error) {
				D("%s:%u is not mine", buf, ntohs(sin->sin_port));
			}
		}
		if (sinp)
			SCTP_INP_DECR_REF(sinp);
	}
#endif /* SCTP */
	else /* we don't know how to check, take conservative.. */
		error = ENOENT;
	return error;
}
#endif /* __FreeBSD__ */

static int
ms_config(struct nm_ifreq *data)
{
	struct msreq *msr = (struct msreq *)data;
	struct nmreq nmr;
	struct ms_route *mrt = NULL, *tmp;
	struct ms_ptrs ptrs;
	MS_ROUTE_LIST	*head;
	int error = 0, me;
	char addrbuf[64]; /* just for debug message */

	if (msr->mr_cmd != MULTISTACK_BIND && msr->mr_cmd != MULTISTACK_UNBIND)
		return EINVAL;

	/* the process must have a credential, bind()ing beforehand */
	if (ms_pcb_clash(&msr->mr_sa, msr->mr_proto))
		return ENOENT;

	/* Get my index of bridge and port */
	bzero(&nmr, sizeof(nmr));
	nmr.nr_cmd = NETMAP_BDG_LIST;
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, msr->mr_name, sizeof(nmr.nr_name));
	error = netmap_bdg_ctl(&nmr, NULL);
	if (error) { /* invalid request of interface or bridge */
		D("%s is not in the bridge", nmr.nr_name);
		return error;
	}
	me = nmr.nr_arg2;

	/* get pointers to parameters */
	ptrs.proto = &msr->mr_proto;
	if (msr->mr_sa.sa_family == AF_INET) {
		ptrs.addr = (uint32_t *)&msr->mr_sin.sin_addr.s_addr;
		ptrs.port = &msr->mr_sin.sin_port;
		ptrs.addrlen = 4;
		ptrs.hashoff = 0;
	} else if (msr->mr_sa.sa_family == AF_INET6) {
		ptrs.addr = (uint32_t *)&msr->mr_sin6.sin6_addr;
		ptrs.port = &msr->mr_sin6.sin6_port;
		ptrs.addrlen = 16;
		ptrs.hashoff = 3; /* use least significant 4 byte */
	} else
		return EINVAL;

	MS_WLOCK();

	/* Find an existing entry */
	head = &ms_global.routelist[ms_rthash(&ptrs)];
	/* Linux terminate the end of the list with head, while
	 * FreeBSD does so with NULL
	 */
	MS_LIST_FOREACH(tmp, head, next) {
		if (ms_addr_equal(tmp, &ptrs)) {
			mrt = tmp;
			break;
		}
	}
	if (msr->mr_cmd == MULTISTACK_UNBIND) {
		if (!mrt) {
			D("UNBIND: not registered");
			error = ENOENT;
			goto out_unlock;
		}
		ms_route_free(mrt);
	} else { /* MULTITACK_BIND */
		char name[IFNAMSIZ];

		if (mrt) {
			D("BIND: already registered");
			error = EBUSY;
			goto out_unlock;
		}
		/* check the local address is valid */
		ms_addr_sprintf(addrbuf, &msr->mr_sa);
		if (!ms_getifname(&msr->mr_sa, name)) {
			D("%s doesn't exist", addrbuf);
			return EINVAL;
		} else
			D("%s is at %s", addrbuf, name);

		/* Is the interface for this address already in the bridge? */
		bzero(&nmr, sizeof(nmr));
		nmr.nr_cmd = NETMAP_BDG_LIST;
		nmr.nr_version = NETMAP_API;
		strcpy(nmr.nr_name, MS_NAME);
		strcat(nmr.nr_name, name);
		error = netmap_bdg_ctl(&nmr, NULL);
		if (error) {
			D("%s is not in the bridge", nmr.nr_name);
			goto out_unlock;
		}

		mrt = (struct ms_route *)malloc(sizeof(*mrt), M_DEVBUF,
			M_NOWAIT|M_ZERO);
		if (!mrt) {
			error = ENOMEM;
			goto out_unlock;
		}
		mrt->addr = msr->mr_ifru.mr_addr;
		mrt->bdg_port = me;
		mrt->bdg_dstport = nmr.nr_arg2;
		MS_LIST_ADD(head, mrt, next);
		ms_global.portinfo[me].flags |= MS_F_STACK;
		++ms_global.num_routes;

		ms_rt2str(mrt, addrbuf);
		D("%s has been registered", addrbuf);
	}
out_unlock:
	MS_WUNLOCK();
	return (error);
}
static struct netmap_bdg_ops ms_ops = {ms_lookup, ms_config, ms_dtor};

#ifdef MULTITACK_MBOXFILTER
static void
init_tables(void)
{
	int i;
	bzero(udp_tbl, sizeof(udp_tbl));
	bzero(tcp_tbl, sizeof(tcp_tbl));
	for (i = 0; i < NM_BDG_MAXPORTS; i++)
		udp_tbl[i] = tcp_tbl[i] = i;
}
#endif /* MULTITACK_MBOXFILTER */

/* we assume a bridge with MS_NAME is already created */
int
ms_init(void)
{
	struct nmreq nmr;
	int i;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, MS_NAME, strlen(MS_NAME));
	nmr.nr_cmd = NETMAP_BDG_REGOPS;
	if (netmap_bdg_ctl(&nmr, &ms_ops)) {
		D("no bridge named %s", nmr.nr_name);
		return ENOENT;
	}

	bzero(&ms_global, sizeof(ms_global));
	MS_RWINIT(&ms_global.lock, "multistack lock");
	for (i = 0; i < MS_ROUTEHASHSIZ; i++)
		MS_LIST_INIT(&ms_global.routelist[i]);

#ifdef MULTITACK_MBOXFILTER
	init_tables();
#endif /* MULTITACK_MBOXFILTER */
	printf("MultiStack: loaded module\n");
	return 0;
}

void
ms_fini(void)
{
	struct nmreq nmr;
	int error;
	struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, MS_NAME, sizeof(nmr.nr_name));
	nmr.nr_cmd = NETMAP_BDG_REGOPS;
	error = netmap_bdg_ctl(&nmr, &tmp);
	if (error)
		D("failed to release VALE bridge %d", error);
	printf("MultiStack: Unloaded module\n");
}

#ifdef __FreeBSD__
static int
ms_loader(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = ms_init();
		break;
	case MOD_UNLOAD:
		ms_fini();
		break;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

DEV_MODULE(multistack, ms_loader, NULL);
#endif /* __FreeBSD__ */
