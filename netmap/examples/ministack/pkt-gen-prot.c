/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
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

/*
 * $FreeBSD: head/tools/tools/netmap/pkt-gen.c 227614 2011-11-17 12:17:39Z luigi $
 * $Id: pkt-gen.c 10639 2012-02-24 16:40:10Z luigi $
 *
 * Example program to show how to build a multithreaded packet
 * source/sink using the netmap device.
 *
 * In this example we create a programmable number of threads
 * to take care of all the queues of the interface used to
 * send or receive traffic.
 *
 */

const char *default_payload="netmap pkt-gen Luigi Rizzo and Matteo Landi\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

#include "nm_util.h"
#include "tcplib.h"
#include "dttcp.h"
#include <sys/queue.h>
#if defined(__linux__)
#define	STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = STAILQ_FIRST((head));				\
	    (var) && ((tvar) = ((var)->field.stqe_next), 1);		\
	    (var) = (tvar))
#endif /* linux */

int verbose = 0;
#define MAX_QUEUES 64	/* no need to limit */

#define SKIP_PAYLOAD 1 /* do not check payload. */
#define DEFAULT_CONN_LEN 16

struct pkt {
	struct ether_header eh;
	struct ip ip;
	struct udphdr udp;
	uint8_t body[0];
} __attribute__((__packed__));

struct ip_range {
	char *name;
	struct in_addr start, end;
};

struct mac_range {
	char *name;
	struct ether_addr start, end;
};

struct rpkt {
	uint8_t body[0];
} __attribute__((__packed__));

#define PKT_CMD_ALL 0x00000001
#define PKT_CMD_PRE 0x00000002
#define PKT_CMD_NOTCPCSUM 0x0000020
static inline int
PKT_CMD_VALID(uint32_t cmd) {
	if (!cmd)
		return 1;
	if (!(cmd & (PKT_CMD_ALL | PKT_CMD_PRE)))
		return 0;
	return 1;
}


#ifdef COPYTEST
struct netmap_vring { /* for modifying const variables */
	/*
	 * nr_buf_base_ofs is meant to be used through macros.
	 * It contains the offset of the buffer region from this
	 * descriptor.
	 */
	ssize_t		buf_ofs;
	uint32_t	num_slots;	/* number of slots in the ring. */
	uint32_t	avail;		/* number of usable slots */
	uint32_t        cur;		/* 'current' r/w position */
	uint32_t	reserved;	/* not refilled before current */

	uint16_t	nr_buf_size;
	uint16_t	flags;
#define	NR_TIMESTAMP	0x0002		/* set timestamp on *sync() */

	struct timeval	ts;		/* time of last *sync() */

	/* the slots follow. This struct has variable size */
	struct netmap_slot slot[0];	/* array of slots. */
};
#define NETMAP_BUF_SIZE 2048
static struct netmap_ring *
create_pseudo_ring(int num_slots)
{
	struct netmap_vring *ring;
	int size, i;

	size = sizeof(*ring) +
		(sizeof(struct netmap_slot) + NETMAP_BUF_SIZE) * num_slots;
	ring = calloc(1, size);
	if (ring == NULL) {
		D("failed to create virtual ring");
		return NULL;
	}
	ring->nr_buf_size = NETMAP_BUF_SIZE;
	ring->buf_ofs = size - NETMAP_BUF_SIZE * num_slots;
	for (i = 0; i < num_slots; i++)
		ring->slot[i].buf_idx = i;
	ring->num_slots = num_slots;
	ring->cur = 0;
	ring->avail = num_slots;
	D("created virtual ring for %d slots", num_slots);
	return (struct netmap_ring *)ring;
}
#endif /* COPYTEST */

/*
 * global arguments for all threads
 */
struct glob_arg {
	struct ip_range src_ip;
	struct ip_range dst_ip;
	struct mac_range dst_mac;
	struct mac_range src_mac;
	int pkt_size;
	int burst;
	int npackets;	/* total packets to send */
	int nthreads;
	int cpus;
	int options;	/* testing */
#define OPT_PREFETCH	1
#define OPT_ACCESS	2
#define OPT_COPY	4
#define OPT_MEMCPY	8
#define OPT_TS		16	/* add a timestamp */
	int use_pcap;
	pcap_t *p;
	/* Extended for uProt experiment */
	int mstack;
	uint32_t ifaflags;
	uint32_t pkt_cmd;
	uint32_t pkt_options;
	int n_pktbufs;
	int nproto;
	int tproto;
	uint16_t sport;
	uint16_t dport;
	char *hwifname;
	uint16_t bdg_num_rings;
	int dport_interval;
	int dport_tinterval;
	int sport_interval;
	int sport_tinterval;
	int n_tcpconn;
	u_int conn_len;
	uint8_t tcpflags;
	int http_timer_type;
#ifdef COPYTEST
	int slot_lim;
	int vring;
#endif
};

struct mystat {
	uint64_t containers[8];
};

/*
 * Arguments for a new thread. The same structure is used by
 * the source and the sink
 */
STAILQ_HEAD(tcblisthead, prot_cb);
struct targ {
	struct glob_arg *g;
	int used;
	int completed;
	int fd;
	struct nmreq nmr;
	struct netmap_if *nifp;
	uint16_t	qfirst, qlast; /* range of queues to scan */
	uint64_t count;
	struct timeval tic, toc;
	int me;
	int n_pktbufs;
	int pkt_size;
	pthread_t thread;
	int affinity;

	struct pkt **pkts;
	/* Extended by micchie */
	struct tcblisthead tcbhead;
	struct prot_cb *lcb;
	struct prot_cb *ncb;
	struct prot_cb *tcb;
	char *payload;
	int paylen;
	int snd_nxt; /* for pkts */
	int (*make_pkt_func)(char *, size_t, struct prot_cb *,
	    struct prot_cb *, struct prot_cb *, const char *, int, uint32_t);
#define DEFAULT_UDATASIZ 512
#ifdef COPYTEST
	struct netmap_ring *vring_p;
#endif
};

/*
 * extract the extremes from a range of ipv4 addresses.
 * currently only takes the first 4 bytes
 */
static void
extract_ip_range(struct ip_range *r)
{
//	D("extract IP range from %s", r->name);
	inet_aton(r->name, &r->start);
	inet_aton(r->name, &r->end);
#if 0
	p = index(targ->g->src_ip, '-');
	if (p) {
		targ->dst_ip_range = atoi(p+1);
		D("dst-ip sweep %d addresses", targ->dst_ip_range);
	}
#endif
//	D("%s starts at %s", r->name, inet_ntoa(r->start));
}

static void
extract_mac_range(struct mac_range *r)
{
//	D("extract MAC range from %s", r->name);
	bcopy(ether_aton(r->name), &r->start, 6);
	bcopy(ether_aton(r->name), &r->end, 6);
#if 0
	bcopy(targ->src_mac, eh->ether_shost, 6);
	p = index(targ->g->src_mac, '-');
	if (p)
		targ->src_mac_range = atoi(p+1);

	bcopy(ether_aton(targ->g->dst_mac), targ->dst_mac, 6);
	bcopy(targ->dst_mac, eh->ether_dhost, 6);
	p = index(targ->g->dst_mac, '-');
	if (p)
		targ->dst_mac_range = atoi(p+1);
#endif
//	D("%s starts at %s", r->name, ether_ntoa(&r->start));
}

static struct targ *targs;
static int global_nthreads;

//#define PKT_COPY(d, s, l)  (l%64 ? memcpy(d, s, l) : pkt_copy(s, d, l))
#define PKT_COPY(d, s, l) pkt_copy(s, d, l)
//#define PKT_COPY(d, s, l) memcpy(d, s, l)

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	for (i = 0; i < global_nthreads; i++) {
		/* cancel active threads. */
		if (targs[i].used == 0)
			continue;

		D("Cancelling thread #%d\n", i);
		pthread_cancel(targs[i].thread);
		targs[i].used = 0;
	}

	signal(SIGINT, SIG_DFL);
}

/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
#ifdef __FreeBSD__
	int mib[2], ncpus;
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;
	len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);

	return (ncpus);
#else
	return 1;
#endif /* !__FreeBSD__ */
}

/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
#ifdef __linux__
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#endif /* linux */
static int
source_hwaddr(const char *ifname, char *buf)
{
	struct ifaddrs *ifaphead, *ifap;
	int l = sizeof(ifap->ifa_name);

	if (getifaddrs(&ifaphead) != 0) {
		D("getifaddrs %s failed", ifname);
		return (-1);
	}

	for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
		struct sockaddr_dl *sdl =
			(struct sockaddr_dl *)ifap->ifa_addr;
		uint8_t *mac;

		if (!sdl || sdl->sdl_family != AF_LINK)
			continue;
		if (strncmp(ifap->ifa_name, ifname, l) != 0)
			continue;
		mac = (uint8_t *)LLADDR(sdl);
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
		if (verbose)
			D("source hwaddr %s", buf);
		break;
	}
	freeifaddrs(ifaphead);
	return ifap ? 0 : 1;
}

/* set the thread affinity. */
static int
setaffinity(pthread_t me, int i)
{
#ifdef __FreeBSD__
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity");
		return 1;
	}
#else
	(void)me; /* suppress 'unused' warnings */
	(void)i;
#endif /* FreeBSD */
	return 0;
}


static uint16_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return (sum);
}

static u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

#ifdef MSTACK
/* We assume nma->nar_ifname is already set */
static inline void
config_mstack_args(struct glob_arg *g, struct nmaddrreq *nma)
{
	if (g->nproto == AF_INET) {
		nma->nar_laddr.sin.sin_family = AF_INET;
		nma->nar_laddr.sin.sin_port = htons(g->sport);
		inet_pton(AF_INET, g->src_ip.name,
				&nma->nar_laddr.sin.sin_addr);
		nma->nar_raddr.sin.sin_family = AF_INET;
		nma->nar_raddr.sin.sin_port = htons(g->dport);
		inet_pton(AF_INET, g->dst_ip.name,
				&nma->nar_raddr.sin.sin_addr);
	} else if (g->nproto == AF_INET6) {
		nma->nar_laddr.sin6.sin6_family = AF_INET6;
		nma->nar_laddr.sin6.sin6_port = htons(g->sport);
		inet_pton(AF_INET6, g->src_ip.name, &nma->nar_laddr.sin6.sin6_addr);
		nma->nar_raddr.sin6.sin6_family = AF_INET6;
		nma->nar_raddr.sin6.sin6_port = htons(g->dport);
		inet_pton(AF_INET6, g->dst_ip.name,
				&nma->nar_raddr.sin6.sin6_addr);
	}
	nma->nar_protocol = (uint8_t)g->tproto;
	nma->nar_flags = g->ifaflags;
	nma->nar_dst_ringid = 0; /* XXX needed ? */
	strcpy(nma->nar_hwifname, g->hwifname);
}
#endif

static void
set_pcbs_thread(struct targ *targ, struct prot_cb *lcb, struct prot_cb *ncb,
		struct prot_cb *tcb)
{
	targ->lcb = lcb;
	targ->ncb = ncb;
	targ->tcb = tcb;
	if (lcb->prot == AF_INET) {
		if (ncb->prot == IPPROTO_UDP)
			targ->make_pkt_func = make_udp4_dgram;
		else if (ncb->prot == IPPROTO_TCP)
			targ->make_pkt_func = make_tcp4_segment;
	} else if (lcb->prot == AF_INET6) {
		if (ncb->prot == IPPROTO_UDP)
			targ->make_pkt_func = make_udp6_dgram;
		else if (ncb->prot == IPPROTO_TCP)
			targ->make_pkt_func = make_tcp6_segment;
	}
}

static int
reinitialize_packets(struct targ *targ)
{
	int i;

	for (i = 0; i < targ->n_pktbufs; i++)
		if (unlikely(targ->make_pkt_func((char *)targ->pkts[i],
					targ->g->pkt_size, targ->lcb, targ->ncb,
					targ->tcb, targ->payload, targ->paylen,
					targ->g->pkt_options)))
			return -1;
	D("reinitialized %d packets", i);
	return 0;
}

/*
 * Fill a packet with some payload.
 */
#if defined(__linux__)
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif /* linux */
static int
initialize_packets(struct targ *targ)
{
	struct pkt *pkt;
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	uint16_t paylen = targ->g->pkt_size - sizeof(*eh) - sizeof(*ip);
	int i, j, l, l0 = strlen(default_payload);

	targ->pkts = calloc(targ->n_pktbufs, sizeof(struct pkt *));
	if (targ->pkts == NULL)
		return ENOMEM;
	for (i = 0; i < targ->n_pktbufs; i++) {
		targ->pkts[i] = calloc(targ->pkt_size, 1);
		if (targ->pkts[i] == NULL)
			goto free_pkts;
	}

	if (targ->g->pkt_cmd) {
		/* In a single packet buffer case we use a fastpath in
		 * send_packets_x()
		 */
		if (targ->n_pktbufs > 1 || targ->g->pkt_cmd & PKT_CMD_PRE)
			reinitialize_packets(targ);
		return 0;
	}

	for (i = 0; i < targ->n_pktbufs; i++) {
		pkt = targ->pkts[i];

		for (j = 0; j < paylen;) {
			l = min(l0, paylen - j);
			bcopy(default_payload, pkt->body + j, l);
			j += l;
		}
		pkt->body[j-1] = '\0';
		ip = &pkt->ip;

		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		ip->ip_id = 0;
		ip->ip_tos = IPTOS_LOWDELAY;
		ip->ip_len = ntohs(targ->g->pkt_size - sizeof(*eh));
		ip->ip_id = 0;
		ip->ip_off = htons(IP_DF); /* Don't fragment */
		ip->ip_ttl = IPDEFTTL;
		ip->ip_p = IPPROTO_UDP;
		ip->ip_dst.s_addr = targ->g->dst_ip.start.s_addr;
		ip->ip_src.s_addr = targ->g->src_ip.start.s_addr;
		ip->ip_sum = 0;
		ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));

		udp = &pkt->udp;
		udp->uh_sport = htons(4096);
		udp->uh_dport = htons(8192);
		udp->uh_ulen = htons(paylen);
		udp->uh_sum = 0;
		/* Magic: taken from sbin/dhclient/packet.c */
		udp->uh_sum = wrapsum(checksum(udp, sizeof(*udp),
		    checksum(pkt->body,
			targ->g->pkt_size - sizeof(*eh) - sizeof(*ip) - sizeof(*udp),
			checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
			    IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
			)
		    )
		));

		eh = &pkt->eh;
		bcopy(&targ->g->src_mac.start, eh->ether_shost, 6);
		bcopy(&targ->g->dst_mac.start, eh->ether_dhost, 6);
		eh->ether_type = htons(ETHERTYPE_IP);
	}

	return 0;
free_pkts:
	for (i = 0; i < targ->n_pktbufs; i++) {
		if (targ->pkts[i] == NULL)
			break;
		else
			free(targ->pkts[i]);
	}
	free(targ->pkts);
	return -1;
}


/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
static void
check_payload(char *p, int psize)
{
	char temp[64];
	int n_read, size, sizelen;

	/* get the length in ASCII of the length of the packet. */
	sizelen = sprintf(temp, "%d", psize) + 1; // include a whitespace

	/* dummy payload. */
	p += 14; /* skip packet header. */
	n_read = 14;
	while (psize - n_read >= sizelen) {
		sscanf(p, "%d", &size);
		if (size != psize) {
			D("Read %d instead of %d", size, psize);
			break;
		}

		p += sizelen;
		n_read += sizelen;
	}
}


/*
 * create and enqueue a batch of packets on a ring.
 * On the last one set NS_REPORT to tell the driver to generate
 * an interrupt when done.
 */
static int
send_packets(struct netmap_ring *ring, struct pkt *pkt,
		int size, u_int count, int options)
{
	u_int sent, cur = ring->cur;

	if (ring->avail < count)
		count = ring->avail;

	for (sent = 0; sent < count; sent++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

		if (options & OPT_COPY)
			pkt_copy(pkt, p, size);
		else if (options & OPT_MEMCPY)
			memcpy(p, pkt, size);
		else if (options & OPT_PREFETCH)
			prefetch(p);
		slot->len = size;
		if (sent == count - 1)
			slot->flags |= NS_REPORT;
		cur = NETMAP_RING_NEXT(ring, cur);
	}
	ring->avail -= sent;
	ring->cur = cur;

	return (sent);
}

#ifdef COPYTEST
/* lim must be guaranteed to be less than the number of slots */
#define NETMAP_RING_NEXT_LIM(lim, i)                          \
	        ((i)+1 == lim ? 0 : (i) + 1 )
#endif
static int
send_packets_x(struct netmap_ring *ring, u_int count, struct targ *t)
{
	u_int sent = 0, cur = ring->cur;
	char *b;
	struct netmap_slot *slot;
	char *p;
	uint32_t cmd = t->g->pkt_cmd;
#ifdef MPORTS
	int cnt = 0;
#endif
#ifdef COPYTEST
	if (t->vring_p)
		ring = t->vring_p;
#endif

	if (ring->avail < count)
		count = ring->avail;

	if (t->n_pktbufs > 1) {
		for (; sent < count; sent++) {
			slot = &ring->slot[cur];
			p = NETMAP_BUF(ring, slot->buf_idx);
			PKT_COPY(p, t->pkts[t->snd_nxt], t->g->pkt_size);
			if (++t->snd_nxt == t->n_pktbufs)
				t->snd_nxt = 0;
			slot->len = t->g->pkt_size;
			if (sent == count - 1)
				slot->flags |= NS_REPORT;
#ifdef COPYTEST
			cur = NETMAP_RING_NEXT_LIM(t->g->slot_lim, cur);
#else
			cur = NETMAP_RING_NEXT(ring, cur);
#endif
			if (t->g->pkt_cmd & PKT_CMD_ALL && t->snd_nxt == 0) {
				slot->flags |= NS_REPORT;
				break;
			}
		}
	} else if (cmd & PKT_CMD_PRE && t->n_pktbufs == 1) {
		for (; sent < count; sent++) {
			slot = &ring->slot[cur];
			p = NETMAP_BUF(ring, slot->buf_idx);
			PKT_COPY(p, t->pkts[0], t->g->pkt_size);
			slot->len = t->g->pkt_size;
			if (sent == count - 1)
				slot->flags |= NS_REPORT;
#ifdef COPYTEST
			cur = NETMAP_RING_NEXT_LIM(t->g->slot_lim, cur);
#else
			cur = NETMAP_RING_NEXT(ring, cur);
#endif
		}
	} else if (t->n_pktbufs <= 1) {
		for (; sent < count; sent++) {
			slot = &ring->slot[cur];
			p = NETMAP_BUF(ring, slot->buf_idx);
			if (!t->n_pktbufs)
				b = p;
			else
				b = (char *)t->pkts[0];
			t->make_pkt_func(b, t->g->pkt_size, t->lcb, t->ncb,
					t->tcb, t->payload, t->paylen,
					t->g->pkt_options);
#ifdef MPORTS
			if (++cnt == t->g->conn_len) {
				t->tcb = STAILQ_NEXT(t->tcb, next);
				if (!t->tcb)
					t->tcb = STAILQ_FIRST(&t->tcbhead);
				cnt = 0;
			}
#endif
			if (t->n_pktbufs)
				PKT_COPY(p, b, t->g->pkt_size);
			slot->len = t->g->pkt_size;
			if (sent == count - 1)
				slot->flags |= NS_REPORT;
#ifdef COPYTEST
			cur = NETMAP_RING_NEXT_LIM(t->g->slot_lim, cur);
#else
			cur = NETMAP_RING_NEXT(ring, cur);
#endif
		}
	}
#ifndef COPYTEST
	ring->avail -= sent;
	ring->cur = cur;
#endif /* COPYTEST */

	return (sent);
}
#undef NETMAP_RING_NEXT_X

/*
 * Send a packet, and wait for a response.
 * The payload (after UDP header, ofs 42) has a 4-byte sequence
 * followed by a struct timeval (or bintime?)
 */
#define	PAY_OFS	42	/* where in the pkt... */

static void *
pinger_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd fds[1];
	struct netmap_if *nifp = targ->nifp;
	int i, rx = 0, n = targ->g->npackets;

	fds[0].fd = targ->fd;
	fds[0].events = (POLLIN);
	static uint32_t sent;
	struct timespec ts, now, last_print;
	uint32_t count = 0, min = 1000000, av = 0;

	if (targ->g->nthreads > 1) {
		D("can only ping with 1 thread");
		return NULL;
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &last_print);
	while (n == 0 || (int)sent < n) {
		struct netmap_ring *ring = NETMAP_TXRING(nifp, 0);
		struct netmap_slot *slot;
		char *p;
	    for (i = 0; i < 1; i++) {
		slot = &ring->slot[ring->cur];
		slot->len = targ->g->pkt_size;
		p = NETMAP_BUF(ring, slot->buf_idx);

		if (ring->avail == 0) {
			D("-- ouch, cannot send");
		} else {
			pkt_copy(&targ->pkts[0], p, targ->g->pkt_size);
			clock_gettime(CLOCK_REALTIME_PRECISE, &ts);
			bcopy(&sent, p+42, sizeof(sent));
			bcopy(&ts, p+46, sizeof(ts));
			sent++;
			ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
			ring->avail--;
		}
	    }
		/* should use a parameter to decide how often to send */
		if (poll(fds, 1, 3000) <= 0) {
			D("poll error/timeout on queue %d", targ->me);
			continue;
		}
		/* see what we got back */
		for (i = targ->qfirst; i < targ->qlast; i++) {
			ring = NETMAP_RXRING(nifp, i);
			while (ring->avail > 0) {
				uint32_t seq;
				slot = &ring->slot[ring->cur];
				p = NETMAP_BUF(ring, slot->buf_idx);

				clock_gettime(CLOCK_REALTIME_PRECISE, &now);
				bcopy(p+42, &seq, sizeof(seq));
				bcopy(p+46, &ts, sizeof(ts));
				ts.tv_sec = now.tv_sec - ts.tv_sec;
				ts.tv_nsec = now.tv_nsec - ts.tv_nsec;
				if (ts.tv_nsec < 0) {
					ts.tv_nsec += 1000000000;
					ts.tv_sec--;
				}
				if (0) D("seq %d/%d delta %d.%09d", seq, sent,
					(int)ts.tv_sec, (int)ts.tv_nsec);
				if (ts.tv_nsec < (int)min)
					min = ts.tv_nsec;
				count ++;
				av += ts.tv_nsec;
				ring->avail--;
				ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
				rx++;
			}
		}
		//D("tx %d rx %d", sent, rx);
		//usleep(100000);
		ts.tv_sec = now.tv_sec - last_print.tv_sec;
		ts.tv_nsec = now.tv_nsec - last_print.tv_nsec;
		if (ts.tv_nsec < 0) {
			ts.tv_nsec += 1000000000;
			ts.tv_sec--;
		}
		if (ts.tv_sec >= 1) {
			D("count %d min %d av %d",
				count, min, av/count);
			count = 0;
			av = 0;
			min = 100000000;
			last_print = now;
		}
	}
	return NULL;
}

/*
 * reply to ping requests
 */
static void *
ponger_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd fds[1];
	struct netmap_if *nifp = targ->nifp;
	struct netmap_ring *txring, *rxring;
	int i, rx = 0, sent = 0, n = targ->g->npackets;
	fds[0].fd = targ->fd;
	fds[0].events = (POLLIN);

	if (targ->g->nthreads > 1) {
		D("can only reply ping with 1 thread");
		return NULL;
	}
	D("understood ponger %d but don't know how to do it", n);
	while (n == 0 || sent < n) {
		uint32_t txcur, txavail;
//#define BUSYWAIT
#ifdef BUSYWAIT
		ioctl(fds[0].fd, NIOCRXSYNC, NULL);
#else
		if (poll(fds, 1, 1000) <= 0) {
			D("poll error/timeout on queue %d", targ->me);
			continue;
		}
#endif
		txring = NETMAP_TXRING(nifp, 0);
		txcur = txring->cur;
		txavail = txring->avail;
		/* see what we got back */
		for (i = targ->qfirst; i < targ->qlast; i++) {
			rxring = NETMAP_RXRING(nifp, i);
			while (rxring->avail > 0) {
				uint32_t cur = rxring->cur;
				struct netmap_slot *slot = &rxring->slot[cur];
				char *src, *dst;
				src = NETMAP_BUF(rxring, slot->buf_idx);
				//D("got pkt %p of size %d", src, slot->len);
				rxring->avail--;
				rxring->cur = NETMAP_RING_NEXT(rxring, cur);
				rx++;
				if (txavail == 0)
					continue;
				dst = NETMAP_BUF(txring,
				    txring->slot[txcur].buf_idx);
				/* copy... */
				pkt_copy(src, dst, slot->len);
				txring->slot[txcur].len = slot->len;
				/* XXX swap src dst mac */
				txcur = NETMAP_RING_NEXT(txring, txcur);
				txavail--;
				sent++;
			}
		}
		txring->cur = txcur;
		txring->avail = txavail;
		targ->count = sent;
#ifdef BUSYWAIT
		ioctl(fds[0].fd, NIOCTXSYNC, NULL);
#endif
		//D("tx %d rx %d", sent, rx);
	}
	return NULL;
}

static void *
http_server_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct netmap_if *nifp = targ->nifp;
//	struct netmap_ring *txring, *rxring;
	int i = targ->qfirst, sent = 0;
	struct http_worker_args args;

	if (setaffinity(targ->thread, targ->affinity))
		goto quit;
	/* main loop.*/
	gettimeofday(&targ->tic, NULL);

	memset(&args, 0, sizeof(args));
	args.rxring = NETMAP_RXRING(nifp, i);
	args.txring = NETMAP_TXRING(nifp, i);
	args.filelen = targ->g->conn_len; /* XXX shit hack */
	args.port = ((struct tcp_cb *)targ->tcb)->sport;
	args.fd = targ->fd;
	args.timer_type = targ->g->http_timer_type;
	sent = http_worker_body(&args);

	gettimeofday(&targ->toc, NULL);
	targ->completed = 1;
	targ->count = sent;

	/* reset the ``used`` flag. */
quit:
	targ->used = 0;

	return (NULL);
}

static void *
sender_body(void *data)
{
	struct targ *targ = (struct targ *) data;

	struct pollfd fds[1];
	struct netmap_if *nifp = targ->nifp;
	struct netmap_ring *txring;
	int i, n = targ->g->npackets / targ->g->nthreads, sent = 0;
	int options = targ->g->options | OPT_COPY;

	if (setaffinity(targ->thread, targ->affinity))
		goto quit;
	/* setup poll(2) mechanism. */
	memset(fds, 0, sizeof(fds));
	fds[0].fd = targ->fd;
	fds[0].events = (POLLOUT);

	/* main loop.*/
	gettimeofday(&targ->tic, NULL);
    if (targ->g->use_pcap) {
	int size = targ->g->pkt_size;
	void *pkt = targ->pkts;
	pcap_t *p = targ->g->p;

	for (; sent < n; sent++) {
		if (pcap_inject(p, pkt, size) == -1)
			break;
	}
    } else {
	while (sent < n) {

		/*
		 * wait for available room in the send queue(s)
		 */
#ifndef COPYTEST
		if (poll(fds, 1, 1000) <= 0) {
			D("poll error/timeout on queue %d\n", targ->me);
			goto quit;
		}
#endif

		/*
		 * we need to fill *all* the packets of *all* the queues at
		 * least once.Once we are done, set to copy_all global
		 * parameter.
		 */
		if (options & OPT_COPY && sent > 100000 && !(targ->g->options & OPT_COPY)) {
			D("drop copy");
			options &= ~OPT_COPY;
		}

		/*
		 * scan our queues and send on those with room
		 */
		for (i = targ->qfirst; i < targ->qlast; i++) {
			int m, limit = MIN(n - sent, targ->g->burst);

			txring = NETMAP_TXRING(nifp, i);
			if (txring->avail == 0)
				continue;
			if (targ->g->pkt_cmd)
				m = send_packets_x(txring, limit, targ);
			else
				m = send_packets(txring, targ->pkts[0],
					targ->g->pkt_size, limit, options);
			sent += m;
			targ->count = sent;
			if (targ->g->pkt_cmd & PKT_CMD_ALL &&
			    targ->n_pktbufs > 1 && targ->snd_nxt == 0)
				(void)reinitialize_packets(targ);
		}
	}
#ifndef COPYTEST
	/* Tell the interface that we have new packets. */
	ioctl(fds[0].fd, NIOCTXSYNC, NULL);

	/* final part: wait all the TX queues to be empty. */
	for (i = targ->qfirst; i < targ->qlast; i++) {
		txring = NETMAP_TXRING(nifp, i);
		while (!NETMAP_TX_RING_EMPTY(txring)) {
			ioctl(fds[0].fd, NIOCTXSYNC, NULL);
			usleep(1); /* wait 1 tick */
		}
	}
#endif
    }

	gettimeofday(&targ->toc, NULL);
	targ->completed = 1;
	targ->count = sent;

quit:
	/* reset the ``used`` flag. */
	targ->used = 0;

	return (NULL);
}


static void
receive_pcap(u_char *user, const struct pcap_pkthdr * h,
	const u_char * bytes)
{
	int *count = (int *)user;
	(*count)++;
}

static int
receive_packets(struct netmap_ring *ring, u_int limit, int skip_payload)
{
	u_int cur, rx;

	cur = ring->cur;
	if (ring->avail < limit)
		limit = ring->avail;
	for (rx = 0; rx < limit; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

		if (!skip_payload)
			check_payload(p, slot->len);

		cur = NETMAP_RING_NEXT(ring, cur);
	}
	ring->avail -= rx;
	ring->cur = cur;

	return (rx);
}

static int
receive_packets_x(struct netmap_ring *ring, u_int limit, int skip_payload,
		struct prot_cb *ncb, struct prot_cb *tcb, uint32_t *advanced)
{
	u_int cur, rx;
//	char pbuf[2048];
	int adv = 0;
//	int err = 0;

//	dump_pkts_rxring(ring);
	cur = ring->cur;
	if (ring->avail < limit)
		limit = ring->avail;
	for (rx = 0; rx < limit; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

//		if (copy_all)
//			memcpy(pbuf, p, slot->len);
		if (!skip_payload)
			check_payload(p, slot->len);
//		adv += tcp4_input(p, ncb, tcb, &err);
		cur = NETMAP_RING_NEXT(ring, cur);
	}
	ring->avail -= rx;
	ring->cur = cur;

	*advanced = adv;
	return (rx);
}

static void *
receiver_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd fds[1];
	struct netmap_if *nifp = targ->nifp;
	struct netmap_ring *rxring;
	int i, received = 0;

	if (setaffinity(targ->thread, targ->affinity))
		goto quit;

	/* setup poll(2) mechanism. */
	memset(fds, 0, sizeof(fds));
	fds[0].fd = targ->fd;
	fds[0].events = (POLLIN);

	/* unbounded wait for the first packet. */
	for (;;) {
		i = poll(fds, 1, 1000);
		if (i > 0 && !(fds[0].revents & POLLERR))
			break;
		D("waiting for initial packets, poll returns %d %d", i, fds[0].revents);
	}

	/* main loop, exit after 1s silence */
	gettimeofday(&targ->tic, NULL);
    if (targ->g->use_pcap) {
	for (;;) {
		pcap_dispatch(targ->g->p, targ->g->burst, receive_pcap, NULL);
	}
    } else {
	while (1) {
		/* Once we started to receive packets, wait at most 1 seconds
		   before quitting. */
		if (poll(fds, 1, 1 * 1000) <= 0) {
			gettimeofday(&targ->toc, NULL);
			targ->toc.tv_sec -= 1; /* Subtract timeout time. */
			break;
		}

		for (i = targ->qfirst; i < targ->qlast; i++) {
			int m;

			rxring = NETMAP_RXRING(nifp, i);
			if (rxring->avail == 0)
				continue;

			if (targ->g->pkt_cmd &&
			    targ->g->tproto == IPPROTO_TCP &&
			    targ->g->nproto == AF_INET)
				m = receive_packets_x(rxring, targ->g->burst,
					SKIP_PAYLOAD, targ->ncb, targ->tcb,
					&((struct tcp_cb *)targ->tcb)->report);
			else
				m = receive_packets(rxring, targ->g->burst,
					SKIP_PAYLOAD);
			received += m;
			targ->count = received;
		}

		// tell the card we have read the data
		//ioctl(fds[0].fd, NIOCRXSYNC, NULL);
	}
    }

	targ->completed = 1;
	targ->count = received;

quit:
	if (targ->g->pkt_cmd && targ->g->tproto == IPPROTO_TCP &&
	    targ->g->nproto == AF_INET)
		printf("cumulatively received %u packets\n",
		    ((struct tcp_cb *)targ->tcb)->report);
	/* reset the ``used`` flag. */
	targ->used = 0;

	return (NULL);
}

static void
tx_output(uint64_t sent, int size, double delta)
{
	double amount = 8.0 * (1.0 * size * sent) / delta;
	double pps = sent / delta;
	char units[4] = { '\0', 'K', 'M', 'G' };
	int aunit = 0, punit = 0;

	while (amount >= 1000) {
		amount /= 1000;
		aunit += 1;
	}
	while (pps >= 1000) {
		pps /= 1000;
		punit += 1;
	}

	printf("Sent %" PRIu64 " packets, %d bytes each, in %.2f seconds.\n",
	       sent, size, delta);
	printf("Speed: %.2f%cpps. Bandwidth: %.2f%cbps.\n",
	       pps, units[punit], amount, units[aunit]);
}


static void
rx_output(uint64_t received, double delta)
{

	double pps = received / delta;
	char units[4] = { '\0', 'K', 'M', 'G' };
	int punit = 0;

	while (pps >= 1000) {
		pps /= 1000;
		punit += 1;
	}

	printf("Received %" PRIu64 " packets, in %.2f seconds.\n", received, delta);
	printf("Speed: %.2f%cpps.\n", pps, units[punit]);
}

static void
usage(void)
{
	const char *cmd = "pkt-gen";
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-i interface		interface name\n"
		"\t-t pkts_to_send	also forces send mode\n"
		"\t-r pkts_to_receive	also forces receive mode\n"
		"\t-l pkts_size		in bytes excluding CRC\n"
		"\t-d dst-ip		end with %%n to sweep n addresses\n"
		"\t-s src-ip		end with %%n to sweep n addresses\n"
		"\t-D dst-mac		end with %%n to sweep n addresses\n"
		"\t-S src-mac		end with %%n to sweep n addresses\n"
		"\t-a cpu_id		use setaffinity\n"
		"\t-b burst size		testing, mostly\n"
		"\t-c cores		cores to use\n"
		"\t-p threads		processes/threads to use\n"
		"\t-T report_ms		milliseconds between reports\n"
		"\t-w wait_for_link_time	in seconds\n"
		"\t-C			copy all packets\n"
		"",
		cmd);

	exit(0);
}

struct sf {
	char *key;
	void *f;
};

static struct sf func[] = {
	{ "tx",	sender_body },
	{ "rx",	receiver_body },
	{ "ping",	pinger_body },
	{ "pong",	ponger_body },
	{ "httpserver", http_server_body},
//	{ "dttcpclient", dttcp_client_body},
	{ NULL, NULL }
};

int
main(int arc, char **argv)
{
	int i, fd;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	struct glob_arg g;

	struct nmreq nmr;
	void *mmap_addr;		/* the mmap address */
	void *(*td_body)(void *) = receiver_body;
	int ch;
	int report_interval = 1000;	/* report interval */
	char *ifname = NULL;
	int wait_link = 2;
	int devqueues = 1;	/* how many device queues */
	int affinity = -1;

	bzero(&g, sizeof(g));

	/* ip addresses can also be a range x.x.x.x-x.x.x.y */
	g.src_ip.name = "10.0.0.1";
	g.dst_ip.name = "10.1.0.1";
	g.dst_mac.name = "ff:ff:ff:ff:ff:ff";
	g.src_mac.name = NULL;
	g.pkt_size = 60;
	g.burst = 512;		// default
	g.nthreads = 1;
	g.pkt_cmd = 0;
	g.mstack = 0;
	g.ifaflags = 0;
	g.nproto = g.tproto = 0;
	/* compatibility with pkt-gen */
	g.nproto = AF_INET; /* default IPv4 */
	g.tproto = IPPROTO_UDP;
	g.sport = DEFAULT_SPORT;
	g.dport = DEFAULT_DPORT;
	g.hwifname = NULL;
	g.bdg_num_rings = 1;
	g.dport_interval = 0;
	g.dport_tinterval = 0;
	g.sport_interval = 0;
	g.sport_tinterval = 0;
	g.n_tcpconn = 1;
	g.conn_len = DEFAULT_CONN_LEN;
	g.n_pktbufs = -1; /* later set to the number of slots in the ring */
	g.tcpflags = TH_ACK;
	g.http_timer_type = HTTP_TIMER_MONO;
#ifdef COPYTEST
	g.slot_lim = 0;
	g.vring = 0;
#endif


	while ( (ch = getopt(arc, argv,
			"a:f:n:i:t:r:l:d:s:D:S:b:c:o:p:PT:w:M:x:U:Y:y:h:H:q:Q:j:J:N:L:m:X:F:C:vEu6V")) != -1) {
		struct sf *fn;

		switch(ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'n':
			g.npackets = atoi(optarg);
			break;

		case 'f':
			for (fn = func; fn->key; fn++) {
				if (!strcmp(fn->key, optarg))
					break;
			}
			if (fn->key)
				td_body = fn->f;
			else
				D("unrecognised function %s", optarg);
			break;

		case 'o':
			g.options = atoi(optarg);
			break;
		case 'a':	/* force affinity */
			affinity = atoi(optarg);
			break;
		case 'i':	/* interface */
			ifname = optarg;
			break;
		case 't':	/* send */
			td_body = sender_body;
			g.npackets = atoi(optarg);
			break;
		case 'r':	/* receive */
			td_body = receiver_body;
			g.npackets = atoi(optarg);
			break;
		case 'l':	/* pkt_size */
			g.pkt_size = atoi(optarg);
			break;
		case 'd':
			g.dst_ip.name = optarg;
			break;
		case 's':
			g.src_ip.name = optarg;
			break;
		case 'T':	/* report interval */
			report_interval = atoi(optarg);
			break;
		case 'w':
			wait_link = atoi(optarg);
			break;
		case 'b':	/* burst */
			g.burst = atoi(optarg);
			break;
		case 'c':
			g.cpus = atoi(optarg);
			break;
		case 'p':
			g.nthreads = atoi(optarg);
			break;

		case 'P':
			g.use_pcap = 1;
			break;

		/* XXX */
		case 'D': /* destination mac */
			g.dst_mac.name = optarg;
	{
		struct ether_addr *mac = ether_aton(g.dst_mac.name);
		D("ether_aton(%s) gives %p", g.dst_mac.name, mac);
	}
			break;
		case 'S': /* source mac */
			g.src_mac.name = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'M':
			if (strlen(optarg) > 2 && !strncmp("0x", optarg, 2)) {
				char *dummy;
				g.pkt_cmd = (int)strtol(optarg, &dummy, 16);
			} else
				g.pkt_cmd = atoi(optarg);
			break;
		case 'E':
			g.pkt_options |= PKT_CONF_NOTCPCSUM;
			break;
		case 'F':
			if (strlen(optarg) > 2 && !strncmp("0x", optarg, 2)) {
				char *dummy;
				g.tcpflags = (uint8_t)strtol(optarg, &dummy, 16);
			}
			break;
		case 'x':
			if (!strncmp(optarg, "tcp", 3))
				g.tproto = IPPROTO_TCP;
			else if (!strncmp(optarg, "udp", 3))
				g.tproto = IPPROTO_UDP;
			else
				usage();
			break;
		case 'm':
			g.n_pktbufs = atoi(optarg);
			break;
		case '6':
			g.nproto = AF_INET6;
			break;
		case 'Y':
			g.sport = atoi(optarg);
			break;
		case 'y':
			g.dport = atoi(optarg);
			break;
		case 'N':
			g.n_tcpconn = atoi(optarg);
			break;
		case 'L':
			g.conn_len = atoi(optarg);
			break;
		case 'C':
			g.http_timer_type = atoi(optarg);
			break;
#ifdef MSTACK
		case 'u':
			g.mstack = 1;
			break;
		case 'U':
			g.mstack = 1;
			/* Must be like 0x0a. 0x10 for any addr */
			if (strlen(optarg) > 2 && !strncmp("0x", optarg, 2)) {
				char *dummy;
				g.ifaflags = (uint32_t)
					strtoul(optarg, &dummy, 16);
			}
			break;
		case 'h':
			g.hwifname = optarg;
			break;
		case 'H':
			/* Must be like 0x000 */
			g.bdg_num_rings = atoi(optarg);
			break;
		/* Generate traffic to different destinations ports */
		case 'q':
			g.dport_interval = atoi(optarg);
			break;
		case 'Q':
			g.dport_tinterval = atoi(optarg);
			break;
		case 'j':
			g.sport_interval = atoi(optarg);
			break;
		case 'J':
			g.sport_tinterval = atoi(optarg);
			break;
#endif /* MSTACK */
#ifdef COPYTEST
		case 'X':
			g.slot_lim = atoi(optarg);
			break;
		case 'V':
			g.vring = 1;
			break;
#endif
		}
	}

	if (ifname == NULL) {
		D("missing ifname");
		usage();
	}
	if (!PKT_CMD_VALID(g.pkt_cmd)) {
		D("Bad packet composition option");
		usage();
	}

	if (g.nproto == AF_INET6 && g.tproto == IPPROTO_TCP &&
	    g.pkt_size < 74) {
		D("The minimum IPv6 TCP packet is 74 byte\n");
		usage();
	}
#ifdef MSTACK
	if (g.mstack) {
		if (strncmp("vale", ifname, 4)) {
			D("MiniStack only works on vale port\n");
			usage();
		} else if (!g.hwifname) {
			D("MiniStack requires NIC's name");
			usage();
		}
		if (g.ifaflags == 0 || g.ifaflags & NM_ADDRFLAG_AUTO_SADDR)
			g.pkt_options |= PKT_CONF_NOSADDR;
		if (g.ifaflags & NM_ADDRFLAG_AUTO_SRCDST)
			g.pkt_options |= PKT_CONF_NODADDR;
	}
#endif /* MSTACK */
	if (g.pkt_cmd & PKT_CMD_NOTCPCSUM)
		g.pkt_options |= PKT_CONF_NOTCPCSUM;

	{
		int n = system_ncpus();
		if (g.cpus < 0 || g.cpus > n) {
			D("%d cpus is too high, have only %d cpus", g.cpus, n);
			usage();
		}
		if (g.cpus == 0)
			g.cpus = n;
	}
	if (g.pkt_size < 16 || g.pkt_size > 1536) {
		D("bad pktsize %d\n", g.pkt_size);
		usage();
	}

	if (g.src_mac.name == NULL) {
		static char mybuf[20] = "00:00:00:00:00:00";
		/* retrieve source mac address. */
		if (source_hwaddr(ifname, mybuf) == -1) {
			D("Unable to retrieve source mac");
			// continue, fail later
		}
		g.src_mac.name = mybuf;
	}
	/* extract address ranges */
	extract_ip_range(&g.src_ip);
	extract_ip_range(&g.dst_ip);
	extract_mac_range(&g.src_mac);
	extract_mac_range(&g.dst_mac);

    if (g.use_pcap) {
	D("using pcap on %s", ifname);
	g.p = pcap_open_live(ifname, 0, 1, 100, pcap_errbuf);
	if (g.p == NULL) {
		D("cannot open pcap on %s", ifname);
		usage();
	}
	mmap_addr = NULL;
	fd = -1;
    } else {
	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	/*
	 * Open the netmap device to fetch the number of queues of our
	 * interface.
	 *
	 * The first NIOCREGIF also detaches the card from the
	 * protocol stack and may cause a reset of the card,
	 * which in turn may take some time for the PHY to
	 * reconfigure.
	 */
	fd = open("/dev/netmap", O_RDWR);
	if (fd == -1) {
		D("Unable to open /dev/netmap");
		// fail later
	} else {
		if ((ioctl(fd, NIOCGINFO, &nmr)) == -1) {
			D("Unable to get if info without name");
		} else {
			D("map size is %d Kb", nmr.nr_memsize >> 10);
		}
		bzero(&nmr, sizeof(nmr));
		nmr.nr_version = NETMAP_API;
		strncpy(nmr.nr_name, ifname, sizeof(nmr.nr_name));
		/* Multiple rings of a VALE port is specified here */
#ifdef MSTACK
		nmr.nr_tx_rings = nmr.nr_rx_rings = g.bdg_num_rings;
#endif
		if ((ioctl(fd, NIOCGINFO, &nmr)) == -1) {
			D("Unable to get if info for %s", ifname);
		}
		devqueues = nmr.nr_rx_rings;
	}

	/* validate provided nthreads. */
	if (g.nthreads < 1 || g.nthreads > devqueues) {
		D("bad nthreads %d, have %d queues", g.nthreads, devqueues);
		// continue, fail later
	}

	/*
	 * Map the netmap shared memory: instead of issuing mmap()
	 * inside the body of the threads, we prefer to keep this
	 * operation here to simplify the thread logic.
	 */
	D("mmapping %d Kbytes", nmr.nr_memsize>>10);
	mmap_addr = (struct netmap_d *) mmap(0, nmr.nr_memsize,
					    PROT_WRITE | PROT_READ,
					    MAP_SHARED, fd, 0);
	if (mmap_addr == MAP_FAILED) {
		D("Unable to mmap %d KB", nmr.nr_memsize >> 10);
		// continue, fail later
	}

	/*
	 * Register the interface on the netmap device: from now on,
	 * we can operate on the network interface without any
	 * interference from the legacy network stack.
	 *
	 * We decide to put the first interface registration here to
	 * give time to cards that take a long time to reset the PHY.
	 */
	nmr.nr_version = NETMAP_API;
	if (ioctl(fd, NIOCREGIF, &nmr) == -1) {
		D("Unable to register interface %s", ifname);
		//continue, fail later
	}


	/* Print some debug information. */
	for (i = 0;i < arc; i++)
		fprintf(stdout, "%s ", argv[i]);
	fprintf(stdout, "\n");
	fprintf(stdout,
		"%s %s: %d queues, %d threads and %d cpus.\n",
		(td_body == sender_body) ? "Sending on" : "Receiving from",
		ifname,
		devqueues,
		g.nthreads,
		g.cpus);
	if (td_body == sender_body) {
		fprintf(stdout, "%s -> %s (%s -> %s)\n",
			g.src_ip.name, g.dst_ip.name,
			g.src_mac.name, g.dst_mac.name);
	}

	/* Exit if something went wrong. */
	if (fd < 0) {
		D("aborting");
		usage();
	}
    }

	if (g.options) {
		D("special options:%s%s%s%s\n",
			g.options & OPT_PREFETCH ? " prefetch" : "",
			g.options & OPT_ACCESS ? " access" : "",
			g.options & OPT_MEMCPY ? " memcpy" : "",
			g.options & OPT_COPY ? " copy" : "");
	}
	/* Wait for PHY reset. */
	if (strncmp(nmr.nr_name, "vale", 4)) {
		D("Wait %d secs for phy reset", wait_link);
		sleep(wait_link);
		D("Ready...");
	}
#ifdef MSTACK
	if (g.mstack) {
		int error;
		struct nmaddrreq nma;

		memset(&nma, 0, sizeof(nma));
		strcpy(nma.nar_ifname, nmr.nr_name);
		config_mstack_args(&g, &nma);
		/*
		 * Although this violates MiniStack's principle, transmitting
		 * packet from multiple ports is useful for some experiments
		 */
		if (g.sport_interval || g.sport_tinterval) {
			g.ifaflags |= NM_ADDRFLAG_ANY_ADDR;
			nma.nar_flags = g.ifaflags; /* overwriting */
			g.pkt_options &= ~PKT_CONF_NOSADDR;
			g.pkt_options &= ~PKT_CONF_NODADDR; /* XXX needed ? */
		}
		error = ioctl(fd, NIOCSMSOPEN, &nma);
		D("%s in NIOCSMSOPEN for %s -> %s", error?"failed":"success", nma.nar_ifname, nma.nar_hwifname);
		if (error)
			exit(1);
		sleep(wait_link);
		D("Ready...");
	}
#endif /* MSTACK */

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);

	if (g.use_pcap) {
		g.p = pcap_open_live(ifname, 0, 1, 100, NULL);
		if (g.p == NULL) {
			D("cannot open pcap on %s", ifname);
			usage();
		} else
			D("using pcap %p on %s", g.p, ifname);
	}

	targs = calloc(g.nthreads, sizeof(*targs));
	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
	 */
	for (i = 0; i < g.nthreads; i++) {
		struct netmap_if *tnifp;
		struct nmreq tifreq;
		int tfd;

	    if (g.use_pcap) {
		tfd = -1;
		tnifp = NULL;
	    } else {
		/* register interface. */
		tfd = open("/dev/netmap", O_RDWR);
		if (tfd == -1) {
			D("Unable to open /dev/netmap");
			continue;
		}

		bzero(&tifreq, sizeof(tifreq));
		strncpy(tifreq.nr_name, ifname, sizeof(tifreq.nr_name));
		tifreq.nr_version = NETMAP_API;
		tifreq.nr_ringid = (g.nthreads > 1) ? (i | NETMAP_HW_RING) : 0;

		/*
		 * if we are acting as a receiver only, do not touch the transmit ring.
		 * This is not the default because many apps may use the interface
		 * in both directions, but a pure receiver does not.
		 */
		if (td_body == receiver_body) {
			tifreq.nr_ringid |= NETMAP_NO_TX_POLL;
		}

		if ((ioctl(tfd, NIOCREGIF, &tifreq)) == -1) {
			D("Unable to register %s", ifname);
			continue;
		}
		tnifp = NETMAP_IF(mmap_addr, tifreq.nr_offset);
	    }
		/* start threads. */
		bzero(&targs[i], sizeof(targs[i]));
		targs[i].g = &g;
		targs[i].used = 1;
		targs[i].completed = 0;
		targs[i].fd = tfd;
		targs[i].nmr = tifreq;
		targs[i].nifp = tnifp;
		targs[i].qfirst = (g.nthreads > 1) ? i : 0;
		targs[i].qlast = (g.nthreads > 1) ? i+1 :
			(td_body == receiver_body ? tifreq.nr_rx_rings : tifreq.nr_tx_rings);
		targs[i].me = i;
		 /* By default the same number as the slots */
		if (g.n_pktbufs < 0)
			g.n_pktbufs = NETMAP_TXRING(tnifp, i)->num_slots;
		targs[i].n_pktbufs = g.n_pktbufs;
#ifdef COPYTEST
		if (!g.slot_lim ||
		    g.slot_lim > NETMAP_TXRING(tnifp, i)->num_slots) {
			g.slot_lim = NETMAP_TXRING(tnifp, i)->num_slots;
		}
		D("highest slot idx is set to %d / %d", g.slot_lim, NETMAP_TXRING(tnifp, i)->num_slots);
		if (g.vring) {
			targs[i].vring_p = create_pseudo_ring(1024);
			if (!targs[i].vring_p)
				continue;
		}
#endif
		targs[i].pkt_size = NETMAP_TXRING(tnifp, i)->nr_buf_size;
		if (affinity >= 0) {
			if (affinity < g.cpus)
				targs[i].affinity = affinity;
			else /* affinity >= g.cpus */
				targs[i].affinity = i % g.cpus;
		} else
			targs[i].affinity = -1;
		if (g.pkt_cmd || td_body == http_server_body) {
			/* Initialize PCBs */
			struct prot_cb *lcb, *ncb, *tcb;
			int j;

			targs[i].payload = (char *)malloc(DEFAULT_UDATASIZ);
			if (targs[i].payload == NULL)
				exit(1);
			targs[i].paylen = DEFAULT_UDATASIZ;
			memset(targs[i].payload, 1, DEFAULT_UDATASIZ);

			lcb = ncb = tcb = NULL;
			lcb = ethcb_new(g.src_mac.name, g.dst_mac.name, g.nproto);
			if (!lcb) {
pcb_alloc_fail:
				free(targs[i].payload);
				exit(1);
			}
			if (lcb->prot == AF_INET)
				ncb = ipv4cb_new(g.src_ip.name, g.dst_ip.name, g.tproto);
			else if (lcb->prot == AF_INET6)
				ncb = ipv6cb_new(g.src_ip.name, g.dst_ip.name, g.tproto);
			if (!ncb) {
				free(lcb);
				goto pcb_alloc_fail;
			}
			/*
			 * Depending on Q, q, J, j options, we use different
			 * source/destination ports.
			 * We allow one threads to handle multiple TCBs
			 */
			STAILQ_INIT(&targs[i].tcbhead);
			for (j = 0; j < g.n_tcpconn; ++j) {
				uint16_t sport, dport;

				/* different srcs if j or J is present */
				sport = g.sport + i * g.sport_tinterval + j *
					g.sport_interval;
				/* different dsts if q or Q is present */
				dport = g.dport + i * g.dport_tinterval + j *
					g.dport_interval;
				if (ncb->prot == IPPROTO_TCP) {
					tcb = tcpcb_new(sport, dport,
					    DEFAULT_ISN, 0, g.tcpflags,
					    DEFAULT_AWND, NULL, 0);
					if (g.tcpflags & TH_SYN &&
					    !(g.tcpflags & TH_ACK))
						tcpcb_set_mss(tcb, 512);
				} else if (ncb->prot == IPPROTO_UDP)
					tcb = udpcb_new(sport, dport);
				else {
					D("Unsupported transport protocol\n");
					free(lcb);
					free(ncb);
					goto pcb_alloc_fail;
				}
				STAILQ_INSERT_TAIL(&targs[i].tcbhead,
						tcb, next);
			}
			tcb = STAILQ_FIRST(&targs[i].tcbhead);
			set_pcbs_thread(&targs[i], lcb, ncb, tcb);
		}
		if (td_body != receiver_body) { /* XXX */
			/* initialize the packet to send. */
			if (initialize_packets(&targs[i])) {
				D("initialize_packets failed for thread %d", i);
				targs[i].used = 0;
				continue;
			}
		}

		if (pthread_create(&targs[i].thread, NULL, td_body,
				   &targs[i]) == -1) {
			D("Unable to create thread %d", i);
			targs[i].used = 0;
		}
	}

    {
	uint64_t my_count = 0, prev = 0;
	uint64_t count = 0;
	double delta_t;
	struct timeval tic, toc;

	gettimeofday(&toc, NULL);
	for (;;) {
		struct timeval now, delta;
		uint64_t pps;
		int done = 0;

		delta.tv_sec = report_interval/1000;
		delta.tv_usec = (report_interval%1000)*1000;
		select(0, NULL, NULL, NULL, &delta);
		gettimeofday(&now, NULL);
		timersub(&now, &toc, &toc);
		my_count = 0;
		for (i = 0; i < g.nthreads; i++) {
			my_count += targs[i].count;
			if (targs[i].used == 0)
				done++;
		}
		pps = toc.tv_sec* 1000000 + toc.tv_usec;
		if (pps < 10000)
			continue;
		pps = (my_count - prev)*1000000 / pps;
		D("%" PRIu64 " pps %s", pps, nmr.nr_name);
		prev = my_count;
		toc = now;
		if (done == g.nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	for (i = 0; i < g.nthreads; i++) {
		struct prot_cb *c, *tmp;
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		pthread_join(targs[i].thread, NULL);
		ioctl(targs[i].fd, NIOCUNREGIF, &targs[i].nmr);
		close(targs[i].fd);

		if (targs[i].pkts != NULL) {
			int j;
			for (j = 0; j < targs[i].n_pktbufs; j++) {
				if (targs[i].pkts[j] != NULL) {
					free(targs[i].pkts[j]);
				}
			}
			free(targs[i].pkts);
		}
#ifdef COPYTEST
		if (targs[i].vring_p)
			free(targs[i].vring_p);
#endif

		if (targs[i].completed == 0)
			continue;

		/*
		 * Collect threads output and extract information about
		 * how long it took to send all the packets.
		 */
		count += targs[i].count;
		if (!timerisset(&tic) || timercmp(&targs[i].tic, &tic, <))
			tic = targs[i].tic;
		if (!timerisset(&toc) || timercmp(&targs[i].toc, &toc, >))
			toc = targs[i].toc;
		if (g.pkt_cmd) {
			free(targs[i].lcb);
			free(targs[i].ncb);
//			printf("last seqno is %u\n", ntohl(((struct tcp_cb *)targs[i].tcb)->seqno));
			STAILQ_FOREACH_SAFE(c, &targs[i].tcbhead, next, tmp)
				free(c);
		}
	}

	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	if (td_body == sender_body)
		tx_output(count, g.pkt_size, delta_t);
	else
		rx_output(count, delta_t);
    }

	ioctl(fd, NIOCUNREGIF, &nmr);
	munmap(mmap_addr, nmr.nr_memsize);
	close(fd);

	return (0);
}
/* end of file */
