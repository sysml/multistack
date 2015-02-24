#ifndef _TCPLIB_H_
#define _TCPLIB_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#ifdef __linux__
#include <netinet/ether.h>
#include <linux/if_packet.h>
#define sockaddr_dl	sockaddr_ll
#define sdl_family	sll_family
#define AF_LINK	AF_PACKET
#define LLADDR(s)	s->sll_addr;
#else /* FreeBSD */
#include <net/if_dl.h>
#include <net/if_types.h>
#endif /* __linux__ */

/* For struct ip , struct udphdr*/
#ifdef __linux__
#define ar_sha(ap)      (((caddr_t)((ap)+1)) +   0)
#define ar_spa(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln)
#define ar_tha(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap)      (((caddr_t)((ap)+1)) + 2*(ap)->ar_hln + (ap)->ar_pln)

#define arphdr_len2(ar_hln, ar_pln)                                     \
        (sizeof(struct arphdr) + 2*(ar_hln) + 2*(ar_pln))
#define arphdr_len(ap)  (arphdr_len2((ap)->ar_hln, (ap)->ar_pln))

#ifndef __USE_BSD
#define __USE_BSD 1
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif
#endif /* __linux__ */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>
#include <sys/queue.h>
#include <pcap/pcap.h>
#ifdef TCPLIB_NETMAP
#include <net/netmap.h>
#include <net/netmap_user.h>
#endif
#include <poll.h>
#include <string.h>

/* Useful for header manipulation */
#define MIN_FRAME_SIZ 60
#define ETHERHDR_SIZ 14
#define ETHER_TYPE_OFF 12
#define DEFAULT_IPHDR_SIZ 20
#define UDPHDR_SIZ 8
#define DEFAULT_TCPHDR_SIZ 20
#define DEFAULT_V4TCP_HDRS_SIZ (ETHERHDR_SIZ + DEFAULT_IPHDR_SIZ + DEFAULT_TCPHDR_SIZ)
#define DEFAULT_IW	10
#define TCP_DUPACK_MAX	3

/* TCP Flags */
#define TH_ACK 0x10
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_URG 0x20

/* TCP options */
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOLEN_MSS 4

#define DEFTTL 128
#define DEFAULT_DPORT 10510
#define DEFAULT_SPORT 10511
#define DEFAULT_ISN 20000
#define DEFAULT_AWND 65000

#define PKT_CONF_NOSADDR 0x00000001
#define PKT_CONF_NODADDR 0x00000002
#define PKT_CONF_NOTCPCSUM 0x00000004

#define TCP_DEFAULT_TCBS 2048
#define TCP_TCBHASHSIZ 1024

/* From Linux kernel */
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	uint32_t	ts_recent;	/* Time stamp to echo next		*/
	uint32_t	rcv_tsval;	/* Time stamp value			*/
	uint32_t	rcv_tsecr;	/* Time stamp echo reply		*/
	uint16_t	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	uint8_t	cookie_plus:6,	/* bytes in authenticator/cookie option	*/
		cookie_out_never:1,
		cookie_in_always:1;
	uint8_t	num_sacks;	/* Number of SACK blocks		*/
	uint16_t	user_mss;	/* mss requested by user in ioctl	*/
	uint16_t	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static __inline void
pkt_bzero(void *buf, int l)
{
	uint64_t *p = buf;
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
	if (unlikely(l > 2048)) {
		bzero(buf, 0);
		return;
	}
	for (; l > 0; l-=64) {
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
		*p++ = (uint64_t)0;
	}
}

static __inline unsigned long long int rdtsc(void)
{
 //  unsigned long long int x;
   unsigned a, d;

   __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

static __inline void
user_clock_gettime(struct timespec *ts, uint64_t freq)
{
	uint64_t now, nsec;

        now = rdtsc();
        nsec = now*1000/(freq/1000000);
        ts->tv_sec = nsec/1000000000; //
        ts->tv_nsec = (long)(nsec - ts->tv_sec * 1000000000); // long
//      printf("%"PRIu64".%"PRIu64"\n", ts->tv_sec, ts->tv_nsec);
}


LIST_HEAD(mpkts_head, mpkts_entry);

/* Taken from linux's ipv6.h */
static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr
		 *a2)
{
	        return memcmp(a1, a2, sizeof(struct in6_addr));
}
static inline void ipv6_addr_copy(struct in6_addr *a1, const struct in6_addr *a2
		)
{
	        memcpy(a1, a2, sizeof(struct in6_addr));
}

typedef struct pkt_hdrs {
	char *buf;
	struct ether_header *eth;
	union {
		struct ip *iph;
		struct ip6_hdr *ip6h;
		void *nh;
	} nh;
	union {
		struct udphdr *udph;
		struct tcphdr *tcph;
		void *th;
	} th;
	int hdrs_len;
	char *data;
	int datalen;
} pkt_t;

struct sendbuf {
	struct iovec *data_p;
	int iovcnt;
	/* current offset */
	int cur_idx;
	int offset;
	/* for convenience */
	u_int unsent;
};
extern void init_sendbuf(struct sendbuf *, struct iovec *, int);

struct mpkts_entry {
	char *buf;
	int pktlen;
	LIST_ENTRY(mpkts_entry) next;
};

struct ether_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	u_char sether[6];
	u_char dether[6];
};

struct ipv4_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	struct in_addr saddr;
	struct in_addr daddr;
};

struct ipv6_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct udp_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	uint16_t dport;
	uint16_t sport;
};

#define TCP_FEATURE_SEPARATE_FIN 0x00000001

/* Taken from the kernel */
#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)

enum {
	TCP_INPUT_RST = 0,
	TCP_INPUT_NEWACK,
	TCP_INPUT_OLDACK,
	TCP_INPUT_DUPACK,
	TCP_INPUT_FIN,
	TCP_INPUT_FINACK,
};

struct tcp_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	uint16_t dport;
	uint16_t sport;
	uint32_t seqno;
	uint32_t ackno;
	u_char flags;
	uint16_t awnd;
	uint16_t peer_awnd;
	u_char opt[40];
	size_t optlen;
	uint16_t peer_mss;
	uint32_t cwnd;
	uint32_t flight;
	uint32_t snd_una;
	uint32_t rcv_next;
	int num_dupack;
	uint32_t feature_flags;
	struct timespec start_at;
	u_int myhash;
	/* hint to make IP header */
	pkt_t hint;
	char hintbuf[DEFAULT_V4TCP_HDRS_SIZ];
	struct sendbuf data;
	struct pcb_channel *pcbc;
	/* Above is used in packet composition functions */
	uint32_t gap[8]; /* we store maximum 8 gaps */
	uint32_t gapsiz[8]; /* we store maximum 8 gaps */
	uint32_t report;
	TAILQ_ENTRY(tcp_cb) tailq_next; /* linked with an established list */
	LIST_ENTRY(tcp_cb) list_next; /* linked with an established list */
};

/* dump with clock_spent/count */
enum {
	TCP_PROF_FINDTCB = 0,
	TCP_PROF_SYN,
	TCP_PROF_ACCEPT,
	TCP_PROF_SEGMENT,
	TCP_PROF_ACKIN,
	TCP_PROF_CLEAN,
	TCP_PROF_END,
};

#define TCP_PROFILE_COUNT 100000
struct clockstat {
	uint64_t clock_spent;
	uint64_t count;
};

static __inline void
add_to_current(struct clockstat *stat, uint64_t start)
{
	uint64_t now = rdtsc();

	now -= start;
	stat->clock_spent += now;
	if (unlikely(++stat->count == TCP_PROFILE_COUNT))
		stat->clock_spent = stat->count = 0;
}

LIST_HEAD(pcbc_listhead, tcp_cb);
TAILQ_HEAD(pcbc_tailqhead, tcp_cb);
struct pcb_channel {
	int num_tcbs;
	uint16_t sport;
	struct pollfd fds[1];
	struct pcbc_listhead avail_list;
	struct pcbc_tailqhead avail_tailq;
	int num_avail;
	struct pcbc_listhead inuse_list[TCP_TCBHASHSIZ];
	struct pcbc_tailqhead inuse_tailq[TCP_TCBHASHSIZ];
	int num_inuse;
	struct timespec ts;
	uint64_t cpu_freq;
	struct netmap_ring *txring;
	struct netmap_ring *rxring;
	struct netmap_if *nifp;
	struct clockstat clstat[TCP_PROF_END];
};

int tcp_attach_sendbuf(struct tcp_cb *, struct iovec *, int);
void tcp_free_tcbs(struct pcb_channel *);
void tcp_release_tcb(struct tcp_cb *);
int tcp_prealloc_tcbs(int, int, struct pcb_channel *);

static __inline int
is_tcp_separate_fin(struct tcp_cb *tcb)
{
	return tcb->feature_flags & TCP_FEATURE_SEPARATE_FIN;
}

static __inline void
tcpcb_set_mss(struct prot_cb *cb, int mssval)
{
	uint32_t mssopt;
	struct tcp_cb *tcb = (struct tcp_cb *)cb;

	mssopt = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mssval);
	memcpy(tcb->opt, &mssopt, TCPOLEN_MSS);
	tcb->optlen = TCPOLEN_MSS;
}

struct prot_cb {
	int myprot;
	int prot;
	STAILQ_ENTRY(prot_cb) next;
	u_char data[0];
};



static __inline void *
ip_nexthdr(struct ip *iph)
{
	if (likely(iph->ip_hl == 5))
		return (void *)(iph + 1);
	return (void *)(((uint8_t *)iph) + (iph->ip_hl << 2));
}

static __inline uint16_t
ether_type(char *pkt)
{
	return ntohs(*((uint16_t *)(pkt + ETHER_TYPE_OFF)));
}

/* tcplib.c */
int ipv4_tcp_pkt(char *, pkt_t *, int);
void print_pkt(char *, uint8_t);
int get_ether_addr(const char *, u_char *);
int ether_dst_lookup(u_char *, const struct in_addr *, const struct in_addr *, const u_char *, char *);
void ether_pton(const char *, unsigned char *);
void ether_ntop(const u_char *, char *, size_t);

//void write_ether6_header(char *, const u_char *, const u_char *);
//void write_ether4_header(char *, const u_char *, const u_char *);
//uint16_t csum_pseudohdr6_data(uint16_t *, int, struct in6_addr *, struct in6_addr *, u_char);
//uint16_t csum_pseudohdr_data(uint16_t *, int, uint32_t, uint32_t, u_char);
//void write_ipv6_header(char *, size_t, struct in6_addr *, struct in6_addr *, u_char, uint32_t);
//void write_ipv4_header(char *, size_t, uint32_t, uint32_t, u_char, uint32_t);
//void write_udp_header(char *, size_t, uint16_t, uint16_t);
//void write_tcp_header(char *, uint16_t, uint16_t, uint32_t, uint32_t, u_char, uint16_t, void *, size_t);

int make_udp4_dgram(char *, size_t, struct prot_cb *, struct prot_cb *,
		struct prot_cb *, const char *, int, uint32_t);
int make_udp6_dgram(char *, size_t, struct prot_cb *, struct prot_cb *,
		struct prot_cb *, const char *, int, uint32_t);
int make_tcp4_segment(char *, size_t, struct prot_cb *, struct prot_cb *,
		struct prot_cb *, const char *, int, uint32_t);
int make_tcp6_segment(char *, size_t, struct prot_cb *, struct prot_cb *,
		struct prot_cb *, const char *, int, uint32_t);
int make_packet(char *, size_t, struct prot_cb *, struct prot_cb *,
		struct prot_cb *, const char *, int, uint32_t);

int tcp4_input(char *, struct prot_cb *, struct prot_cb *, int *);

struct prot_cb *ethcb_new(const char *, const char *, int);
struct prot_cb *ipv4cb_new(const char *, const char *, int);
struct prot_cb *ipv6cb_new(const char *, const char *, int);
struct prot_cb *udpcb_new(uint16_t, uint16_t);
struct prot_cb *tcpcb_new(uint16_t, uint16_t, uint32_t, uint32_t, uint16_t, uint16_t, char *, int);

/* tcpsrlib.c */
int pcap_send_segments(const char *, struct mpkts_head *,pcap_t **);


static inline uint16_t __get_unaligned_be16(const uint8_t *p)
{
	return p[0] << 8 | p[1];
}
static inline uint32_t __get_unaligned_be32(const uint8_t *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}
static inline uint64_t __get_unaligned_be64(const uint8_t *p)
{
	return (uint64_t)__get_unaligned_be32(p) << 32 |
		__get_unaligned_be32(p + 4);
}

uint32_t tcp_syncookie_sequence(struct ip *, struct tcphdr *, uint32_t, uint16_t *);
uint16_t tcp_v4_cookie_valid(pkt_t *, uint32_t);
int tcp_make_v4_response(char *, pkt_t *, char *, int);
int tcp_make_v4_tcb(char *, pkt_t *, struct prot_cb *, char *, u_int, u_int);
int tcp_v4_append_data(char *, char *, u_int, u_int, pkt_t *, int);
int tcp_v4_segment(char *, pkt_t *, struct sendbuf *, u_int);
void tcp_v4_hint_from_response(pkt_t *, pkt_t *);
void tcp_make_v4_synack(char *, pkt_t *, uint32_t, uint16_t);
uint32_t rthash(uint8_t *, uint8_t *, u_int);
unsigned long long int get_cpufreq(void);

struct tcp_cb * tcp_find_established(pkt_t *, struct pcb_channel *);
uint16_t *tcp_mssp_slowpath(struct tcphdr *);
void tcp_make_v4_rst(char *, pkt_t *, uint32_t, uint32_t);
struct tcp_cb *tcp_v4_accept(pkt_t *, struct pcb_channel *, uint16_t);
void tcp_print_tcb(struct tcp_cb *, char *);

/*
 * check whether the pkt's source matches to tcb's destination
 * The destination is already verified by the kernel
 */
static __inline int
tcp_v4_dst_match(pkt_t *pkt, struct tcp_cb *tcb)
{
	if (ntohs(pkt->th.tcph->th_sport) == tcb->dport)
		if (likely(pkt->nh.iph->ip_src.s_addr ==
			tcb->hint.nh.iph->ip_dst.s_addr))
			return 1;
	return 0;
}

static __inline void
tcp_init_tcb_from_ack(struct tcp_cb *tcb, pkt_t *ack, int mss, struct timespec *t)
{
	tcb->dport = ntohs(ack->th.tcph->th_sport);
	tcb->sport = ntohs(ack->th.tcph->th_dport);
	tcb->seqno = ntohl(ack->th.tcph->th_ack);
	tcb->ackno = ntohl(ack->th.tcph->th_seq) + ack->datalen; /* XXX */
	tcb->flags = TH_ACK;
	tcb->awnd = DEFAULT_AWND;
	tcb->peer_awnd = ntohs(ack->th.tcph->th_win);
	tcb->peer_mss = mss;
	tcb->cwnd = mss * DEFAULT_IW;
	tcb->flight = 0;
	tcb->snd_una = tcb->seqno;
	tcb->num_dupack = 0;
	tcb->feature_flags |= TCP_FEATURE_SEPARATE_FIN;
	memcpy(&tcb->start_at, t, sizeof(*t));
	/* hint for header prediction */
	tcb->hint.buf = tcb->hintbuf;
	tcb->hint.datalen = 0;
	tcp_v4_hint_from_response(&tcb->hint, ack);
}
#ifdef TCPLIB_NETMAP
int dump_pkts_rxring(struct netmap_ring *);
int netmap_tcp_output(struct tcp_cb *, pkt_t *, struct sendbuf *, struct netmap_ring *);
int netmap_tcp_finack(pkt_t *, struct netmap_ring *);
int netmap_tcp_tcbreset(struct tcp_cb *, struct netmap_ring *);
int netmap_tcp_synack(pkt_t *, struct netmap_ring *, uint32_t);
int netmap_tcp_ootb(pkt_t *, struct netmap_ring *);
int tcp_input_established(struct tcp_cb *, pkt_t *, struct netmap_ring *, int *);
#endif
void print_profiles(struct clockstat *, int, uint64_t);
#endif
