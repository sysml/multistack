#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif
#include "tcplib.h"
#ifdef TCPLIB_NETMAP
#include "nm_util.h"
#endif

#ifndef TCPLIB_NETMAP
/* from nm_util.h */
static __inline int min(int a, int b) { return a < b ? a : b; }
#endif

/* Make sure these are global so cannot be used with multiple threads */
#define TCP_SEGGPROFILE_COUNT 1000000
static struct clockstat cl_segment = {0, 0};
static struct clockstat cl_chksum = {0, 0};

unsigned long long int
get_cpufreq(void)
{
        uint64_t val = 0;
#ifdef __FreeBSD__
        char *mibname = "machdep.tsc_freq";
        size_t miblen, size;
        int mib[2];

        miblen = 2;
        if (sysctlnametomib(mibname, mib, (size_t *)&miblen) < 0)
                return 0;
        if (sysctl(mib, 2, NULL, &size, NULL, 0) < 0)
                return 0;
        if (sysctl(mib, 2, &val, &size, NULL, 0) < 0)
                return 0;
//        printf("VALUE %Lu (error %d)\n", (unsigned long long)val, error);
#elif __linux__
        FILE *fp;
        char readline[256] = {'\0'};
        double mhz = 0;

        fp = fopen("/proc/cpuinfo", "r");
        if (!fp) {
                perror("fopen");
                return 0;
        }
        while (fgets(readline, sizeof(readline), fp)) {
                char *p;

                if (strncmp(readline, "cpu MHz", 7))
                        continue;
                for (p = readline; *p != '\0'; p++) {
                        if (*p < '0' || *p > '9')
                                continue;
                        mhz = atof(p);
                        mhz *= 1000;
                        val = (unsigned long long)mhz * 1000;
                        break;
                }
                if (val)
                        break;
        }
        fclose(fp);
#endif /* __linux__ */
        return (unsigned long long)val;
}

void
ether_pton(const char *src, u_char *dst)
{
	memcpy(dst, ether_aton(src), ETHER_ADDR_LEN);
}

void
ether_ntop(const u_char *src, char *dst, size_t buflen)
{
	memcpy(dst, ether_ntoa((struct ether_addr *)src), buflen);
}

#ifdef __FreeBSD__
int
get_ether_addr(const char *ifname, u_char *ethaddr)
{
	struct ifaddrs *ifas, *ifas0;
	struct sockaddr_dl *sdl;
	int retval = -1;

	if (getifaddrs(&ifas0) < 0) {
		perror("getifaddrs");
		return retval;
	}
	for (ifas = ifas0; ifas; ifas = ifas->ifa_next) {
		sdl = (struct sockaddr_dl *)ifas->ifa_addr;
		if (sdl->sdl_family != AF_LINK || sdl->sdl_type != IFT_ETHER)
			continue;
		if (strncmp(ifname, sdl->sdl_data, sdl->sdl_nlen))
			continue;
		memcpy(ethaddr, LLADDR(sdl), ETHER_ADDR_LEN);
		retval = 0;
		break;
	}
	freeifaddrs(ifas0);
	return retval;
}
#endif /* __FreeBSD__ */

static __inline void
write_ether6_header(char *buf, const u_char *src, const u_char *dst)
{
	struct ether_header *eth;

	eth = (struct ether_header *)buf;
	memcpy(eth->ether_dhost, dst, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, src, ETHER_ADDR_LEN);
	eth->ether_type = htons(0x86DD);
}

static __inline void
write_ether4_header(char *buf, const u_char *src, const u_char *dst)
{
	struct ether_header *eth;

	eth = (struct ether_header *)buf;
	memcpy(eth->ether_dhost, dst, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, src, ETHER_ADDR_LEN);
	eth->ether_type = htons(0x0800);
}

/* This also writes ethernet header */
static __inline void
write_arp_ether_header(char *buf, const u_char *srcether, const u_char *dstether, const struct in_addr *saddr, const struct in_addr *taddr)
{
	struct arphdr *ah;
	struct ether_header *eth;

	eth = (struct ether_header *)buf;
	memcpy(eth->ether_dhost, dstether, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, srcether, ETHER_ADDR_LEN);
	eth->ether_type = htons(0x0806);
	eth++;

	ah = (struct arphdr *)eth;
	ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETHERTYPE_IP);
	ah->ar_hln = ETHER_ADDR_LEN;
	ah->ar_pln = sizeof(struct in_addr);
	ah->ar_op = htons(ARPOP_REQUEST);
	memcpy(ar_sha(ah), srcether, ah->ar_hln);
	memcpy(ar_spa(ah), saddr, ah->ar_pln);
	memset(ar_tha(ah), 0, ah->ar_hln);
	memcpy(ar_tpa(ah), taddr, ah->ar_pln);
}

#define ARP_RETRY 3
int
ether_dst_lookup(u_char *targetether, const struct in_addr *srcip, const struct in_addr *targetip, const u_char *srcether, char *ifname)
{
	char *buf;
	u_char dstether[ETHER_ADDR_LEN];
	char srcip_str[16], targetip_str[16];
	struct bpf_program fp;
	char filter[255], errbuf[255];
	struct pcap_pkthdr *p_pkth;
	const u_char *p_pktd;
	struct arphdr *ah;
	int i, retval;
	pcap_t *pd;

	buf = (char *)malloc(ETHERHDR_SIZ + sizeof(struct arphdr) + ETHER_ADDR_LEN*2 + 8);
	if (buf == NULL) {
		perror("malloc");
		return -1;
	}
	memset(dstether, 0xFF, sizeof(dstether));
	write_arp_ether_header(buf, srcether, dstether, srcip, targetip);

	memset(errbuf, 0, sizeof(errbuf));
	pd = pcap_open_live(ifname, 65535, 1, 1000, errbuf);
	if (pd == NULL) {
		perror("pcap_open_live");
		free(buf);
		return -1;
	}
	inet_ntop(AF_INET, srcip, srcip_str, sizeof(srcip_str));
	inet_ntop(AF_INET, targetip, targetip_str, sizeof(targetip_str));
	snprintf(filter, sizeof(filter)-1,
	    "arp and arp[6:2]=0x0002");
	if (pcap_compile(pd, &fp, filter, 1, 0) < 0) {
		perror("pcap_compile");
		pcap_close(pd);
		return -1;
	}
	if (pcap_setfilter(pd, &fp) < 0) {
		perror("pcap_setfilter");
		pcap_close(pd);
		return -1;
	}
	if (pcap_sendpacket(pd, (u_char *)buf, sizeof(struct arphdr)+ETHERHDR_SIZ + 8 + ETHER_ADDR_LEN*2) < 0) {
		perror("pcap_sendpacket");
		pcap_close(pd);
		free(buf);
		return -1;
	}
	for (i = 0; i < ARP_RETRY; ++i) {
		retval = pcap_next_ex(pd, &p_pkth, &p_pktd);
	        if (retval == 1) {

			ah = (struct arphdr *)(p_pktd + ETHERHDR_SIZ);
			if (memcmp(ar_spa(ah), targetip, sizeof(struct in_addr)) == 0) {
				memcpy(targetether, ar_sha(ah), ETHER_ADDR_LEN);
				break;
			}
		}
	}
	pcap_close(pd);
	free(buf);
	return 0;
}

/* from tcp_lro.c iph->ip_sum = 0xffff ^ do_csum_data(...) */
uint16_t
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

/* Taken from kernel KAME code */
#ifdef __linux__
#define __u6_addr __in6_u
#define __IPV6_ADDR_SCOPE_NODELOCAL     0x01
#define __IPV6_ADDR_SCOPE_INTFACELOCAL  0x01
#define __IPV6_ADDR_SCOPE_LINKLOCAL     0x02
#define __IPV6_ADDR_SCOPE_SITELOCAL     0x05
#define __IPV6_ADDR_SCOPE_ORGLOCAL      0x08    /* just used in this file */
#define __IPV6_ADDR_SCOPE_GLOBAL        0x0e
#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#define IPV6_VERSION			0x60
#define IPV6_VERSION_MASK		0xf0
#endif /* __linux__ */

#define IN6_IS_SCOPE_LINKLOCAL(a)       \
        ((IN6_IS_ADDR_LINKLOCAL(a)) ||  \
         (IN6_IS_ADDR_MC_LINKLOCAL(a)))
#define IN6_IS_ADDR_MC_INTFACELOCAL(a)  \
        (IN6_IS_ADDR_MULTICAST(a) &&    \
         (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_INTFACELOCAL))
#if !defined(__linux__)
#define s6_addr16 __u6_addr.__u6_addr16
#endif


uint16_t
in6_getscope(struct in6_addr *in6)
{

        if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6))
                return (in6->s6_addr16[1]);

        return (0);
}

#if 0
#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; (void)ADDCARRY(sum);}

static int
_in6_cksum_pseudo(struct ip6_hdr *ip6, uint32_t len, uint8_t nxt, uint16_t csum)
{
        int sum;
        uint16_t scope, *w;
        union {
                u_int16_t phs[4];
                struct {
                        u_int32_t       ph_len;
                        u_int8_t        ph_zero[3];
                        u_int8_t        ph_nxt;
                } __packed ph;
        } uph;

        sum = csum;

        /*
         * First create IP6 pseudo header and calculate a summary.
         */
        uph.ph.ph_len = htonl(len);
        uph.ph.ph_zero[0] = uph.ph.ph_zero[1] = uph.ph.ph_zero[2] = 0;
        uph.ph.ph_nxt = nxt;

        /* Payload length and upper layer identifier. */
        sum += uph.phs[0];  sum += uph.phs[1];
        sum += uph.phs[2];  sum += uph.phs[3];
	printf("sum is %d\n", sum);

        /* IPv6 source address. */
        scope = in6_getscope(&ip6->ip6_src);
        w = (u_int16_t *)&ip6->ip6_src;
        sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
        sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
        if (scope != 0)
                sum -= scope;

        /* IPv6 destination address. */
        scope = in6_getscope(&ip6->ip6_dst);
        w = (u_int16_t *)&ip6->ip6_dst;
        sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
        sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
        if (scope != 0)
                sum -= scope;

	printf("sum is %d\n", sum);
        return (sum);
}

int
in6_cksum_pseudo(struct ip6_hdr *ip6, uint32_t len, uint8_t nxt, uint16_t csum)
{
        int sum;
        union {
                u_int16_t s[2];
                u_int32_t l;
        } l_util;

        sum = _in6_cksum_pseudo(ip6, len, nxt, csum);
        REDUCE;
        return (sum);
}
#endif /* 0 */

static __inline uint16_t
csum_pseudohdr6_data(uint16_t *raw, int len, struct in6_addr *ip6src, struct in6_addr *ip6dst, u_char proto)
{
	uint32_t csum;
	union {
		uint16_t phs[4];
		struct {
			uint32_t ph_len;
			uint8_t ph_zero[3];
			uint8_t ph_nxt;
		} __attribute__((packed)) ph;
	} uph;
	uint16_t scope;
	uint16_t *p;

        csum = 0;
        uph.ph.ph_len = htonl(len);
        uph.ph.ph_zero[0] = uph.ph.ph_zero[1] = uph.ph.ph_zero[2] = 0;
        uph.ph.ph_nxt = proto;

        /* Payload length and upper layer identifier. */
        csum += uph.phs[0];  csum += uph.phs[1];
        csum += uph.phs[2];  csum += uph.phs[3];

        scope = in6_getscope(ip6src);
        p = (u_int16_t *)ip6src;
        csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3];
        csum += p[4]; csum += p[5]; csum += p[6]; csum += p[7];
        if (scope != 0)
                csum -= scope;
        scope = in6_getscope(ip6dst);
        p = (u_int16_t *)ip6dst;
        csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3];
        csum += p[4]; csum += p[5]; csum += p[6]; csum += p[7];
        if (scope != 0)
                csum -= scope;

	p = raw;
	while (len > 1) {
		csum += *p;
		p++;
		len -= 2;
	}
	if (len == 1)
		csum += (*p & 0x00ff);
        csum = (csum >> 16) + (csum & 0xffff);
        csum = (csum >> 16) + (csum & 0xffff);
        return (uint16_t)csum;
}

static __inline uint16_t
csum_pseudohdr_data(uint16_t *raw, int len, uint32_t ipsrc, uint32_t ipdst, u_char proto)
{
	uint32_t csum;
	u_char pseudo_hdr[12];
	uint16_t *p;

	csum = 0;
	p = (uint16_t *)pseudo_hdr;

	memcpy(&pseudo_hdr[0], &ipsrc, 4);
	csum += *p++;
	csum += *p++;
	memcpy(&pseudo_hdr[4], &ipdst, 4);
	csum += *p++;
	csum += *p++;
	pseudo_hdr[8] = 0;
	pseudo_hdr[9] = proto;
	csum += *p++;
	pseudo_hdr[10] = (u_char)((len >> 8) & 0x00FF);
	pseudo_hdr[11] = (u_char)(len & 0x00FF);
	csum += *p;

	p = raw;
	while (len > 1) {
                csum += *p;
                p++;
                len -= 2;
        }
	if (len == 1)
		csum += (*p & 0x00ff);
        csum = (csum >> 16) + (csum & 0xffff);
        csum = (csum >> 16) + (csum & 0xffff);
        return (uint16_t)csum;
}

static __inline uint16_t
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

static __inline u_int16_t
wrapsum(u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}

/*
 * buflen must be length ***FROM*** buf
 */
static __inline void
write_ipv6_header(char *buf, size_t len, struct in6_addr *saddr, struct in6_addr *daddr, u_char protocol, uint32_t pktflags)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_flow = 0; //inp->inp_flow & IPV6_FLOWINFO_MASK;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_short)len-40);
	ip6->ip6_nxt  = protocol;
	ip6->ip6_hlim = DEFTTL;
	if ((pktflags & PKT_CONF_NODADDR) && (pktflags & PKT_CONF_NOSADDR))
		return;
	ipv6_addr_copy(&ip6->ip6_dst, daddr);
	if (!(pktflags & PKT_CONF_NOSADDR))
		ipv6_addr_copy(&ip6->ip6_src, saddr);

}

static __inline void
write_ipv4_header(char *buf, size_t len, uint32_t saddr, uint32_t daddr, u_char protocol, uint32_t pktflags)
{
	struct ip *iph;

//	srand((unsigned int)time(NULL));
	iph = (struct ip *)buf;
	iph->ip_v = IPVERSION;
	iph->ip_hl = (sizeof(struct ip) >> 2);
//	iph->ip_id = rand() >> 16;
	iph->ip_id = 0;
	iph->ip_ttl = DEFTTL;
	iph->ip_len = htons(len);
	iph->ip_p = protocol;
	if (pktflags & PKT_CONF_NODADDR && pktflags & PKT_CONF_NOSADDR)
		return;
	iph->ip_dst.s_addr = daddr;
	if (pktflags & PKT_CONF_NOSADDR)
		return;
	iph->ip_src.s_addr = saddr;
	iph->ip_sum = 0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(struct ip));
}

static __inline void
write_udp_header(char *buf, size_t len, uint16_t sport, uint16_t dport)
{
	struct udphdr *udph;

	udph = (struct udphdr *)buf;
	udph->uh_sport = sport;
	udph->uh_dport = dport;
	udph->uh_ulen = htons(len);
	udph->uh_sum = 0;
}

static __inline void
write_tcp_header(char *buf, uint16_t sport, uint16_t dport, uint32_t seqno, uint32_t ackno, u_char flags, uint16_t awnd, void *opt, size_t optlen)
{
	struct tcphdr *tcph;

	tcph = (struct tcphdr *)buf;
	tcph->th_sport = htons(sport);
	tcph->th_dport = htons(dport);
	tcph->th_seq = htonl(seqno);
	tcph->th_ack = htonl(ackno);
	tcph->th_off = (DEFAULT_TCPHDR_SIZ + optlen) >> 2;
	tcph->th_flags = flags;
	tcph->th_win = htons(awnd);
	tcph->th_sum = 0;
	tcph->th_urp = 0;
	if (optlen)
		memcpy(tcph+1, opt, optlen);
}

/* buflen must be the final packet size including ether, ip and transport
 * header
 */
int
make_udp4_dgram(char *buf, size_t pktlen, struct prot_cb *lcb,
		struct prot_cb *ncb, struct prot_cb *tcb,
		const char *payload, int payloadlen, uint32_t pktflags)
{
	struct ether_cb *ecb = (struct ether_cb *)lcb;
	struct ipv4_cb *ip4cb = (struct ipv4_cb *)ncb;
	struct udp_cb *udpcb = (struct udp_cb *)tcb;
	struct udphdr *udph;
	char *p;
	size_t len = pktlen;
	int j, l, l0 = payloadlen;

	pkt_bzero(buf, pktlen);
	p = buf;
	write_ether4_header(p, ecb->sether, ecb->dether);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv4_header(p, len, ip4cb->saddr.s_addr, ip4cb->daddr.s_addr,
				IPPROTO_UDP, pktflags);
	p += sizeof(struct ip);
	len -= sizeof(struct ip);
	write_udp_header(p, len, udpcb->sport, udpcb->dport);
	udph = (struct udphdr *)p;
	p += sizeof(struct udphdr);
	len -= sizeof(struct udphdr);
	for (j = 0; j < len;) {
		l = min(l0, len - j);
		bcopy(payload, p + j, l);
		j += l;
	}
	p[j-1] = '\0';

	if (!(pktflags & PKT_CONF_NOTCPCSUM))
		udph->uh_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)udph,
				ntohs(udph->uh_ulen), ip4cb->saddr.s_addr,
				ip4cb->daddr.s_addr, IPPROTO_UDP);
	return 0;
}

int
make_udp6_dgram(char *buf, size_t pktlen, struct prot_cb *lcb,
		struct prot_cb *ncb, struct prot_cb *tcb,
		const char *payload, int payloadlen, uint32_t pktflags)
{
	struct ether_cb *ecb = (struct ether_cb *)lcb;
	struct ipv6_cb *ip6cb = (struct ipv6_cb *)ncb;
	struct udp_cb *udpcb = (struct udp_cb *)tcb;
	struct udphdr *udph;
	char *p;
	size_t len = pktlen;
	int j, l, l0 = payloadlen;

	pkt_bzero(buf, pktlen);
	p = buf;
	write_ether6_header(p, ecb->sether, ecb->dether);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv6_header(p, len, &ip6cb->saddr, &ip6cb->daddr, IPPROTO_UDP,
			pktflags);
	p += 40;
	len -= 40;
	write_udp_header(p, len, udpcb->sport, udpcb->dport);
	udph = (struct udphdr *)p;
	p += sizeof(struct udphdr);
	len -= sizeof(struct udphdr);
	for (j = 0; j < len;) {
		l = min(l0, len - j);
		bcopy(payload, p + j, l);
		j += l;
	}
	p[j-1] = '\0';

	if (!(pktflags & PKT_CONF_NOTCPCSUM))
		udph->uh_sum = 0xffff ^ csum_pseudohdr6_data((uint16_t *)udph,
			ntohs(udph->uh_ulen), &ip6cb->saddr, &ip6cb->daddr,
			IPPROTO_UDP);
	return 0;
}

int
make_tcp4_segment(char *buf, size_t pktlen, struct prot_cb *lcb,
		struct prot_cb *ncb, struct prot_cb *tcb,
		const char *payload, int payloadlen, uint32_t pktflags)

{
	struct ether_cb *ecb = (struct ether_cb *)lcb;
	struct ipv4_cb *ip4cb = (struct ipv4_cb *)ncb;
	struct tcp_cb *tcpcb = (struct tcp_cb *)tcb;
	struct tcphdr *tcph;
	char *p;
	size_t len = pktlen;
	size_t tlen;
	int j, l, l0 = payloadlen;

	pkt_bzero(buf, pktlen);
	p = buf;
	write_ether4_header(p, ecb->sether, ecb->dether);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv4_header(p, len, ip4cb->saddr.s_addr, ip4cb->daddr.s_addr,
				IPPROTO_TCP, pktflags);
	p += sizeof(struct ip);
	len -= sizeof(struct ip);
	write_tcp_header(p, tcpcb->sport, tcpcb->dport, tcpcb->seqno,
			tcpcb->ackno, tcpcb->flags, tcpcb->awnd, tcpcb->opt,
			tcpcb->optlen);
	tcph = (struct tcphdr *)p;
	tlen = len;
	p += sizeof(struct tcphdr);
	len -= (sizeof(struct tcphdr) + tcpcb->optlen);

	for (j = 0; j < len;) {
		l = min(l0, len - j);
		bcopy(payload, p + j, l);
		j += l;
	}
	p[j-1] = '\0';

	if (!(pktflags & PKT_CONF_NOTCPCSUM))
		tcph->th_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph,
			tlen, ip4cb->saddr.s_addr, ip4cb->daddr.s_addr,
			IPPROTO_TCP);
	tcpcb->seqno += len;
	return 0;
}

/* likely a bit expensive but useful to append data after app's header */
int
tcp_v4_append_data(char *buf, char *data, u_int datalen, u_int mss, pkt_t *hint, int fin)
{
	u_int iph_len, tlen, lim;
	struct ip *iph;
	struct tcphdr *tcph;
	char *p;

	iph = (struct ip *)(buf + ETHERHDR_SIZ);
	iph_len = iph->ip_hl << 2;
	tcph = (struct tcphdr *)(((uint8_t *)iph) + iph_len);
	tlen = ntohs(iph->ip_len) - iph_len;
	p = ((char *)tcph) + tlen;

	lim = min(datalen, DEFAULT_TCPHDR_SIZ + mss - tlen);
	memcpy(p, data, lim);

	iph->ip_len = htons(ntohs(iph->ip_len) + lim);
//	iph->ip_sum = 0;
//	iph->ip_sum = 0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(struct ip));
	/* Nothing is changed in TCP header */
	if (fin)
		tcph->th_flags |= TH_FIN;
	tcph->th_sum = 0;
	tcph->th_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph,
			tlen + lim, hint->nh.iph->ip_dst.s_addr,
			hint->nh.iph->ip_src.s_addr, IPPROTO_TCP);
	return lim;
}

/*
 * Based on V.J.'s header prediction.  hint must cover ethernet IPv4 and TCP
 * headers.  TCP options can be given in the TCP header.
 * Returns number of data bytes written.
 * Use tcp_v4_hint_from_response() to create the header skeleton
 * We assume buf has at least mss space
 */
int
tcp_v4_segment(char *buf, pkt_t *hint, struct sendbuf *sbuf, u_int mss)
{
	char *p;
	const struct iovec *data_p = sbuf->data_p;
	u_int iphlen, tcphlen, avail, i, lim, off;
	struct ip *iph;
	struct tcphdr *tcph;
#ifdef TCP_PROFILE
	uint64_t seg_start, ck_start;
	struct clockstat *seg_stat = &cl_segment;
	struct clockstat *chk_stat = &cl_chksum;

	seg_start = rdtsc();
#endif

        /* copy the header template */
        pkt_bzero(buf, hint->hdrs_len + mss);
        memcpy(buf, hint->buf, hint->hdrs_len);

	/* extract true available data length */
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	iphlen = iph->ip_hl << 2;
	tcph = (struct tcphdr *)((char *)iph + iphlen);
	tcphlen = tcph->th_off << 2;
	mss -= tcphlen - DEFAULT_TCPHDR_SIZ;

	/* Pack payload. */
        p = buf + hint->hdrs_len;
	avail = mss;
	lim = sbuf->iovcnt;
	off = sbuf->offset;
	for (i = sbuf->cur_idx; i < lim; i++) {
		char *src = data_p[i].iov_base + off;
		u_int len = data_p[i].iov_len - off;

		prefetch(p);
		if (avail < len) {
			pkt_copy(src, p, avail);
		//	memcpy(p, src, avail);
			off += avail;
			avail = 0;
			break;
		}
//		memcpy(p, src, len);
		pkt_copy(src, p, len);
		avail -= len;
		p += len;
		off = 0;
	}
	sbuf->cur_idx = i;
	sbuf->offset = off;

	i = mss - avail;
	iph->ip_len = htons(iphlen + tcphlen + i);
	/*
	if (!(pktflags & PKT_CONF_NOSADDR))
		iph->ip_sum = 0xffff ^
			ipv4_csum((uint16_t *)iph, sizeof(struct ip));
			*/
	/*
	if (!(pktflags & PKT_CONF_NOTCPCSUM))
	*/
#ifdef TCP_PROFILE
	ck_start = rdtsc();
#endif
	tcph->th_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph,
			tcphlen + i, iph->ip_src.s_addr, iph->ip_dst.s_addr,
			IPPROTO_TCP);
	/*
	tcph->th_sum = wrapsum(checksum(tcph, sizeof(*tcph),
		    checksum(buf + hint->hdrs_len, i,
			checksum(&iph->ip_src, 2 * sizeof(iph->ip_src),
			    IPPROTO_TCP + (u_int32_t)(tcphlen + i))
			)
		    )
		);
		*/

#ifdef TCP_PROFILE
	add_to_current(chk_stat, ck_start);
	add_to_current(seg_stat, seg_start);
#endif

	return i;
}

/*
 * Create header template - no IP or TCP options
 * XXX Timestamp should be here?
 */
void
tcp_v4_hint_from_response(pkt_t *hint, pkt_t *res)
{
	char *p;
	int len;

	p = hint->buf;
	len = hint->hdrs_len = DEFAULT_V4TCP_HDRS_SIZ;
	pkt_bzero(p, len);
	write_ether4_header(p, res->eth->ether_dhost, res->eth->ether_shost);
	hint->eth = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);

	/* checksum is by MiniStack, but we need source address */
	write_ipv4_header(p, len, res->nh.iph->ip_dst.s_addr,
			res->nh.iph->ip_src.s_addr,
			IPPROTO_TCP, 0);
	hint->nh.iph = (struct ip *)p;
	hint->nh.iph->ip_sum = 0;
	p += sizeof(struct ip);
	len -= sizeof(struct ip);

	write_tcp_header(p, ntohs(res->th.tcph->th_dport),
		ntohs(res->th.tcph->th_sport), 0, 0, TH_ACK, 0, NULL, 0);
	hint->th.tcph = (struct tcphdr *)p;
}

/* Returns bytes of data composed */
int
tcp_make_v4_tcb(char *buf, pkt_t *hint, struct prot_cb *tcb, char *data, u_int datalen, u_int mss)
{
	char *p;
	int len, tlen;
	struct tcphdr *tcph;
	struct ip *r_iph;
	struct tcp_cb *tcpcb = (struct tcp_cb *)tcb;

	r_iph = hint->nh.iph;
	len = min(DEFAULT_V4TCP_HDRS_SIZ + mss,
			DEFAULT_V4TCP_HDRS_SIZ + tcpcb->optlen + datalen);
	pkt_bzero(buf, len);
	p = buf;
	write_ether4_header(p, hint->eth->ether_dhost, hint->eth->ether_shost);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv4_header(p, len, r_iph->ip_dst.s_addr, r_iph->ip_src.s_addr,
			IPPROTO_TCP, PKT_CONF_NOSADDR);
	p += sizeof(struct ip);
	len -= sizeof(struct ip);

	write_tcp_header(p, tcpcb->sport, tcpcb->dport,
			tcpcb->seqno, tcpcb->ackno, tcpcb->flags,
			tcpcb->awnd, tcpcb->opt, tcpcb->optlen);

	tcph = (struct tcphdr *)p;
	tlen = len; // used later for checksum calculation
	p += sizeof(struct tcphdr) + tcpcb->optlen;
	len -= sizeof(struct tcphdr) + tcpcb->optlen;
	if (len)
		bcopy(data, p, len);

	tcph->th_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph, tlen,
		r_iph->ip_dst.s_addr, r_iph->ip_src.s_addr, IPPROTO_TCP);

	tcpcb->seqno += len;
	return len;
}

/*
 * Send a response packet, like ACK (for data and FIN) and RST
 * No data can be given
 * To provide our window and flags, modify pkt's ones.
 */
int
tcp_make_v4_response(char *buf, pkt_t *pkt, char *opt, int optlen)
{
	char *p;
	int len;
	struct tcphdr *tcph, *r_tcph;
	struct ip *r_iph;

	r_tcph = pkt->th.tcph;
	r_iph = pkt->nh.iph;

	len = DEFAULT_V4TCP_HDRS_SIZ + optlen;
	pkt_bzero(buf, len);
	p = buf;
	write_ether4_header(p, pkt->eth->ether_dhost, pkt->eth->ether_shost);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv4_header(p, len, r_iph->ip_dst.s_addr, r_iph->ip_src.s_addr,
			IPPROTO_TCP, PKT_CONF_NOSADDR);
	p += sizeof(struct ip);
	len -= sizeof(struct ip);

	write_tcp_header(p, ntohs(r_tcph->th_dport), ntohs(r_tcph->th_sport),
			ntohl(r_tcph->th_ack), ntohl(r_tcph->th_seq) +
			pkt->datalen, r_tcph->th_flags, ntohs(r_tcph->th_win),
			opt, optlen);

	tcph = (struct tcphdr *)p;
	tcph->th_sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph, len,
		r_iph->ip_dst.s_addr, r_iph->ip_src.s_addr, IPPROTO_TCP);
	return len;
}

void
tcp_make_v4_synack(char *buf, pkt_t *syn, uint32_t isn, uint16_t mss)
{
	uint32_t mssopt;

	mssopt = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss);
	syn->th.tcph->th_ack = htonl(isn);
	syn->datalen = 1; /* to advance ACK number */
	syn->th.tcph->th_flags = TH_SYN | TH_ACK;
	syn->th.tcph->th_win = DEFAULT_AWND;
	tcp_make_v4_response(buf, syn, (char *)&mssopt, TCPOLEN_MSS);
}


int
make_tcp6_segment(char *buf, size_t pktlen, struct prot_cb *lcb,
		struct prot_cb *ncb, struct prot_cb *tcb,
		const char *payload, int payloadlen, uint32_t pktflags)

{
	struct ether_cb *ecb = (struct ether_cb *)lcb;
	struct ipv6_cb *ip6cb = (struct ipv6_cb *)ncb;
	struct tcp_cb *tcpcb = (struct tcp_cb *)tcb;
	struct tcphdr *tcph;
	char *p;
	size_t len = pktlen;
	size_t tlen;
	int j, l, l0 = payloadlen;

	pkt_bzero(buf, pktlen);
	p = buf;
	write_ether6_header(p, ecb->sether, ecb->dether);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	write_ipv6_header(p, len, &ip6cb->saddr, &ip6cb->daddr, IPPROTO_TCP,
			pktflags);
	p += 40;
	len -= 40;
	write_tcp_header(p, tcpcb->sport, tcpcb->dport, tcpcb->seqno,
			tcpcb->ackno, tcpcb->flags, tcpcb->awnd, tcpcb->opt,
			tcpcb->optlen);
	tcph = (struct tcphdr *)p;
	tlen = len;
	p += sizeof(struct tcphdr);
	len -= (sizeof(struct tcphdr) + tcpcb->optlen);

	for (j = 0; j < len;) {
		l = min(l0, len - j);
		bcopy(payload, p + j, l);
		j += l;
	}
	p[j-1] = '\0';

	if (!(pktflags & PKT_CONF_NOTCPCSUM))
		tcph->th_sum = 0xffff ^ csum_pseudohdr6_data((uint16_t *)tcph,
			tlen, &ip6cb->saddr, &ip6cb->daddr, IPPROTO_TCP);
	tcpcb->seqno = htonl(ntohl(tcpcb->seqno) + len);
	return 0;
}

int
make_packet(char *buf, size_t pktlen, struct prot_cb *ethcb,
		struct prot_cb *ipcb, struct prot_cb *tcb,
		const char *payload, int payloadlen, uint32_t pktflags)
{
	if (ipcb->myprot == AF_INET) {
		if (ipcb->prot == IPPROTO_UDP)
			return make_udp4_dgram(buf, pktlen, ethcb, ipcb,
					tcb, payload, payloadlen, pktflags);
		else if (ipcb->prot == IPPROTO_TCP)
			return make_tcp4_segment(buf, pktlen, ethcb, ipcb,
					tcb, payload, payloadlen, pktflags);
	} else if (ipcb->myprot == AF_INET6) {
		if (ipcb->prot == IPPROTO_UDP)
			return make_udp6_dgram(buf, pktlen, ethcb, ipcb,
					tcb, payload, payloadlen, pktflags);
		else if (ipcb->prot == IPPROTO_TCP)
			return make_tcp6_segment(buf, pktlen, ethcb, ipcb,
					tcb, payload, payloadlen, pktflags);
	}
	return -1;
}

int tcp4_input(char *buf, struct prot_cb *ncb, struct prot_cb *tcb, int *err)
{
	uint16_t ether_type;
	struct tcp_cb *tcpcb = (struct tcp_cb *)tcb;
	int advanced = 0, i, tlen = 0;
	struct tcphdr *th = NULL;
	struct ip *iph = (struct ip *)(buf + ETHER_HDR_LEN);
		int hlen, off;

	ether_type = ntohs(*((uint16_t *)(buf + 12)));
	if (unlikely(ether_type != 0x0800)) {
		*err = -1;
		return 0;
	}
        if (unlikely(iph->ip_hl != 5)) {
		printf("bad packet\n");
		*err = -1;
		return 0; /* XXX */
	}
	hlen = iph->ip_hl << 2;
	tlen = ntohs(iph->ip_len);
	th = (struct tcphdr *)(iph+1);
	off = th->th_off << 2;
	if (off < sizeof(struct tcphdr) || off > tlen) {
		printf("bad packet\n");
		*err = -1;
		return 0;
	}
	tlen -= hlen;
	tlen -= off;

	/* here tlen is the length of payload */
	printf("we expect next to receive %u, act receiving %d\n", tcpcb->rcv_next, ntohl(th->th_seq));
	if (tcpcb->rcv_next == 0 || ntohl(th->th_seq) == tcpcb->rcv_next) {
		if (tcpcb->rcv_next == 0)
			tcpcb->rcv_next = ntohl(th->th_seq);
		tcpcb->rcv_next += tlen;
		advanced++;
		for (i = 0; i < sizeof(tcpcb->gap) >> 2; ++i) {
			if (tcpcb->gap[i] && tcpcb->gap[i] == tcpcb->rcv_next) {
				tcpcb->rcv_next += tcpcb->gapsiz[i];
				printf("gap seqno %u-%u is filled\n",
					tcpcb->gap[i],
					tcpcb->gap[i] + tcpcb->gapsiz[i]);
				tcpcb->gap[i] = tcpcb->gapsiz[i] = 0;
				advanced++;
			}
		}
		return advanced;
	} else {
		for (i = 0; i < sizeof(tcpcb->gap) >> 2; ++i) {
			if (tcpcb->gap[i] == 0) {
				tcpcb->gap[i] = ntohl(th->th_seq);
				tcpcb->gapsiz[i] = tlen;
				printf("gap seqno %u-%u is appended\n",
					tcpcb->gap[i],
					tcpcb->gap[i] + tcpcb->gapsiz[i]);
				return 0;
			}
		}
		printf("gap queue is full, dropping seqno %u-%u \n",
				ntohl(th->th_seq), ntohl(th->th_seq)+tlen);
	}
	return advanced;
}


/* From the kernel */
static int
tcp_dump_seqno(uint8_t *buf, uint32_t *seq, uint32_t *endseq)
{
	struct ip *iph;
	uint16_t ether_type;
	char *tcphdr;
	uint32_t *seq_p;

	ether_type = ntohs(*((uint16_t *)(buf + ETHER_TYPE_OFF)));
	if (ether_type != 0x0800) {
		return -1;
	}
	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	if (unlikely(iph->ip_hl != 5)) {
		return -1;
	}
	tcphdr = (char *)(iph+1);
	if (unlikely((tcphdr[12] >> 4) != 5)) {
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
int
dump_pkts_rxring(struct netmap_ring *ring)
{
	u_int k = ring->cur;
	int lim, scanned = 0, j;
	uint32_t seq=0, endseq=0, tot_seq=0, tot_endseq=0;
	int num_pkts=0;
	int validpkt=0;
	int p;

	lim = ring->num_slots - 1;
	k = ring->cur + ring->avail;
	if (k > lim)
		k -= lim;
	for (j = ring->cur; likely(j != k); j = unlikely(j == lim) ? 0 : j+1) {
		struct netmap_slot *slot = &ring->slot[j];
		char *buf = NETMAP_BUF(ring, slot->buf_idx);
		int len = slot->len;

		scanned++;
		if (unlikely(len < 14))
			continue;
		p = proto_number((uint8_t *)buf);
		if (p > 0)
			validpkt++;
		if (p != IPPROTO_TCP) {
			if (validpkt%256 == 0)
				fprintf(stderr, "proto number %u", p);
			continue;
		}
		if (tcp_dump_seqno((uint8_t *)buf, &seq, &endseq) < 0) {
			fprintf(stderr, "invalid TCP packet\n");
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
			fprintf(stdout, "seq %u-%u by %d pkts in %d slots\n",tot_seq, tot_endseq, num_pkts, scanned);
			tot_seq = tot_endseq = 0;
			num_pkts = 0;
		}
	}
	if (num_pkts)
		fprintf(stdout, "seq %u-%u by %d pkts in %d slots\n", tot_seq,
				tot_endseq, num_pkts, scanned);
	return scanned;
}

struct prot_cb *
ethcb_new(const char *saddr, const char *daddr, int nproto)
{
	struct ether_cb *ecb;
	ecb = (struct ether_cb *)malloc(sizeof(*ecb));
	if (!ecb)
		return NULL;
	ecb->myprot = 0xFF;
	ecb->prot = nproto;
	memcpy(ecb->dether, ether_aton(daddr), ETHER_ADDR_LEN);
	memcpy(ecb->sether, ether_aton(saddr), ETHER_ADDR_LEN);
	return (struct prot_cb *)ecb;
}

struct prot_cb *
ipv4cb_new(const char *saddr, const char *daddr, int tproto)
{
	struct ipv4_cb *ip4cb;

	ip4cb = (struct ipv4_cb *)malloc(sizeof(*ip4cb));
	if (!ip4cb)
		return NULL;
	ip4cb->myprot = AF_INET;
	ip4cb->prot = tproto;
	if (saddr)
		inet_pton(AF_INET, saddr, &ip4cb->saddr.s_addr);
	if (daddr)
		inet_pton(AF_INET, daddr, &ip4cb->daddr.s_addr);
	return (struct prot_cb *)ip4cb;
}

struct prot_cb *
ipv6cb_new(const char *saddr, const char *daddr, int tproto)
{
	struct ipv6_cb *ip6cb;
	ip6cb = (struct ipv6_cb *)malloc(sizeof(*ip6cb));
	if (!ip6cb)
		return NULL;
	bzero(ip6cb, sizeof(*ip6cb));
	ip6cb->myprot = AF_INET6;
	ip6cb->prot = tproto;
	inet_pton(AF_INET6, saddr, &ip6cb->saddr);
	inet_pton(AF_INET6, daddr, &ip6cb->daddr);
	return (struct prot_cb *)ip6cb;
}

struct prot_cb *
udpcb_new(uint16_t sport, uint16_t dport)
{
	struct udp_cb *ucb;

	ucb = (struct udp_cb *)malloc(sizeof(*ucb));
	bzero(ucb, sizeof(*ucb));
	ucb->myprot = IPPROTO_UDP;
	ucb->sport = htons(sport);
	ucb->dport = htons(dport);
	return (struct prot_cb *)ucb;
}

struct prot_cb *
tcpcb_new(uint16_t sport, uint16_t dport, uint32_t seqno, uint32_t ackno, uint16_t flags, uint16_t awnd, char *opt, int optlen)
{
	struct tcp_cb *tcb;

	tcb = (struct tcp_cb *)malloc(sizeof(*tcb));
	bzero(tcb, sizeof(*tcb));
	tcb->myprot = IPPROTO_TCP;
	tcb->sport = sport;
	tcb->dport = dport;
	tcb->seqno = seqno;
	tcb->ackno = ackno;
	tcb->flags = flags;
	tcb->awnd = awnd;
	tcb->optlen = optlen;
	if (tcb->optlen)
		memcpy(tcb->opt, opt, tcb->optlen);
	return (struct prot_cb *)tcb;
}

/* XXX now only IPv4 */
#define PRINT_PKT_ETHER 0x01
void
print_pkt(char *pkt, uint8_t level)
{
	struct ether_header *eth;
	uint16_t eth_type;
	char saddr_str[40], daddr_str[40], pkt_str[256], *p;
	u_int pktsiz, iphsiz;

	bzero(saddr_str, sizeof(saddr_str));
	bzero(daddr_str, sizeof(daddr_str));
	bzero(pkt_str, sizeof(pkt_str));
	p = pkt_str;

	eth = (struct ether_header *)pkt;
	if (level & PRINT_PKT_ETHER) {
		/*
		p += sprintf(p, "%s -> %s ",
			ether_ntoa((struct ether_addr *)eth->ether_shost),
			ether_ntoa((struct ether_addr *)eth->ether_dhost));
			*/
		/* XXX Don't know why, but above doesn't work... */
		p += sprintf(p, "%s -> ",
			ether_ntoa((struct ether_addr *)eth->ether_shost));
		p += sprintf(p, "%s ",
			ether_ntoa((struct ether_addr *)eth->ether_dhost));
	}
	eth_type = ether_type(pkt);
	if (eth_type == 0x0800) { /* IPv4 */
		struct ip *iph;

		iph = (struct ip *)(pkt + ETHER_HDR_LEN);
		inet_ntop(AF_INET, &iph->ip_src, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET, &iph->ip_dst, daddr_str, sizeof(daddr_str));
		pktsiz = ntohs(iph->ip_len);
		iphsiz = iph->ip_hl << 2;

		if (iph->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcph;

			tcph = (struct tcphdr *)ip_nexthdr(iph);
			p += sprintf(p, "%s:%u -> %s:%u iphl %u %s flags 0x%02x seq %u ack %u off %u length %u\n",
				saddr_str, ntohs(tcph->th_sport),
				daddr_str, ntohs(tcph->th_dport), iphsiz,
				"tcp", tcph->th_flags, ntohl(tcph->th_seq),
				ntohl(tcph->th_ack), tcph->th_off << 2, pktsiz);
		} else if (iph->ip_p == IPPROTO_UDP) {
			struct udphdr *udph;

			udph = (struct udphdr *)ip_nexthdr(iph);
			p += sprintf(p, "%s:%u -> %s:%u iphl %u %s length %u \n",
				saddr_str, ntohs(udph->uh_sport), daddr_str,
				ntohs(udph->uh_dport), iphsiz, "udp", pktsiz);
		} else if (iph->ip_p == IPPROTO_ICMP) {
			/* XXX */
		}
	} else if (eth_type == 0x86DD) {
		p += sprintf(p, "IPv6 packet");
	} else {
		p += sprintf(p, "Unknown packet (0x%04x)", eth_type);
	}
	fprintf(stdout, "%s\n", pkt_str);
}

int
ipv4_tcp_pkt(char *buf, pkt_t *pkt, int nocsum)
{
	struct ip *iph;
	struct tcphdr *tcph;
	char *data;
	int iph_len, tcph_len, tlen;
	uint16_t sum=0, recvsum=0;

	iph = (struct ip *)(buf + ETHER_HDR_LEN);
	iph_len = iph->ip_hl << 2;
	tcph = (struct tcphdr *)(((uint8_t *)iph) + iph_len);
	tlen = ntohs(iph->ip_len) - iph_len;
	tcph_len = tcph->th_off << 2;
	data = ((char *)tcph) + tcph_len;

	recvsum = tcph->th_sum;
	tcph->th_sum = 0;
	if (!nocsum) {
		sum = 0xffff ^ csum_pseudohdr_data((uint16_t *)tcph, tlen,
			iph->ip_src.s_addr, iph->ip_dst.s_addr, IPPROTO_TCP);
		if (unlikely(sum != recvsum))
			return -1;
	}
	pkt->buf = buf;
	pkt->eth = (struct ether_header *)buf;
	pkt->nh.iph = iph;
	pkt->th.tcph = tcph;
	pkt->hdrs_len = ETHER_HDR_LEN + iph_len + tcph_len;
	pkt->data = data;
	pkt->datalen = tlen - tcph_len;
	return 0;
}

int msstab[8] = {512, 1096, 1160, 1224, 1288, 1352, 1416, 1460};
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

uint32_t
rthash(uint8_t *addr, uint8_t *port, u_int mask)
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
	return (c & mask-1);
}

static __inline uint32_t
tcp_cookie_hash(uint8_t *raddr, uint8_t *laddr, uint16_t rport,
		uint16_t lport, uint32_t t)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	p = (uint8_t *)&rport;
	b += p[1] << 16;
	b += p[0] << 8;
	p = raddr;
	b += p[3];
	b += p[2] << 24;
	b += p[1] << 16;
	b += p[0] << 8;

	p = (uint8_t *)&lport;
	a += p[1] << 16;
	a += p[0] << 8;
	p = laddr;
	a += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	a += t;
#define TCP_SYN_COOKIE_MASK (24-1)
	mix(a, b, c);
	return (c & TCP_SYN_COOKIE_MASK);
}

static uint32_t
tcp_syn_cookie(uint8_t *raddr, uint8_t *laddr, uint16_t rport, uint16_t lport, uint32_t t, uint32_t mssind)
{
	uint32_t hashed;

	hashed = tcp_cookie_hash(raddr, laddr, rport, lport, t);
	return ((t%32) << 27 | mssind << 24 | hashed);
}

/* if valid, returns MSS value */
uint16_t
tcp_v4_cookie_valid(pkt_t *ack, uint32_t tsec)
{
	struct ip *iph = ack->nh.iph;
	struct tcphdr *tcph = ack->th.tcph;
	uint32_t hashval, rcvd_cookie;
	uint8_t mssind;

	rcvd_cookie = ntohl(tcph->th_ack) - 1;
	if ((tsec >> 6)%32 != rcvd_cookie >> 27)
		return 0; /* cookie expired */

	hashval = tcp_cookie_hash((uint8_t *)&iph->ip_src, (uint8_t *)&iph->ip_dst, tcph->th_sport, tcph->th_dport, tsec >> 6);
	if (hashval != (rcvd_cookie & 0x00FFFFFF))
		return 0; /* invalid cookie */
	mssind = ((rcvd_cookie << 5) >> 29);
	return msstab[mssind];
}

/* Based on Linux kernel (mssp is received option in request socket) */
uint32_t
tcp_syncookie_sequence(struct ip *iph, struct tcphdr *tcph, uint32_t tsec, uint16_t *mssp)
{
	int mssind;
	const uint16_t mss = *mssp;

	for (mssind = sizeof(msstab)/sizeof(int) - 1; likely(mssind) ; mssind--)
		if (mss >= msstab[mssind])
			break;
	*mssp = msstab[mssind];

	/* Taken from Linux kernel, but we don't use sseq */
	return tcp_syn_cookie((uint8_t *)&iph->ip_src,
			(uint8_t *)&iph->ip_dst, tcph->th_sport,
			tcph->th_dport, tsec >> 6, mssind);
}

/* Should I optimize it? */
struct tcp_cb *
tcp_find_established(pkt_t *pkt, struct pcb_channel *pcbc)
{
	struct tcp_cb *tcb;
	uint32_t hashval;

	hashval = rthash((uint8_t *)&pkt->nh.iph->ip_src.s_addr,
			(uint8_t *)&pkt->th.tcph->th_sport, TCP_TCBHASHSIZ);
#ifdef TCP_TCB_LIST
	LIST_FOREACH(tcb, &pcbc->inuse_list[hashval], list_next)
#else
	TAILQ_FOREACH(tcb, &pcbc->inuse_tailq[hashval], tailq_next)
#endif
		if (tcp_v4_dst_match(pkt, tcb))
			return tcb;
	return NULL;
}


uint16_t *
tcp_mssp_slowpath(struct tcphdr *tcph)
{
	char *p;
	int length;

	length = (int)(tcph->th_off << 2) - sizeof(struct tcphdr);

	D("slowpath to obtain MSS");
	p = (char *)(tcph + 1);
	while (length > 0) {
		int opcode = *p++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *p++;
			if (opsize < 2)
				return NULL;
			else if (opsize > length)
				return NULL;
			if (opcode == TCPOPT_MSS)
				return (uint16_t *)p;
			p += opsize-2;
			length -= opsize;
		}
	}
	return NULL;
}

/*
 * If no seqno is given, hint's one is used.  ackno is by default 0, but
 * overwritten if it is given.
 */
void
tcp_make_v4_rst(char *buf, pkt_t *recvd, uint32_t seqno, uint32_t ackno)
{
	/* We don't cumulatively ack recvd */
	recvd->datalen = 0;
	/* The ACK number of the recvd is used unless explicitly given */
	if (seqno)
		recvd->th.tcph->th_ack = htonl(seqno);
	/* Ack number is zero unless otherwise specified */
	recvd->th.tcph->th_seq = ackno ? htonl(ackno): htonl(0);

	recvd->th.tcph->th_win = 0; /* XXX */
	recvd->th.tcph->th_flags = ackno ? (TH_ACK|TH_RST) : TH_RST;
	tcp_make_v4_response(buf, recvd, NULL, 0);
}

/* NULL is returned if no available TCB */
struct tcp_cb *
tcp_v4_accept(pkt_t *ack, struct pcb_channel *pcbc, uint16_t mss)
{
	struct tcp_cb *tcb;
	uint32_t hashval;

#ifdef TCP_TCB_LIST
	tcb = LIST_FIRST(&pcbc->avail_list);
#else
	tcb = TAILQ_FIRST(&pcbc->avail_tailq);
#endif
#ifdef TCP_TCB_LIST
	LIST_REMOVE(tcb, list_next);
#else
	TAILQ_REMOVE(&pcbc->avail_tailq, tcb, tailq_next);
#endif
	pcbc->num_avail--;

	tcp_init_tcb_from_ack(tcb, ack, mss, &pcbc->ts);
	hashval = rthash((uint8_t *)&ack->nh.iph->ip_src.s_addr,
			(uint8_t *)&ack->th.tcph->th_sport, TCP_TCBHASHSIZ);
	tcb->myhash = hashval;
#ifdef TCP_TCB_LIST
	LIST_INSERT_HEAD(&pcbc->inuse_list[hashval], tcb, list_next);
#else
	TAILQ_INSERT_TAIL(&pcbc->inuse_tailq[hashval], tcb, tailq_next);
#endif
	pcbc->num_inuse++;
	tcb->pcbc = pcbc;
	return tcb;
}

/* str must have enough length */
void
tcp_print_tcb(struct tcp_cb *tcb, char *str)
{
	char saddr_str[18], daddr_str[18];
	pkt_t *hint = &tcb->hint;

	inet_ntop(AF_INET, &hint->nh.iph->ip_dst, saddr_str, sizeof(saddr_str));
	inet_ntop(AF_INET, &hint->nh.iph->ip_src, daddr_str, sizeof(daddr_str));
	sprintf(str, "%s:%u->%s:%u snd_una %u snd_nxt %u rcv_nxt %u", saddr_str, tcb->sport, daddr_str, tcb->dport, tcb->snd_una, tcb->seqno, tcb->ackno);
	return;
}

void
init_sendbuf(struct sendbuf *sbuf, struct iovec *data_p, int iov_cnt)
{
	int i, unsent = 0;

	sbuf->iovcnt = iov_cnt;
	sbuf->cur_idx = 0;
	sbuf->offset = 0;

	for (i = 0; i < iov_cnt; ++i)
		unsent += data_p[i].iov_len;
	sbuf->unsent = unsent;
	sbuf->data_p = data_p;
}

int
tcp_attach_sendbuf(struct tcp_cb *tcb, struct iovec *data, int iov_cnt)
{
	bzero(&tcb->data, sizeof(struct sendbuf));
	init_sendbuf(&tcb->data, data, iov_cnt);
	return 0;
}

void
tcp_free_tcbs(struct pcb_channel *pcbc)
{
	struct tcp_cb *tcb;
	int i;

#ifdef TCP_TCB_LIST
	LIST_FOREACH(tcb, &pcbc->avail_list, list_next)
#else
	TAILQ_FOREACH(tcb, &pcbc->avail_tailq, tailq_next)
#endif
		free(tcb);
	for (i = 0; i < TCP_TCBHASHSIZ; i++) {
#ifdef TCP_TCB_LIST
		LIST_FOREACH(tcb, &pcbc->inuse_list[i], list_next)
#else
		TAILQ_FOREACH(tcb, &pcbc->inuse_tailq[i], tailq_next)
#endif
			free(tcb);
	}
}

void
tcp_release_tcb(struct tcp_cb *tcb)
{
	struct pcb_channel *pcbc = tcb->pcbc;

#ifdef TCP_TCB_LIST
	LIST_REMOVE(tcb, list_next);
#else
	TAILQ_REMOVE(&pcbc->inuse_tailq[tcb->myhash], tcb, tailq_next);
#endif
	pcbc->num_inuse--;
#ifdef TCP_TCB_LIST
	LIST_INSERT_HEAD(&pcbc->avail_list, tcb, list_next);
#else
	TAILQ_INSERT_TAIL(&pcbc->avail_tailq, tcb, tailq_next);
#endif
	pcbc->num_avail++;
}

int
tcp_prealloc_tcbs(int num, int pcbsiz, struct pcb_channel *pcbc)
{
	struct tcp_cb *tcb;
	int i;

#ifdef TCP_TCB_LIST
	LIST_INIT(&pcbc->avail_list);
#else
	TAILQ_INIT(&pcbc->avail_tailq);
#endif
	for (i = 0; i < num; i++) {
		tcb = (struct tcp_cb *)calloc(1, pcbsiz);
		if (!tcb) {
			D("failed to allocate dcb's structure");
#ifdef TCP_TCB_LIST
			LIST_FOREACH(tcb, &pcbc->avail_list, list_next)
#else
			TAILQ_FOREACH(tcb, &pcbc->avail_tailq, tailq_next)
#endif
				free(tcb);
			return ENOMEM;
		}
		/* XXX */
		tcb->pcbc = pcbc;
#ifdef TCP_TCB_LIST
		LIST_INSERT_HEAD(&pcbc->avail_list, tcb, list_next);
#else
		TAILQ_INSERT_TAIL(&pcbc->avail_tailq, tcb, tailq_next);
#endif
	}
	pcbc->num_tcbs = pcbc->num_avail = num;
	pcbc->num_inuse = 0;

	for (i = 0; i < TCP_TCBHASHSIZ; ++i)
#ifdef TCP_TCB_LIST
		LIST_INIT(&pcbc->inuse_list[i]);
#else
		TAILQ_INIT(&pcbc->inuse_tailq[i]);
#endif

	return 0;
}

#ifdef TCPLIB_NETMAP
/* Common to send data packets and pure FIN packet */
int
netmap_tcp_output(struct tcp_cb *tcb, pkt_t *hint, struct sendbuf *data,
		struct netmap_ring *txring)
{
	char *p = NULL;
	struct netmap_slot *slot;
	u_int cur = txring->cur;
	u_int count, unsent, sent, total_sent = 0;
	u_int win;
	u_int mss;
	struct tcphdr *tcph;
	int might_fin = 1;

	if (!txring->avail) {
		D("no avail, return");
		return 0;
	}

#ifdef DEBUG
	if (unlikely(tcb->cwnd < tcb->flight))
		D("funny, cwnd (%u) < flight (%u)", tcb->cwnd, tcb->flight);
#endif
	win = tcb->cwnd - tcb->flight;
	if (unlikely(win > tcb->peer_awnd)) {
#ifdef DEBUG
		D("bounced by the flow control %u <- %u", tcb->peer_awnd, win);
#endif
		win = tcb->peer_awnd;
	}
	unsent = data->unsent;
	if (unsent > win) {
		unsent = win;
		might_fin = 0;
	}

	/* If unsent is 0, we will send pure ack or FIN */
	tcph = hint->th.tcph;
	tcph->th_win = htons(tcb->awnd);
	tcph->th_ack = htonl(tcb->ackno);
	mss = tcb->peer_mss;
	for (count = 0;;) {
		slot = &txring->slot[cur];
		p = NETMAP_BUF(txring, slot->buf_idx);
		/* Linux transmit FIN | PSH with the final data, while FreeBSD
		 * sends a separate FIN packet.
		 */
		if (might_fin && unsent <= mss) {
			if (likely(unsent))
				tcph->th_flags |= TH_PUSH;
			if (!is_tcp_separate_fin(tcb) ||
			    (is_tcp_separate_fin(tcb) && !unsent))
				tcph->th_flags |= TH_FIN;
		}

		tcph->th_seq = htonl(tcb->seqno);

		/* data offset is updated in tcp_v4_segment() */
		sent = tcp_v4_segment(p, hint, data, mss);
		tcb->seqno += sent;
		unsent -= sent;
		slot->len = hint->hdrs_len + sent;
		cur = NETMAP_RING_NEXT(txring, cur);
		total_sent += sent;
		if (++count == txring->avail || !unsent) {
			slot->flags |= NS_REPORT;
			break;
		}
	}
	tcb->flight += total_sent;
	if (tcph->th_flags & TH_FIN)
		tcb->seqno++;
	tcph->th_flags &= ~(TH_PUSH | TH_FIN);
	data->unsent -= total_sent;

	txring->avail -= count;
	txring->cur = cur;
//	D("sent (snd_una %u snd_nxt %u flight %u / cwnd %u, data_off %u / eof_off %u)", dcb->snd_una, dcb->seqno, dcb->flight, dcb->cwnd, dcb->data_off, dcb->eof_off);
#ifdef DEBUG
	if (tcb->flight > tcb->cwnd)
		D("finished, something is funny (flight %u cwnd %u)", tcb->flight, tcb->cwnd);
#endif
	return total_sent;
}

int
netmap_tcp_finack(pkt_t *fin, struct netmap_ring *txring)
{
	char *p = NULL;
	struct netmap_slot *slot;

	if (!txring->avail) {
		D("no avail, return");
		return 0;
	}

	slot = &txring->slot[txring->cur];
	p = NETMAP_BUF(txring, slot->buf_idx);
	fin->datalen = 1; /* to advance ack */
	fin->th.tcph->th_flags = TH_ACK;
	tcp_make_v4_response(p, fin, NULL, 0);
	slot->len = DEFAULT_V4TCP_HDRS_SIZ;
	txring->cur = NETMAP_RING_NEXT(txring, txring->cur);
	txring->avail--;
	return 0;
}

int
netmap_tcp_tcbreset(struct tcp_cb *tcb, struct netmap_ring *txring)
{
	char *p = NULL;
	struct netmap_slot *slot;
	struct sendbuf *sbuf = &tcb->data;
	pkt_t *hint = &tcb->hint;

	if (!txring->avail) {
		D("no avail, return");
		return 0;
	}

	slot = &txring->slot[txring->cur];
	p = NETMAP_BUF(txring, slot->buf_idx);

	/*
	 * XXX what the sequence number should be ?
	 *
	 * If we assume the last ACK is lost snd_nxt is correct.
	 * But in this case, if we filled up the receiver's window, snd_nxt is
	 * wrong. This condition must be checked, and if applied snd_nxt - 1
	 * would be safe.  But peer's awnd might be incorrect already.
	 *
         * If we assume the last segments are lost and acks sent from the
	 * receiver are all received, snd_una is correct.
	 * In this case, the last_ack_sent of the receiver might be sent again
	 * Then our ootb reset will send correct RST.
	 * Therefore we take this choice at this point
	 */
	hint->th.tcph->th_seq = htonl(tcb->snd_una);
	hint->th.tcph->th_ack = 0;
	hint->th.tcph->th_win = 0;
	hint->th.tcph->th_flags = TH_RST;
	tcp_v4_segment(p, hint, sbuf, 0);
//	print_pkt(p, 0);
//	tcp_make_v4_rst(p, &tcb->hint, tcb->seqno, 0);
	slot->len = DEFAULT_V4TCP_HDRS_SIZ;
	txring->cur = NETMAP_RING_NEXT(txring, txring->cur);
	txring->avail--;
	return 0;
}

int
netmap_tcp_synack(pkt_t *syn, struct netmap_ring *txring, uint32_t tsec)
{
	char *p = NULL;
	uint16_t default_mss = msstab[0];
	uint16_t *mssp = &default_mss;
	uint32_t isn;
	struct tcphdr *tcph = syn->th.tcph;
	struct netmap_slot *slot;

	/* XXX Should be checked earlier ? */
	if (!txring->avail) {
		D("no avail, return");
		return -1;
	}

	if (likely(tcph->th_off << 2 > DEFAULT_TCPHDR_SIZ)) {
		p = (char *)(tcph + 1);
		if (likely(*p == TCPOPT_MSS))
			mssp = (uint16_t *)(p + 2);
		else /* slow path */
			mssp = tcp_mssp_slowpath(tcph);
	}
	isn = tcp_syncookie_sequence(syn->nh.iph, tcph, tsec, (uint16_t *)mssp);
	/* Directly compose SYN-ACK to a slot */
	slot = &txring->slot[txring->cur];
	p = NETMAP_BUF(txring, slot->buf_idx);
	tcp_make_v4_synack(p, syn, isn, *mssp);

	slot->len = DEFAULT_V4TCP_HDRS_SIZ + TCPOLEN_MSS;
	txring->cur = NETMAP_RING_NEXT(txring, txring->cur);
	txring->avail--;
	return 0;
}

int
netmap_tcp_ootb(pkt_t *pkt, struct netmap_ring *txring)
{
	struct netmap_slot *slot;
	char *p;

	if (!txring->avail) {
		D("no avail, return");
		return -1;
	}
	slot = &txring->slot[txring->cur];
	p = NETMAP_BUF(txring, slot->buf_idx);
	tcp_make_v4_rst(p, pkt, 0, 0);
//	print_pkt(p, 0x01);
	slot->len = DEFAULT_V4TCP_HDRS_SIZ;

	txring->cur = NETMAP_RING_NEXT(txring, txring->cur);
	txring->avail--;
	return 0;
}

int
tcp_input_established(struct tcp_cb *tcb, pkt_t *pkt, struct netmap_ring *txring, int *status)
{
	struct sendbuf *data = &tcb->data;
	pkt_t *hint = &tcb->hint;
	uint32_t ack, ack_advanced;
	u_int got_fin;
#ifdef TCP_PROFILE /* XXX */
	int sent = 0;
	uint64_t start;
	struct clockstat *stat = &tcb->pcbc->clstat[TCP_PROF_SEGMENT];
#endif

	if (pkt->th.tcph->th_flags & TH_RST) {
//		dttcp_cb_release(tcb);
		*status = TCP_INPUT_RST;
		return 0;
	}
	got_fin = pkt->th.tcph->th_flags & TH_FIN;

	/*
	 * Algorithm to detect packet loss.
	 * To deal with an ACK reordering case, we accept ACK < snd_nxt
	 * We just detect ACK of snd_una.
	 * On receiving ACK < snd_nxt, we keep sending according to snd_nxt
	 * In other words, snd_nxt increases according to cwnd openins up.
	 * If one or more packets are lost before snd_nxt, ACK == snd_una
	 * will be received afterwords
	 */
	ack = ntohl(pkt->th.tcph->th_ack);
	if (SEQ_LT(ack, tcb->snd_una)) {
		*status = TCP_INPUT_OLDACK;
		return 0;
	} else if (ack == tcb->snd_una && !got_fin) {
		/* client might send the same ack number for sending fin */
		tcb->seqno = ack; /* XXX */
		tcb->peer_awnd = ntohs(pkt->th.tcph->th_win);
		netmap_tcp_tcbreset(tcb, txring);
		*status = TCP_INPUT_DUPACK;
		return 0;
	}
	tcb->peer_awnd = ntohs(pkt->th.tcph->th_win);
	/* Open up congestion window */
	ack_advanced = ack - tcb->snd_una;
	tcb->cwnd += ack_advanced;
	tcb->flight -= ack_advanced;

	/* Update ack history */
	tcb->snd_una += ack_advanced;
	tcb->ackno = ntohl(pkt->th.tcph->th_seq) + pkt->datalen;

	/*
	 * We assume two cases: before and after my FIN.
	 * Actually we want process FIN at outbound.  But since ACK for FIN
	 * updates highest ACK number, we cannot do it :(
	 */
	if (unlikely(got_fin))
		tcb->ackno++; /* Don't forget Acking later */

	/* the ack is for the final data piece ? */
	if (unlikely(!data->unsent && ack == tcb->seqno)) {
		/*
		 * Here, the client might not have sent fin yet.
		 * But in such a case FIN will be acked outbound
		 */
		if (unlikely(got_fin))
			netmap_tcp_finack(pkt, txring);
		if (is_tcp_separate_fin(tcb))
			/* send FIN */
			netmap_tcp_output(tcb, hint, data, txring);
		/* Otherwise automatically put FIN at the end of data */
		//dcb->worker->completed++;
		*status = TCP_INPUT_FINACK;
		return 0;
	}
	*status = TCP_INPUT_NEWACK;
	if (!data->unsent && !got_fin)
		return 0;
	/* flight, seqno and data_off will be updated in dttcp_data() */
#ifdef TCP_PROFILE
	start = rdtsc();
	sent = netmap_tcp_output(tcb, hint, data, txring);
	add_to_current(stat, start);
	return sent;
#else
	return netmap_tcp_output(tcb, hint, data, txring);
#endif /* TCP_PROFILE */
}

#endif /* TCPLIB_NETMAP */

void
print_profiles(struct clockstat *stat, int lim, uint64_t cpu_freq)
{
	int i;
	struct clockstat *s;
	uint64_t spent;

	for (i = 0; i < lim; ++i) {

		s = stat + i;
		if (!s->count)
			continue;
		spent = s->clock_spent/s->count;
		D("%d: %"PRIu64" cycles (%"PRIu64" nsec) (%"PRIu64" time ave.)",
	            i, spent, spent*1000/(cpu_freq/1000000), s->count);
		s->clock_spent = s->count = 0;
	}
	s = &cl_segment;
	if (s->count) {
		spent = s->clock_spent/s->count;
		D("%d: %"PRIu64" cycles (%"PRIu64" nsec) (%"PRIu64" time ave.)",
		    i++, spent, spent*1000/(cpu_freq/1000000), s->count);
		    s->clock_spent = s->count = 0;
	}
	s = &cl_chksum;
	if (s->count) {
		spent = s->clock_spent/s->count;
		D("%d: %"PRIu64" cycles (%"PRIu64" nsec) (%"PRIu64" time ave.)",
		    i++, spent, spent*1000/(cpu_freq/1000000), s->count);
		    s->clock_spent = s->count = 0;
	}
}
