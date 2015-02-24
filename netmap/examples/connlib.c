#include "connlib.h"

static int verbose = 1;
static int verbose_arp = 1;

#define TX_ALLQUEUE 1 /* if 0 send_udp_packet function will use only the first
                       * queue */
#if !TX_ALLQUEUE
static int poll_done = 0;
#endif

/*
 * Put MAC and IP addresses of interface `if_name' into the netmap socket
 * information.
 *
 * Return 0 if ok, 1 on error.
 */
static int
get_if_info(struct params *p, char *if_name)
{
	struct ifaddrs *head, *cur;
	struct sockaddr_dl *sa_dl;
	struct sockaddr_in *sa_in;
	uint8_t *mac;
	int found = 0;

	if (getifaddrs(&head) == -1) {
		D("an errror occurred while retrieving interface info");
		return(1);
	}
	for (cur = head; cur; cur = cur->ifa_next) {
		if (strcmp(cur->ifa_name, if_name) != 0)
			continue;
		sa_dl = (struct sockaddr_dl *) cur->ifa_addr;
		sa_in = (struct sockaddr_in *) cur->ifa_addr;
		if (!sa_dl && !sa_in)
			continue;
		if (sa_in->sin_family != AF_INET &&
		    sa_dl->sdl_family != AF_LINK) {
			continue;
		}
		if (sa_in->sin_family == AF_INET) {
			if (verbose)
				D("interface %s ip address: %s",
				  if_name,
				  inet_ntoa(sa_in->sin_addr));
			memcpy(&p->rx, sa_in, sizeof(struct sockaddr_in));
			memcpy(&p->if_ip_address,
			       &sa_in->sin_addr,
			       sizeof(struct in_addr));
			found++;
		} else if (sa_dl->sdl_family == AF_LINK) {
			mac = (uint8_t *) LLADDR(sa_dl);
			memcpy(&p->if_mac_address, mac, ETHER_ADDR_LEN);
			if (verbose)
				D("interface %s hw address: %s",
				  if_name,
				  ether_ntoa(&p->if_mac_address));
			found += 2;
		}
	}
	freeifaddrs(head);
	if (found < 3) {
		switch(found) {
		case 0:
			D("ERROR: unable to retrieve IP and MAC addresses"
			  " of interface %s", if_name);
			break;
		case 1:
			D("ERROR: unable to retrieve MAC address"
			  " of interface %s", if_name);
			break;
		case 2:
			D("ERROR: unable to retrieve IP address"
			  " of interface %s", if_name);
		}
		return(1);
	}
	return(0);
}

/*
 * Perform a query in the ARP table, looking for a MAC address correspondig to
 * `p->dst_ip_address'.
 *
 * Return 0 on success, 1 otherwise.
 */
static int
find_mac_address(struct params *p)
{
	int mib[6];
	size_t needed;
	char *buf, *lim, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	int st, not_found = 1;
	uint8_t *mac;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
#ifdef RTF_LLINFO
	mib[5] = RTF_LLINFO;
#else
	mib[5] = 0;
#endif
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		D("route-sysctl-estimate");
		return(0);
	}
	if (needed == 0)	/* empty table */
		return(0);
	buf = NULL;
	for (;;) {
		buf = reallocf(buf, needed);
		if (buf == NULL) {
			D("could not reallocate memory");
			return(0);
		}
		st = sysctl(mib, 6, buf, &needed, NULL, 0);
		if (st == 0 || errno != ENOMEM)
			break;
		needed += needed / 8;
	}
	if (st == -1) {
		free(buf);
		D("actual retrieval of routing table");
		return(0);
	}
	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *) next;
		sin = (struct sockaddr_inarp *) (rtm + 1);
		sdl = (struct sockaddr_dl *) ((char *)sin + SA_SIZE(sin));

		if (p->tx.sin_addr.s_addr != sin->sin_addr.s_addr)
			continue;
		not_found = 0;
		mac = (uint8_t *) LLADDR(sdl);
		memcpy(&p->dst_mac_address, mac, ETHER_ADDR_LEN);
		if (verbose_arp)
			D("MAC address of destination found: %s",
			  ether_ntoa(&p->dst_mac_address));
		break;
	}
	free(buf);
	return(not_found);
}

/*
 * Netmap device opener.
 *
 * Return 0 on success, -1 otherwise.
 */
static int
nm_open(struct my_ring *me, int ringid)
{
	int fd, err, l;
	struct nmreq req;

	me->fd = fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D("Unable to open /dev/netmap");
		return (-1);
	}
	bzero(&req, sizeof(struct nmreq));
	strncpy(req.nr_name, me->ifname, sizeof(req.nr_name));
	req.nr_ringid = ringid;
	err = ioctl(fd, NIOCGINFO, &req);
	if (err) {
		D("cannot get info on %s", me->ifname);
		goto error;
	}
	me->memsize = l = req.nr_memsize;
	if (verbose)
		D("memsize is %d MB", l>>20);
	err = ioctl(fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to register %s", me->ifname);
		goto error;
	}

	if (me->mem == NULL) {
		me->mem = mmap(0,
		               l,
		               PROT_WRITE | PROT_READ,
		               MAP_SHARED,
		               fd,
		               0);
		if (me->mem == MAP_FAILED) {
			D("Unable to mmap");
			me->mem = NULL;
			goto error;
		}
	}

	me->nifp = NETMAP_IF(me->mem, req.nr_offset);
	me->queueid = ringid;
	if (ringid & NETMAP_SW_RING) {
		me->begin = req.nr_numrings;
		me->end = me->begin + 1;
	} else if (ringid & NETMAP_HW_RING) {
		me->begin = ringid & NETMAP_RING_MASK;
		me->end = me->begin + 1;
	} else {
		me->begin = 0;
		me->end = req.nr_numrings;
	}
	me->tx = NETMAP_TXRING(me->nifp, me->begin);
	me->rx = NETMAP_RXRING(me->nifp, me->begin);
	return (0);
error:
	close(me->fd);
	return -1;
}

/*
 * Close netmap device.
 */
static void
nm_close(struct my_ring *me)
{
	if (verbose)
		D("*****");
	if (me->mem)
		munmap(me->mem, me->memsize);
	ioctl(me->fd, NIOCUNREGIF, NULL);
	close(me->fd);
}

/*
 * Allocate and initialize `params' structure.
 *
 * Return a pointer to it on success, NULL otherwise.
 */
struct params*
nm_socket(char *if_name, int domain, int protocol)
{
	int sockfd, ret;
	struct ifreq ifr;
	struct params *p;

	if (domain != PF_INET) {
		D("ERROR: unsupported protocol family");
		return(NULL);
	}
	if (protocol != UDP) {
		D("ERROR: unsupported protocol");
		return(NULL);
	}
	p = calloc(1, sizeof(struct params));
	if (p == NULL) {
		D("ERROR: unable to allocate `params' structure");
		return(NULL);
	}
	/* netmap */
	p->me[0].ifname = if_name;	/* 0: STACK */
	p->me[1].ifname = if_name;	/* 1: NIC */
	if (nm_open(p->me, NETMAP_SW_RING)) {
		D("an error occurred while opening netmap software ring");
		free(p);
		return(NULL);
	}
	if (nm_open(&p->me[1], 0)) {
		D("an error occurred while opening netmap hardware ring");
		D("closing software ring...");
		nm_close(p->me);
		free(p);
		return(NULL);
	}
	if (get_if_info(p, if_name)) {
		nm_close(&p->me[0]);
		nm_close(&p->me[1]);
		free(p);
		return(NULL);
	}
	p->rx.sin_port = htons(55555); /* default port, will be overwritten in
	                                * nm_bind */
	/* get interface MTU */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if ((ret = ioctl(sockfd, SIOCGIFMTU, &ifr)) != -1) {
		p->max_payload_size = ifr.ifr_ifru.ifru_mtu -
		                      sizeof(struct ether_header) -
		                      sizeof(struct ip) -
		                      sizeof(struct udphdr);
	} else {
		D("WARNING: unable to get interface MTU, setting packet size"
		  " to 1500 bytes");
		p->max_payload_size = 1500 -
		                      sizeof(struct ether_header) -
		                      sizeof(struct ip) -
		                      sizeof(struct udphdr);
	}
	return(p);
}

/*
 * Initialize the header of an UDP packet, which will be sent by the trasmitter.
 */
static void
build_udp_header(struct params *p)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;

	bzero(&p->udp_pkt_hdr, sizeof(struct udp_packet_headers));
	/* ethernet header */
	eh = &p->udp_pkt_hdr.eh;
	eh->ether_type = htons(ETHERTYPE_IP);
	bcopy(&p->if_mac_address, eh->ether_shost, ETHER_ADDR_LEN);
	bcopy(&p->dst_mac_address, eh->ether_dhost, ETHER_ADDR_LEN);

	/* IP header */
	ip = &p->udp_pkt_hdr.ip;
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_len = htons(p->max_payload_size +
	                   sizeof(struct udphdr) +
	                   sizeof(struct ip));
	ip->ip_id = 0;
	ip->ip_p = IPPROTO_UDP;
	/*memcpy(&ip->ip_src, &p->rx.sin_addr, sizeof(struct in_addr));*/ // XXX
	memcpy(&ip->ip_src, &p->if_ip_address, sizeof(struct in_addr));
	memcpy(&ip->ip_dst, &p->tx.sin_addr, sizeof(struct in_addr));

	/* UDP header */
	udp = &p->udp_pkt_hdr.udp;
	udp->uh_sport = p->rx.sin_port;
	udp->uh_dport = p->tx.sin_port;
}

/*
 * Allocate an ARP request packet.
 *
 * Return a pointer to it on success, NULL otherwise.
 */
static struct arp_packet*
build_arp_request_packet(const struct params *p)
{
	struct ether_header *eh;
	struct arphdr *arp;

	/*
	   sizeof(struct ether_header) +
	   sizeof(struct arphdr)       +
	   2 * sizeof(struct in_addr)  +
	   2 * ETHER_ADDR_LEN          =
	   -----------------------------
	   42 bytes

	   Ethernet minimum frame size = 60 bytes (+ 4 bytes CRC)
	*/
	struct arp_packet *pkt = calloc(1, 60);

	if (pkt == NULL) {
		D("ERROR: an error occurred while allocating packet memory");
		return(NULL);
	}
	if (verbose_arp) {
		D("***DEBUG*** p->rx.sin_addr %s", inet_ntoa(p->rx.sin_addr));
		D("***DEBUG*** p->if_ip_address %s",
		  inet_ntoa(p->if_ip_address));
		D("***DEBUG*** p->tx.sin_addr %s", inet_ntoa(p->tx.sin_addr));
	}

	eh = &pkt->eh;
	bcopy(&p->if_mac_address, eh->ether_shost, ETHER_ADDR_LEN);
	bcopy(ether_aton("FF:FF:FF:FF:FF:FF"), eh->ether_dhost, ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERTYPE_ARP);

	arp = &pkt->arp;
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = ETHER_ADDR_LEN;
	arp->ar_pln = 4;	// XXX is there a MACRO for this?
	arp->ar_op = htons(ARPOP_REQUEST);
	bcopy(&p->if_mac_address, ar_sha(arp), ETHER_ADDR_LEN);
	/*bcopy(&p->rx.sin_addr, ar_spa(arp), sizeof(struct in_addr));*/
	bcopy(&p->if_ip_address, ar_spa(arp), sizeof(struct in_addr));
	bcopy(&p->tx.sin_addr, ar_tpa(arp), sizeof(struct in_addr));
	return(pkt);
}

/*
 * Copy the packet in the first available slot of NIC tx ring.
 *
 * Return 1 on success, 0 if there are no available slots.
 */
static int
send_udp_packet(struct params *p, const void *payload, int payload_len,
                struct pollfd *pollfd)
{
	char *pnt;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	u_int cur, index = p->me[1].begin;

#if TX_ALLQUEUE
	/* scroll NIC tx rings */
	while (index < p->me[1].end) {
		ring = NETMAP_TXRING(p->me[1].nifp, index);
		if (ring->avail == 0) {
			index++;
			continue;
		} else {
#else
			ring = NETMAP_TXRING(p->me[1].nifp, index);
			if (ring->avail == 0)
				return(0);
#endif
			cur = ring->cur;
			slot = &ring->slot[cur];
			pnt = NETMAP_BUF(ring, slot->buf_idx);
			memcpy(pnt,
			       &p->udp_pkt_hdr,
			       sizeof(struct udp_packet_headers));
			memcpy(pnt + sizeof(struct udp_packet_headers),
			       payload,
			       payload_len);
			slot->len = sizeof(struct udp_packet_headers) +
			            payload_len;
			cur = NETMAP_RING_NEXT(ring, cur);
			ring->avail--;
			ring->cur = cur;
#if !TX_ALLQUEUE
			if (ring->avail < 100 && !poll_done && pollfd != NULL) {
				/* XXX when remove this part, remove pollfd
				 * argument in the definition as well */
				poll(pollfd, 1, 1000);
				poll_done = 1;	// make it only once
			} else if (poll_done) {
				poll_done = 0;
			}
#endif
			return(1);
#if TX_ALLQUEUE
		}
	}
	return(0);
#endif
}

/*
 * Analyze `packet' and (if it is an ARP reply) copy MAC address in the socket
 * structure.
 *
 * Return 1 if it's an ARP reply addressed to "this" host, 0 otherwise.
 */
static int
is_arp_reply(struct params *p, char *packet)
{
	struct ether_header *eh;
	struct arphdr *arp;

	eh = (struct ether_header *) packet;
	arp = (struct arphdr *) &eh[1];

	/* ethernet header */
	if (memcmp(eh->ether_dhost, &p->if_mac_address, ETHER_ADDR_LEN)) {
		if (verbose_arp)
			D("***DEBUG*** ethernet address %s doesn't match"
			  " my address = %s",
			  ether_ntoa((struct ether_addr *) eh->ether_dhost),
			  ether_ntoa(&p->if_mac_address));
		return(0);
	}
	if (ntohs(eh->ether_type) != ETHERTYPE_ARP) {
		if (verbose_arp)
			D("***DEBUG*** ethernet type doesn't match %d",
			  ntohs(eh->ether_type));
		return(0);
	}

	/* ARP header */
	if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
	    ntohs(arp->ar_pro) != ETHERTYPE_IP ||
	    arp->ar_hln != ETHER_ADDR_LEN ||
	    arp->ar_pln != 4 ||
	    ntohs(arp->ar_op) != ARPOP_REPLY) {
		if (verbose_arp)
			D("***DEBUG*** ARP header doesn't match");
		return(0);
	}
	if (memcmp(ar_tha(arp),
	           &p->if_mac_address,
	           ETHER_ADDR_LEN) ||
	    memcmp((struct in_addr *) ar_spa(arp),
	           &p->tx.sin_addr,
	           sizeof(struct in_addr)) ||
	    memcmp((struct in_addr *) ar_tpa(arp),
	           &p->if_ip_address,
	           sizeof(struct in_addr))) {
		if (verbose_arp) {
			D("***DEBUG*** ARP addresses don't match");
			D("***DEBUG*** spa %s",
			  inet_ntoa(*((struct in_addr *) ar_spa(arp))));
			D("***DEBUG*** tpa %s",
			  inet_ntoa(*((struct in_addr *) ar_tpa(arp))));
		}
		return(0);
	}

	/* copy MAC address */
	bzero(&p->dst_mac_address, ETHER_ADDR_LEN);
	memcpy(&p->dst_mac_address, ar_sha(arp), ETHER_ADDR_LEN);
	return(1);
}

/*
 * Send an ARP request for `p->dst_ip_address', receive ARP response and route
 * it to the STACK.
 *
 * Return 0 on success, 1 if unable to send ARP request or ARP reply hasn't
 * been catched.
 */
static int
handle_arp_request(struct params *p)
{
	char *pkt, *pnt;
	int sent = 0, ret, avail, received = 0, swapped, i, timeout = 30000000;
	u_int si = p->me[1].begin, di = p->me[0].begin, j, k;
	uint32_t index, cur;
	struct netmap_ring *stackring = NULL, *nicring = NULL, *txring;
	struct pollfd pollfd;
	struct arp_packet *ap;
	struct netmap_slot *nicslot, *stackslot;

	ap = build_arp_request_packet(p);
	if (ap == NULL) {
		D("unable to build an ARP request packet");
		return(1);
	}
	bzero(&pollfd, sizeof(struct pollfd));
	pollfd.fd = p->me[1].fd;
	pollfd.events |= POLLOUT;
	for (i = 0; i < timeout;) {
		pollfd.revents = 0;
		ret = poll(&pollfd, 1, 1000);
		if (ret <= 0) {
			if (pollfd.revents & POLLERR)
				D("error on fd, txavail %d / txcur %d",
				  p->me[1].tx->avail, p->me[1].tx->cur);
			if (++i == timeout) {
				free(ap);
				goto error;
			}
			continue;
		} else if (pollfd.events & POLLOUT) {
			/* send ARP request */
			index = p->me[1].begin;
			while (index < p->me[1].end) {
				txring = NETMAP_TXRING(p->me[1].nifp, index);
				if (txring->avail == 0) {
					index++;
					continue;
				} else {
					cur = txring->cur;
					nicslot = &txring->slot[cur];
					pnt = NETMAP_BUF(txring,
					                 nicslot->buf_idx);
					memcpy(pnt, ap, 60);
					nicslot->len = 60;
					cur = NETMAP_RING_NEXT(txring, cur);
					txring->avail--;
					txring->cur = cur;
					ioctl(p->me[1].fd, NIOCTXSYNC, NULL);
					free(ap);
					pollfd.events = POLLIN;
					i = 0; /* reset counter */
					sent = 1;
					if (verbose_arp)
						D("ARP request sent,"
						  " waiting for reply...");
					break;
				}
			}
			if (sent) {
				continue;
			} else {
				if (++i == timeout) {
					free(ap);
					goto error;
				}
			}
		} else if (pollfd.events & POLLIN) {
			/* get ARP reply and give it to the STACK */
			while (si < p->me[1].end && di < p->me[0].end) {
				if (nicring == NULL || nicring->avail == 0)
					nicring = NETMAP_RXRING(p->me[1].nifp,
					                        si);
				if (stackring == NULL || stackring->avail == 0)
					stackring = NETMAP_TXRING(p->me[0].nifp,
					                          di);
				if (nicring->avail == 0) {
					si++;
					continue;
				}
				if (stackring->avail == 0) {
					di++;
					continue;
				}
				avail = MIN(nicring->avail, stackring->avail);
				j = nicring->cur;
				k = stackring->cur;
				swapped = 0;
				while (avail-- > 0) {
					nicslot = &nicring->slot[j];
					stackslot = &stackring->slot[k];
					pkt = NETMAP_BUF(nicring,
						nicring->slot[j].buf_idx);
					/* check if it's an ARP reply */
					if (is_arp_reply(p, pkt)) {
						if (verbose_arp) {
							D("***DEBUG*** ARP"
							  " reply received");
							D("***DEBUG***"
							  " destination MAC"
							  " address: %s",
					  ether_ntoa(&p->dst_mac_address));
						}
						received = 1;
					}
					index = stackslot->buf_idx;
					stackslot->buf_idx = nicslot->buf_idx;
					nicslot->buf_idx = index;
					/* copy the packet lenght */
					stackslot->len = nicslot->len;
					/* report the buffer change */
					stackslot->flags |= NS_BUF_CHANGED;
					nicslot->flags |= NS_BUF_CHANGED;
					swapped++;
					j = NETMAP_RING_NEXT(nicring, j);
					k = NETMAP_RING_NEXT(stackring, k);
					if (received)
						break;
				}
				nicring->avail -= swapped;
				stackring->avail -= swapped;
				nicring->cur = j;
				stackring->cur = k;
				if (received)
					goto found;
			}
			if (++i == timeout)
				goto error;
		}
	}
found:
	return(0);

error:
	if (verbose_arp) {
		if (pollfd.events & POLLOUT)
			D("Unable to send ARP request");
		else
			D("Unable to catch ARP reply");
	}
	return(1);
}

/*
 * Copy destination informations in `params' structure.
 * Eventually retrieve destination MAC address (if not known yet).
 * Set UDP header info.
 *
 * Return 0 on success, 1 otherwise.
 */
int
nm_connect(struct params *p, const struct sockaddr *name, socklen_t namelen)
{
	struct ip *ip;
	struct udphdr *udp;
	uint64_t sum;

	if (p == NULL) {
		D("ERROR: invalid pointer to struct params");
		return(1);
	}
	if (name == NULL) {
		D("ERROR: invalid pointer to struct sockaddr");
		return(1);
	}
	if (memcmp(name, &p->tx, namelen)) {
		bzero(&p->tx, sizeof(struct sockaddr_in));
		memcpy(&p->tx, name, namelen);
	}
	/* retrieve destination MAC address in the ARP table */
	if (find_mac_address(p)) {
		D("unable to retrieve MAC address of destination from the ARP"
		  " table");
		/* send an ARP request and get the reply */
		if (handle_arp_request(p))
			return(1);
	}
	/* initialize header structure for UDP packets */
	build_udp_header(p);
	/* compute checksum for constant header fields */
	ip = &p->udp_pkt_hdr.ip;
	udp = &p->udp_pkt_hdr.udp;
	sum = * (uint16_t *) ip +
	      * (u_char *) &ip->ip_tos +
	      * (uint16_t *) &ip->ip_ttl +
	      * (uint32_t *) &ip->ip_src +
	      * (uint32_t *) &ip->ip_dst;
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	p->ip_const_hdr = sum;
	sum = * (uint32_t *) &ip->ip_src +
	      * (uint32_t *) &ip->ip_dst +
	      * (uint32_t *) &udp->uh_sport;
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	p->udp_const_hdr = sum;
	return(0);
}

/*
 * Close all netmap devices and free the memory belonging to `params'
 * structure.
 */
void
nm_close_socket(struct params *p)
{
	int i, count = 0;
	uint64_t sum = 0;
	for (i = 0; i < NUMTS; i++) {
		if (p->ts[i].container[0] != 0 && p->ts[i].container[1] != 0) {
			sum += (p->ts[i].container[1] - p->ts[i].container[0]);
			count++;
		}
	}
	if (count) {
		sum /= count;
		D("average delta: %llu, count = %d",
		  sum,
		  count);
	}
	ioctl(p->me[1].fd, NIOCTXSYNC, NULL);
	nm_close(&p->me[0]);
	nm_close(&p->me[1]);
	free(p);
}

static inline uint64_t
sum32u(const unsigned char *addr, int count)
{
	uint64_t sum = 0;
	const uint32_t *p = (uint32_t *) addr;

	for (; count >= 32; count -= 32) {
		sum += (uint64_t) p[0] + p[1] + p[2] + p[3] +
		                  p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
	for (; count >= 16; count -= 16) {
		sum += (uint64_t) p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	for (; count >= 4; count -= 4) {
		sum += *p++;
	}
	addr = (unsigned char *)p;
	if (count > 1) {
		sum += * (uint16_t *) addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	return sum;
}

/*
 * If mode = 0: return the number of availabe slots in the ring.
 *
 * If mode > 0: return 1 if there is at least an available slot in the ring;
 * 0 otherwise.
 */
static int
slothunter(const struct my_ring *me, int tx, int mode)
{
	u_int i, tot = 0;

	for (i = me->begin; i < me->end; i++) {
		struct netmap_ring *ring = tx ?
			NETMAP_TXRING(me->nifp, i) :
			NETMAP_RXRING(me->nifp, i);
		if (mode && ring->avail)
			return(1);
		tot += ring->avail;
	}
	return tot;
}

/*
 * MUST follow a nm_connect.
 * Update packet headers and execute a poll loop until it will be sent.
 *
 * Return the number of bytes sent.
 */
int
nm_send(struct params *p, const void *buf, int buf_len)
{
	int ret, len;
	uint64_t sum;
	struct ip *ip;
	struct udphdr *udp;
	struct pollfd pollfd;

	len = MIN(p->max_payload_size, buf_len);

	/* update IP header and checksum */
	ip = &p->udp_pkt_hdr.ip;
	ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + len);
	ip->ip_id = htons((ntohs(ip->ip_id) + 1)%65536);
	sum = p->ip_const_hdr + * (uint32_t *) &ip->ip_len;
	/* wrap into 16-bit */
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	ip->ip_sum = ~sum;

	/* update UDP header and checksum */
	udp = &p->udp_pkt_hdr.udp;
	udp->uh_ulen = htons(sizeof(struct udphdr) + len);
	/* pseudo header checksum */
	sum = p->udp_const_hdr +
	      (uint16_t) (IPPROTO_UDP << 8) +
	      2*udp->uh_ulen;
	/* payload checksum */
	sum += sum32u((unsigned char *) buf, len);
	/* wrap into 16-bit */
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	udp->uh_sum = ~sum;

	if (send_udp_packet(p, buf, len, &pollfd))
		return(len);
	bzero(&pollfd, sizeof(struct pollfd));
	pollfd.fd = p->me[1].fd;
	pollfd.events |= POLLOUT;
	for (;;) {
		pollfd.revents = 0;
		ret = poll(&pollfd, 1, 1000);
#if 0
		if (ret <= 0 || verbose)
			D("poll %s ev %x %x tx->cur: %d howmany %d",
			  ret <= 0 ? "timeout" : "ok",
			  pollfd.events,
			  pollfd.revents,
			  p->me[1].tx->cur,
			  slothunter(&p->me[1], 1, 0));
#endif
		if (ret <= 0) {
			if (pollfd.revents & POLLERR)
				D("error on fd, txavail %d / txcur %d",
				  p->me[1].tx->avail,
				  p->me[1].tx->cur);
			continue;
		}
		if (send_udp_packet(p, buf, len, &pollfd))
			break;
	}
	return(len);
}

/*
 * Compare `to' with the informations in the socket: if not equal call
 * nm_connect.
 * Call nm_send.
 *
 * Return the number of bytes sent.
 */
int
nm_sendto(struct params *p, const void *buf, int buf_len,
          const struct sockaddr *to, socklen_t tolen)
{
	u_int bytes_sent;

	if (((struct sockaddr_in *) to)->sin_family != AF_INET) {
		D("ERROR: family protocol not supported: %d",
		  ((struct sockaddr_in *) to)->sin_family);
		return(-1);
	}
	if (buf == NULL) {
		// XXX use default payload?
		D("ERROR: buffer pointer is NULL");
		return(-1);
	}
	/* connect */
	if (memcmp(to, &p->tx, tolen)) {
		if (nm_connect(p, to, tolen)) {
			D("ERROR: netmap connect returned -1");
			return(-1);
		}
	}
	/* send */
	bytes_sent = nm_send(p, buf, buf_len);
	return(bytes_sent);
}

/*
 * Analyze the content of `pkt'.
 *
 * Return 1 if it's an UDP packet addressed to "this" host, 0 otherwise.
 */
static int
check_udp_packet(struct params *p, char *pkt, int packet_size)
{
	uint64_t sum;
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;

	eh = (struct ether_header *) pkt;
	ip = (struct ip *) &eh[1];
	udp = (struct udphdr *) &ip[1];

#if 0
	if (packet_size < ntohs(udp->uh_ulen)) { /* minimum ethernet frame size
	                                          * is 60 bytes */
		if (verbose)
			D("***DEBUG*** wrong packet length");
		return(0);
	}
#endif

	/* ethernet header */
	if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
		if (verbose)
			D("***DEBUG*** ethernet type doesn't match");
		return(0);
	}
	if (memcmp(eh->ether_dhost,
	           &p->if_mac_address,
	           ETHER_ADDR_LEN)) {	// XXX match with broadcast ethernet?
		if (verbose)
			D("***DEBUG*** ethernet destination address"
			  " doesn't match");
		return(0);
	}

	/* IP header */
	if (ip->ip_p != IPPROTO_UDP) {
		if (verbose)
			D("***DEBUG*** IP protocol is not UDP");
		return(0);
	}
	if (!p->inaddr_any_enabled &&
	    memcmp(&ip->ip_dst,
	           &p->rx.sin_addr,
	           sizeof(struct in_addr))) {	// XXX match with broadcast IP?
		if (verbose) {
			D("***DEBUG*** IP destination address doesn't match");
			D("***DEBUG*** ip->ip_dst %s", inet_ntoa(ip->ip_dst));
			D("***DEBUG*** p->rx.sin_addr %s",
			  inet_ntoa(p->rx.sin_addr));
		}
		return(0);
	}

	/* UDP port */
	if (udp->uh_dport != p->rx.sin_port) {
		if (verbose)
			D("***DEBUG*** UDP header doesn't match: uh_sport %d"
			  " uh_dport %d tx.sin_port %d rx.sin_port %d",
			  ntohs(udp->uh_sport), ntohs(udp->uh_dport),
			  ntohs(p->tx.sin_port), ntohs(p->rx.sin_port));
		return(0);
	}
#if 0
	netmap_rdtsc(p->ts[p->cur].container[0]);
	netmap_rdtsc(p->ts[p->cur].container[1]);
	p->cur = (p->cur + 1)%NUMTS;
#endif

	/* IP checksum control */
	sum = sum32u((unsigned char *) ip, sizeof(struct ip));
	/* wrap into 16-bit */
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	if ((uint16_t) ~sum) {
		if (verbose)
			D("***DEBUG*** bad IP checksum");
		return(0);
	}

	/* UDP checksum control */
	/* pseudo header checksum */
	sum = sum32u((unsigned char *) &ip->ip_src, 2*sizeof(struct in_addr));
	sum += (uint16_t) (IPPROTO_UDP << 8) + udp->uh_ulen;
	sum += udp->uh_sport + udp->uh_dport + udp->uh_ulen + udp->uh_sum;
	/* payload checksum */
	sum += sum32u((unsigned char *) &udp[1],
	              ntohs(udp->uh_ulen) - sizeof(struct udphdr));
	/* wrap into 16-bit */
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	if ((uint16_t) ~sum) {
		if (verbose)
			D("***DEBUG*** bad UDP checksum");
		return(0);
	}

	return(1);
}

/*
 * Copy payload into `buf'.
 *
 * Return the number of bytes copied.
 */
static int
get_udp_payload(char *pkt, void *buf, int len, struct sockaddr_in *from)
{
	uint16_t payload_length;
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;

	eh = (struct ether_header *) pkt;
	ip = (struct ip *) &eh[1];
	udp = (struct udphdr *) &ip[1];

	bzero(from, sizeof(struct sockaddr_in));
	memcpy(&from->sin_addr, &ip->ip_src, sizeof (struct in_addr));
	from->sin_port = udp->uh_sport;
	payload_length = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
	payload_length = MIN(len, payload_length);
	// XXX erase buffer before copy?
	memcpy(buf, &udp[1], payload_length);
	return(payload_length);
}

/*
 * Move packets from `src' to `dst' swapping their slots.
 *
 * Return ring pointer if find an UDP packet coming from the NIC; 0 otherwise.
 *
 * `direction' = 0 STACK -> NIC
 * `direction' = 1 NIC -> STACK
 */
static struct netmap_ring*
process_rings(struct params *p, struct my_ring *src, struct my_ring *dst)
{
	int direction = (src->queueid & NETMAP_SW_RING) ?  0 : 1;
	u_int j, k, count, swapped = 0, si = src->begin, di = dst->begin;
	uint32_t index;
	char *pkt;
	struct netmap_slot *rs, *ts;
	struct netmap_ring *txring, *rxring;

	while (si < src->end && di < dst->end) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		/* find available slot in rx and tx ring */
		if (rxring->avail == 0) {
			si++;
			continue;
		}
		if (txring->avail == 0) {
			di++;
			continue;
		}
		/* number of slot we can process with this pair of ring */
		count = MIN(rxring->avail, txring->avail);
		/* scroll every available slot in the ring */
		while (count-- > 0) {
			j = rxring->cur;
			k = txring->cur;
			rs = &rxring->slot[j];
			ts = &txring->slot[k];
			if (direction) {
				/* NIC -> STACK */
				pkt = NETMAP_BUF(rxring,
				                 rxring->slot[j].buf_idx);
				if (check_udp_packet(p, pkt, rs->len)) {
					/* indexes of this slot will be updated
					 * in the function `nm_recvfrom' */
					/* update ring info */
					rxring->avail -= swapped;
					txring->avail -= swapped;
					rxring->cur = j;
					txring->cur = k;
					return(rxring);
				} else {
					/* forward the packet to the STACK */
					p->exchanges++;
				}
			}
			/* swap slot index */
			index = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = index;
#if 0
			if (rs->len < 14 || rs->len > 2048)
				D("WARNING: wrong len %d rx[%d] -> tx[%d]",
				  rs->len,
				  j,
				  k);
#endif
			/* copy the packet length */
			ts->len = rs->len;
			/* report the buffer change */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			j = NETMAP_RING_NEXT(rxring, j);
			k = NETMAP_RING_NEXT(txring, k);
			swapped++;
		}
		/* update ring info */
		rxring->avail -= swapped;
		txring->avail -= swapped;
		rxring->cur = j;
		txring->cur = k;
	}
	return(NULL);
}

/*
 * Add IP address and port to the netmap socket informations.
 *
 * Return 0 on success, 1 otherwise.
 */
int
nm_bind(struct params *p, const struct sockaddr *addr, socklen_t addrlen)
{
	if (p == NULL) {
		D("ERROR: invalid pointer to struct params");
		return(1);
	}
	if (addr == NULL) {
		D("ERROR: invalid pointer to struct sockaddr");
		return(1);
	}
	if (((struct sockaddr_in *) addr)->sin_family != AF_INET) {
		D("ERROR: family protocol not supported");
		return(1);
	}
	if (((struct sockaddr_in *) addr)->sin_addr.s_addr == INADDR_ANY)
		p->inaddr_any_enabled = 1;
	else
		p->inaddr_any_enabled = 0;
	/* even if p->inaddr_any_enabled = 1, make a copy anyway for the port
	 * value */
	if (memcmp(addr, &p->rx, addrlen)) {
		bzero(&p->rx, sizeof(struct sockaddr_in));
		memcpy(&p->rx, addr, addrlen);
	}
	return(0);
}

/*
 * Wait for an UDP packet coming from the NIC and copy its payload in the
 * user-supplied buffer. Slots contatining other kind of packets both from the
 * STACK and the NIC will be swapped.
 *
 * Return the number of received bytes.
 */
int
nm_recvfrom(struct params *p, void *buf, int len,
            struct sockaddr *from, socklen_t fromlen)
{
	int nic, stack, ret, bytes = 0;
	u_int cur;
	char *packet;
	struct pollfd pollfd[2];
	struct netmap_ring *ring;
	struct netmap_slot *slot;

	bzero(pollfd, 2*sizeof(struct pollfd));
	pollfd[0].fd = p->me[0].fd;	/* STACK */
	pollfd[1].fd = p->me[1].fd;	/* NIC */

	for (;;) {
		pollfd[0].revents = pollfd[1].revents = 0;
		/* search for "readable" slots in STACK and NIC rings */
		nic = slothunter(&p->me[1], 0, 1);
		stack = slothunter(&p->me[0], 0, 1);
		if (p->exchanges > 0 || (!nic && !stack)) {
			/* there are no packets in STACK / NIC rings or I have
			 * swapped NIC slots with STACK ones */
			pollfd[0].events = pollfd[1].events = 0;
			if (!nic)
				pollfd[1].events |= POLLIN;
			if (!stack)
				pollfd[0].events |= POLLIN;
make_poll:
			ret = poll(pollfd, 2, 1000);
			p->exchanges = 0;
#if 0
			if (ret <= 0 || verbose) {
				D("poll %s\n"
				  "\t[0] ev %x %x {RX} homany: %d;"
				  " cur: %d {TX} howmany %d\n"
				  "\t[1] ev %x %x {RX} homany: %d;"
				  " cur: %d {TX} howmany %d",
				  ret <= 0 ? "timeout" : "ok",
				  pollfd[0].events,
				  pollfd[0].revents,
				  slothunter(&p->me[0], 0, 0),
				  p->me[0].rx->cur,
				  slothunter(&p->me[0], 1, 0),
				  pollfd[1].events,
				  pollfd[1].revents,
				  slothunter(&p->me[1], 0, 0),
				  p->me[1].rx->cur,
				  slothunter(&p->me[1], 1, 0));
			}
#endif
			if (ret <= 0) {
				if (pollfd[0].revents & POLLERR)
					D("error on fd0, rxcur %d@%d",
					  p->me[0].rx->avail,
					  p->me[0].rx->cur);
				if (pollfd[1].revents & POLLERR)
					D("error on fd1, rxcur %d@%d",
					  p->me[1].rx->avail,
					  p->me[1].rx->cur);
				continue;
			}
		}
		/* STACK -> NIC */
		if (stack || (pollfd[0].revents & POLLIN)) {
			process_rings(p, &p->me[0], &p->me[1]);
			pollfd[0].revents = pollfd[0].events = 0;
			if ((nic = slothunter(&p->me[1], 0, 1)))
				stack = 0; /* may occur starvation if there's
				            * high traffic coming from the
				            * stack */
			else
				stack = slothunter(&p->me[0], 0, 1);
			goto make_poll;
		}
		/* NIC -> STACK */
		if (nic || (pollfd[1].revents & POLLIN)) {
			if ((ring = process_rings(p,
			                          &p->me[1],
			                          &p->me[0])) != NULL) {
				cur = ring->cur;
				slot = &ring->slot[cur];
				/* get packet from slot */
				packet = NETMAP_BUF(ring, slot->buf_idx);
				bytes = get_udp_payload(packet,
				                        buf,
				                        len,
				                        (struct sockaddr_in *)
				                        from);
				/* update ring indexes */
				ring->avail--;
				ring->cur = NETMAP_RING_NEXT(ring, cur);
				break;
			}
		}
	}
	return(bytes);
}
