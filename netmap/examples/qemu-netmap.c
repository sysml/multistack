/*
 * netmap access for qemu (from tap-bsd.c and tap.c)
 *
 * Copyright (c) 2012 Luigi Rizzo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu-common.h"
#include "sysemu.h"
#include "qemu-error.h"
#include <net/if.h>
#include <sys/mman.h>
#include "/home/luigi/FreeBSD/head/sys/net/netmap.h"
#include "/home/luigi/FreeBSD/head/sys/net/netmap_user.h"
#include <sys/ioctl.h>

#include "config-host.h"

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <net/if.h>

#include "net.h"
#include "sysemu.h"
#include "qemu-char.h"
#include "qemu-common.h"
#include "qemu-error.h"

static int nm_verbose=0;

#define TAP_BUFSIZE (4096 + 65536)

/*
 * private netmap info
 */
struct netmap_state {
    int fd;
    int	memsize;
    void *mem;
    struct netmap_if *nifp;
    struct netmap_ring *rx, *tx;
    char fdname[128];	/* normally /dev/netmap */
    char ifname[128];	/* maybe the nmreq here ? */
    uint8_t _buf[TAP_BUFSIZE];
};

struct nm_state {
    VLANClientState nc;
    struct netmap_state me;
    unsigned int read_poll;
    unsigned int write_poll;
};

// XXX only for multiples of 64 bytes, non overlapped.
static inline void
pkt_copy(const void *_src, void *_dst, int l)
{
        const uint64_t *src = _src;
        uint64_t *dst = _dst;
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
        if (unlikely(l >= 1024)) {
                bcopy(src, dst, l);
                return;
        }
        for (; l > 0; l-=64) {
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

static void pkt_dump(const uint8_t *buf, int len)
{
// ....: .. .. .. .. .. .. .. ..  .. .. .. .. .. .. .. ..  ________ ________
	int i;
	char t[128];
	char hex[] = "0123456789abcdef";
#define P(x) ((c >= ' ' && c < 0x7f) ? c : '.')
	fprintf(stderr, "--- %d bytes at %p\n", len, buf);
	if (len > 160)
		len = 160;
	for (i = 0; i < len; i++) {
		uint8_t c = buf[i];
		int o = i % 16;
		if (o == 0) {
			if (i > 0)
				fprintf(stderr, "%s\n", t);
			memset(t, ' ', 79);
			t[80] = '\0';
			t[0] = hex[(i>>12) & 0xf];
			t[1] = hex[(i>>8) & 0xf];
			t[2] = hex[(i>>4) & 0xf];
			t[3] = hex[(i>>0) & 0xf];
			t[4] = ':';
		}
		t[6 + 3*o + (o >> 3)] = hex[c >> 4];
		t[7 + 3*o + (o >> 3)] = hex[c & 0xf];
		t[56 + o + (o >> 3)] = P(c);
	}
	if (i % 16 != 0)
		fprintf(stderr, "%s\n", t);
}

#if 1 // NM_RATE
void nm_report_name(struct nm_rate *r, char *name)
{
	int lim = sizeof(r->name);
	int l = strlen(name);
	if (l > lim - 1)
		l = lim - 1;
	bzero(&r->name, lim);
	bcopy(name, r->name, l);
}

/*
 * init or report the current receive rate
 */
void nm_report_rate(struct nm_rate *r, int delta)
{
	uint64_t cnt, us;
	double rate;

	if (delta < -1) {
		r->delta = -delta;
		fprintf(stderr, "%p set delta %llu\n", r, r->delta);
		delta = -1;
	}
	if (delta == -1) {
		r->prev = r->curr = 0;
		gettimeofday(&r->t_prev, NULL);
		return;
	}
	r->curr += delta;
	cnt = r->curr - r->prev;
	if (r->delta == 0) {
		r->delta = 100000;
		fprintf(stderr, "%p force delta %llu\n", r, r->delta);
	}
	if (cnt < r->delta)
		return;
	gettimeofday(&r->t_curr, NULL);
	us = 1000000*(r->t_curr.tv_sec - r->t_prev.tv_sec) +
		(r->t_curr.tv_usec - r->t_prev.tv_usec) + 1; /* avoid div-0 */
	rate = cnt*1.0 / us;
	r->t_prev = r->t_curr;
	r->prev = r->curr;
	fprintf(stderr, "%s delta %llu rate %8.6f Mpps\n", r->name, cnt, rate);
}
#endif // NM_RATE

/*
 * open a netmap device. We assume there is only one queue
 * (which is the case for the VALE bridge).
 */
static int netmap_open(struct netmap_state *me)
{
    int fd, l, err;
    struct nmreq req;

    fprintf(stderr, "%s for %s\n", __FUNCTION__, me->ifname);
    me->fd = fd = open(me->fdname, O_RDWR);
    if (fd < 0) {
	error_report("Unable to open netmap device '%s'", me->fdname);
	return -1;
    }
    bzero(&req, sizeof(req));
    strncpy(req.nr_name, me->ifname, sizeof(req.nr_name));
    req.nr_ringid = 0;
    req.nr_version = NETMAP_API;
    err = ioctl(fd, NIOCGINFO, &req);
    if (err) {
	error_report("cannot get info on %s", me->ifname);
	goto error;
    }
    l = me->memsize = req.nr_memsize;
    err = ioctl(fd, NIOCREGIF, &req);
    if (err) {
	error_report("Unable to register %s", me->ifname);
	goto error;
    }

    me->mem = mmap(0, l, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    if (me->mem == MAP_FAILED) {
	error_report("Unable to mmap");
	me->mem = NULL;
	goto error;
    }

    me->nifp = NETMAP_IF(me->mem, req.nr_offset);
    me->tx = NETMAP_TXRING(me->nifp, 0);
    me->rx = NETMAP_RXRING(me->nifp, 0);
    fprintf(stderr, "  %d MB at %p, tx %p rx %p slots %d\n",
	me->memsize >> 20, me->mem, me->tx, me->rx, me->tx->num_slots);
    return 0;
error:
    // testing, if name is not /dev/netmap still return ok
    if (strcmp(me->fdname, "/dev/netmap") != 0)
	return 0;
    close(me->fd);
    return -1;
}

/*
 * XXX check whether this is necessary
 */
static int netmap_can_send(void *opaque)
{
    struct nm_state *s = opaque;
    int ret;

RATE_ME(__FUNCTION__, 1000000, 1);
    ret = qemu_can_send_packet(&s->nc);
    // fprintf(stderr, "%s for %s gives %d\n", __FUNCTION__, s->me.ifname, ret);
    return ret;
}

static void netmap_send(void *opaque);
static void netmap_writable(void *opaque);

/*
 * set the handlers for the device
 */
static void netmap_update_fd_handler(struct nm_state *s)
{
RATE_ME(__FUNCTION__, 1000000, 1);
    // fprintf(stderr, "%s for %s\n", __FUNCTION__, s->me.ifname);
#if 1
    qemu_set_fd_handler2(s->me.fd,
                         s->read_poll  ? netmap_can_send : NULL,
                         s->read_poll  ? netmap_send     : NULL,
                         s->write_poll ? netmap_writable : NULL,
                         s);
#else
    qemu_set_fd_handler(s->me.fd,
                         s->read_poll  ? netmap_send     : NULL,
                         s->write_poll ? netmap_writable : NULL,
                         s);
#endif
}

/*
 * prepare for reading
 */
static void netmap_read_poll(struct nm_state *s, int enable)
{
RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
	fprintf(stderr, "%s for %s\n", __FUNCTION__, s->me.ifname);
    s->read_poll = !!enable;
    netmap_update_fd_handler(s);
}

/*
 * prepare for writing.
 * But we should almost never do that with netmap.
 */
static void netmap_write_poll(struct nm_state *s, int enable)
{
RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
	fprintf(stderr, "%s for %s: %s\n", __FUNCTION__, s->me.ifname,
		enable ? "enable" : "disable");
    s->write_poll = !!enable;
    netmap_update_fd_handler(s);
}

static void netmap_writable(void *opaque)
{
    struct nm_state *s = opaque;

RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
	fprintf(stderr, "%s for %s\n", __FUNCTION__, s->me.ifname);
    netmap_write_poll(s, 0);

    qemu_flush_queued_packets(&s->nc);
}

/*
 * receive from the virtual machine means pushing to the stack
 */
static ssize_t netmap_receive_raw(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    struct nm_state *s = DO_UPCAST(struct nm_state, nc, nc);
    struct netmap_ring *ring = s->me.tx;

RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose) {
	fprintf(stderr, "TX %s for %s size %d at %p\n",
	    __FUNCTION__, s->me.ifname, (int)size, buf);
	pkt_dump(buf, size);
    }
    if (ring) {
	if (ring->avail == 0) { // cannot write
RATE_ME( "rx_raw cannot write", 1000000, 1);
	    if (nm_verbose)
		fprintf(stderr, "cannot write, set poll\n");
	    netmap_write_poll(s, 1);
	    return 0;
	}
	uint32_t i = ring->cur;
	uint32_t idx = ring->slot[i].buf_idx;
	uint8_t *dst = (u_char *)NETMAP_BUF(ring, idx);
	ring->slot[i].len = size;
	pkt_copy(buf, dst, size);
	ring->cur = NETMAP_RING_NEXT(ring, i);
	ring->avail--;
RATE_ME( "rx_raw written", 1000000, 1);
	if (nm_verbose)
	    fprintf(stderr, "written %d at %d, avail %d\n",
		(int)size, ring->cur, ring->avail);
        // netmap_write_poll(s, 0); // XXX lr 20120607
    }
    return size;
}

/*
 * complete a previous send
 */
static void netmap_send_completed(VLANClientState *nc, ssize_t len)
{
    struct nm_state *s = DO_UPCAST(struct nm_state, nc, nc);
    struct netmap_ring *ring = s->me.rx;
    int i = ring->cur;

RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
        fprintf(stderr, "RXok %s for %s cur %d avail %d\n",
		__FUNCTION__, s->me.ifname, ring->cur, ring->avail);
    ring->cur = NETMAP_RING_NEXT(ring, i);
    ring->avail--;
    //netmap_read_poll(s, 1); // XXX only if avail == 0 ?
}

/*
 * there is traffic available from the network, try to send it up.
 */
static void netmap_send(void *opaque)
{
    struct nm_state *s = opaque;
    static int sent_max = 0;
    int sent = 0;
    struct netmap_ring *ring = s->me.rx;

RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
        fprintf(stderr, "RX %s for %s cur %d avail %d\n",
		__FUNCTION__, s->me.ifname, ring->cur, ring->avail);
    while (ring->avail > 0 && qemu_can_send_packet(&s->nc) ) {
	uint32_t i = ring->cur;
	uint32_t idx = ring->slot[i].buf_idx;
	uint8_t *src = (u_char *)NETMAP_BUF(ring, idx);
	int size = ring->slot[i].len;
	/* XXX is this a busy wait loop ? */
        size = qemu_send_packet_async(&s->nc, src, size, netmap_send_completed);
	if (size == 0) {
	    if (1 || nm_verbose)
		fprintf(stderr, "RX %d -> to host blocking\n", ring->cur);
	    netmap_read_poll(s, 0);
	    return;
	}
	// fprintf(stderr, "RX %d -> to host was successful\n", ring->cur);
	ring->cur = NETMAP_RING_NEXT(ring, i);
	ring->avail--;
	sent++;
    }
    if (sent > sent_max) {
	fprintf(stderr, "%s burst of %d\n", __FUNCTION__, sent);
	sent_max = sent;
    }
    netmap_read_poll(s, 1); // XXX only if avail == 0 ?
}


/*
 * flush and close
 */
static void netmap_cleanup(VLANClientState *nc)
{
    struct nm_state *s = DO_UPCAST(struct nm_state, nc, nc);

    fprintf(stderr, "%s for %s\n", __FUNCTION__, s->me.ifname);
    qemu_purge_queued_packets(nc);

    netmap_read_poll(s, 0);
    netmap_write_poll(s, 0);
    close(s->me.fd);

    s->me.fd = -1;
}

static void netmap_poll(VLANClientState *nc, bool enable)
{
    struct nm_state *s = DO_UPCAST(struct nm_state, nc, nc);

RATE_ME(__FUNCTION__, 1000000, 1);
    if (nm_verbose)
	fprintf(stderr, "PPP %s for %s\n", __FUNCTION__, s->me.ifname);
    netmap_read_poll(s, enable);
    netmap_write_poll(s, enable);
}


/* fd support */

static NetClientInfo net_netmap_info = {
    .type = NET_CLIENT_TYPE_NETMAP,
    .size = sizeof(struct nm_state),
    .receive = netmap_receive_raw,
//    .receive_raw = netmap_receive_raw,
//    .receive_iov = netmap_receive_iov,
    .poll = netmap_poll,
    .cleanup = netmap_cleanup,
};

/* the external calls */

/*
 * net_init_netmap() is called from the outside, this is why we need
 * a prototype. Should try to open the device, and if successful
 * also qemu_new_net_client()
 *
 * opts are the command line options ?)
 * name is passed with -net netmap,name=...
 * vlan is ...
 * mon is ...
 *
 * We need to be sure it can be opened before calling qemu_new_net_client
 */
int net_init_netmap(QemuOpts *opts, Monitor *mon, const char *name, VLANState *vlan);
int net_init_netmap(QemuOpts *opts, Monitor *mon, const char *name, VLANState *vlan)
{
    VLANClientState *nc;
    struct netmap_state me;
    struct nm_state *s;

    fprintf(stderr, "=== %s for %s vlan %p\n", __FUNCTION__, name, vlan);
    /* force a default name */
    if (!qemu_opt_get(opts, "ifname"))
        qemu_opt_set(opts, "ifname", "vale0");
    pstrcpy(me.fdname, sizeof(me.fdname), name ? name : "/dev/netmap");
    pstrcpy(me.ifname, sizeof(me.ifname), qemu_opt_get(opts, "ifname"));
    if (netmap_open(&me))
	return -1;

    /* create the object -- use name or ifname ? */
    nc = qemu_new_net_client(&net_netmap_info, vlan, NULL, "netmap", name);
    s = DO_UPCAST(struct nm_state, nc, nc);
    s->me = me;
    netmap_read_poll(s, 1);

    return 0;
}
